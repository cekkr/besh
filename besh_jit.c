/*
 * besh_jit.c - BSH IR, WebAssembly lowering and the Fayasm execution driver.
 *
 * === What gets compiled ===
 *
 * A function body is normalised into single statements (the same splitting the
 * interpreter does), parsed once into the IR below, and lowered into one
 * WebAssembly function. Two tiers come out of the same IR:
 *
 *   kernel   every statement lowers to native WebAssembly. Variables live in
 *            wasm locals, integers are unboxed, and the body runs with no host
 *            calls at all. This is the tier `framework/strlib.bsh` and
 *            `framework/list.bsh` are written for.
 *
 *   general  statements lower to `besh.v1` host imports: scoped variable
 *            access, operator dispatch, function calls, builtins. Control flow
 *            is still real WebAssembly. Any statement the compiler does not
 *            model individually becomes a `raw` import that hands the original
 *            source line back to `process_line`, so every B[e]SH command and
 *            every syntax form remains available inside a compiled function.
 *
 * A function is only refused (and interpreted whole) when a statement would
 * open a block the compiler does not own - a nested `defunc`, for instance.
 *
 * === Values ===
 *
 * Everything on the wasm stack is a 32-bit handle:
 *
 *   bit0 = 1        small signed integer, value = (int32_t)h >> 1
 *   bit0=0, bit1=1  index into the permanent table (compile-time constants)
 *   bit0=0, bit1=0  index into the temporary table (per-invocation values)
 *
 * Handle 0 is the empty string. The temporary table is released back to a
 * mark when a compiled call returns, so recursion cannot leak it.
 *
 * === Abort word ===
 *
 * Offset 0 of the shared linear memory is reserved (besh_mem never allocates
 * there) and holds a non-zero value when a callee requested `return` or `exit`.
 * Compiled code checks it after any statement that can re-enter the
 * interpreter, which costs three instructions instead of a host call.
 */

#include "besh_core.h"
#include "besh_wasm.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "fa_wasm.h"
#include "fa_runtime.h"
#include "fa_job.h"

/* ------------------------------------------------------------------ */
/* Handles                                                             */
/* ------------------------------------------------------------------ */

#define H_INT_BIT   1u
#define H_PERM_BIT  2u
#define H_INT_MAX   1073741823
#define H_INT_MIN   (-1073741824)

#define H_MAKE_INT(v)   ((uint32_t)(((int32_t)(v) << 1) | 1))
#define H_IS_INT(h)     (((h) & H_INT_BIT) != 0)
#define H_GET_INT(h)    ((int32_t)(h) >> 1)
#define H_IS_PERM(h)    (((h) & (H_INT_BIT | H_PERM_BIT)) == H_PERM_BIT)
#define H_PERM_INDEX(h) ((h) >> 2)
#define H_TEMP_INDEX(h) ((h) >> 2)
#define H_MAKE_PERM(i)  (((uint32_t)(i) << 2) | H_PERM_BIT)
#define H_MAKE_TEMP(i)  ((uint32_t)(i) << 2)

typedef struct {
    char**   items;
    uint32_t count;
    uint32_t capacity;
} HandleTable;

static HandleTable g_perm;
static HandleTable g_temp;

static bool table_push(HandleTable* t, const char* text, uint32_t* out_index) {
    if (t->count == t->capacity) {
        uint32_t want = t->capacity ? t->capacity * 2 : 64;
        char** grown = (char**)realloc(t->items, want * sizeof(char*));
        if (!grown) return false;
        t->items = grown;
        t->capacity = want;
    }
    char* copy = strdup(text ? text : "");
    if (!copy) return false;
    t->items[t->count] = copy;
    *out_index = t->count++;
    return true;
}

static uint32_t handle_perm(const char* text) {
    uint32_t index = 0;
    if (!table_push(&g_perm, text, &index)) return 0;
    return H_MAKE_PERM(index);
}

static uint32_t handle_temp(const char* text) {
    if (!text || !*text) return H_MAKE_TEMP(0);
    uint32_t index = 0;
    if (!table_push(&g_temp, text, &index)) return H_MAKE_TEMP(0);
    return H_MAKE_TEMP(index);
}

/* Formats an integer handle into `scratch`; returns the text of any handle. */
static const char* handle_text(uint32_t h, char* scratch, size_t scratch_size) {
    if (H_IS_INT(h)) {
        snprintf(scratch, scratch_size, "%d", H_GET_INT(h));
        return scratch;
    }
    if (H_IS_PERM(h)) {
        uint32_t i = H_PERM_INDEX(h);
        return (i < g_perm.count) ? g_perm.items[i] : "";
    }
    uint32_t i = H_TEMP_INDEX(h);
    return (i < g_temp.count) ? g_temp.items[i] : "";
}

/* Converts a handle to a 32-bit integer, tolerating textual numbers. */
static int32_t handle_int(uint32_t h) {
    if (H_IS_INT(h)) return H_GET_INT(h);
    char scratch[32];
    const char* text = handle_text(h, scratch, sizeof(scratch));
    return (int32_t)strtol(text, NULL, 0);
}

static uint32_t temp_mark(void) { return g_temp.count; }

static void temp_release(uint32_t mark) {
    while (g_temp.count > mark) {
        free(g_temp.items[--g_temp.count]);
        g_temp.items[g_temp.count] = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* IR                                                                  */
/* ------------------------------------------------------------------ */

typedef enum {
    IE_CONST,    /* .handle is the value                          */
    IE_INTERP,   /* .handle is a template; host `expand`          */
    IE_VAR,      /* .handle is a name; host `get`                 */
    IE_LOCAL,    /* .local is a wasm local holding a handle       */
    IE_INDEX,    /* .handle base name, .a index                   */
    IE_BINOP,    /* .handle operator, .a lhs, .b rhs              */
    IE_UNOP,     /* .handle operator, .a operand, .local prefix   */
    IE_INTOP,    /* .opcode over untagged ints, .a, .b            */
    IE_INTOP1,   /* one-operand integer opcode, .a                */
    IE_LOAD,     /* .opcode is a wasm load, .a is the address     */
    IE_COMPARE   /* .handle operator, .a lhs, .b rhs; yields 0/1  */
} IRExprKind;

typedef struct IRExpr {
    IRExprKind kind;
    uint32_t   handle;
    uint32_t   local;
    uint8_t    opcode;
    /* IE_CONST only: the literal as a machine integer. Handles can carry a
     * small integer inline, but only 31 bits of one, so a literal outside that
     * range still needs its exact value for native code. */
    int32_t    ival;
    bool       has_ival;
    struct IRExpr* a;
    struct IRExpr* b;
} IRExpr;

typedef enum {
    IS_SET,      /* name/local <- value                                   */
    IS_SETIDX,   /* base[index] <- value                                  */
    IS_IF,
    IS_WHILE,
    IS_RETURN,
    IS_ECHO,
    IS_CALL,     /* command word plus argument expressions                */
    IS_PRIM,
    IS_MEM,
    IS_STORE,    /* native memory store                                   */
    IS_RAW       /* hand the source line back to process_line             */
} IRStmtKind;

#define IR_MAX_ARGS 16

typedef struct IRStmt {
    IRStmtKind kind;

    /* IS_SET / IS_SETIDX / IS_PRIM / IS_MEM result target */
    uint32_t   target_handle;  /* constant variable name             */
    IRExpr*    target;         /* computed variable name, when not constant */
    int        target_local;   /* >= 0 when promoted                 */

    uint32_t   handle;         /* command word, operator, prim op, raw line */
    uint8_t    opcode;         /* IS_STORE width opcode      */

    IRExpr*    value;
    IRExpr*    index;
    IRExpr*    cond;

    IRExpr*    args[IR_MAX_ARGS];
    int        arg_count;

    struct IRStmt* body;       /* IS_IF then-branch, IS_WHILE body */
    struct IRStmt* alt;        /* IS_IF else-branch                */
    struct IRStmt* next;
} IRStmt;

/* ------------------------------------------------------------------ */
/* Compiled unit                                                       */
/* ------------------------------------------------------------------ */

#define BESH_MAX_LOCAL_VARS 48

typedef struct CompiledUnit {
    char        name[MAX_VAR_NAME_LEN];
    bool        kernel;              /* every statement lowered natively */
    IRStmt*     body;

    /* promoted variables, in wasm local order after the parameters */
    char        local_names[BESH_MAX_LOCAL_VARS][MAX_VAR_NAME_LEN];
    int         local_count;
    int         param_count;

    uint32_t*   perm_handles;        /* constants owned by this unit */
    uint32_t    perm_count;
    uint32_t    perm_capacity;

    uint32_t    scratch_local;       /* wasm local used to reorder values */

    BeshBuf     bytes;               /* the emitted module            */
    uint32_t    entry_index;
    bool        ready;               /* emitted and usable            */
    bool        refused;             /* will never compile            */

    struct UnitRuntime* runtimes;

    struct CompiledUnit* next;
} CompiledUnit;

/* One parsed module plus runtime. A unit keeps several so that a recursive or
 * re-entrant call never executes two jobs on the same runtime. */
typedef struct UnitRuntime {
    WasmModule* module;
    fa_Runtime* runtime;
    uint32_t    mem_generation;
    bool        busy;
    struct UnitRuntime* next;
} UnitRuntime;

static CompiledUnit* g_units = NULL;
static BeshCompileMode g_mode = BESH_MODE_AUTO;
static int  g_exec_depth = 0;
static long g_compiled_calls = 0;
static long g_compiled_kernels = 0;
static long g_fallbacks = 0;
static long g_compile_failures = 0;
static long g_deopts = 0;
static bool g_initialised = false;

bool besh_jit_is_executing(void) { return g_exec_depth > 0; }

/* ------------------------------------------------------------------ */
/* Abort word                                                          */
/* ------------------------------------------------------------------ */

#define BESH_ABORT_ADDR 0u

static void abort_word_set(uint32_t value) {
    uint8_t* base = besh_mem_base();
    if (base) memcpy(base + BESH_ABORT_ADDR, &value, 4);
}

static uint32_t abort_word_get(void) {
    uint8_t* base = besh_mem_base();
    uint32_t value = 0;
    if (base) memcpy(&value, base + BESH_ABORT_ADDR, 4);
    return value;
}

/* Reflects the interpreter's unwind state into the shared memory word. */
static void abort_word_sync(void) {
    abort_word_set(current_exec_state == STATE_RETURN_REQUESTED ? 1u : 0u);
}

/* ------------------------------------------------------------------ */
/* Host imports (besh.v1)                                              */
/* ------------------------------------------------------------------ */

enum {
    IMP_GET = 0, IMP_SET, IMP_GETIDX, IMP_SETIDX, IMP_EXPAND,
    IMP_BINOP, IMP_UNOP, IMP_TRUTHY, IMP_PUSH, IMP_CALL,
    IMP_ECHO, IMP_PRIM, IMP_MEM, IMP_RAW, IMP_RET, IMP_TRAP,
    IMP_INT, IMP_COND, IMP_GUARD, IMP_BOX,
    IMP_COUNT
};

static const char* const kImportNames[IMP_COUNT] = {
    "get", "set", "getidx", "setidx", "expand",
    "binop", "unop", "truthy", "push", "call",
    "echo", "prim", "mem", "raw", "ret", "trap",
    "int", "cond", "guard", "box"
};

/* Argument vector shared by push/call/echo/prim/mem. */
#define BESH_HOST_ARGS 32
static char     g_host_args[BESH_HOST_ARGS][INPUT_BUFFER_SIZE];
static uint32_t g_host_arg_handles[BESH_HOST_ARGS];
static int      g_host_arg_count = 0;

static void host_args_reset(void) { g_host_arg_count = 0; }

static void host_args_push(uint32_t h) {
    if (g_host_arg_count >= BESH_HOST_ARGS) return;
    char scratch[32];
    const char* text = handle_text(h, scratch, sizeof(scratch));
    snprintf(g_host_args[g_host_arg_count], INPUT_BUFFER_SIZE, "%s", text);
    g_host_arg_handles[g_host_arg_count] = h;
    g_host_arg_count++;
}

static int host_arg(const fa_RuntimeHostCall* call, uint32_t index, uint32_t* out) {
    i32 value = 0;
    if (!fa_RuntimeHostCall_arg_i32(call, index, &value)) return 0;
    *out = (uint32_t)value;
    return 1;
}

static int host_ret(const fa_RuntimeHostCall* call, uint32_t value) {
    return fa_RuntimeHostCall_set_i32(call, 0, (i32)value) ? FA_RUNTIME_OK : FA_RUNTIME_ERR_TRAP;
}

static int host_get(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t name_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &name_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    const char* name = handle_text(name_h, scratch, sizeof(scratch));
    char* value = get_variable_scoped(name);
    return host_ret(call, handle_temp(value ? value : ""));
}

static int host_set(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t name_h, val_h;
    if (!fa_RuntimeHostCall_expect(call, 2, 0) ||
        !host_arg(call, 0, &name_h) || !host_arg(call, 1, &val_h)) return FA_RUNTIME_ERR_TRAP;
    char name_scratch[32], val_scratch[32];
    const char* name = handle_text(name_h, name_scratch, sizeof(name_scratch));
    const char* value = handle_text(val_h, val_scratch, sizeof(val_scratch));
    set_variable_scoped(name, value, false);
    return FA_RUNTIME_OK;
}

static int host_getidx(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t base_h, idx_h;
    if (!fa_RuntimeHostCall_expect(call, 2, 1) ||
        !host_arg(call, 0, &base_h) || !host_arg(call, 1, &idx_h)) return FA_RUNTIME_ERR_TRAP;
    char b[32], i[32];
    char* value = get_array_element_scoped(handle_text(base_h, b, sizeof(b)),
                                           handle_text(idx_h, i, sizeof(i)));
    return host_ret(call, handle_temp(value ? value : ""));
}

static int host_setidx(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t base_h, idx_h, val_h;
    if (!fa_RuntimeHostCall_expect(call, 3, 0) ||
        !host_arg(call, 0, &base_h) || !host_arg(call, 1, &idx_h) ||
        !host_arg(call, 2, &val_h)) return FA_RUNTIME_ERR_TRAP;
    char b[32], i[32], v[32];
    set_array_element_scoped(handle_text(base_h, b, sizeof(b)),
                             handle_text(idx_h, i, sizeof(i)),
                             handle_text(val_h, v, sizeof(v)));
    return FA_RUNTIME_OK;
}

static int host_expand(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t tmpl_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &tmpl_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    const char* tmpl = handle_text(tmpl_h, scratch, sizeof(scratch));
    static char expanded[INPUT_BUFFER_SIZE];
    expand_variables_in_string_advanced(tmpl, expanded, sizeof(expanded));
    return host_ret(call, handle_temp(expanded));
}

static int host_binop(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t op_h, a_h, b_h;
    if (!fa_RuntimeHostCall_expect(call, 3, 1) ||
        !host_arg(call, 0, &op_h) || !host_arg(call, 1, &a_h) || !host_arg(call, 2, &b_h))
        return FA_RUNTIME_ERR_TRAP;

    char op_scratch[32], a_scratch[32], b_scratch[32];
    const char* op = handle_text(op_h, op_scratch, sizeof(op_scratch));
    char lhs[INPUT_BUFFER_SIZE], rhs[INPUT_BUFFER_SIZE];
    snprintf(lhs, sizeof(lhs), "%s", handle_text(a_h, a_scratch, sizeof(a_scratch)));
    snprintf(rhs, sizeof(rhs), "%s", handle_text(b_h, b_scratch, sizeof(b_scratch)));

    OperatorDefinition* def = get_operator_definition(op);
    if (!def || def->bsh_handler_name[0] == '\0') {
        return host_ret(call, handle_temp("NO_HANDLER_ERROR"));
    }
    const char* args[2] = { lhs, rhs };
    char result[INPUT_BUFFER_SIZE];
    result[0] = '\0';
    if (!invoke_bsh_operator_handler(def->bsh_handler_name, op, 2, args,
                                     "__BESH_JIT_OP_RESULT", result, sizeof(result))) {
        return host_ret(call, handle_temp("EXPR_EVAL_ERROR"));
    }
    abort_word_sync();
    return host_ret(call, handle_temp(result));
}

static int host_unop(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t op_h, a_h, prefix;
    if (!fa_RuntimeHostCall_expect(call, 3, 1) ||
        !host_arg(call, 0, &op_h) || !host_arg(call, 1, &a_h) || !host_arg(call, 2, &prefix))
        return FA_RUNTIME_ERR_TRAP;
    char op_scratch[32], a_scratch[32];
    const char* op = handle_text(op_h, op_scratch, sizeof(op_scratch));
    char operand[INPUT_BUFFER_SIZE];
    snprintf(operand, sizeof(operand), "%s", handle_text(a_h, a_scratch, sizeof(a_scratch)));

    OperatorDefinition* def = get_operator_definition(op);
    if (!def || def->bsh_handler_name[0] == '\0') {
        return host_ret(call, handle_temp("NO_HANDLER_ERROR"));
    }
    const char* args[1] = { operand };
    char result[INPUT_BUFFER_SIZE];
    result[0] = '\0';
    if (!invoke_bsh_operator_handler(def->bsh_handler_name, op, 1, args,
                                     "__BESH_JIT_OP_RESULT", result, sizeof(result))) {
        return host_ret(call, handle_temp("UNARY_PREFIX_OP_ERROR"));
    }
    abort_word_sync();
    return host_ret(call, handle_temp(result));
}

static int host_truthy(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t h, if_semantics;
    if (!fa_RuntimeHostCall_expect(call, 2, 1) ||
        !host_arg(call, 0, &h) || !host_arg(call, 1, &if_semantics)) return FA_RUNTIME_ERR_TRAP;
    if (H_IS_INT(h)) return host_ret(call, H_GET_INT(h) != 0 ? 1u : 0u);
    char scratch[32];
    return host_ret(call,
        besh_value_is_true(handle_text(h, scratch, sizeof(scratch)), if_semantics != 0) ? 1u : 0u);
}

static int host_push(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t h;
    if (!fa_RuntimeHostCall_expect(call, 1, 0) || !host_arg(call, 0, &h)) return FA_RUNTIME_ERR_TRAP;
    host_args_push(h);
    return FA_RUNTIME_OK;
}

static int host_call(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t name_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &name_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    char name[MAX_VAR_NAME_LEN];
    snprintf(name, sizeof(name), "%s", handle_text(name_h, scratch, sizeof(scratch)));

    int argc = g_host_arg_count;
    static const char* argv[BESH_HOST_ARGS];
    for (int i = 0; i < argc; ++i) argv[i] = g_host_args[i];
    host_args_reset();

    char result[INPUT_BUFFER_SIZE];
    result[0] = '\0';
    besh_dispatch_command_values(name, argv, argc, result, sizeof(result));
    abort_word_sync();
    return host_ret(call, handle_temp(result));
}

static int host_echo(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    if (!fa_RuntimeHostCall_expect(call, 0, 0)) return FA_RUNTIME_ERR_TRAP;
    for (int i = 0; i < g_host_arg_count; ++i) {
        if (i) printf(" ");
        printf("%s", g_host_args[i]);
    }
    printf("\n");
    host_args_reset();
    return FA_RUNTIME_OK;
}

static int host_prim(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t op_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &op_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    char op[MAX_VAR_NAME_LEN];
    snprintf(op, sizeof(op), "%s", handle_text(op_h, scratch, sizeof(scratch)));

    char result[INPUT_BUFFER_SIZE];
    result[0] = '\0';
    if (!besh_prim_dispatch(op, g_host_args, g_host_arg_count, result, sizeof(result))) {
        snprintf(result, sizeof(result), "PRIM_ERR_UNKNOWN_OP");
    }
    host_args_reset();
    return host_ret(call, handle_temp(result));
}

static int host_mem(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t sub_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &sub_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    char sub[MAX_VAR_NAME_LEN];
    snprintf(sub, sizeof(sub), "%s", handle_text(sub_h, scratch, sizeof(scratch)));

    char result[INPUT_BUFFER_SIZE];
    char err[256];
    if (!besh_mem_command(sub, g_host_args, g_host_arg_count, result, sizeof(result), err, sizeof(err))) {
        fprintf(stderr, "mem: %s\n", err);
        snprintf(result, sizeof(result), "MEM_ERR");
    }
    host_args_reset();
    return host_ret(call, handle_temp(result));
}

static int host_raw(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t line_h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &line_h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    char line[MAX_LINE_LENGTH];
    snprintf(line, sizeof(line), "%s", handle_text(line_h, scratch, sizeof(scratch)));
    process_line(line, NULL, 0, STATE_NORMAL);
    abort_word_sync();
    return host_ret(call, abort_word_get());
}

static int host_ret_value(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t h;
    if (!fa_RuntimeHostCall_expect(call, 1, 0) || !host_arg(call, 0, &h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    snprintf(bsh_last_return_value, sizeof(bsh_last_return_value), "%s",
             handle_text(h, scratch, sizeof(scratch)));
    bsh_return_value_is_set = true;
    return FA_RUNTIME_OK;
}

static int host_trap(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t h;
    if (!fa_RuntimeHostCall_expect(call, 1, 0) || !host_arg(call, 0, &h)) return FA_RUNTIME_ERR_TRAP;
    char scratch[32];
    fprintf(stderr, "bsh (compiled): %s\n", handle_text(h, scratch, sizeof(scratch)));
    return FA_RUNTIME_ERR_TRAP;
}

/* Comparison for `if`/`while`, using the interpreter's own rules. */
static int host_cond(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t op_h, a_h, b_h;
    if (!fa_RuntimeHostCall_expect(call, 3, 1) ||
        !host_arg(call, 0, &op_h) || !host_arg(call, 1, &a_h) || !host_arg(call, 2, &b_h))
        return FA_RUNTIME_ERR_TRAP;
    char op_scratch[32], a_scratch[32], b_scratch[32];
    char lhs[INPUT_BUFFER_SIZE], rhs[INPUT_BUFFER_SIZE];
    snprintf(lhs, sizeof(lhs), "%s", handle_text(a_h, a_scratch, sizeof(a_scratch)));
    snprintf(rhs, sizeof(rhs), "%s", handle_text(b_h, b_scratch, sizeof(b_scratch)));
    const char* op = handle_text(op_h, op_scratch, sizeof(op_scratch));
    return host_ret(call, besh_compare_values(lhs, op, rhs) ? 1u : 0u);
}

/* Set when a kernel-tier prologue read a variable whose text does not behave
 * like the machine integer the kernel would treat it as. The compiled function
 * then bails out before doing anything and the interpreter runs the body. */
static bool g_kernel_guard_failed = false;

/* A value is safe to hold as a machine integer when it parses as one, or when
 * it is one of the spellings the interpreter also treats as zero/false. */
static bool value_behaves_as_int(const char* text) {
    if (!text || text[0] == '\0') return true;
    if (strcmp(text, "false") == 0) return true;
    const char* p = text;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '+' || *p == '-') p++;
    if (!isdigit((unsigned char)*p)) return false;
    while (isdigit((unsigned char)*p)) p++;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '\0';
}

/* Handle -> raw 32-bit integer, for the kernel-tier prologue. */
static int host_toint(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t h;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &h)) return FA_RUNTIME_ERR_TRAP;
    if (!H_IS_INT(h)) {
        char scratch[32];
        if (!value_behaves_as_int(handle_text(h, scratch, sizeof(scratch)))) {
            g_kernel_guard_failed = true;
        }
    }
    return host_ret(call, (uint32_t)handle_int(h));
}

/* Raw 32-bit integer -> handle. A handle only carries 31 bits inline, so
 * anything wider is interned as text rather than silently truncated. */
static int host_box(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    uint32_t raw;
    if (!fa_RuntimeHostCall_expect(call, 1, 1) || !host_arg(call, 0, &raw)) return FA_RUNTIME_ERR_TRAP;
    int32_t value = (int32_t)raw;
    if (value >= H_INT_MIN && value <= H_INT_MAX) return host_ret(call, H_MAKE_INT(value));
    char text[32];
    snprintf(text, sizeof(text), "%d", value);
    return host_ret(call, handle_temp(text));
}

static int host_guard(fa_Runtime* rt, const fa_RuntimeHostCall* call, void* ud) {
    (void)rt; (void)ud;
    if (!fa_RuntimeHostCall_expect(call, 0, 1)) return FA_RUNTIME_ERR_TRAP;
    return host_ret(call, g_kernel_guard_failed ? 1u : 0u);
}

static fa_RuntimeHostFunction host_function_for(int import_id) {
    switch (import_id) {
        case IMP_GET:    return host_get;
        case IMP_SET:    return host_set;
        case IMP_GETIDX: return host_getidx;
        case IMP_SETIDX: return host_setidx;
        case IMP_EXPAND: return host_expand;
        case IMP_BINOP:  return host_binop;
        case IMP_UNOP:   return host_unop;
        case IMP_TRUTHY: return host_truthy;
        case IMP_PUSH:   return host_push;
        case IMP_CALL:   return host_call;
        case IMP_ECHO:   return host_echo;
        case IMP_PRIM:   return host_prim;
        case IMP_MEM:    return host_mem;
        case IMP_RAW:    return host_raw;
        case IMP_RET:    return host_ret_value;
        case IMP_TRAP:   return host_trap;
        case IMP_INT:    return host_toint;
        case IMP_COND:   return host_cond;
        case IMP_GUARD:  return host_guard;
        case IMP_BOX:    return host_box;
        default:         return NULL;
    }
}

/* argument and result counts, in import order */
static const uint8_t kImportArgs[IMP_COUNT]    = { 1, 2, 2, 3, 1, 3, 3, 2, 1, 1, 0, 1, 1, 1, 1, 1, 1, 3, 0, 1 };
static const uint8_t kImportResults[IMP_COUNT] = { 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1 };

/* ------------------------------------------------------------------ */
/* Unit helpers                                                        */
/* ------------------------------------------------------------------ */

static uint32_t unit_const(CompiledUnit* unit, const char* text) {
    if (unit->perm_count == unit->perm_capacity) {
        uint32_t want = unit->perm_capacity ? unit->perm_capacity * 2 : 32;
        uint32_t* grown = (uint32_t*)realloc(unit->perm_handles, want * sizeof(uint32_t));
        if (!grown) return 0;
        unit->perm_handles = grown;
        unit->perm_capacity = want;
    }
    uint32_t h = handle_perm(text);
    unit->perm_handles[unit->perm_count++] = h;
    return h;
}

static int unit_local_index(CompiledUnit* unit, const char* name) {
    for (int i = 0; i < unit->local_count; ++i) {
        if (strcmp(unit->local_names[i], name) == 0) return i;
    }
    return -1;
}

static int unit_local_add(CompiledUnit* unit, const char* name) {
    int existing = unit_local_index(unit, name);
    if (existing >= 0) return existing;
    if (unit->local_count >= BESH_MAX_LOCAL_VARS) return -1;
    snprintf(unit->local_names[unit->local_count], MAX_VAR_NAME_LEN, "%s", name);
    return unit->local_count++;
}

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

/* "$name" or "${name}" -> name. Returns false for anything with a dot or a
 * bracket, which the interpreter resolves through its own expansion rules. */
static bool plain_var_name(const char* text, char* out, size_t out_size) {
    if (!text || text[0] != '$') return false;
    const char* p = text + 1;
    size_t len;
    if (*p == '{') {
        const char* close = strchr(p + 1, '}');
        if (!close || close[1] != '\0') return false;
        p++;
        len = (size_t)(close - p);
    } else {
        len = strlen(p);
    }
    if (len == 0 || len >= out_size) return false;
    for (size_t i = 0; i < len; ++i) {
        char c = p[i];
        if (!isalnum((unsigned char)c) && c != '_') return false;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

static bool token_has_expansion(const Token* t) {
    for (int i = 0; i < t->len; ++i) {
        if (t->text[i] == '$') return true;
    }
    return false;
}

static IRExpr* expr_new(IRExprKind kind) {
    IRExpr* e = (IRExpr*)calloc(1, sizeof(IRExpr));
    if (e) e->kind = kind;
    return e;
}

static void expr_free(IRExpr* e) {
    if (!e) return;
    expr_free(e->a);
    expr_free(e->b);
    free(e);
}

static void stmt_free(IRStmt* s) {
    while (s) {
        IRStmt* next = s->next;
        expr_free(s->value);
        expr_free(s->index);
        expr_free(s->cond);
        expr_free(s->target);
        for (int i = 0; i < s->arg_count; ++i) expr_free(s->args[i]);
        stmt_free(s->body);
        stmt_free(s->alt);
        free(s);
        s = next;
    }
}

/* Builds the IR for one operand token. */
static IRExpr* compile_operand(CompiledUnit* unit, const Token* t, bool* native_ok) {
    char buffer[INPUT_BUFFER_SIZE];
    char name[MAX_VAR_NAME_LEN];

    if (t->type == TOKEN_NUMBER) {
        snprintf(buffer, sizeof(buffer), "%.*s", t->len, t->text);
        char* end = NULL;
        long long value = strtoll(buffer, &end, 10);
        IRExpr* e = expr_new(IE_CONST);
        if (!e) return NULL;
        if (end && *end == '\0' && value >= -2147483648LL && value <= 4294967295LL) {
            e->has_ival = true;
            e->ival = (int32_t)(uint32_t)value;
        }
        if (e->has_ival && value >= H_INT_MIN && value <= H_INT_MAX) {
            e->handle = H_MAKE_INT((int32_t)value);
        } else {
            e->handle = unit_const(unit, buffer);
        }
        if (native_ok && !e->has_ival) *native_ok = false;
        return e;
    }

    if (t->type == TOKEN_STRING) {
        snprintf(buffer, sizeof(buffer), "%.*s", t->len, t->text);
        char unescaped[INPUT_BUFFER_SIZE];
        unescape_string(buffer, unescaped, sizeof(unescaped));
        /* A string that is nothing but one plain variable expands to exactly
         * that variable's value, so `"$i"` and `$i` compile identically. This
         * is what lets loop counters written the idiomatic way stay in wasm
         * locals. */
        if (plain_var_name(unescaped, name, sizeof(name))) {
            int local = unit_local_index(unit, name);
            if (local >= 0) {
                IRExpr* e = expr_new(IE_LOCAL);
                if (!e) return NULL;
                e->local = (uint32_t)local;
                return e;
            }
            IRExpr* e = expr_new(IE_VAR);
            if (!e) return NULL;
            e->handle = unit_const(unit, name);
            if (native_ok) *native_ok = false;
            return e;
        }
        IRExpr* e = expr_new(strchr(unescaped, '$') ? IE_INTERP : IE_CONST);
        if (!e) return NULL;
        e->handle = unit_const(unit, unescaped);
        if (native_ok && e->kind == IE_INTERP) *native_ok = false;
        return e;
    }

    if (t->type == TOKEN_VARIABLE) {
        snprintf(buffer, sizeof(buffer), "%.*s", t->len, t->text);
        if (plain_var_name(buffer, name, sizeof(name))) {
            int local = unit_local_index(unit, name);
            if (local >= 0) {
                IRExpr* e = expr_new(IE_LOCAL);
                if (!e) return NULL;
                e->local = (uint32_t)local;
                return e;
            }
            IRExpr* e = expr_new(IE_VAR);
            if (!e) return NULL;
            e->handle = unit_const(unit, name);
            if (native_ok) *native_ok = false;
            return e;
        }
        IRExpr* e = expr_new(IE_INTERP);
        if (!e) return NULL;
        e->handle = unit_const(unit, buffer);
        if (native_ok) *native_ok = false;
        return e;
    }

    /* Words are literal unless they carry a $, in which case the interpreter
     * would have expanded them. */
    snprintf(buffer, sizeof(buffer), "%.*s", t->len, t->text);
    IRExpr* e = expr_new(token_has_expansion(t) ? IE_INTERP : IE_CONST);
    if (!e) return NULL;
    e->handle = unit_const(unit, buffer);
    if (native_ok && e->kind == IE_INTERP) *native_ok = false;
    return e;
}

/* Precedence-climbing over the token range [start, end], mirroring the
 * interpreter's parse_expression_recursive but producing IR instead of a
 * value. Returns NULL when the range is not a shape the compiler models. */
static IRExpr* compile_expr_range(CompiledUnit* unit, Token* tokens, int start, int end,
                                  int min_precedence, int* consumed, bool* native_ok);

static IRExpr* compile_primary(CompiledUnit* unit, Token* tokens, int start, int end,
                               int* consumed, bool* native_ok) {
    if (start > end) return NULL;

    if (tokens[start].type == TOKEN_LPAREN) {
        int inner_used = 0;
        IRExpr* inner = compile_expr_range(unit, tokens, start + 1, end, 0, &inner_used, native_ok);
        if (!inner) return NULL;
        int close = start + 1 + inner_used;
        if (close > end || tokens[close].type != TOKEN_RPAREN) { expr_free(inner); return NULL; }
        *consumed = (close - start) + 1;
        return inner;
    }

    if (tokens[start].type == TOKEN_OPERATOR) {
        OperatorDefinition* def = get_operator_definition(tokens[start].text);
        if (!def || def->op_type_prop != OP_TYPE_UNARY_PREFIX) return NULL;
        int inner_used = 0;
        IRExpr* operand = compile_expr_range(unit, tokens, start + 1, end, def->precedence,
                                             &inner_used, native_ok);
        if (!operand) return NULL;
        IRExpr* e = expr_new(IE_UNOP);
        if (!e) { expr_free(operand); return NULL; }
        e->handle = unit_const(unit, def->op_str);
        e->a = operand;
        e->local = 1;
        if (native_ok) *native_ok = false;
        *consumed = 1 + inner_used;
        return e;
    }

    /* `$name[index]` */
    if (tokens[start].type == TOKEN_VARIABLE && start + 1 <= end &&
        tokens[start + 1].type == TOKEN_LBRACKET) {
        char raw[MAX_VAR_NAME_LEN], name[MAX_VAR_NAME_LEN];
        snprintf(raw, sizeof(raw), "%.*s", tokens[start].len, tokens[start].text);
        if (!plain_var_name(raw, name, sizeof(name))) return NULL;
        int inner_used = 0;
        IRExpr* index = compile_expr_range(unit, tokens, start + 2, end, 0, &inner_used, native_ok);
        if (!index) return NULL;
        int close = start + 2 + inner_used;
        if (close > end || tokens[close].type != TOKEN_RBRACKET) { expr_free(index); return NULL; }
        IRExpr* e = expr_new(IE_INDEX);
        if (!e) { expr_free(index); return NULL; }
        e->handle = unit_const(unit, name);
        e->a = index;
        if (native_ok) *native_ok = false;
        *consumed = (close - start) + 1;
        return e;
    }

    if (tokens[start].type == TOKEN_WORD || tokens[start].type == TOKEN_STRING ||
        tokens[start].type == TOKEN_NUMBER || tokens[start].type == TOKEN_VARIABLE) {
        IRExpr* e = compile_operand(unit, &tokens[start], native_ok);
        if (!e) return NULL;
        *consumed = 1;
        return e;
    }
    return NULL;
}

static IRExpr* compile_expr_range(CompiledUnit* unit, Token* tokens, int start, int end,
                                  int min_precedence, int* consumed, bool* native_ok) {
    int used = 0;
    IRExpr* left = compile_primary(unit, tokens, start, end, &used, native_ok);
    if (!left) return NULL;
    int pos = start + used;

    while (pos <= end && tokens[pos].type == TOKEN_OPERATOR) {
        OperatorDefinition* def = get_operator_definition(tokens[pos].text);
        if (!def) break;

        if (def->op_type_prop == OP_TYPE_UNARY_POSTFIX) {
            if (def->precedence < min_precedence) break;
            IRExpr* e = expr_new(IE_UNOP);
            if (!e) { expr_free(left); return NULL; }
            e->handle = unit_const(unit, def->op_str);
            e->a = left;
            e->local = 0;
            if (native_ok) *native_ok = false;
            left = e;
            pos++;
            continue;
        }
        if (def->op_type_prop != OP_TYPE_BINARY_INFIX) break;
        if (def->precedence < min_precedence) break;

        int next_min = (def->associativity == ASSOC_LEFT) ? def->precedence + 1 : def->precedence;
        int rhs_used = 0;
        IRExpr* right = compile_expr_range(unit, tokens, pos + 1, end, next_min, &rhs_used, native_ok);
        if (!right) { expr_free(left); return NULL; }

        IRExpr* e = expr_new(IE_BINOP);
        if (!e) { expr_free(left); expr_free(right); return NULL; }
        e->handle = unit_const(unit, def->op_str);
        e->a = left;
        e->b = right;
        if (native_ok) *native_ok = false;
        left = e;
        pos += 1 + rhs_used;
    }

    *consumed = pos - start;
    return left;
}

/* ------------------------------------------------------------------ */
/* Native integer and memory operations                                */
/* ------------------------------------------------------------------ */

/* `prim` operations the compiler lowers to raw WebAssembly. They are also
 * implemented in besh_prim_dispatch, so an interpreted run of the same source
 * produces the same values. */
static uint8_t int_binary_opcode(const char* op) {
    if (strcmp(op, "iadd") == 0) return OP_I32_ADD;
    if (strcmp(op, "isub") == 0) return OP_I32_SUB;
    if (strcmp(op, "imul") == 0) return OP_I32_MUL;
    if (strcmp(op, "idiv") == 0) return OP_I32_DIV_S;
    if (strcmp(op, "imod") == 0) return OP_I32_REM_S;
    if (strcmp(op, "iand") == 0) return OP_I32_AND;
    if (strcmp(op, "ior") == 0)  return OP_I32_OR;
    if (strcmp(op, "ixor") == 0) return OP_I32_XOR;
    if (strcmp(op, "ishl") == 0) return OP_I32_SHL;
    if (strcmp(op, "ishr") == 0) return OP_I32_SHR_S;
    if (strcmp(op, "ieq") == 0)  return OP_I32_EQ;
    if (strcmp(op, "ine") == 0)  return OP_I32_NE;
    if (strcmp(op, "ilt") == 0)  return OP_I32_LT_S;
    if (strcmp(op, "igt") == 0)  return OP_I32_GT_S;
    if (strcmp(op, "ile") == 0)  return OP_I32_LE_S;
    if (strcmp(op, "ige") == 0)  return OP_I32_GE_S;
    return 0;
}

static uint8_t int_unary_opcode(const char* op) {
    if (strcmp(op, "inot") == 0) return OP_I32_EQZ;
    return 0;
}

/* `mem` subcommands lowered to native loads and stores. */
static uint8_t mem_load_opcode(const char* sub, uint32_t* align) {
    if (strcmp(sub, "peek") == 0 || strcmp(sub, "peek8") == 0)  { *align = 0; return OP_I32_LOAD8_U; }
    if (strcmp(sub, "peek16") == 0) { *align = 1; return OP_I32_LOAD16_U; }
    if (strcmp(sub, "peek32") == 0) { *align = 2; return OP_I32_LOAD; }
    return 0;
}

static uint8_t mem_store_opcode(const char* sub, uint32_t* align) {
    if (strcmp(sub, "poke") == 0 || strcmp(sub, "poke8") == 0)  { *align = 0; return OP_I32_STORE8; }
    if (strcmp(sub, "poke16") == 0) { *align = 1; return OP_I32_STORE16; }
    if (strcmp(sub, "poke32") == 0) { *align = 2; return OP_I32_STORE; }
    return 0;
}

static bool expr_is_native(const IRExpr* e) {
    if (!e) return false;
    switch (e->kind) {
        case IE_CONST:  return e->has_ival;
        case IE_LOCAL:  return true;
        case IE_INTOP:  return expr_is_native(e->a) && expr_is_native(e->b);
        case IE_INTOP1: return expr_is_native(e->a);
        case IE_LOAD:   return expr_is_native(e->a);
        default:        return false;
    }
}

/* ------------------------------------------------------------------ */
/* Statement compilation                                               */
/* ------------------------------------------------------------------ */

/* Builtins the interpreter dispatches itself. Everything on this list is
 * handed back to `process_line` through the `raw` import, except the four
 * modelled natively below. Keep it in step with the chain in process_line. */
static bool is_interpreter_builtin(const char* word) {
    static const char* const kBuiltins[] = {
        "defkeyword", "defoperator", "if", "else", "while", "defunc",
        "loadlib", "calllib", "import", "update_cwd", "eval", "exit",
        "libloaded", "writefile", "readfile", "process", "bytecode",
        NULL
    };
    for (int i = 0; kBuiltins[i]; ++i) {
        if (strcmp(word, kBuiltins[i]) == 0) return true;
    }
    return false;
}

typedef enum { CLOSE_EOF = 0, CLOSE_BRACE = 1, CLOSE_ELSE = 2 } BlockClose;

typedef struct {
    CompiledUnit* unit;
    char**        lines;
    int           count;
    int           pos;
    bool          fatal;   /* a construct the compiler must not own */
} StmtParser;

static IRStmt* compile_block(StmtParser* p, BlockClose* close);

static IRStmt* stmt_new(IRStmtKind kind) {
    IRStmt* s = (IRStmt*)calloc(1, sizeof(IRStmt));
    if (s) { s->kind = kind; s->target_local = -1; }
    return s;
}

/* Compiles the token range [start,end] as one expression; NULL when the shape
 * is not modelled. */
static IRExpr* compile_full_expr(CompiledUnit* unit, Token* tokens, int start, int end) {
    if (start > end) return NULL;
    int used = 0;
    IRExpr* e = compile_expr_range(unit, tokens, start, end, 0, &used, NULL);
    if (!e) return NULL;
    if (start + used - 1 != end) { expr_free(e); return NULL; }
    return e;
}

/* advanced_tokenize_line terminates its output with TOKEN_EOF and may leave a
 * trailing comment; neither is part of the statement. */
static int statement_token_count(Token* tokens, int num_tokens) {
    for (int i = 0; i < num_tokens; ++i) {
        if (tokens[i].type == TOKEN_COMMENT || tokens[i].type == TOKEN_EOF) return i;
    }
    return num_tokens;
}

static IRStmt* compile_one(StmtParser* p, const char* line, Token* tokens, int num_tokens) {
    CompiledUnit* unit = p->unit;
    char word[MAX_VAR_NAME_LEN];

    /* --- assignment ------------------------------------------------- */
    if (num_tokens >= 3 && tokens[0].type == TOKEN_VARIABLE &&
        (tokens[1].type == TOKEN_ASSIGN ||
         (tokens[1].type == TOKEN_OPERATOR && strcmp(tokens[1].text, "=") == 0))) {

        char raw[MAX_VAR_NAME_LEN], name[MAX_VAR_NAME_LEN];
        snprintf(raw, sizeof(raw), "%.*s", tokens[0].len, tokens[0].text);
        if (!plain_var_name(raw, name, sizeof(name))) return NULL; /* indirect target */

        IRExpr* value = compile_full_expr(unit, tokens, 2, num_tokens - 1);
        if (!value) return NULL;

        IRStmt* s = stmt_new(IS_SET);
        if (!s) { expr_free(value); return NULL; }
        s->value = value;
        s->target_local = unit_local_index(unit, name);
        s->target_handle = unit_const(unit, name);
        return s;
    }

    /* --- indexed assignment: $arr[expr] = expr ---------------------- */
    if (num_tokens >= 5 && tokens[0].type == TOKEN_VARIABLE &&
        tokens[1].type == TOKEN_LBRACKET) {
        int close = -1, depth = 0;
        for (int i = 1; i < num_tokens; ++i) {
            if (tokens[i].type == TOKEN_LBRACKET) depth++;
            else if (tokens[i].type == TOKEN_RBRACKET) { if (--depth == 0) { close = i; break; } }
        }
        if (close > 0 && close + 1 < num_tokens &&
            (tokens[close + 1].type == TOKEN_ASSIGN ||
             (tokens[close + 1].type == TOKEN_OPERATOR && strcmp(tokens[close + 1].text, "=") == 0))) {
            char raw[MAX_VAR_NAME_LEN], name[MAX_VAR_NAME_LEN];
            snprintf(raw, sizeof(raw), "%.*s", tokens[0].len, tokens[0].text);
            if (!plain_var_name(raw, name, sizeof(name))) return NULL;
            IRExpr* index = compile_full_expr(unit, tokens, 2, close - 1);
            if (!index) return NULL;
            IRExpr* value = compile_full_expr(unit, tokens, close + 2, num_tokens - 1);
            if (!value) { expr_free(index); return NULL; }
            IRStmt* s = stmt_new(IS_SETIDX);
            if (!s) { expr_free(index); expr_free(value); return NULL; }
            s->target_handle = unit_const(unit, name);
            s->index = index;
            s->value = value;
            return s;
        }
        return NULL;
    }

    if (tokens[0].type != TOKEN_WORD) return NULL;

    const char* resolved = resolve_keyword_alias(tokens[0].text);
    snprintf(word, sizeof(word), "%s", resolved);

    /* --- if / while -------------------------------------------------- */
    if (strcmp(word, "if") == 0 || strcmp(word, "while") == 0) {
        if (num_tokens < 3 || tokens[num_tokens - 1].type != TOKEN_LBRACE) return NULL;

        /* `if` and `while` read their conditions differently, and neither uses
         * the generic expression path for the plain comparison form. Compiled
         * code has to make the same choices or the two tiers disagree. */
        bool is_if = (strcmp(word, "if") == 0);
        int cond_end = num_tokens - 1;
        if (tokens[cond_end].type == TOKEN_LBRACE) cond_end--;
        if (cond_end < 1) return NULL;

        IRExpr* cond = NULL;
        bool negate = false;
        bool compare_form = false;
        int idx = 1;

        if (is_if) {
            compare_form = (cond_end == 3 && tokens[2].type == TOKEN_OPERATOR &&
                            is_comparison_or_assignment_operator(tokens[2].text) &&
                            strcmp(tokens[2].text, "=") != 0);
        } else {
            if (tokens[idx].type == TOKEN_OPERATOR && strcmp(tokens[idx].text, "!") == 0) {
                negate = true;
                idx++;
                if (idx > cond_end) return NULL;
            }
            compare_form = (num_tokens >= idx + 3 && tokens[idx + 1].type == TOKEN_OPERATOR);
        }

        if (compare_form) {
            IRExpr* lhs = compile_operand(unit, &tokens[idx], NULL);
            IRExpr* rhs = lhs ? compile_operand(unit, &tokens[idx + 2], NULL) : NULL;
            if (!lhs || !rhs) { expr_free(lhs); expr_free(rhs); return NULL; }
            cond = expr_new(IE_COMPARE);
            if (!cond) { expr_free(lhs); expr_free(rhs); return NULL; }
            char op[MAX_OPERATOR_LEN + 1];
            snprintf(op, sizeof(op), "%.*s", tokens[idx + 1].len, tokens[idx + 1].text);
            cond->handle = unit_const(unit, op);
            cond->a = lhs;
            cond->b = rhs;
        } else if (is_if) {
            /* Everything else goes through the operator handlers, exactly as
             * handle_if_statement_advanced does. */
            cond = compile_full_expr(unit, tokens, 1, cond_end);
        } else {
            cond = compile_operand(unit, &tokens[idx], NULL);
        }
        if (!cond) return NULL;

        IRStmt* s = stmt_new(strcmp(word, "if") == 0 ? IS_IF : IS_WHILE);
        if (!s) { expr_free(cond); return NULL; }
        s->cond = cond;
        s->opcode = (uint8_t)((negate ? 1 : 0) | (is_if ? 2 : 0));

        BlockClose close = CLOSE_EOF;
        s->body = compile_block(p, &close);
        if (p->fatal) { stmt_free(s); return NULL; }
        if (s->kind == IS_IF && close == CLOSE_ELSE) {
            BlockClose else_close = CLOSE_EOF;
            s->alt = compile_block(p, &else_close);
            if (p->fatal) { stmt_free(s); return NULL; }
        }
        return s;
    }

    /* --- return ------------------------------------------------------ */
    if (strcmp(word, "return") == 0) {
        IRStmt* s = stmt_new(IS_RETURN);
        if (!s) return NULL;
        if (num_tokens > 1) {
            s->value = compile_full_expr(unit, tokens, 1, num_tokens - 1);
            if (!s->value) { stmt_free(s); return NULL; }
        }
        return s;
    }

    /* --- echo -------------------------------------------------------- */
    if (strcmp(word, "echo") == 0) {
        IRStmt* s = stmt_new(IS_ECHO);
        if (!s) return NULL;
        for (int i = 1; i < num_tokens && s->arg_count < IR_MAX_ARGS; ++i) {
            IRExpr* arg = compile_operand(unit, &tokens[i], NULL);
            if (!arg) { stmt_free(s); return NULL; }
            s->args[s->arg_count++] = arg;
        }
        return s;
    }

    /* --- prim -------------------------------------------------------- */
    if (strcmp(word, "prim") == 0) {
        if (num_tokens < 3 || tokens[1].type != TOKEN_WORD) return NULL;
        char op[MAX_VAR_NAME_LEN];
        snprintf(op, sizeof(op), "%.*s", tokens[1].len, tokens[1].text);

        /* The result variable is the last token, written as a bare name. A
         * token carrying a '$' names the destination indirectly, so it has to
         * be evaluated at run time. */
        const Token* target_token = &tokens[num_tokens - 1];
        char raw[MAX_VAR_NAME_LEN], target[MAX_VAR_NAME_LEN];
        snprintf(raw, sizeof(raw), "%.*s", target_token->len, target_token->text);
        bool plain_target = (target_token->type == TOKEN_WORD) && strchr(raw, '$') == NULL;
        snprintf(target, sizeof(target), "%s", raw);

        int arg_first = 2, arg_last = num_tokens - 2;
        uint8_t binary = int_binary_opcode(op);
        uint8_t unary = int_unary_opcode(op);

        /* Native integer form: prim iadd <a> <b> $result */
        if (binary && arg_last - arg_first == 1) {
            IRExpr* a = compile_operand(unit, &tokens[arg_first], NULL);
            IRExpr* b = compile_operand(unit, &tokens[arg_first + 1], NULL);
            if (a && b && expr_is_native(a) && expr_is_native(b) && plain_target) {
                IRExpr* e = expr_new(IE_INTOP);
                if (e) {
                    e->opcode = binary;
                    e->a = a;
                    e->b = b;
                    IRStmt* s = stmt_new(IS_SET);
                    if (s) {
                        s->value = e;
                        s->target_local = unit_local_index(unit, target);
                        s->target_handle = unit_const(unit, target);
                        return s;
                    }
                    expr_free(e);
                    a = b = NULL;
                }
            }
            expr_free(a);
            expr_free(b);
        }
        if (unary && arg_last == arg_first) {
            IRExpr* a = compile_operand(unit, &tokens[arg_first], NULL);
            if (a && expr_is_native(a) && plain_target) {
                IRExpr* e = expr_new(IE_INTOP1);
                if (e) {
                    e->opcode = unary;
                    e->a = a;
                    IRStmt* s = stmt_new(IS_SET);
                    if (s) {
                        s->value = e;
                        s->target_local = unit_local_index(unit, target);
                        s->target_handle = unit_const(unit, target);
                        return s;
                    }
                    expr_free(e);
                    a = NULL;
                }
            }
            expr_free(a);
        }

        IRStmt* s = stmt_new(IS_PRIM);
        if (!s) return NULL;
        s->handle = unit_const(unit, op);
        for (int i = arg_first; i <= arg_last && s->arg_count < IR_MAX_ARGS; ++i) {
            IRExpr* arg = compile_operand(unit, &tokens[i], NULL);
            if (!arg) { stmt_free(s); return NULL; }
            s->args[s->arg_count++] = arg;
        }
        if (plain_target) {
            s->target_local = unit_local_index(unit, target);
            s->target_handle = unit_const(unit, target);
        } else {
            s->target_local = -1;
            s->target = compile_operand(unit, target_token, NULL);
            if (!s->target) { stmt_free(s); return NULL; }
        }
        return s;
    }

    /* --- mem --------------------------------------------------------- */
    if (strcmp(word, "mem") == 0) {
        if (num_tokens < 3 || tokens[1].type != TOKEN_WORD) return NULL;
        char sub[MAX_VAR_NAME_LEN];
        snprintf(sub, sizeof(sub), "%.*s", tokens[1].len, tokens[1].text);

        uint32_t align = 0;
        uint8_t load = mem_load_opcode(sub, &align);
        uint8_t store = mem_store_opcode(sub, &align);

        /* Native load: mem peek32 <addr> $result */
        if (load && num_tokens == 4) {
            char raw[MAX_VAR_NAME_LEN], target[MAX_VAR_NAME_LEN];
            snprintf(raw, sizeof(raw), "%.*s", tokens[3].len, tokens[3].text);
            snprintf(target, sizeof(target), "%s", raw);
            IRExpr* addr = compile_operand(unit, &tokens[2], NULL);
            if (addr && expr_is_native(addr) &&
                tokens[3].type == TOKEN_WORD && strchr(raw, '$') == NULL) {
                IRExpr* e = expr_new(IE_LOAD);
                if (e) {
                    e->opcode = load;
                    e->local = align;
                    e->a = addr;
                    IRStmt* s = stmt_new(IS_SET);
                    if (s) {
                        s->value = e;
                        s->target_local = unit_local_index(unit, target);
                        s->target_handle = unit_const(unit, target);
                        return s;
                    }
                    expr_free(e);
                    addr = NULL;
                }
            }
            expr_free(addr);
        }
        /* Native store: mem poke32 <addr> <value> */
        if (store && num_tokens == 4) {
            IRExpr* addr = compile_operand(unit, &tokens[2], NULL);
            IRExpr* value = compile_operand(unit, &tokens[3], NULL);
            if (addr && value && expr_is_native(addr) && expr_is_native(value)) {
                IRStmt* s = stmt_new(IS_STORE);
                if (s) {
                    s->opcode = store;
                    s->handle = align;
                    s->index = addr;
                    s->value = value;
                    return s;
                }
            }
            expr_free(addr);
            expr_free(value);
        }

        IRStmt* s = stmt_new(IS_MEM);
        if (!s) return NULL;
        s->handle = unit_const(unit, sub);
        /* `mem free`, `mem copy` and friends produce no value and so have no
         * trailing result variable. */
        bool has_target = besh_mem_produces_value(sub) && num_tokens > 3;
        int arg_last = has_target ? num_tokens - 2 : num_tokens - 1;
        for (int i = 2; i <= arg_last && s->arg_count < IR_MAX_ARGS; ++i) {
            IRExpr* arg = compile_operand(unit, &tokens[i], NULL);
            if (!arg) { stmt_free(s); return NULL; }
            s->args[s->arg_count++] = arg;
        }
        s->target_local = -1;
        if (has_target) {
            const Token* target_token = &tokens[num_tokens - 1];
            char raw[MAX_VAR_NAME_LEN];
            snprintf(raw, sizeof(raw), "%.*s", target_token->len, target_token->text);
            if (target_token->type == TOKEN_WORD && strchr(raw, '$') == NULL) {
                s->target_local = unit_local_index(unit, raw);
                s->target_handle = unit_const(unit, raw);
            } else {
                s->target = compile_operand(unit, target_token, NULL);
                if (!s->target) { stmt_free(s); return NULL; }
            }
        } else {
            s->target_handle = 0;
        }
        return s;
    }

    /* --- other builtins go back to the interpreter -------------------- */
    if (is_interpreter_builtin(word)) {
        if (tokens[num_tokens - 1].type == TOKEN_LBRACE) {
            /* Opens a block the compiler does not own (a nested defunc). */
            p->fatal = true;
            return NULL;
        }
        IRStmt* s = stmt_new(IS_RAW);
        if (!s) return NULL;
        s->handle = unit_const(unit, line);
        return s;
    }

    /* --- user function, or an external command ------------------------ */
    {
        IRStmt* s = stmt_new(IS_CALL);
        if (!s) return NULL;
        s->handle = unit_const(unit, word);
        for (int i = 1; i < num_tokens && s->arg_count < IR_MAX_ARGS; ++i) {
            IRExpr* arg = compile_operand(unit, &tokens[i], NULL);
            if (!arg) { stmt_free(s); return NULL; }
            s->args[s->arg_count++] = arg;
        }
        return s;
    }
}

static IRStmt* compile_block(StmtParser* p, BlockClose* close) {
    IRStmt* head = NULL;
    IRStmt* tail = NULL;
    *close = CLOSE_EOF;

    while (p->pos < p->count && !p->fatal) {
        const char* line = p->lines[p->pos];
        Token tokens[MAX_ARGS];
        char storage[TOKEN_STORAGE_SIZE];
        int num_tokens = advanced_tokenize_line(line, 0, tokens, MAX_ARGS, storage, sizeof(storage));
        num_tokens = statement_token_count(tokens, num_tokens);
        if (num_tokens == 0) { p->pos++; continue; }

        if (tokens[0].type == TOKEN_RBRACE) {
            p->pos++;
            if (num_tokens >= 2 && tokens[1].type == TOKEN_WORD &&
                strcmp(resolve_keyword_alias(tokens[1].text), "else") == 0) {
                *close = CLOSE_ELSE;
            } else {
                *close = CLOSE_BRACE;
            }
            return head;
        }
        if (tokens[0].type == TOKEN_WORD &&
            strcmp(resolve_keyword_alias(tokens[0].text), "else") == 0) {
            /* A bare `else {` right after a closed block. */
            *close = CLOSE_ELSE;
            p->pos++;
            return head;
        }

        p->pos++;
        IRStmt* s = compile_one(p, line, tokens, num_tokens);
        if (getenv("BSH_COMPILE_DEBUG")) {
            fprintf(stderr, "[bytecode]   stmt '%s' -> %s (ntok=%d last=%d)\n", line,
                    s ? "modelled" : "raw", num_tokens,
                    num_tokens ? (int)tokens[num_tokens-1].type : -1);
        }
        if (!s) {
            if (p->fatal) { stmt_free(head); return NULL; }
            /* Not modelled: hand the original line back to the interpreter. */
            s = stmt_new(IS_RAW);
            if (!s) { stmt_free(head); p->fatal = true; return NULL; }
            s->handle = unit_const(p->unit, line);
        }
        if (tail) tail->next = s; else head = s;
        tail = s;
        while (tail->next) tail = tail->next;
    }
    return head;
}

/* Collects promotion candidates: the function's parameters first, so their
 * local indices follow the source order, then every plain `$name` mentioned in
 * the body - including the `"$name"` spelling, which the compiler treats as the
 * same reference. */
static void collect_locals(CompiledUnit* unit, char** lines, int count, UserFunction* func) {
    if (func) {
        for (int i = 0; i < func->param_count; ++i) unit_local_add(unit, func->params[i]);
    }
    for (int i = 0; i < count; ++i) {
        Token tokens[MAX_ARGS];
        char storage[TOKEN_STORAGE_SIZE];
        int num_tokens = advanced_tokenize_line(lines[i], 0, tokens, MAX_ARGS, storage, sizeof(storage));
        num_tokens = statement_token_count(tokens, num_tokens);
        for (int t = 0; t < num_tokens; ++t) {
            char raw[INPUT_BUFFER_SIZE], name[MAX_VAR_NAME_LEN];
            snprintf(raw, sizeof(raw), "%.*s", tokens[t].len, tokens[t].text);
            if (tokens[t].type == TOKEN_VARIABLE) {
                if (plain_var_name(raw, name, sizeof(name))) unit_local_add(unit, name);
            } else if (tokens[t].type == TOKEN_STRING) {
                char unescaped[INPUT_BUFFER_SIZE];
                unescape_string(raw, unescaped, sizeof(unescaped));
                if (plain_var_name(unescaped, name, sizeof(name))) unit_local_add(unit, name);
            }
        }
    }
}

/* True when every statement in the list lowers without a host import. */
static bool block_is_native(const IRStmt* s) {
    for (; s; s = s->next) {
        switch (s->kind) {
            case IS_SET:
                if (s->target_local < 0 || !expr_is_native(s->value)) return false;
                break;
            case IS_STORE:
                if (!expr_is_native(s->index) || !expr_is_native(s->value)) return false;
                break;
            case IS_IF:
                if (!expr_is_native(s->cond)) return false;
                if (!block_is_native(s->body) || !block_is_native(s->alt)) return false;
                break;
            case IS_WHILE:
                if (!expr_is_native(s->cond)) return false;
                if (!block_is_native(s->body)) return false;
                break;
            case IS_RETURN:
                if (s->value && !expr_is_native(s->value)) return false;
                break;
            default:
                return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Emission                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    CompiledUnit*   unit;
    BeshWasmModule* module;
    BeshBuf*        code;
    uint32_t        imports[IMP_COUNT];
    bool            kernel;
    bool            may_abort;
    bool            failed;
} EmitCtx;

static void emit_import(EmitCtx* ctx, int id) {
    besh_emit_op_u32(ctx->code, OP_CALL, ctx->imports[id]);
}

static void emit_abort_check(EmitCtx* ctx) {
    if (!ctx->may_abort) return;
    besh_emit_i32_const(ctx->code, (int32_t)BESH_ABORT_ADDR);
    besh_emit_mem(ctx->code, OP_I32_LOAD, 2, 0);
    besh_emit_op(ctx->code, OP_IF);
    besh_buf_u8(ctx->code, WT_VOID);
    besh_emit_op(ctx->code, OP_RETURN);
    besh_emit_op(ctx->code, OP_END);
    ctx->may_abort = false;
}

/* Pushes an untagged 32-bit integer. */
static void emit_int(EmitCtx* ctx, const IRExpr* e) {
    switch (e->kind) {
        case IE_CONST:
            besh_emit_i32_const(ctx->code, e->ival);
            break;
        case IE_LOCAL:
            besh_emit_op_u32(ctx->code, OP_LOCAL_GET, e->local);
            break;
        case IE_INTOP:
            emit_int(ctx, e->a);
            emit_int(ctx, e->b);
            besh_emit_op(ctx->code, e->opcode);
            break;
        case IE_INTOP1:
            emit_int(ctx, e->a);
            besh_emit_op(ctx->code, e->opcode);
            break;
        case IE_LOAD:
            emit_int(ctx, e->a);
            besh_emit_mem(ctx->code, e->opcode, e->local, 0);
            break;
        default:
            ctx->failed = true;
            break;
    }
}

/* Pushes a handle. */
static void emit_value(EmitCtx* ctx, const IRExpr* e) {
    if (!e) { besh_emit_i32_const(ctx->code, 0); return; }
    switch (e->kind) {
        case IE_CONST:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            break;
        case IE_LOCAL:
            /* A promoted local holds a raw integer; box it on the way out. */
            besh_emit_op_u32(ctx->code, OP_LOCAL_GET, e->local);
            emit_import(ctx, IMP_BOX);
            break;
        case IE_INTERP:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            emit_import(ctx, IMP_EXPAND);
            break;
        case IE_VAR:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            emit_import(ctx, IMP_GET);
            break;
        case IE_INDEX:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            emit_value(ctx, e->a);
            emit_import(ctx, IMP_GETIDX);
            break;
        case IE_BINOP:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            emit_value(ctx, e->a);
            emit_value(ctx, e->b);
            emit_import(ctx, IMP_BINOP);
            ctx->may_abort = true;
            break;
        case IE_UNOP:
            besh_emit_i32_const(ctx->code, (int32_t)e->handle);
            emit_value(ctx, e->a);
            besh_emit_i32_const(ctx->code, (int32_t)e->local);
            emit_import(ctx, IMP_UNOP);
            ctx->may_abort = true;
            break;
        case IE_INTOP:
        case IE_INTOP1:
        case IE_LOAD:
            emit_int(ctx, e);
            emit_import(ctx, IMP_BOX);
            break;
        default:
            ctx->failed = true;
            break;
    }
}

/* Leaves a 0/1 condition on the stack. */
static void emit_condition(EmitCtx* ctx, const IRExpr* cond, bool negate, bool if_semantics) {
    if (cond->kind == IE_COMPARE) {
        besh_emit_i32_const(ctx->code, (int32_t)cond->handle);
        emit_value(ctx, cond->a);
        emit_value(ctx, cond->b);
        emit_import(ctx, IMP_COND);
    } else if (expr_is_native(cond)) {
        emit_int(ctx, cond);
        /* Normalise to 0/1 so a later negation behaves. */
        besh_emit_op(ctx->code, OP_I32_EQZ);
        besh_emit_op(ctx->code, OP_I32_EQZ);
    } else {
        emit_value(ctx, cond);
        besh_emit_i32_const(ctx->code, if_semantics ? 1 : 0);
        emit_import(ctx, IMP_TRUTHY);
    }
    if (negate) besh_emit_op(ctx->code, OP_I32_EQZ);
}

static void emit_block(EmitCtx* ctx, const IRStmt* s);

static void emit_store_result(EmitCtx* ctx, const IRStmt* s) {
    /* The value handle is on the stack. */
    if (s->target_local >= 0 && ctx->kernel) {
        /* Kernel locals hold raw integers. */
        emit_import(ctx, IMP_INT);
        besh_emit_op_u32(ctx->code, OP_LOCAL_SET, (uint32_t)s->target_local);
        return;
    }
    if (!s->target && s->target_handle == 0) {
        besh_emit_op(ctx->code, OP_DROP);
        return;
    }
    /* set(name, value): the import wants the name first, so stash the value. */
    besh_emit_op_u32(ctx->code, OP_LOCAL_SET, ctx->unit->scratch_local);
    if (s->target) emit_value(ctx, s->target);
    else besh_emit_i32_const(ctx->code, (int32_t)s->target_handle);
    besh_emit_op_u32(ctx->code, OP_LOCAL_GET, ctx->unit->scratch_local);
    emit_import(ctx, IMP_SET);
}

static void emit_stmt(EmitCtx* ctx, const IRStmt* s) {
    switch (s->kind) {
        case IS_SET:
            if (ctx->kernel && s->target_local >= 0 && expr_is_native(s->value)) {
                emit_int(ctx, s->value);
                besh_emit_op_u32(ctx->code, OP_LOCAL_SET, (uint32_t)s->target_local);
            } else {
                emit_value(ctx, s->value);
                emit_store_result(ctx, s);
            }
            break;

        case IS_SETIDX:
            besh_emit_i32_const(ctx->code, (int32_t)s->target_handle);
            emit_value(ctx, s->index);
            emit_value(ctx, s->value);
            emit_import(ctx, IMP_SETIDX);
            break;

        case IS_STORE:
            emit_int(ctx, s->index);
            emit_int(ctx, s->value);
            besh_emit_mem(ctx->code, s->opcode, s->handle, 0);
            break;

        case IS_IF:
            emit_condition(ctx, s->cond, (s->opcode & 1) != 0, (s->opcode & 2) != 0);
            besh_emit_op(ctx->code, OP_IF);
            besh_buf_u8(ctx->code, WT_VOID);
            emit_block(ctx, s->body);
            if (s->alt) {
                besh_emit_op(ctx->code, OP_ELSE);
                emit_block(ctx, s->alt);
            }
            besh_emit_op(ctx->code, OP_END);
            break;

        case IS_WHILE:
            besh_emit_op(ctx->code, OP_BLOCK);
            besh_buf_u8(ctx->code, WT_VOID);
            besh_emit_op(ctx->code, OP_LOOP);
            besh_buf_u8(ctx->code, WT_VOID);
            emit_condition(ctx, s->cond, (s->opcode & 1) != 0, (s->opcode & 2) != 0);
            besh_emit_op(ctx->code, OP_I32_EQZ);
            besh_emit_op_u32(ctx->code, OP_BR_IF, 1);
            emit_block(ctx, s->body);
            besh_emit_op_u32(ctx->code, OP_BR, 0);
            besh_emit_op(ctx->code, OP_END);
            besh_emit_op(ctx->code, OP_END);
            break;

        case IS_RETURN:
            if (s->value) {
                emit_value(ctx, s->value);
                emit_import(ctx, IMP_RET);
            }
            besh_emit_op(ctx->code, OP_RETURN);
            break;

        case IS_ECHO:
            for (int i = 0; i < s->arg_count; ++i) {
                emit_value(ctx, s->args[i]);
                emit_import(ctx, IMP_PUSH);
            }
            emit_import(ctx, IMP_ECHO);
            break;

        case IS_CALL:
            for (int i = 0; i < s->arg_count; ++i) {
                emit_value(ctx, s->args[i]);
                emit_import(ctx, IMP_PUSH);
            }
            besh_emit_i32_const(ctx->code, (int32_t)s->handle);
            emit_import(ctx, IMP_CALL);
            besh_emit_op(ctx->code, OP_DROP);
            ctx->may_abort = true;
            break;

        case IS_PRIM:
        case IS_MEM:
            for (int i = 0; i < s->arg_count; ++i) {
                emit_value(ctx, s->args[i]);
                emit_import(ctx, IMP_PUSH);
            }
            besh_emit_i32_const(ctx->code, (int32_t)s->handle);
            emit_import(ctx, s->kind == IS_PRIM ? IMP_PRIM : IMP_MEM);
            emit_store_result(ctx, s);
            break;

        case IS_RAW:
            besh_emit_i32_const(ctx->code, (int32_t)s->handle);
            emit_import(ctx, IMP_RAW);
            besh_emit_op(ctx->code, OP_DROP);
            ctx->may_abort = true;
            break;
    }
    emit_abort_check(ctx);
}

static void emit_block(EmitCtx* ctx, const IRStmt* s) {
    for (; s && !ctx->failed; s = s->next) emit_stmt(ctx, s);
}


/* ------------------------------------------------------------------ */
/* Module construction                                                 */
/* ------------------------------------------------------------------ */

static void unit_release_ir(CompiledUnit* unit) {
    stmt_free(unit->body);
    unit->body = NULL;
}

static void unit_release_runtimes(CompiledUnit* unit) {
    UnitRuntime* r = unit->runtimes;
    while (r) {
        UnitRuntime* next = r->next;
        if (r->runtime) fa_Runtime_free(r->runtime);
        if (r->module) wasm_module_free(r->module);
        free(r);
        r = next;
    }
    unit->runtimes = NULL;
}

static void unit_reset(CompiledUnit* unit) {
    unit_release_ir(unit);
    unit_release_runtimes(unit);
    besh_buf_free(&unit->bytes);
    free(unit->perm_handles);
    unit->perm_handles = NULL;
    unit->perm_count = 0;
    unit->perm_capacity = 0;
    unit->local_count = 0;
    unit->ready = false;
    unit->kernel = false;
}

/* Emits the module for `unit` from its IR. */
static bool unit_emit(CompiledUnit* unit) {
    BeshWasmModule* module = besh_wasm_new();
    if (!module) return false;

    EmitCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.unit = unit;
    ctx.module = module;
    ctx.kernel = unit->kernel;

    /* Import types, then the imports themselves, then the shared memory. */
    uint8_t params[4] = { WT_I32, WT_I32, WT_I32, WT_I32 };
    uint8_t results[1] = { WT_I32 };
    for (int i = 0; i < IMP_COUNT; ++i) {
        uint32_t type_index = besh_wasm_type(module, params, kImportArgs[i],
                                             results, kImportResults[i]);
        ctx.imports[i] = besh_wasm_import_func(module, "besh.v1", kImportNames[i], type_index);
    }
    besh_wasm_import_memory(module, "besh.v1", "memory", 1);

    uint32_t entry_type = besh_wasm_type(module, NULL, 0, NULL, 0);
    uint32_t entry = besh_wasm_add_func(module, entry_type);

    for (int i = 0; i < unit->local_count; ++i) besh_wasm_add_local(module, entry, WT_I32);
    unit->scratch_local = besh_wasm_add_local(module, entry, WT_I32);

    ctx.code = besh_wasm_code(module, entry);
    if (!ctx.code) { besh_wasm_free(module); return false; }

    /* Kernel prologue: load each promoted variable into its local as a raw
     * integer. The general tier reads variables where it needs them. */
    if (unit->kernel) {
        for (int i = 0; i < unit->local_count; ++i) {
            besh_emit_i32_const(ctx.code, (int32_t)unit_const(unit, unit->local_names[i]));
            besh_emit_op_u32(ctx.code, OP_CALL, ctx.imports[IMP_GET]);
            besh_emit_op_u32(ctx.code, OP_CALL, ctx.imports[IMP_INT]);
            besh_emit_op_u32(ctx.code, OP_LOCAL_SET, (uint32_t)i);
        }
        /* If any of those values would not behave as a machine integer, leave
         * before the body runs. Nothing has been written yet, so the caller can
         * safely hand the whole body to the interpreter instead. */
        besh_emit_op_u32(ctx.code, OP_CALL, ctx.imports[IMP_GUARD]);
        besh_emit_op(ctx.code, OP_IF);
        besh_buf_u8(ctx.code, WT_VOID);
        besh_emit_op(ctx.code, OP_RETURN);
        besh_emit_op(ctx.code, OP_END);
    }

    emit_block(&ctx, unit->body);
    if (ctx.failed || ctx.code->failed) { besh_wasm_free(module); return false; }

    besh_wasm_export_func(module, "besh_entry", entry);

    besh_buf_free(&unit->bytes);
    bool ok = besh_wasm_finish(module, &unit->bytes);
    besh_wasm_free(module);
    if (!ok) { besh_buf_free(&unit->bytes); return false; }

    unit->entry_index = 0; /* resolved from the export table on first use */
    return true;
}

/* ------------------------------------------------------------------ */
/* Compiling a UserFunction                                            */
/* ------------------------------------------------------------------ */

#define BESH_MAX_STATEMENTS (MAX_FUNC_LINES * 4)

typedef struct {
    char* items[BESH_MAX_STATEMENTS];
    int   count;
    bool  owned[BESH_MAX_STATEMENTS];
} StatementList;

static void statements_free(StatementList* list) {
    for (int i = 0; i < list->count; ++i) {
        if (list->owned[i]) free(list->items[i]);
    }
    list->count = 0;
}

/* Normalises the stored body into one statement per entry, using the same
 * splitting the interpreter applies before dispatching a line. */
static bool statements_from_body(StatementList* list, UserFunction* func) {
    list->count = 0;
    for (int i = 0; i < func->line_count; ++i) {
        char* line = func->body[i];
        if (!line) continue;
        while (*line && isspace((unsigned char)*line)) line++;
        if (*line == '\0' || *line == '#') continue;

        if (besh_line_needs_statement_split(line)) {
            char* parts[32];
            int part_count = besh_split_line_into_statements(line, parts, 32);
            for (int k = 0; k < part_count; ++k) {
                if (list->count >= BESH_MAX_STATEMENTS) { free(parts[k]); continue; }
                list->items[list->count] = parts[k];
                list->owned[list->count] = true;
                list->count++;
            }
        } else {
            if (list->count >= BESH_MAX_STATEMENTS) return false;
            list->items[list->count] = line;
            list->owned[list->count] = false;
            list->count++;
        }
    }
    return true;
}

static bool unit_build_ir(CompiledUnit* unit, StatementList* list, UserFunction* func, bool try_kernel) {
    unit_release_ir(unit);
    unit->local_count = 0;
    unit->kernel = false;
    if (try_kernel) collect_locals(unit, list->items, list->count, func);

    StmtParser parser;
    parser.unit = unit;
    parser.lines = list->items;
    parser.count = list->count;
    parser.pos = 0;
    parser.fatal = false;

    BlockClose close = CLOSE_EOF;
    unit->body = compile_block(&parser, &close);
    if (getenv("BSH_COMPILE_DEBUG")) {
        fprintf(stderr, "[bytecode]   parse: fatal=%d close=%d pos=%d/%d\n",
                parser.fatal ? 1 : 0, (int)close, parser.pos, parser.count);
    }
    if (parser.fatal) { unit_release_ir(unit); return false; }
    if (close != CLOSE_EOF) { unit_release_ir(unit); return false; } /* unbalanced */

    if (try_kernel) {
        if (!block_is_native(unit->body)) { unit_release_ir(unit); return false; }
        unit->kernel = true;
    }
    return true;
}

static bool unit_compile(CompiledUnit* unit, UserFunction* func) {
    StatementList list;
    memset(&list, 0, sizeof(list));
    if (!statements_from_body(&list, func)) { statements_free(&list); return false; }

    unit_reset(unit);
    unit->param_count = func->param_count;
    if (getenv("BSH_COMPILE_DEBUG")) {
        fprintf(stderr, "[bytecode] %s: %d statements\n", func->name, list.count);
        for (int i = 0; i < list.count; ++i) fprintf(stderr, "[bytecode]   %2d| %s\n", i, list.items[i]);
    }

    /* Prefer the kernel tier; fall back to the general tier. */
    bool built = unit_build_ir(unit, &list, func, true);
    if (!built) {
        unit->perm_count = 0; /* constants from the abandoned attempt stay interned */
        built = unit_build_ir(unit, &list, func, false);
    }
    statements_free(&list);
    if (getenv("BSH_COMPILE_DEBUG")) {
        fprintf(stderr, "[bytecode] %s: ir=%s tier=%s\n", func->name,
                built ? "ok" : "failed", unit->kernel ? "kernel" : "general");
    }
    if (!built) return false;

    if (!unit_emit(unit)) {
        if (getenv("BSH_COMPILE_DEBUG")) fprintf(stderr, "[bytecode] %s: emit failed\n", func->name);
        unit_release_ir(unit);
        return false;
    }
    unit->ready = true;
    return true;
}

/* ------------------------------------------------------------------ */
/* Runtime pool                                                        */
/* ------------------------------------------------------------------ */

static bool runtime_bind_memory(UnitRuntime* slot) {
    fa_RuntimeHostMemory memory;
    memory.data = besh_mem_base();
    memory.size_bytes = besh_mem_size();
    if (!memory.data) return false;
    if (fa_Runtime_bindImportedMemory(slot->runtime, "besh.v1", "memory", &memory) != FA_RUNTIME_OK) {
        return false;
    }
    slot->mem_generation = besh_mem_generation();
    return true;
}

static bool runtime_find_entry(WasmModule* module, uint32_t* out_index) {
    if (!module || !module->exports) return false;
    for (uint32_t i = 0; i < module->num_exports; ++i) {
        if (module->exports[i].kind != 0 || !module->exports[i].name) continue;
        if (strcmp(module->exports[i].name, "besh_entry") == 0) {
            *out_index = module->exports[i].index;
            return true;
        }
    }
    return false;
}

static UnitRuntime* unit_acquire_runtime(CompiledUnit* unit) {
    for (UnitRuntime* r = unit->runtimes; r; r = r->next) {
        if (r->busy) continue;
        if (r->mem_generation != besh_mem_generation() && !runtime_bind_memory(r)) return NULL;
        r->busy = true;
        return r;
    }

    UnitRuntime* slot = (UnitRuntime*)calloc(1, sizeof(UnitRuntime));
    if (!slot) return NULL;

    bool debug = getenv("BSH_COMPILE_DEBUG") != NULL;
    slot->module = wasm_module_init_from_memory(unit->bytes.data, unit->bytes.len);
    if (!slot->module) { if (debug) fprintf(stderr, "[bytecode] module init failed\n"); free(slot); return NULL; }
    int step = 0;
    if ((step = 1, wasm_load_header(slot->module) != 0) ||
        (step = 2, wasm_scan_sections(slot->module) != 0) ||
        (step = 3, wasm_load_types(slot->module) != 0) ||
        (step = 4, wasm_load_functions(slot->module) != 0) ||
        (step = 5, wasm_load_exports(slot->module) != 0) ||
        (step = 6, wasm_load_tables(slot->module) != 0) ||
        (step = 7, wasm_load_memories(slot->module) != 0) ||
        (step = 8, wasm_load_globals(slot->module) != 0) ||
        (step = 9, wasm_load_elements(slot->module) != 0) ||
        (step = 10, wasm_load_data(slot->module) != 0)) {
        if (debug) fprintf(stderr, "[bytecode] module load failed at step %d\n", step);
        wasm_module_free(slot->module);
        free(slot);
        return NULL;
    }

    slot->runtime = fa_Runtime_init();
    if (!slot->runtime) { wasm_module_free(slot->module); free(slot); return NULL; }

    /* An imported memory has to be bound before the module is attached:
     * fa_Runtime_attachModule resolves memory imports as part of attaching. */
    if (!runtime_bind_memory(slot)) {
        if (debug) fprintf(stderr, "[bytecode] memory bind failed\n");
        fa_Runtime_free(slot->runtime);
        wasm_module_free(slot->module);
        free(slot);
        return NULL;
    }
    if (fa_Runtime_attachModule(slot->runtime, slot->module) != FA_RUNTIME_OK) {
        if (debug) fprintf(stderr, "[bytecode] attach failed\n");
        fa_Runtime_free(slot->runtime);
        wasm_module_free(slot->module);
        free(slot);
        return NULL;
    }
    for (int i = 0; i < IMP_COUNT; ++i) {
        if (fa_Runtime_bindHostFunction(slot->runtime, "besh.v1", kImportNames[i],
                                        host_function_for(i), unit) != FA_RUNTIME_OK) {
            if (debug) fprintf(stderr, "[bytecode] bind '%s' failed\n", kImportNames[i]);
            fa_Runtime_free(slot->runtime);
            wasm_module_free(slot->module);
            free(slot);
            return NULL;
        }
    }
    if (!runtime_find_entry(slot->module, &unit->entry_index)) {
        if (debug) fprintf(stderr, "[bytecode] entry export not found\n");
        fa_Runtime_free(slot->runtime);
        wasm_module_free(slot->module);
        free(slot);
        return NULL;
    }

    slot->busy = true;
    slot->next = unit->runtimes;
    unit->runtimes = slot;
    return slot;
}

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

static CompiledUnit* unit_find(const char* name) {
    for (CompiledUnit* u = g_units; u; u = u->next) {
        if (strcmp(u->name, name) == 0) return u;
    }
    return NULL;
}

static CompiledUnit* unit_create(const char* name) {
    CompiledUnit* unit = (CompiledUnit*)calloc(1, sizeof(CompiledUnit));
    if (!unit) return NULL;
    snprintf(unit->name, sizeof(unit->name), "%s", name);
    besh_buf_init(&unit->bytes);
    unit->next = g_units;
    g_units = unit;
    return unit;
}

void besh_jit_init(void) {
    if (g_initialised) return;
    g_initialised = true;
    besh_mem_init(0);
    /* Handle 0 must be the empty string. */
    uint32_t unused = 0;
    if (g_temp.count == 0) table_push(&g_temp, "", &unused);
    abort_word_set(0);

    const char* mode = getenv("BSH_COMPILE");
    if (mode) {
        if (strcmp(mode, "off") == 0) g_mode = BESH_MODE_OFF;
        else if (strcmp(mode, "force") == 0) g_mode = BESH_MODE_FORCE;
        else g_mode = BESH_MODE_AUTO;
    }
}

void besh_jit_shutdown(void) {
    CompiledUnit* unit = g_units;
    while (unit) {
        CompiledUnit* next = unit->next;
        unit_reset(unit);
        free(unit);
        unit = next;
    }
    g_units = NULL;
    for (uint32_t i = 0; i < g_perm.count; ++i) free(g_perm.items[i]);
    free(g_perm.items);
    memset(&g_perm, 0, sizeof(g_perm));
    for (uint32_t i = 0; i < g_temp.count; ++i) free(g_temp.items[i]);
    free(g_temp.items);
    memset(&g_temp, 0, sizeof(g_temp));
    besh_mem_shutdown();
    g_initialised = false;
}

BeshCompileMode besh_jit_get_mode(void) { return g_mode; }

void besh_jit_set_mode(BeshCompileMode mode) {
    if (mode != g_mode) besh_jit_invalidate_all("compile mode changed");
    g_mode = mode;
}

void besh_jit_invalidate_all(const char* reason) {
    (void)reason;
    if (g_exec_depth > 0) return; /* a module on the stack must not be freed */
    for (CompiledUnit* u = g_units; u; u = u->next) {
        unit_reset(u);
        u->refused = false;
    }
}

void besh_jit_invalidate_function(const char* name) {
    if (g_exec_depth > 0) return;
    CompiledUnit* unit = unit_find(name);
    if (unit) { unit_reset(unit); unit->refused = false; }
}

BeshRunStatus besh_jit_run_function(UserFunction* func) {
    if (!func || g_mode == BESH_MODE_OFF) return BESH_RUN_FALLBACK;
    besh_jit_init();

    CompiledUnit* unit = unit_find(func->name);
    if (!unit) unit = unit_create(func->name);
    if (!unit) return BESH_RUN_FALLBACK;
    if (unit->refused) { g_fallbacks++; return BESH_RUN_FALLBACK; }

    if (!unit->ready) {
        if (!unit_compile(unit, func)) {
            unit->refused = true;
            g_compile_failures++;
            if (g_mode == BESH_MODE_FORCE) {
                fprintf(stderr, "bytecode: cannot compile function '%s'\n", func->name);
            }
            g_fallbacks++;
            return BESH_RUN_FALLBACK;
        }
    }

    UnitRuntime* slot = unit_acquire_runtime(unit);
    if (!slot) {
        unit->refused = true;
        g_compile_failures++;
        if (g_mode == BESH_MODE_FORCE) {
            fprintf(stderr, "bytecode: cannot instantiate module for '%s'\n", func->name);
        }
        g_fallbacks++;
        return BESH_RUN_FALLBACK;
    }

    fa_Job* job = fa_Runtime_createJob(slot->runtime);
    if (!job) { slot->busy = false; g_fallbacks++; return BESH_RUN_FALLBACK; }

    uint32_t mark = temp_mark();
    int saved_args = g_host_arg_count;
    bool saved_guard = g_kernel_guard_failed;
    g_host_arg_count = 0;
    g_kernel_guard_failed = false;
    abort_word_set(0);
    besh_mem_lock(true);
    g_exec_depth++;

    int status = fa_Runtime_executeJob(slot->runtime, job, unit->entry_index);

    g_exec_depth--;
    if (g_exec_depth == 0) besh_mem_lock(false);
    g_host_arg_count = saved_args;
    temp_release(mark);
    abort_word_set(0);

    (void)fa_Runtime_destroyJob(slot->runtime, job);
    slot->busy = false;

    bool deoptimised = g_kernel_guard_failed;
    g_kernel_guard_failed = saved_guard;
    if (deoptimised && status == FA_RUNTIME_OK) {
        /* The kernel prologue bailed out; the body never ran. */
        g_deopts++;
        g_fallbacks++;
        return BESH_RUN_FALLBACK;
    }

    g_compiled_calls++;
    if (unit->kernel) g_compiled_kernels++;

    if (status != FA_RUNTIME_OK) {
        fprintf(stderr, "bytecode: function '%s' trapped (fayasm status %d)\n", func->name, status);
        return BESH_RUN_ERROR;
    }
    return BESH_RUN_OK;
}

/* ------------------------------------------------------------------ */
/* Builtins                                                            */
/* ------------------------------------------------------------------ */

/* Expands one token the way the interpreter's command handlers do. */
static void expand_token(const Token* t, char* out, size_t out_size) {
    char raw[INPUT_BUFFER_SIZE];
    snprintf(raw, sizeof(raw), "%.*s", t->len, t->text);
    if (t->type == TOKEN_STRING) {
        char unescaped[INPUT_BUFFER_SIZE];
        unescape_string(raw, unescaped, sizeof(unescaped));
        expand_variables_in_string_advanced(unescaped, out, out_size);
    } else {
        expand_variables_in_string_advanced(raw, out, out_size);
    }
}

void handle_mem_statement(Token* tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    if (num_tokens < 2) {
        fprintf(stderr, "Syntax: mem <subcommand> [args...] [result_var]\n");
        return;
    }
    besh_jit_init();

    static char expanded[MAX_CALL_ARGS][INPUT_BUFFER_SIZE];
    int count = 0;
    for (int i = 1; i < num_tokens && count < MAX_CALL_ARGS; ++i) {
        if (tokens[i].type == TOKEN_COMMENT) break;
        expand_token(&tokens[i], expanded[count], INPUT_BUFFER_SIZE);
        count++;
    }
    if (count < 1) { fprintf(stderr, "mem: missing subcommand.\n"); return; }

    char sub[MAX_VAR_NAME_LEN];
    snprintf(sub, sizeof(sub), "%s", expanded[0]);

    /* Value-producing subcommands end with a result variable, exactly like
     * `prim`; the rest take only their operands. */
    bool has_result = besh_mem_produces_value(sub);
    char result_var[MAX_VAR_NAME_LEN];
    result_var[0] = '\0';
    int arg_count = count - 1;
    if (has_result) {
        if (arg_count < 1) {
            fprintf(stderr, "mem %s: missing result variable name.\n", sub);
            return;
        }
        snprintf(result_var, sizeof(result_var), "%s", expanded[count - 1]);
        trim_whitespace(result_var);
        arg_count--;
    }

    char result[INPUT_BUFFER_SIZE];
    char err[256];
    if (!besh_mem_command(sub, &expanded[1], arg_count, result, sizeof(result), err, sizeof(err))) {
        fprintf(stderr, "mem: %s\n", err);
        set_variable_scoped("LAST_MEM_STATUS", "1", false);
        if (result_var[0]) set_variable_scoped(result_var, "MEM_ERR", false);
        return;
    }
    set_variable_scoped("LAST_MEM_STATUS", "0", false);
    if (result_var[0]) set_variable_scoped(result_var, result, false);
}

void handle_bytecode_statement(Token* tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    besh_jit_init();

    static char expanded[MAX_CALL_ARGS][INPUT_BUFFER_SIZE];
    int count = 0;
    for (int i = 1; i < num_tokens && count < MAX_CALL_ARGS; ++i) {
        if (tokens[i].type == TOKEN_COMMENT) break;
        expand_token(&tokens[i], expanded[count], INPUT_BUFFER_SIZE);
        count++;
    }

    if (count == 0 || strcmp(expanded[0], "status") == 0) {
        const char* mode = (g_mode == BESH_MODE_OFF) ? "off"
                         : (g_mode == BESH_MODE_FORCE) ? "force" : "auto";
        printf("bytecode: mode=%s calls=%ld kernels=%ld fallbacks=%ld refused=%ld deopts=%ld heap=%u bytes\n",
               mode, g_compiled_calls, g_compiled_kernels, g_fallbacks, g_compile_failures,
               g_deopts, besh_mem_size());
        return;
    }

    if (strcmp(expanded[0], "mode") == 0) {
        if (count < 2) {
            const char* mode = (g_mode == BESH_MODE_OFF) ? "off"
                             : (g_mode == BESH_MODE_FORCE) ? "force" : "auto";
            set_variable_scoped("LAST_BYTECODE_MODE", mode, false);
            printf("%s\n", mode);
            return;
        }
        if (strcmp(expanded[1], "off") == 0) besh_jit_set_mode(BESH_MODE_OFF);
        else if (strcmp(expanded[1], "auto") == 0) besh_jit_set_mode(BESH_MODE_AUTO);
        else if (strcmp(expanded[1], "force") == 0) besh_jit_set_mode(BESH_MODE_FORCE);
        else fprintf(stderr, "bytecode mode: expected off, auto or force\n");
        return;
    }

    if (strcmp(expanded[0], "invalidate") == 0) {
        if (count >= 2) besh_jit_invalidate_function(expanded[1]);
        else besh_jit_invalidate_all("requested");
        return;
    }

    if (strcmp(expanded[0], "compile") == 0 || strcmp(expanded[0], "info") == 0) {
        if (count < 2) { fprintf(stderr, "bytecode %s <function> [result_var]\n", expanded[0]); return; }
        UserFunction* func = function_list;
        while (func && strcmp(func->name, expanded[1]) != 0) func = func->next;
        if (!func) {
            fprintf(stderr, "bytecode: no function named '%s'\n", expanded[1]);
            if (count >= 3) set_variable_scoped(expanded[2], "missing", false);
            return;
        }
        CompiledUnit* unit = unit_find(func->name);
        if (!unit) unit = unit_create(func->name);
        if (!unit) return;
        if (!unit->ready && !unit->refused) {
            if (!unit_compile(unit, func)) unit->refused = true;
        }
        const char* tier = unit->refused ? "interpreted" : (unit->kernel ? "kernel" : "general");
        if (count >= 3) {
            set_variable_scoped(expanded[2], tier, false);
        } else {
            printf("%s: %s (%zu module bytes, %d promoted locals)\n",
                   func->name, tier, unit->ready ? unit->bytes.len : (size_t)0, unit->local_count);
        }
        return;
    }

    if (strcmp(expanded[0], "dump") == 0) {
        if (count < 2) { fprintf(stderr, "bytecode dump <function>\n"); return; }
        CompiledUnit* unit = unit_find(expanded[1]);
        if (!unit || !unit->ready) { fprintf(stderr, "bytecode: '%s' is not compiled\n", expanded[1]); return; }
        for (size_t i = 0; i < unit->bytes.len; ++i) {
            printf("%02x", unit->bytes.data[i]);
            if ((i % 32) == 31) printf("\n");
        }
        if (unit->bytes.len % 32) printf("\n");
        return;
    }

    fprintf(stderr, "bytecode: unknown subcommand '%s'\n", expanded[0]);
}
