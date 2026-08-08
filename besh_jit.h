/*
 * besh_jit.h - the compiled (bytecode) execution path.
 *
 * A BSH function body is parsed once into an intermediate representation,
 * lowered to a WebAssembly module by besh_wasm.c, and executed by the pinned
 * Fayasm runtime. Shell state stays in the C core: compiled code reaches
 * variables, operators and other functions through the versioned `besh.v1`
 * host imports, and reaches the heap directly through the shared linear
 * memory described in besh_mem.h.
 *
 * The interpreter remains the reference implementation. Anything the compiler
 * cannot lower keeps running through `process_line`, either as a whole
 * function (mode `auto` falls back) or one statement at a time (the `raw`
 * host import).
 */
#ifndef BESH_JIT_H
#define BESH_JIT_H

#include <stdbool.h>
#include <stddef.h>

/* besh_core.h includes this header after Token and UserFunction exist. */
struct UserFunction;

typedef enum {
    BESH_MODE_OFF = 0,   /* interpreter only                                   */
    BESH_MODE_AUTO = 1,  /* compile what is supported, interpret the rest      */
    BESH_MODE_FORCE = 2  /* report anything that will not compile              */
} BeshCompileMode;

typedef enum {
    BESH_RUN_FALLBACK = 0, /* not compiled; the interpreter must run the body */
    BESH_RUN_OK = 1,       /* the body ran as bytecode                        */
    BESH_RUN_ERROR = 2     /* the body ran as bytecode and trapped            */
} BeshRunStatus;

void besh_jit_init(void);
void besh_jit_shutdown(void);

BeshCompileMode besh_jit_get_mode(void);
void            besh_jit_set_mode(BeshCompileMode mode);

/* Runs `func`'s body as bytecode if it can. The caller has already created the
 * function scope and bound the parameters. */
BeshRunStatus besh_jit_run_function(struct UserFunction* func);

/* Drops every cached module. Called when `defoperator`, `defkeyword` or a
 * redefinition changes how source would be parsed or resolved. */
void besh_jit_invalidate_all(const char* reason);

/* Drops the cached module for one function, by name. */
void besh_jit_invalidate_function(const char* name);

/* Built-ins implemented by the bytecode path. */
void handle_bytecode_statement(Token* tokens, int num_tokens);
void handle_mem_statement(Token* tokens, int num_tokens);

/* Set while compiled code is on the C stack, so that anything which would move
 * the heap knows to refuse. */
bool besh_jit_is_executing(void);

#endif /* BESH_JIT_H */
