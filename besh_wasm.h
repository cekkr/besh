/*
 * besh_wasm.h - a small WebAssembly binary writer.
 *
 * This is the "bytecode" half of the compiled path: it turns emitted
 * instructions into the bytes of a complete in-memory module that Fayasm can
 * parse with `wasm_module_init_from_memory`. It knows nothing about BSH.
 *
 * Only the sections the B[e]SH compiler actually needs are produced: type,
 * import (host functions plus the shared linear memory), function, export and
 * code. Indices follow the WebAssembly rule that imported functions occupy the
 * low end of the function index space, so every import must be declared before
 * the first defined function.
 */
#ifndef BESH_WASM_H
#define BESH_WASM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- value types ----------------------------------------------------- */
#define WT_I32 0x7F
#define WT_I64 0x7E
#define WT_F32 0x7D
#define WT_F64 0x7C
#define WT_VOID 0x40 /* empty block type */

/* --- opcodes used by the emitter ------------------------------------- */
#define OP_UNREACHABLE 0x00
#define OP_NOP         0x01
#define OP_BLOCK       0x02
#define OP_LOOP        0x03
#define OP_IF          0x04
#define OP_ELSE        0x05
#define OP_END         0x0B
#define OP_BR          0x0C
#define OP_BR_IF       0x0D
#define OP_RETURN      0x0F
#define OP_CALL        0x10
#define OP_DROP        0x1A
#define OP_SELECT      0x1B
#define OP_LOCAL_GET   0x20
#define OP_LOCAL_SET   0x21
#define OP_LOCAL_TEE   0x22
#define OP_I32_LOAD    0x28
#define OP_I64_LOAD    0x29
#define OP_F64_LOAD    0x2B
#define OP_I32_LOAD8_U 0x2D
#define OP_I32_LOAD16_U 0x2F
#define OP_I32_STORE   0x36
#define OP_I64_STORE   0x37
#define OP_F64_STORE   0x39
#define OP_I32_STORE8  0x3A
#define OP_I32_STORE16 0x3B
#define OP_I32_CONST   0x41
#define OP_I64_CONST   0x42
#define OP_F64_CONST   0x44
#define OP_I32_EQZ     0x45
#define OP_I32_EQ      0x46
#define OP_I32_NE      0x47
#define OP_I32_LT_S    0x48
#define OP_I32_GT_S    0x4A
#define OP_I32_LE_S    0x4C
#define OP_I32_GE_S    0x4E
#define OP_I32_ADD     0x6A
#define OP_I32_SUB     0x6B
#define OP_I32_MUL     0x6C
#define OP_I32_DIV_S   0x6D
#define OP_I32_REM_S   0x6F
#define OP_I32_AND     0x71
#define OP_I32_OR      0x72
#define OP_I32_XOR     0x73
#define OP_I32_SHL     0x74
#define OP_I32_SHR_S   0x75
#define OP_F64_ADD     0xA0
#define OP_F64_SUB     0xA1
#define OP_F64_MUL     0xA2
#define OP_F64_DIV     0xA3

/* --- growable byte buffer -------------------------------------------- */

typedef struct {
    uint8_t* data;
    size_t   len;
    size_t   cap;
    bool     failed;  /* sticky: set when an allocation failed */
} BeshBuf;

void besh_buf_init(BeshBuf* b);
void besh_buf_free(BeshBuf* b);
void besh_buf_reset(BeshBuf* b);
void besh_buf_u8(BeshBuf* b, uint8_t v);
void besh_buf_bytes(BeshBuf* b, const void* data, size_t n);
void besh_buf_uleb(BeshBuf* b, uint64_t v);
void besh_buf_sleb(BeshBuf* b, int64_t v);
void besh_buf_f64(BeshBuf* b, double v);
void besh_buf_name(BeshBuf* b, const char* s);

/* Instruction shorthands, all appending to a code buffer. */
void besh_emit_op(BeshBuf* b, uint8_t op);
void besh_emit_op_u32(BeshBuf* b, uint8_t op, uint32_t imm);
void besh_emit_i32_const(BeshBuf* b, int32_t v);
void besh_emit_f64_const(BeshBuf* b, double v);
void besh_emit_mem(BeshBuf* b, uint8_t op, uint32_t align_log2, uint32_t offset);

/* --- module builder --------------------------------------------------- */

typedef struct BeshWasmModule BeshWasmModule;

BeshWasmModule* besh_wasm_new(void);
void            besh_wasm_free(BeshWasmModule* m);

/* Interns a function type and returns its index. */
uint32_t besh_wasm_type(BeshWasmModule* m,
                        const uint8_t* params, uint32_t param_count,
                        const uint8_t* results, uint32_t result_count);

/* Declares an imported function. Must be called before besh_wasm_add_func.
 * Returns the function index of the import. */
uint32_t besh_wasm_import_func(BeshWasmModule* m, const char* module_name,
                               const char* field_name, uint32_t type_index);

/* Declares the imported linear memory. At most one. */
bool besh_wasm_import_memory(BeshWasmModule* m, const char* module_name,
                             const char* field_name, uint32_t min_pages);

/* Adds a defined function and returns its function index (already offset past
 * the imports). Locals are all i32 and are appended with besh_wasm_add_local. */
uint32_t besh_wasm_add_func(BeshWasmModule* m, uint32_t type_index);

/* Returns the local index of a fresh i32 local in `func_index`, counting past
 * that function's parameters. */
uint32_t besh_wasm_add_local(BeshWasmModule* m, uint32_t func_index, uint8_t type);

/* The code buffer for a defined function. Valid until the module is freed. */
BeshBuf* besh_wasm_code(BeshWasmModule* m, uint32_t func_index);

void besh_wasm_export_func(BeshWasmModule* m, const char* name, uint32_t func_index);

/* Serialises the module. `out` is initialised by the call and owned by the
 * caller. Returns false if any step ran out of memory. */
bool besh_wasm_finish(BeshWasmModule* m, BeshBuf* out);

/* Number of imported functions declared so far. */
uint32_t besh_wasm_import_count(const BeshWasmModule* m);

#endif /* BESH_WASM_H */
