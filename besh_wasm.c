/*
 * besh_wasm.c - WebAssembly binary writer. See besh_wasm.h.
 */

#include "besh_wasm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BESH_WASM_MAX_TYPES   64
#define BESH_WASM_MAX_IMPORTS 64
#define BESH_WASM_MAX_FUNCS   512
#define BESH_WASM_MAX_EXPORTS 512
#define BESH_WASM_NAME_LEN    64

/* --- byte buffer ------------------------------------------------------ */

void besh_buf_init(BeshBuf* b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->failed = false;
}

void besh_buf_free(BeshBuf* b) {
    free(b->data);
    besh_buf_init(b);
}

void besh_buf_reset(BeshBuf* b) {
    b->len = 0;
    b->failed = false;
}

static bool buf_reserve(BeshBuf* b, size_t extra) {
    if (b->failed) return false;
    if (b->len + extra <= b->cap) return true;
    size_t want = b->cap ? b->cap : 128;
    while (want < b->len + extra) want *= 2;
    uint8_t* grown = (uint8_t*)realloc(b->data, want);
    if (!grown) { b->failed = true; return false; }
    b->data = grown;
    b->cap = want;
    return true;
}

void besh_buf_u8(BeshBuf* b, uint8_t v) {
    if (!buf_reserve(b, 1)) return;
    b->data[b->len++] = v;
}

void besh_buf_bytes(BeshBuf* b, const void* data, size_t n) {
    if (n == 0) return;
    if (!buf_reserve(b, n)) return;
    memcpy(b->data + b->len, data, n);
    b->len += n;
}

void besh_buf_uleb(BeshBuf* b, uint64_t v) {
    do {
        uint8_t byte = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if (v) byte |= 0x80u;
        besh_buf_u8(b, byte);
    } while (v);
}

void besh_buf_sleb(BeshBuf* b, int64_t v) {
    /* Signed LEB128. The shift is done on an unsigned copy with the sign bits
     * put back by hand, because shifting a negative signed value right is not
     * portably defined. */
    uint64_t bits = (uint64_t)v;
    bool done = false;
    while (!done) {
        uint8_t byte = (uint8_t)(bits & 0x7Fu);
        /* Shift in the sign bit explicitly so the result does not depend on
         * how the platform shifts signed values. */
        bool sign = (bits & 0x8000000000000000ull) != 0;
        bits >>= 7;
        if (sign) bits |= 0xFE00000000000000ull;
        if ((bits == 0 && (byte & 0x40u) == 0) ||
            (bits == 0xFFFFFFFFFFFFFFFFull && (byte & 0x40u) != 0)) {
            done = true;
        } else {
            byte |= 0x80u;
        }
        besh_buf_u8(b, byte);
    }
}

void besh_buf_f64(BeshBuf* b, double v) {
    uint64_t bits;
    memcpy(&bits, &v, 8);
    for (int i = 0; i < 8; ++i) besh_buf_u8(b, (uint8_t)((bits >> (i * 8)) & 0xFFu));
}

void besh_buf_name(BeshBuf* b, const char* s) {
    size_t n = strlen(s);
    besh_buf_uleb(b, n);
    besh_buf_bytes(b, s, n);
}

void besh_emit_op(BeshBuf* b, uint8_t op) { besh_buf_u8(b, op); }

void besh_emit_op_u32(BeshBuf* b, uint8_t op, uint32_t imm) {
    besh_buf_u8(b, op);
    besh_buf_uleb(b, imm);
}

void besh_emit_i32_const(BeshBuf* b, int32_t v) {
    besh_buf_u8(b, OP_I32_CONST);
    besh_buf_sleb(b, v);
}

void besh_emit_f64_const(BeshBuf* b, double v) {
    besh_buf_u8(b, OP_F64_CONST);
    besh_buf_f64(b, v);
}

void besh_emit_mem(BeshBuf* b, uint8_t op, uint32_t align_log2, uint32_t offset) {
    besh_buf_u8(b, op);
    besh_buf_uleb(b, align_log2);
    besh_buf_uleb(b, offset);
}

/* --- module ----------------------------------------------------------- */

typedef struct {
    uint8_t  params[8];
    uint32_t param_count;
    uint8_t  results[2];
    uint32_t result_count;
} WasmTypeEntry;

typedef struct {
    char     module_name[BESH_WASM_NAME_LEN];
    char     field_name[BESH_WASM_NAME_LEN];
    uint32_t type_index;
} WasmFuncImport;

typedef struct {
    uint32_t type_index;
    uint8_t  local_types[64];
    uint32_t local_count;
    BeshBuf  code;
} WasmFuncDef;

typedef struct {
    char     name[BESH_WASM_NAME_LEN];
    uint32_t func_index;
} WasmFuncExport;

struct BeshWasmModule {
    WasmTypeEntry  types[BESH_WASM_MAX_TYPES];
    uint32_t       type_count;

    WasmFuncImport imports[BESH_WASM_MAX_IMPORTS];
    uint32_t       import_count;

    bool           has_memory;
    char           memory_module[BESH_WASM_NAME_LEN];
    char           memory_field[BESH_WASM_NAME_LEN];
    uint32_t       memory_min_pages;

    WasmFuncDef*   funcs;
    uint32_t       func_count;
    uint32_t       func_capacity;

    WasmFuncExport exports[BESH_WASM_MAX_EXPORTS];
    uint32_t       export_count;

    bool           overflowed;
};

BeshWasmModule* besh_wasm_new(void) {
    BeshWasmModule* m = (BeshWasmModule*)calloc(1, sizeof(BeshWasmModule));
    return m;
}

void besh_wasm_free(BeshWasmModule* m) {
    if (!m) return;
    for (uint32_t i = 0; i < m->func_count; ++i) besh_buf_free(&m->funcs[i].code);
    free(m->funcs);
    free(m);
}

uint32_t besh_wasm_import_count(const BeshWasmModule* m) {
    return m ? m->import_count : 0;
}

uint32_t besh_wasm_type(BeshWasmModule* m,
                        const uint8_t* params, uint32_t param_count,
                        const uint8_t* results, uint32_t result_count) {
    if (!m || param_count > 8 || result_count > 2) { if (m) m->overflowed = true; return 0; }
    for (uint32_t i = 0; i < m->type_count; ++i) {
        WasmTypeEntry* t = &m->types[i];
        if (t->param_count != param_count || t->result_count != result_count) continue;
        if (param_count && memcmp(t->params, params, param_count) != 0) continue;
        if (result_count && memcmp(t->results, results, result_count) != 0) continue;
        return i;
    }
    if (m->type_count >= BESH_WASM_MAX_TYPES) { m->overflowed = true; return 0; }
    WasmTypeEntry* t = &m->types[m->type_count];
    t->param_count = param_count;
    t->result_count = result_count;
    if (param_count) memcpy(t->params, params, param_count);
    if (result_count) memcpy(t->results, results, result_count);
    return m->type_count++;
}

uint32_t besh_wasm_import_func(BeshWasmModule* m, const char* module_name,
                               const char* field_name, uint32_t type_index) {
    if (!m || m->import_count >= BESH_WASM_MAX_IMPORTS) { if (m) m->overflowed = true; return 0; }
    if (m->func_count > 0) { m->overflowed = true; return 0; } /* imports must come first */
    WasmFuncImport* imp = &m->imports[m->import_count];
    snprintf(imp->module_name, sizeof(imp->module_name), "%s", module_name);
    snprintf(imp->field_name, sizeof(imp->field_name), "%s", field_name);
    imp->type_index = type_index;
    return m->import_count++;
}

bool besh_wasm_import_memory(BeshWasmModule* m, const char* module_name,
                             const char* field_name, uint32_t min_pages) {
    if (!m || m->has_memory) return false;
    m->has_memory = true;
    snprintf(m->memory_module, sizeof(m->memory_module), "%s", module_name);
    snprintf(m->memory_field, sizeof(m->memory_field), "%s", field_name);
    m->memory_min_pages = min_pages ? min_pages : 1;
    return true;
}

uint32_t besh_wasm_add_func(BeshWasmModule* m, uint32_t type_index) {
    if (!m) return 0;
    if (m->func_count == m->func_capacity) {
        uint32_t want = m->func_capacity ? m->func_capacity * 2 : 8;
        if (want > BESH_WASM_MAX_FUNCS) { m->overflowed = true; return 0; }
        WasmFuncDef* grown = (WasmFuncDef*)realloc(m->funcs, want * sizeof(WasmFuncDef));
        if (!grown) { m->overflowed = true; return 0; }
        memset(grown + m->func_capacity, 0, (want - m->func_capacity) * sizeof(WasmFuncDef));
        m->funcs = grown;
        m->func_capacity = want;
    }
    WasmFuncDef* f = &m->funcs[m->func_count];
    memset(f, 0, sizeof(*f));
    f->type_index = type_index;
    besh_buf_init(&f->code);
    return m->import_count + m->func_count++;
}

static WasmFuncDef* func_at(BeshWasmModule* m, uint32_t func_index) {
    if (!m || func_index < m->import_count) return NULL;
    uint32_t slot = func_index - m->import_count;
    if (slot >= m->func_count) return NULL;
    return &m->funcs[slot];
}

uint32_t besh_wasm_add_local(BeshWasmModule* m, uint32_t func_index, uint8_t type) {
    WasmFuncDef* f = func_at(m, func_index);
    if (!f) return 0;
    if (f->local_count >= (uint32_t)(sizeof(f->local_types))) { m->overflowed = true; return 0; }
    uint32_t params = m->types[f->type_index].param_count;
    f->local_types[f->local_count] = type;
    return params + f->local_count++;
}

BeshBuf* besh_wasm_code(BeshWasmModule* m, uint32_t func_index) {
    WasmFuncDef* f = func_at(m, func_index);
    return f ? &f->code : NULL;
}

void besh_wasm_export_func(BeshWasmModule* m, const char* name, uint32_t func_index) {
    if (!m || m->export_count >= BESH_WASM_MAX_EXPORTS) { if (m) m->overflowed = true; return; }
    WasmFuncExport* e = &m->exports[m->export_count++];
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->func_index = func_index;
}

/* Appends `section_id` followed by the LEB-prefixed contents of `body`. */
static void append_section(BeshBuf* out, uint8_t section_id, const BeshBuf* body) {
    if (body->len == 0) return;
    besh_buf_u8(out, section_id);
    besh_buf_uleb(out, body->len);
    besh_buf_bytes(out, body->data, body->len);
}

bool besh_wasm_finish(BeshWasmModule* m, BeshBuf* out) {
    besh_buf_init(out);
    if (!m || m->overflowed) return false;

    static const uint8_t header[] = { 0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00 };
    besh_buf_bytes(out, header, sizeof(header));

    BeshBuf body;

    /* 1: types */
    besh_buf_init(&body);
    besh_buf_uleb(&body, m->type_count);
    for (uint32_t i = 0; i < m->type_count; ++i) {
        WasmTypeEntry* t = &m->types[i];
        besh_buf_u8(&body, 0x60);
        besh_buf_uleb(&body, t->param_count);
        for (uint32_t p = 0; p < t->param_count; ++p) besh_buf_u8(&body, t->params[p]);
        besh_buf_uleb(&body, t->result_count);
        for (uint32_t r = 0; r < t->result_count; ++r) besh_buf_u8(&body, t->results[r]);
    }
    append_section(out, 1, &body);
    besh_buf_free(&body);

    /* 2: imports */
    besh_buf_init(&body);
    {
        uint32_t total = m->import_count + (m->has_memory ? 1u : 0u);
        besh_buf_uleb(&body, total);
        for (uint32_t i = 0; i < m->import_count; ++i) {
            besh_buf_name(&body, m->imports[i].module_name);
            besh_buf_name(&body, m->imports[i].field_name);
            besh_buf_u8(&body, 0x00); /* func */
            besh_buf_uleb(&body, m->imports[i].type_index);
        }
        if (m->has_memory) {
            besh_buf_name(&body, m->memory_module);
            besh_buf_name(&body, m->memory_field);
            besh_buf_u8(&body, 0x02); /* memory */
            besh_buf_u8(&body, 0x00); /* limits: min only */
            besh_buf_uleb(&body, m->memory_min_pages);
        }
        if (total == 0) besh_buf_reset(&body);
    }
    append_section(out, 2, &body);
    besh_buf_free(&body);

    /* 3: function declarations */
    besh_buf_init(&body);
    besh_buf_uleb(&body, m->func_count);
    for (uint32_t i = 0; i < m->func_count; ++i) besh_buf_uleb(&body, m->funcs[i].type_index);
    if (m->func_count == 0) besh_buf_reset(&body);
    append_section(out, 3, &body);
    besh_buf_free(&body);

    /* 7: exports */
    besh_buf_init(&body);
    besh_buf_uleb(&body, m->export_count);
    for (uint32_t i = 0; i < m->export_count; ++i) {
        besh_buf_name(&body, m->exports[i].name);
        besh_buf_u8(&body, 0x00); /* func */
        besh_buf_uleb(&body, m->exports[i].func_index);
    }
    if (m->export_count == 0) besh_buf_reset(&body);
    append_section(out, 7, &body);
    besh_buf_free(&body);

    /* 10: code */
    besh_buf_init(&body);
    besh_buf_uleb(&body, m->func_count);
    for (uint32_t i = 0; i < m->func_count; ++i) {
        WasmFuncDef* f = &m->funcs[i];
        BeshBuf entry;
        besh_buf_init(&entry);

        /* Locals are run-length encoded by type. */
        uint32_t groups = 0;
        for (uint32_t l = 0; l < f->local_count; ) {
            uint32_t run = 1;
            while (l + run < f->local_count && f->local_types[l + run] == f->local_types[l]) run++;
            l += run;
            groups++;
        }
        besh_buf_uleb(&entry, groups);
        for (uint32_t l = 0; l < f->local_count; ) {
            uint32_t run = 1;
            while (l + run < f->local_count && f->local_types[l + run] == f->local_types[l]) run++;
            besh_buf_uleb(&entry, run);
            besh_buf_u8(&entry, f->local_types[l]);
            l += run;
        }
        besh_buf_bytes(&entry, f->code.data, f->code.len);
        besh_buf_u8(&entry, OP_END);

        besh_buf_uleb(&body, entry.len);
        besh_buf_bytes(&body, entry.data, entry.len);
        if (entry.failed) body.failed = true;
        besh_buf_free(&entry);
    }
    if (m->func_count == 0) besh_buf_reset(&body);
    append_section(out, 10, &body);
    bool code_ok = !body.failed;
    besh_buf_free(&body);

    return code_ok && !out->failed;
}
