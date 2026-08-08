/*
 * besh_mem.c - the B[e]SH linear heap.
 *
 * See besh_mem.h for the layout. The allocator is a first-fit free list over a
 * single contiguous buffer, with immediate coalescing of adjacent free blocks.
 * It is deliberately simple: the buffer has to stay contiguous and stable
 * because Fayasm binds it as an imported WebAssembly memory, so anything
 * fancier would buy nothing.
 */

#include "besh_mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The heap starts with one BESH_MEM_ALIGN-sized dead zone so that address 0 is
 * never a valid payload and can mean "null" everywhere. */
#define BESH_MEM_FIRST  BESH_MEM_ALIGN

static uint8_t*  g_heap = NULL;
static uint32_t  g_heap_size = 0;
static bool      g_locked = false;
static uint32_t  g_generation = 0;

static uint32_t align_up(uint32_t v) {
    return (v + (BESH_MEM_ALIGN - 1u)) & ~(BESH_MEM_ALIGN - 1u);
}

static uint32_t rd32(uint32_t off) {
    uint32_t v;
    memcpy(&v, g_heap + off, 4);
    return v;
}

static void wr32(uint32_t off, uint32_t v) {
    memcpy(g_heap + off, &v, 4);
}

/* Header accessors. `blk` is the address of the header, `addr` the payload. */
static uint32_t blk_size(uint32_t blk) { return rd32(blk); }
static uint32_t blk_tag(uint32_t blk)  { return rd32(blk + 4); }
static void blk_set(uint32_t blk, uint32_t size, uint32_t tag) {
    wr32(blk, size);
    wr32(blk + 4, tag);
}

/* --- lifecycle ------------------------------------------------------- */

bool besh_mem_init(uint32_t bytes) {
    if (g_heap) return true;
    if (bytes == 0) {
        const char* configured = getenv("BSH_HEAP_BYTES");
        bytes = configured ? (uint32_t)strtoul(configured, NULL, 0) : 0u;
        if (bytes == 0) bytes = BESH_MEM_DEFAULT;
    }
    bytes = (bytes + BESH_MEM_PAGE - 1u) / BESH_MEM_PAGE * BESH_MEM_PAGE;
    if (bytes > BESH_MEM_MAX) bytes = BESH_MEM_MAX;

    g_heap = (uint8_t*)calloc(bytes, 1);
    if (!g_heap) {
        fprintf(stderr, "besh: cannot reserve %u bytes for the BSH heap\n", bytes);
        return false;
    }
    g_heap_size = bytes;
    g_generation++;

    /* One free block spanning everything after the dead zone. */
    uint32_t blk = BESH_MEM_FIRST;
    blk_set(blk, g_heap_size - blk - BESH_MEM_HDR, BESH_BLOCK_FREE);
    return true;
}

void besh_mem_shutdown(void) {
    free(g_heap);
    g_heap = NULL;
    g_heap_size = 0;
    g_locked = false;
}

uint8_t* besh_mem_base(void)      { return g_heap; }
uint32_t besh_mem_size(void)      { return g_heap_size; }
uint32_t besh_mem_pages(void)     { return g_heap_size / BESH_MEM_PAGE; }
void     besh_mem_lock(bool l)    { g_locked = l; }
bool     besh_mem_is_locked(void) { return g_locked; }
uint32_t besh_mem_generation(void){ return g_generation; }

/* --- block walking --------------------------------------------------- */

/* Merge `blk` with the following block while that one is free. Does nothing
 * unless `blk` is itself a free block: the merge rewrites `blk`'s header, so
 * calling this on a live allocation would mark it free and lose it. */
static void coalesce_forward(uint32_t blk) {
    if (blk + BESH_MEM_HDR > g_heap_size) return;
    if (blk_tag(blk) != BESH_BLOCK_FREE) return;
    for (;;) {
        uint32_t next = blk + BESH_MEM_HDR + blk_size(blk);
        if (next + BESH_MEM_HDR > g_heap_size) return;
        if (blk_tag(next) != BESH_BLOCK_FREE) return;
        blk_set(blk, blk_size(blk) + BESH_MEM_HDR + blk_size(next), BESH_BLOCK_FREE);
    }
}

/* Grow the buffer. Only legal when no compiled job holds the base pointer. */
static bool grow_heap(uint32_t needed) {
    if (g_locked) return false;
    uint32_t want = g_heap_size;
    while (want < needed && want < BESH_MEM_MAX) want *= 2u;
    if (want < needed) return false;
    if (want > BESH_MEM_MAX) want = BESH_MEM_MAX;
    if (want <= g_heap_size) return false;

    uint8_t* grown = (uint8_t*)realloc(g_heap, want);
    if (!grown) return false;
    memset(grown + g_heap_size, 0, want - g_heap_size);

    uint8_t* previous = g_heap;
    g_heap = grown;

    /* Append the new space as one free block and merge it with the tail. */
    uint32_t tail = BESH_MEM_FIRST;
    uint32_t last = tail;
    while (tail + BESH_MEM_HDR <= g_heap_size) {
        last = tail;
        tail = tail + BESH_MEM_HDR + blk_size(tail);
    }
    uint32_t added = g_heap_size;
    uint32_t old_size = g_heap_size;
    g_heap_size = want;
    blk_set(added, want - added - BESH_MEM_HDR, BESH_BLOCK_FREE);
    (void)old_size;
    if (blk_tag(last) == BESH_BLOCK_FREE) coalesce_forward(last);
    if (previous != grown) g_generation++;
    return true;
}

/* --- raw blocks ------------------------------------------------------ */

bool besh_mem_valid(uint32_t addr, uint32_t len) {
    if (!g_heap || addr == 0) return false;
    if (addr > g_heap_size) return false;
    if (len > g_heap_size - addr) return false;
    return true;
}

bool besh_mem_is_block(uint32_t addr) {
    if (!g_heap || addr < BESH_MEM_FIRST + BESH_MEM_HDR) return false;
    if (addr > g_heap_size) return false;
    uint32_t blk = addr - BESH_MEM_HDR;
    uint32_t tag = blk_tag(blk);
    if (tag != BESH_BLOCK_USED) return false;
    return addr + blk_size(blk) <= g_heap_size;
}

uint32_t besh_mem_block_size(uint32_t addr) {
    if (!besh_mem_is_block(addr)) return 0;
    return blk_size(addr - BESH_MEM_HDR);
}

uint32_t besh_mem_alloc(uint32_t nbytes) {
    if (!g_heap && !besh_mem_init(0)) return 0;
    if (nbytes == 0) nbytes = 1;
    uint32_t want = align_up(nbytes);
    if (want < nbytes) return 0; /* overflow */

    for (int attempt = 0; attempt < 2; ++attempt) {
        uint32_t blk = BESH_MEM_FIRST;
        while (blk + BESH_MEM_HDR <= g_heap_size) {
            uint32_t size = blk_size(blk);
            uint32_t tag = blk_tag(blk);
            if (blk + BESH_MEM_HDR + size > g_heap_size) break; /* corrupt; stop */
            if (tag == BESH_BLOCK_FREE) {
                if (size < want) {
                    coalesce_forward(blk);
                    size = blk_size(blk);
                }
                if (size >= want) {
                    /* Split when the remainder can carry its own header. */
                    if (size >= want + BESH_MEM_HDR + BESH_MEM_ALIGN) {
                        uint32_t rest = blk + BESH_MEM_HDR + want;
                        blk_set(rest, size - want - BESH_MEM_HDR, BESH_BLOCK_FREE);
                        blk_set(blk, want, BESH_BLOCK_USED);
                    } else {
                        blk_set(blk, size, BESH_BLOCK_USED);
                    }
                    return blk + BESH_MEM_HDR;
                }
            }
            blk = blk + BESH_MEM_HDR + size;
        }
        if (attempt == 0 && !grow_heap(g_heap_size + want + BESH_MEM_HDR)) {
            if (g_locked) {
                fprintf(stderr,
                        "besh: heap exhausted while compiled code is running "
                        "(%u bytes); set BSH_HEAP_BYTES higher\n", g_heap_size);
            }
            break;
        }
    }
    return 0;
}

uint32_t besh_mem_calloc(uint32_t nbytes) {
    uint32_t addr = besh_mem_alloc(nbytes);
    if (addr) memset(g_heap + addr, 0, besh_mem_block_size(addr));
    return addr;
}

void besh_mem_free(uint32_t addr) {
    if (!besh_mem_is_block(addr)) return;
    uint32_t blk = addr - BESH_MEM_HDR;
    blk_set(blk, blk_size(blk), BESH_BLOCK_FREE);
    coalesce_forward(blk);
}

uint32_t besh_mem_realloc(uint32_t addr, uint32_t nbytes) {
    if (addr == 0) return besh_mem_alloc(nbytes);
    if (!besh_mem_is_block(addr)) return 0;
    uint32_t have = besh_mem_block_size(addr);
    if (nbytes <= have) return addr;

    /* Try to grow in place by taking part of the free block that follows.
     * Only as much as is needed: absorbing the whole neighbour would hand a
     * small vector the entire remaining heap. */
    uint32_t want = align_up(nbytes);
    uint32_t blk = addr - BESH_MEM_HDR;
    uint32_t next = blk + BESH_MEM_HDR + have;
    coalesce_forward(next); /* merge the free run that follows, if any */
    if (next + BESH_MEM_HDR <= g_heap_size && blk_tag(next) == BESH_BLOCK_FREE) {
        uint32_t merged = have + BESH_MEM_HDR + blk_size(next);
        if (merged >= want) {
            if (merged >= want + BESH_MEM_HDR + BESH_MEM_ALIGN) {
                uint32_t rest = blk + BESH_MEM_HDR + want;
                blk_set(rest, merged - want - BESH_MEM_HDR, BESH_BLOCK_FREE);
                blk_set(blk, want, BESH_BLOCK_USED);
            } else {
                blk_set(blk, merged, BESH_BLOCK_USED);
            }
            return addr;
        }
    }

    uint32_t fresh = besh_mem_alloc(nbytes);
    if (!fresh) return 0;
    memcpy(g_heap + fresh, g_heap + addr, have);
    besh_mem_free(addr);
    return fresh;
}

/* --- scalar access --------------------------------------------------- */

bool besh_mem_read(uint32_t addr, uint32_t width, uint64_t* out) {
    if (!out || (width != 1 && width != 2 && width != 4 && width != 8)) return false;
    if (!besh_mem_valid(addr, width)) return false;
    uint64_t v = 0;
    memcpy(&v, g_heap + addr, width);
    *out = v;
    return true;
}

bool besh_mem_write(uint32_t addr, uint32_t width, uint64_t value) {
    if (width != 1 && width != 2 && width != 4 && width != 8) return false;
    if (!besh_mem_valid(addr, width)) return false;
    memcpy(g_heap + addr, &value, width);
    return true;
}

bool besh_mem_read_f64(uint32_t addr, double* out) {
    if (!out || !besh_mem_valid(addr, 8)) return false;
    memcpy(out, g_heap + addr, 8);
    return true;
}

bool besh_mem_write_f64(uint32_t addr, double value) {
    if (!besh_mem_valid(addr, 8)) return false;
    memcpy(g_heap + addr, &value, 8);
    return true;
}

bool besh_mem_copy(uint32_t dst, uint32_t src, uint32_t n) {
    if (n == 0) return true;
    if (!besh_mem_valid(dst, n) || !besh_mem_valid(src, n)) return false;
    memmove(g_heap + dst, g_heap + src, n);
    return true;
}

bool besh_mem_fill(uint32_t dst, uint8_t byte, uint32_t n) {
    if (n == 0) return true;
    if (!besh_mem_valid(dst, n)) return false;
    memset(g_heap + dst, byte, n);
    return true;
}

/* --- vectors --------------------------------------------------------- */

static bool vec_ok(uint32_t vec) {
    return besh_mem_is_block(vec) && besh_mem_block_size(vec) >= BESH_VEC_HDR;
}

uint32_t besh_vec_new(uint32_t esz, uint32_t kind, uint32_t cap) {
    if (esz != 1 && esz != 2 && esz != 4 && esz != 8) return 0;
    if (cap > (0xFFFFFFFFu - BESH_VEC_HDR) / esz) return 0;
    uint32_t vec = besh_mem_calloc(BESH_VEC_HDR + cap * esz);
    if (!vec) return 0;
    wr32(vec + 0, 0);
    wr32(vec + 4, cap);
    wr32(vec + 8, esz);
    wr32(vec + 12, kind);
    return vec;
}

uint32_t besh_vec_len(uint32_t vec)  { return vec_ok(vec) ? rd32(vec + 0) : 0; }
uint32_t besh_vec_cap(uint32_t vec)  { return vec_ok(vec) ? rd32(vec + 4) : 0; }
uint32_t besh_vec_esz(uint32_t vec)  { return vec_ok(vec) ? rd32(vec + 8) : 0; }
uint32_t besh_vec_kind(uint32_t vec) { return vec_ok(vec) ? rd32(vec + 12) : 0; }
uint32_t besh_vec_data(uint32_t vec) { return vec_ok(vec) ? vec + BESH_VEC_HDR : 0; }

bool besh_vec_set_len(uint32_t vec, uint32_t len) {
    if (!vec_ok(vec) || len > besh_vec_cap(vec)) return false;
    wr32(vec + 0, len);
    if (besh_vec_kind(vec) == BESH_VEC_STR) g_heap[vec + BESH_VEC_HDR + len] = 0;
    return true;
}

uint32_t besh_vec_reserve(uint32_t vec, uint32_t cap) {
    if (!vec_ok(vec)) return 0;
    if (besh_vec_cap(vec) >= cap) return vec;
    uint32_t esz = besh_vec_esz(vec);
    uint32_t grown = besh_vec_cap(vec) ? besh_vec_cap(vec) : 8u;
    while (grown < cap) {
        if (grown > 0x3FFFFFFFu) return 0;
        grown *= 2u;
    }
    uint32_t fresh = besh_mem_realloc(vec, BESH_VEC_HDR + grown * esz);
    if (!fresh) return 0;
    /* realloc keeps the old bytes; zero the new tail so a string stays sane. */
    uint32_t total = besh_mem_block_size(fresh);
    uint32_t used = BESH_VEC_HDR + besh_vec_len(fresh) * esz;
    if (total > used) memset(g_heap + fresh + used, 0, total - used);
    wr32(fresh + 4, (total - BESH_VEC_HDR) / esz);
    return fresh;
}

bool besh_vec_get(uint32_t vec, uint32_t index, uint64_t* out) {
    if (!vec_ok(vec) || index >= besh_vec_len(vec)) return false;
    uint32_t esz = besh_vec_esz(vec);
    return besh_mem_read(vec + BESH_VEC_HDR + index * esz, esz, out);
}

bool besh_vec_put(uint32_t vec, uint32_t index, uint64_t value) {
    if (!vec_ok(vec) || index >= besh_vec_len(vec)) return false;
    uint32_t esz = besh_vec_esz(vec);
    return besh_mem_write(vec + BESH_VEC_HDR + index * esz, esz, value);
}

uint32_t besh_vec_push(uint32_t vec, uint64_t value) {
    if (!vec_ok(vec)) return 0;
    uint32_t len = besh_vec_len(vec);
    uint32_t esz = besh_vec_esz(vec);
    /* A string keeps room for its terminator, so it needs one slot more. */
    uint32_t want = (besh_vec_kind(vec) == BESH_VEC_STR) ? len + 2u : len + 1u;
    uint32_t grown = besh_vec_reserve(vec, want);
    if (!grown) return 0;
    if (!besh_mem_write(grown + BESH_VEC_HDR + len * esz, esz, value)) return 0;
    wr32(grown + 0, len + 1);
    if (besh_vec_kind(grown) == BESH_VEC_STR) g_heap[grown + BESH_VEC_HDR + len + 1] = 0;
    return grown;
}

/* --- strings --------------------------------------------------------- */

uint32_t besh_str_new_n(const char* text, uint32_t len) {
    uint32_t vec = besh_vec_new(1, BESH_VEC_STR, len + 1u);
    if (!vec) return 0;
    if (len && text) memcpy(g_heap + vec + BESH_VEC_HDR, text, len);
    g_heap[vec + BESH_VEC_HDR + len] = 0;
    wr32(vec + 0, len);
    return vec;
}

uint32_t besh_str_new(const char* text) {
    return besh_str_new_n(text, text ? (uint32_t)strlen(text) : 0u);
}

const char* besh_str_cstr(uint32_t vec) {
    if (!vec_ok(vec) || besh_vec_esz(vec) != 1) return NULL;
    uint32_t len = besh_vec_len(vec);
    if (!besh_mem_valid(vec + BESH_VEC_HDR, len + 1u)) return NULL;
    g_heap[vec + BESH_VEC_HDR + len] = 0; /* keep the terminator honest */
    return (const char*)(g_heap + vec + BESH_VEC_HDR);
}

uint32_t besh_str_concat(uint32_t a, uint32_t b) {
    uint32_t la = besh_vec_len(a), lb = besh_vec_len(b);
    if (!vec_ok(a) || !vec_ok(b)) return 0;
    uint32_t out = besh_vec_new(1, BESH_VEC_STR, la + lb + 1u);
    if (!out) return 0;
    memcpy(g_heap + out + BESH_VEC_HDR, g_heap + a + BESH_VEC_HDR, la);
    memcpy(g_heap + out + BESH_VEC_HDR + la, g_heap + b + BESH_VEC_HDR, lb);
    g_heap[out + BESH_VEC_HDR + la + lb] = 0;
    wr32(out + 0, la + lb);
    return out;
}

/* --- the `mem` builtin ----------------------------------------------- */

static bool parse_u32(const char* text, uint32_t* out) {
    if (!text || !*text) return false;
    char* end = NULL;
    long long v = strtoll(text, &end, 0);
    while (end && *end == ' ') end++;
    if (!end || *end != '\0' || v < 0 || v > 0xFFFFFFFFLL) return false;
    *out = (uint32_t)v;
    return true;
}

static bool parse_i64(const char* text, long long* out) {
    if (!text || !*text) return false;
    char* end = NULL;
    long long v = strtoll(text, &end, 0);
    while (end && *end == ' ') end++;
    if (!end || *end != '\0') return false;
    *out = v;
    return true;
}

#define NEED(n) do { \
    if (argc < (n)) { snprintf(err, err_size, "mem %s needs %d argument(s)", sub, (n)); return false; } \
} while (0)

#define ARG_U32(i, var) do { \
    if (!parse_u32(argv[i], &(var))) { snprintf(err, err_size, "mem %s: '%s' is not a number", sub, argv[i]); return false; } \
} while (0)

bool besh_mem_produces_value(const char* sub) {
    static const char* const kVoid[] = {
        "free", "poke", "poke8", "poke16", "poke32", "poke64", "pokef",
        "copy", "fill", "setlen", "put", NULL
    };
    for (int i = 0; kVoid[i]; ++i) {
        if (strcmp(sub, kVoid[i]) == 0) return false;
    }
    return true;
}

bool besh_mem_command(const char* sub, char argv[][BESH_ARG_SIZE], int argc,
                      char* out, size_t out_size,
                      char* err, size_t err_size) {
    if (!besh_mem_init(0)) { snprintf(err, err_size, "heap unavailable"); return false; }
    out[0] = '\0';
    err[0] = '\0';

    uint32_t a = 0, b = 0, c = 0;
    long long v = 0;

    if (strcmp(sub, "alloc") == 0) {
        NEED(1); ARG_U32(0, a);
        snprintf(out, out_size, "%u", besh_mem_calloc(a));
        return true;
    }
    if (strcmp(sub, "free") == 0) {
        NEED(1); ARG_U32(0, a);
        besh_mem_free(a);
        return true;
    }
    if (strcmp(sub, "realloc") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        snprintf(out, out_size, "%u", besh_mem_realloc(a, b));
        return true;
    }
    if (strcmp(sub, "size") == 0) {
        NEED(1); ARG_U32(0, a);
        snprintf(out, out_size, "%u", besh_mem_block_size(a));
        return true;
    }
    if (strcmp(sub, "valid") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        snprintf(out, out_size, "%d", besh_mem_valid(a, b) ? 1 : 0);
        return true;
    }
    if (strcmp(sub, "heapsize") == 0) {
        snprintf(out, out_size, "%u", besh_mem_size());
        return true;
    }

    /* peek/poke with an explicit width: peek, peek16, peek32, peek64. */
    if (strncmp(sub, "peek", 4) == 0 && sub[4] != 'f') {
        uint32_t width = 1;
        if (sub[4] != '\0') { uint32_t bits; if (!parse_u32(sub + 4, &bits) || (bits != 8 && bits != 16 && bits != 32 && bits != 64)) { snprintf(err, err_size, "mem %s: bad width", sub); return false; } width = bits / 8; }
        NEED(1); ARG_U32(0, a);
        uint64_t value = 0;
        if (!besh_mem_read(a, width, &value)) { snprintf(err, err_size, "mem %s: address %u out of range", sub, a); return false; }
        snprintf(out, out_size, "%llu", (unsigned long long)value);
        return true;
    }
    if (strncmp(sub, "poke", 4) == 0 && sub[4] != 'f') {
        uint32_t width = 1;
        if (sub[4] != '\0') { uint32_t bits; if (!parse_u32(sub + 4, &bits) || (bits != 8 && bits != 16 && bits != 32 && bits != 64)) { snprintf(err, err_size, "mem %s: bad width", sub); return false; } width = bits / 8; }
        NEED(2); ARG_U32(0, a);
        if (!parse_i64(argv[1], &v)) { snprintf(err, err_size, "mem %s: '%s' is not a number", sub, argv[1]); return false; }
        if (!besh_mem_write(a, width, (uint64_t)v)) { snprintf(err, err_size, "mem %s: address %u out of range", sub, a); return false; }
        return true;
    }
    if (strcmp(sub, "peekf") == 0) {
        NEED(1); ARG_U32(0, a);
        double d = 0;
        if (!besh_mem_read_f64(a, &d)) { snprintf(err, err_size, "mem peekf: address %u out of range", a); return false; }
        snprintf(out, out_size, "%g", d);
        return true;
    }
    if (strcmp(sub, "pokef") == 0) {
        NEED(2); ARG_U32(0, a);
        if (!besh_mem_write_f64(a, strtod(argv[1], NULL))) { snprintf(err, err_size, "mem pokef: address %u out of range", a); return false; }
        return true;
    }
    if (strcmp(sub, "copy") == 0) {
        NEED(3); ARG_U32(0, a); ARG_U32(1, b); ARG_U32(2, c);
        if (!besh_mem_copy(a, b, c)) { snprintf(err, err_size, "mem copy: out of range"); return false; }
        return true;
    }
    if (strcmp(sub, "fill") == 0) {
        NEED(3); ARG_U32(0, a); ARG_U32(1, b); ARG_U32(2, c);
        if (!besh_mem_fill(a, (uint8_t)b, c)) { snprintf(err, err_size, "mem fill: out of range"); return false; }
        return true;
    }

    /* vectors */
    if (strcmp(sub, "vec") == 0) {
        NEED(3); ARG_U32(0, a); ARG_U32(1, b); ARG_U32(2, c);
        snprintf(out, out_size, "%u", besh_vec_new(a, b, c));
        return true;
    }
    if (strcmp(sub, "len") == 0)  { NEED(1); ARG_U32(0, a); snprintf(out, out_size, "%u", besh_vec_len(a));  return true; }
    if (strcmp(sub, "cap") == 0)  { NEED(1); ARG_U32(0, a); snprintf(out, out_size, "%u", besh_vec_cap(a));  return true; }
    if (strcmp(sub, "esz") == 0)  { NEED(1); ARG_U32(0, a); snprintf(out, out_size, "%u", besh_vec_esz(a));  return true; }
    if (strcmp(sub, "kind") == 0) { NEED(1); ARG_U32(0, a); snprintf(out, out_size, "%u", besh_vec_kind(a)); return true; }
    if (strcmp(sub, "data") == 0) { NEED(1); ARG_U32(0, a); snprintf(out, out_size, "%u", besh_vec_data(a)); return true; }
    if (strcmp(sub, "setlen") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        if (!besh_vec_set_len(a, b)) { snprintf(err, err_size, "mem setlen: %u exceeds capacity", b); return false; }
        return true;
    }
    if (strcmp(sub, "reserve") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        snprintf(out, out_size, "%u", besh_vec_reserve(a, b));
        return true;
    }
    if (strcmp(sub, "at") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        uint64_t value = 0;
        if (!besh_vec_get(a, b, &value)) { snprintf(err, err_size, "mem at: index %u out of range", b); return false; }
        if (besh_vec_kind(a) == BESH_VEC_F64) { double d; memcpy(&d, &value, 8); snprintf(out, out_size, "%g", d); }
        else if (besh_vec_kind(a) == BESH_VEC_I32) snprintf(out, out_size, "%d", (int32_t)(uint32_t)value);
        else snprintf(out, out_size, "%llu", (unsigned long long)value);
        return true;
    }
    if (strcmp(sub, "put") == 0) {
        NEED(3); ARG_U32(0, a); ARG_U32(1, b);
        uint64_t raw;
        if (besh_vec_kind(a) == BESH_VEC_F64) { double d = strtod(argv[2], NULL); memcpy(&raw, &d, 8); }
        else { if (!parse_i64(argv[2], &v)) { snprintf(err, err_size, "mem put: '%s' is not a number", argv[2]); return false; } raw = (uint64_t)v; }
        if (!besh_vec_put(a, b, raw)) { snprintf(err, err_size, "mem put: index %u out of range", b); return false; }
        return true;
    }
    if (strcmp(sub, "push") == 0) {
        NEED(2); ARG_U32(0, a);
        uint64_t raw;
        if (besh_vec_kind(a) == BESH_VEC_F64) { double d = strtod(argv[1], NULL); memcpy(&raw, &d, 8); }
        else { if (!parse_i64(argv[1], &v)) { snprintf(err, err_size, "mem push: '%s' is not a number", argv[1]); return false; } raw = (uint64_t)v; }
        snprintf(out, out_size, "%u", besh_vec_push(a, raw));
        return true;
    }

    /* strings */
    if (strcmp(sub, "str") == 0) {
        NEED(1);
        snprintf(out, out_size, "%u", besh_str_new(argv[0]));
        return true;
    }
    if (strcmp(sub, "cstr") == 0) {
        NEED(1); ARG_U32(0, a);
        const char* text = besh_str_cstr(a);
        if (!text) { snprintf(err, err_size, "mem cstr: %u is not a string", a); return false; }
        snprintf(out, out_size, "%s", text);
        return true;
    }
    if (strcmp(sub, "concat") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        snprintf(out, out_size, "%u", besh_str_concat(a, b));
        return true;
    }
    if (strcmp(sub, "dump") == 0) {
        NEED(2); ARG_U32(0, a); ARG_U32(1, b);
        if (!besh_mem_valid(a, b)) { snprintf(err, err_size, "mem dump: out of range"); return false; }
        size_t used = 0;
        for (uint32_t i = 0; i < b && used + 3 < out_size; ++i) {
            used += (size_t)snprintf(out + used, out_size - used, "%02x", g_heap[a + i]);
        }
        return true;
    }

    snprintf(err, err_size, "unknown mem subcommand '%s'", sub);
    return false;
}
