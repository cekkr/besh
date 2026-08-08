/*
 * besh_mem.h - B[e]SH linear heap: pointers, buffers and vectors.
 *
 * B[e]SH values are strings. That is fine for names and small scalars and
 * hopeless for anything that wants an address: building a string library out
 * of external commands costs a fork per character. This heap gives BSH real
 * addresses instead.
 *
 * The heap is one contiguous byte array owned by the shell. The same bytes are
 * handed to Fayasm as an imported WebAssembly linear memory, so a compiled BSH
 * function reaches them with plain `i32.load`/`i32.store` instructions rather
 * than through a host call. A pointer is therefore the same 32-bit number in
 * interpreted BSH, in the C core and inside emitted bytecode.
 *
 * Address 0 is never returned by an allocation and means "null".
 *
 * Layout of an allocated block:
 *
 *     addr - BESH_MEM_HDR : u32 payload size in bytes
 *                           u32 tag  (BESH_BLOCK_USED / BESH_BLOCK_FREE)
 *     addr                : payload
 *
 * A "vector" is a payload that starts with a four-word header and is used for
 * both strings (element size 1, NUL terminated) and lists (element size 4).
 * One representation keeps `strlib` and `list` on the same primitives.
 *
 *     +0 u32 len   elements in use
 *     +4 u32 cap   elements the payload can hold
 *     +8 u32 esz   element size in bytes (1, 2, 4 or 8)
 *     +12 u32 kind BESH_VEC_*
 *     +16       elements
 */
#ifndef BESH_MEM_H
#define BESH_MEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Width of one BSH value buffer. besh_core.h defines INPUT_BUFFER_SIZE from
 * this so that the `mem` argument vector below cannot drift from it. */
#define BESH_ARG_SIZE       16384

#define BESH_MEM_HDR        8u    /* bytes of block header before a payload */
#define BESH_MEM_ALIGN      8u
#define BESH_VEC_HDR        16u   /* bytes of vector header before elements */

#define BESH_BLOCK_USED     0x42555345u /* "BUSE" */
#define BESH_BLOCK_FREE     0x42465245u /* "BFRE" */

/* Vector kinds. The kind is advisory: it tells `mem` how to stringify the
 * contents and tells `list`/`strlib` what they are looking at. */
#define BESH_VEC_RAW        0u
#define BESH_VEC_STR        1u    /* esz 1, NUL terminated, len excludes NUL */
#define BESH_VEC_LIST       2u    /* esz 4, elements are pointers to vectors  */
#define BESH_VEC_I32        3u    /* esz 4, elements are signed integers      */
#define BESH_VEC_F64        4u    /* esz 8, elements are doubles              */

/* Default and maximum heap sizes; both are page multiples so the heap can be
 * described to WebAssembly without rounding surprises. */
#define BESH_MEM_PAGE       65536u
#define BESH_MEM_DEFAULT    (64u * BESH_MEM_PAGE)   /*  4 MiB */
#define BESH_MEM_MAX        (4096u * BESH_MEM_PAGE) /* 256 MiB */

/* --- lifecycle ------------------------------------------------------- */

/* Idempotent. `bytes` of 0 selects BESH_MEM_DEFAULT. */
bool     besh_mem_init(uint32_t bytes);
void     besh_mem_shutdown(void);
uint8_t* besh_mem_base(void);
uint32_t besh_mem_size(void);
uint32_t besh_mem_pages(void);

/* Growing moves the buffer, which would invalidate a memory already bound to a
 * running job, so it is refused while compiled code is executing. */
void     besh_mem_lock(bool locked);
bool     besh_mem_is_locked(void);

/* Bumped every time the base pointer moves, so the Fayasm binding can tell
 * whether it still describes the live buffer. */
uint32_t besh_mem_generation(void);

/* --- raw blocks ------------------------------------------------------ */

uint32_t besh_mem_alloc(uint32_t nbytes);              /* 0 on failure */
uint32_t besh_mem_calloc(uint32_t nbytes);
uint32_t besh_mem_realloc(uint32_t addr, uint32_t nbytes);
void     besh_mem_free(uint32_t addr);
uint32_t besh_mem_block_size(uint32_t addr);           /* 0 if not a block */
bool     besh_mem_is_block(uint32_t addr);

/* Bounds check for `len` bytes starting at `addr`. */
bool     besh_mem_valid(uint32_t addr, uint32_t len);

/* Scalar accessors. All of them bounds check and report failure rather than
 * touching memory outside the heap. */
bool besh_mem_read(uint32_t addr, uint32_t width, uint64_t* out);
bool besh_mem_write(uint32_t addr, uint32_t width, uint64_t value);
bool besh_mem_read_f64(uint32_t addr, double* out);
bool besh_mem_write_f64(uint32_t addr, double value);
bool besh_mem_copy(uint32_t dst, uint32_t src, uint32_t n);
bool besh_mem_fill(uint32_t dst, uint8_t byte, uint32_t n);

/* --- vectors --------------------------------------------------------- */

uint32_t besh_vec_new(uint32_t esz, uint32_t kind, uint32_t cap);
uint32_t besh_vec_len(uint32_t vec);
uint32_t besh_vec_cap(uint32_t vec);
uint32_t besh_vec_esz(uint32_t vec);
uint32_t besh_vec_kind(uint32_t vec);
bool     besh_vec_set_len(uint32_t vec, uint32_t len);
uint32_t besh_vec_data(uint32_t vec);                  /* address of element 0 */
uint32_t besh_vec_reserve(uint32_t vec, uint32_t cap); /* new vec address, 0 on failure */
bool     besh_vec_get(uint32_t vec, uint32_t index, uint64_t* out);
bool     besh_vec_put(uint32_t vec, uint32_t index, uint64_t value);
uint32_t besh_vec_push(uint32_t vec, uint64_t value);  /* new vec address, 0 on failure */

/* --- strings --------------------------------------------------------- */

uint32_t    besh_str_new(const char* text);
uint32_t    besh_str_new_n(const char* text, uint32_t len);
const char* besh_str_cstr(uint32_t vec);               /* NULL if not a string */
uint32_t    besh_str_concat(uint32_t a, uint32_t b);

/* --- BSH-facing `mem` builtin ---------------------------------------- */

/* Runs one `mem` subcommand. `argv` excludes the word "mem" itself. Returns
 * false when the subcommand is unknown or its arguments are wrong; the
 * diagnostic is written to `err`. On success `out` holds the textual result
 * (empty for subcommands that produce none). */
bool besh_mem_command(const char* sub, char argv[][BESH_ARG_SIZE], int argc,
                      char* out, size_t out_size,
                      char* err, size_t err_size);

/* True when `sub` yields a value, and therefore takes a trailing result
 * variable in `mem <sub> [args...] <result_var>`. */
bool besh_mem_produces_value(const char* sub);

#endif /* BESH_MEM_H */
