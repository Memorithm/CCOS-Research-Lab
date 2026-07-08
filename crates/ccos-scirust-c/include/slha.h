#ifndef SLHA_H
#define SLHA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLHA_D_C 128
#define SLHA_D_S 256
#define SLHA_LATENT_BYTES 64
#define SLHA_RESIDUAL_WORDS 4
#define SLHA_N_GROUPS 8

/**
 * SLHA v2 Tile structure.
 *
 * Total size: exactly 128 bytes. Alignment must match the Rust build:
 *   - 64 bytes by default (all x86_64 and AArch64/Neoverse parts we target),
 *   - 128 bytes when the Rust crate was built with `cfg(cache_line_128)`
 *     (hosts with genuine 128-byte data cache lines, e.g. Apple Silicon).
 * To pair with a 128-byte Rust build, compile the C side with
 * `-DSLHA_CACHE_LINE_128=1` (or `#define SLHA_CACHE_LINE_128 1` before
 * including this header). The size is 128 either way (a multiple of both
 * alignments), so the field layout and offsets are identical regardless.
 */
#if defined(SLHA_CACHE_LINE_128) && SLHA_CACHE_LINE_128
#  define SLHA_TILE_ALIGN 128
#else
#  define SLHA_TILE_ALIGN 64
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define SLHA_ALIGNED(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
#  define SLHA_ALIGNED(x) __declspec(align(x))
#else
#  define SLHA_ALIGNED(x)
#endif

typedef struct SLHA_ALIGNED(SLHA_TILE_ALIGN) {
    uint8_t latent_kv[SLHA_LATENT_BYTES];
    uint64_t residual_bitmap[SLHA_RESIDUAL_WORDS];
    float scale;
    float dynamic_lambda;
    float residual_sigma;
    uint32_t token_id;
    uint32_t position;
    uint16_t head_id;
    uint16_t flags;
    uint8_t group_scales[SLHA_N_GROUPS];
} SciRustSlhaTile;

typedef struct SlhaContext SlhaContext;

/**
 * Initialize the SLHA environment.
 */
SlhaContext* slha_init();

/**
 * Process a single tile and compute the score.
 *
 * Ownership: this is an OUTPUT-BOUNDARY-ONLY FFI — the library NEVER allocates
 * or frees tiles. `tile` is borrowed for the duration of the call (caller-owned;
 * pass a pointer to a stack or caller-managed `SciRustSlhaTile`). There is no
 * `slha_tile_free` to pair with because no tile is ever produced by the library.
 * The only library-allocated output is the JSON string from `slha_audit`, which
 * MUST be freed with `slha_free_string`.
 *
 * Alignment: `tile` MUST be aligned to `SLHA_TILE_ALIGN` (64 by default, 128 when
 * the Rust crate was built with `cfg(cache_line_128)` — compile the C side with
 * `-DSLHA_CACHE_LINE_128=1` to match). The struct above is declared
 * `SLHA_ALIGNED(SLHA_TILE_ALIGN)` so a properly-declared C instance is aligned;
 * a raw `malloc`'d pointer is NOT (malloc returns 16-byte alignment) — use the
 * aligned type or a compliant aligned allocator. A debug build of the Rust
 * side asserts the alignment on entry and traps on violation.
 *
 * Returns 0 on success, negative values on error (-1 null arg, -2 panic).
 */
int32_t slha_process_tile(
    const SciRustSlhaTile* tile,
    const float* q_coarse,
    const uint64_t* q_sign,
    float* score_out
);

/**
 * Run the self-audit and return a JSON string.
 * The caller must free the string using slha_free_string.
 */
char* slha_audit();

/**
 * Free a string allocated by the library.
 */
void slha_free_string(char* s);

#ifdef __cplusplus
}
#endif

#endif /* SLHA_H */
