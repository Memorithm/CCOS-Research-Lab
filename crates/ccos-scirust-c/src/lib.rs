use scirust::attention::slha_v2::{SciRustSlhaTile, D_C, RESIDUAL_WORDS};
use scirust::audit;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::ptr::NonNull;

/// Opaque handle for the SLHA context (if needed in future, currently stateless).
#[repr(C)]
pub struct SlhaContext {
    _unused: [u8; 0],
}

/// Initialize the SLHA environment.
///
/// The kernel is currently stateless, so no context is allocated. We still
/// return a non-null, well-aligned sentinel so C callers can keep a uniform
/// `if (ctx == NULL) { /* error */ }` check without special-casing. The handle
/// is a dangling (zero-sized) pointer that must never be dereferenced; when a
/// real context is added later this will allocate it and gain a paired
/// `slha_shutdown`.
#[no_mangle]
pub extern "C" fn slha_init() -> *mut SlhaContext {
    NonNull::<SlhaContext>::dangling().as_ptr()
}

/// Process a single tile and compute the score.
///
/// # Safety
/// `tile`, `q_coarse`, and `q_sign` must be valid non-null pointers.
/// `q_coarse` must point to an array of `D_C` (128) f32s.
/// `q_sign` must point to an array of `RESIDUAL_WORDS` (4) u64s.
#[no_mangle]
pub unsafe extern "C" fn slha_process_tile(
    tile: *const SciRustSlhaTile,
    q_coarse: *const f32,
    q_sign: *const u64,
    score_out: *mut f32,
) -> i32 {
    let result = catch_unwind(|| {
        if tile.is_null() || q_coarse.is_null() || q_sign.is_null() || score_out.is_null() {
            return -1;
        }

        // Debug-only alignment guard (CCOS_EXTENDED plan P4): the tile MUST be
        // aligned to `align_of::<SciRustSlhaTile>()` (64 by default, 128 when the
        // Rust crate was built with `cfg(cache_line_128)`). A misaligned tile
        // would be UB on dereference; this catches a C-side allocation that
        // ignored the header's `SLHA_ALIGNED(SLHA_TILE_ALIGN)` contract. Stripped
        // in release — the FFI is an output boundary and never allocates tiles.
        debug_assert!(
            (tile as usize) % std::mem::align_of::<SciRustSlhaTile>() == 0,
            "slha_process_tile: tile pointer not aligned to {}",
            std::mem::align_of::<SciRustSlhaTile>(),
        );

        let tile_ref = &*tile;
        let q_coarse_ref = &*(q_coarse as *const [f32; D_C]);
        let q_sign_ref = &*(q_sign as *const [u64; RESIDUAL_WORDS]);

        *score_out = tile_ref.compute_score(q_coarse_ref, q_sign_ref);
        0
    });

    result.unwrap_or(-2) // -2 if panic occurred
}

/// Run the self-audit and return a JSON string.
///
/// # Safety
/// The returned pointer must be freed using `slha_free_string`.
#[no_mangle]
pub unsafe extern "C" fn slha_audit() -> *mut c_char {
    let result = catch_unwind(|| {
        let report = audit::run();
        let s = report.to_compact();
        // CString::into_raw returns *mut c_char on every target; using c_char
        // (not i8) keeps this compiling on aarch64 where c_char == u8.
        std::ffi::CString::new(s).unwrap().into_raw()
    });

    result.unwrap_or(std::ptr::null_mut())
}

/// Free a string allocated by the library.
///
/// # Safety
/// `s` must be a pointer returned by `slha_audit`.
#[no_mangle]
pub unsafe extern "C" fn slha_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` was produced by CString::into_raw in slha_audit and is
        // freed exactly once by the caller.
        let _ = std::ffi::CString::from_raw(s);
    }
}
