//! Build script — native-host cache-line probe (a portability refinement only).
//!
//! By default the tile is `#[repr(C, align(64))]`, which is correct and optimal
//! for every 64-byte-line part — that includes **all** of our targets (x86-64
//! and AArch64/Neoverse-V3AE; the Jetson Thor measures 64 B at every level).
//!
//! The *only* hardware that benefits from `align(128)` is a part with genuine
//! 128-byte cache lines (e.g. Apple Silicon). Alignment must be a compile-time
//! constant, so we detect it here: on a **native** build (host == target) whose
//! host CPU reports a 128-byte L1d line, we emit `cfg(cache_line_128)` and the
//! tile becomes `align(128)` (one line instead of two). For cross-compilation
//! the host line size says nothing about the target, so we keep the safe
//! 64-byte default. Net effect on our actual targets: **none** — the tile stays
//! `align(64)`. This is a strict, opt-in-by-hardware upgrade, never a regression.

use std::fs;

fn main() {
    // Declare the cfg so `cfg!(cache_line_128)` never trips `unexpected_cfgs`.
    println!("cargo::rustc-check-cfg=cfg(cache_line_128)");
    println!("cargo::rerun-if-changed=build.rs");

    // Host probing is only valid for a native build (host == target triple).
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    if host.is_empty() || host != target {
        return; // cross-compiling (or unknown) -> keep align(64)
    }

    if host_l1d_line_bytes() == Some(128) {
        println!("cargo::rustc-cfg=cache_line_128");
    }
}

/// Host L1-data coherency line size in bytes, or `None` if it can't be read.
fn host_l1d_line_bytes() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size")
            .ok()?
            .trim()
            .parse()
            .ok()
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "hw.cachelinesize"])
            .output()
            .ok()?;
        String::from_utf8(out.stdout).ok()?.trim().parse().ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fs::metadata("/"); // keep `fs` used on all platforms
        None
    }
}
