//! Cross-platform SLHA v2 capability + throughput report — the "bench kit".
//!
//! Run with:  `cargo run -p scirust --release --example platform_report`
//!
//! Run this on each deployment target — the **x86-64 server baseline** and the
//! **AArch64 edge device** (e.g. a Jetson Thor AGX 128, Neoverse-V3AE) — to get
//! comparable, on-device numbers. It prints:
//!   * the detected SIMD features (AVX2/AVX-512/VPOPCNTDQ on x86; NEON/dotprod/
//!     i8mm/SVE/SVE2 on AArch64),
//!   * the OS-reported cache-line size at every cache level,
//!   * the tile `size_of`/`align_of` and how many cache lines it spans
//!     (`align(64)` by default — x86-64 and Neoverse both use 64-byte lines, so
//!     the 128-byte tile is two lines; `build.rs` raises it to `align(128)` only
//!     on a native 128-byte-line host),
//!   * which kernel path the runtime dispatcher selects, and
//!   * a wall-clock throughput micro-bench (scalar vs the dispatched SIMD path).
//!
//! The last line is paste-ready for the paper's §7.4 (label it with the arch).
//! No fabricated numbers: throughput is measured on whatever CPU runs the binary.

use scirust::attention::slha_v2::SciRustSlhaTile;
use scirust::scenario::{build_tile, generate, Projection};
use std::hint::black_box;
use std::mem::{align_of, size_of};
use std::time::{Duration, Instant};

/// All CPU0 cache levels: `(level, type, line_bytes, size_str)`, via Linux sysfs.
fn cache_levels() -> Vec<(String, String, usize, String)> {
    let mut out = Vec::new();
    for i in 0..16 {
        let dir = format!("/sys/devices/system/cpu/cpu0/cache/index{i}");
        let Ok(level) = std::fs::read_to_string(format!("{dir}/level")) else {
            break;
        };
        let typ = std::fs::read_to_string(format!("{dir}/type")).unwrap_or_default();
        let line = std::fs::read_to_string(format!("{dir}/coherency_line_size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let size = std::fs::read_to_string(format!("{dir}/size")).unwrap_or_default();
        out.push((
            level.trim().into(),
            typ.trim().into(),
            line,
            size.trim().into(),
        ));
    }
    out
}

/// L1 data cache line size (bytes), if reported — used for the tile/line ratio.
fn l1d_line() -> Option<usize> {
    cache_levels()
        .into_iter()
        .find(|(lvl, typ, line, _)| lvl == "1" && typ == "Data" && *line > 0)
        .map(|(_, _, line, _)| line)
}

/// Runtime-detected SIMD features relevant to the kernel, per architecture.
fn features() -> Vec<(&'static str, bool)> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![
            ("avx2", std::is_x86_feature_detected!("avx2")),
            ("avx512f", std::is_x86_feature_detected!("avx512f")),
            ("avx512vl", std::is_x86_feature_detected!("avx512vl")),
            (
                "avx512vpopcntdq",
                std::is_x86_feature_detected!("avx512vpopcntdq"),
            ),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            ("neon", std::arch::is_aarch64_feature_detected!("neon")),
            (
                "dotprod",
                std::arch::is_aarch64_feature_detected!("dotprod"),
            ),
            ("i8mm", std::arch::is_aarch64_feature_detected!("i8mm")),
            ("fp16", std::arch::is_aarch64_feature_detected!("fp16")),
            ("sve", std::arch::is_aarch64_feature_detected!("sve")),
            ("sve2", std::arch::is_aarch64_feature_detected!("sve2")),
        ]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Vec::new()
    }
}

/// The coarse-dot path `compute_score` selects at runtime on this CPU.
fn dispatched_path() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx512f") {
            "AVX-512"
        } else if std::is_x86_feature_detected!("avx2") {
            "AVX2"
        } else {
            "scalar"
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        "NEON"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "scalar"
    }
}

/// Wall-clock throughput (M scores/s) of `f` over `tiles`, run for a fixed time
/// budget so the measurement adapts to the device speed.
fn throughput<F: Fn(&SciRustSlhaTile) -> f32>(tiles: &[SciRustSlhaTile], f: F) -> f64 {
    let mut warm = 0.0f32;
    for t in tiles {
        warm += f(t);
    }
    black_box(warm);

    let budget = Duration::from_millis(600);
    let t0 = Instant::now();
    let mut sweeps = 0u64;
    let mut sink = 0.0f32;
    while t0.elapsed() < budget {
        for t in tiles {
            sink += f(t);
        }
        sweeps += 1;
    }
    let dt = t0.elapsed().as_secs_f64();
    black_box(sink);
    (sweeps as f64 * tiles.len() as f64) / dt / 1.0e6
}

fn main() {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "other"
    };

    println!("== SLHA v2 — platform & throughput report ==");
    println!("  target_arch     : {arch}  ({}-bit pointers)", usize::BITS);
    let levels = cache_levels();
    if levels.is_empty() {
        println!("  cache levels    : unknown (sysfs unavailable)");
    } else {
        println!("  cache levels    :");
        for (lvl, typ, line, size) in &levels {
            println!("      L{lvl} {typ:<11} line={line} B  size={size}");
        }
    }
    print!("  SIMD features   :");
    for (name, on) in features() {
        print!(" {name}{}", if on { "+" } else { "-" });
    }
    println!();

    let (sz, al) = (size_of::<SciRustSlhaTile>(), align_of::<SciRustSlhaTile>());
    println!("  tile            : size_of={sz} B, align_of={al} B");
    if let Some(c) = l1d_line() {
        println!(
            "  tile vs L1 line : {sz} B tile = {} line(s) of {c} B (align {al} B)",
            sz.div_ceil(c)
        );
    }
    println!("  kernel dispatch : {}\n", dispatched_path());

    // Throughput micro-bench on an L2-resident working set (~1 MB of tiles).
    let proj = Projection::new(1);
    let n = 8192usize;
    let (q, toks) = generate(1, n, 0.3);
    let q_sign = proj.sign_bits(&q);
    let tiles: Vec<SciRustSlhaTile> = toks
        .iter()
        .enumerate()
        .map(|(i, t)| build_tile(&proj, t, i as u32, false))
        .collect();

    let scalar = throughput(&tiles, |t| t.compute_score_scalar(&q, &q_sign));
    let disp = throughput(&tiles, |t| t.compute_score(&q, &q_sign));
    let path = dispatched_path();

    println!(
        "  throughput ({n} tiles, ~{} MB working set, wall-clock):",
        n * 128 / (1 << 20)
    );
    println!("    scalar          : {scalar:7.1} M scores/s   (1.00x)");
    println!(
        "    dispatched      : {disp:7.1} M scores/s   ({:.2}x, {path})",
        disp / scalar
    );
    println!(
        "\n  §7.4 paste line:  [{arch}] {path} {disp:.1} M/s · scalar {scalar:.1} M/s · {:.1}x",
        disp / scalar
    );
}
