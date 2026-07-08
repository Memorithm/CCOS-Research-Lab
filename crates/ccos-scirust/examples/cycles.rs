//! Cycles-per-tile (TSC) for the SLHA v2 score kernel.
//!
//! Run with:  `cargo run -p scirust --release --example cycles`
//!
//! Complements the criterion ns benchmark (`benches/kernel.rs`) with a CPU-cycle
//! view via `rdtsc`.
//!
//! **Honest caveats:**
//! - `_rdtsc()` counts TSC *reference* cycles (constant-rate on modern CPUs),
//!   **not** retired core cycles — treat the numbers as an order of magnitude.
//! - **L1/L2/L3 cache-miss validation requires hardware perf counters (`perf`),
//!   unavailable in this sandbox.** The working-set sweep below shows cycles/tile
//!   *rising* as the batch spills out of cache — an **indirect** signal, not a
//!   measured miss rate.

#[cfg(target_arch = "x86_64")]
use scirust::attention::slha_v2::SciRustSlhaTile;

/// Mean TSC cycles per scored tile over `l` tiles (with warm-up + lfence).
#[cfg(target_arch = "x86_64")]
fn cyc_per<F: Fn(&SciRustSlhaTile) -> f32>(tiles: &[SciRustSlhaTile], l: usize, f: F) -> f64 {
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    let reps = (50_000_000 / l).max(2);

    let mut warm = 0.0f32;
    for t in &tiles[..l] {
        warm += f(t);
    }
    std::hint::black_box(warm);

    let t0 = unsafe {
        _mm_lfence();
        _rdtsc()
    };
    let mut sink = 0.0f32;
    for _ in 0..reps {
        for t in &tiles[..l] {
            sink += f(t);
        }
    }
    let t1 = unsafe {
        _mm_lfence();
        _rdtsc()
    };
    std::hint::black_box(sink);

    (t1 - t0) as f64 / (reps as f64 * l as f64)
}

#[cfg(target_arch = "x86_64")]
fn main() {
    use scirust::scenario::{build_tile, generate, Projection};

    let proj = Projection::new(1);
    let max_l = 1usize << 20;
    let (q, toks) = generate(1, max_l, 0.3);
    let q_sign = proj.sign_bits(&q);
    let tiles: Vec<SciRustSlhaTile> = toks
        .iter()
        .enumerate()
        .map(|(i, t)| build_tile(&proj, t, i as u32, false))
        .collect();

    let avx2 = std::is_x86_feature_detected!("avx2");
    let avx512 = std::is_x86_feature_detected!("avx512f");

    println!("== Cycles/tuile (TSC) — kernel SLHA v2 ==");
    println!("  TSC = cycles de référence (≈, pas cycles cœur) ; cache-miss perf indispo.");
    println!("  Caches : L1d 48K/cœur · L2 2M/cœur · L3 ~260M ; tuile = 128 o\n");

    let l0 = 8192usize; // ~1 Mo : résident L2
    println!("  Par chemin (contexte {l0} tuiles, ~1 Mo) :");
    let cyc_s = cyc_per(&tiles, l0, |t| t.compute_score_scalar(&q, &q_sign));
    println!("    scalaire : {cyc_s:7.1} cyc/tuile   (1×)");
    if avx2 {
        let c = cyc_per(&tiles, l0, |t| unsafe { t.compute_score_avx2(&q, &q_sign) });
        println!("    AVX2     : {c:7.1} cyc/tuile   (×{:.2})", cyc_s / c);
    }
    if avx512 {
        let c = cyc_per(&tiles, l0, |t| unsafe {
            t.compute_score_avx512(&q, &q_sign)
        });
        println!("    AVX-512  : {c:7.1} cyc/tuile   (×{:.2})", cyc_s / c);
    }

    println!("\n  Balayage du working-set (chemin dispatché) :");
    println!("  {:>9} {:>7} | {:>11}", "tuiles", "Mo", "cyc/tuile");
    println!("  {}", "-".repeat(32));
    for &l in &[2048usize, 16_384, 131_072, 1_048_576] {
        let c = cyc_per(&tiles, l, |t| t.compute_score(&q, &q_sign));
        println!("  {:>9} {:>7} | {:>11.1}", l, l * 128 / (1 << 20), c);
    }
    println!(
        "\n  cyc/tuile reste ~plat tant que le working-set est résident, puis croît\n  \
         au débordement de cache (signal INDIRECT — compteurs de miss `perf` indispo)."
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("L'exemple `cycles` est x86_64 uniquement (utilise rdtsc).");
}
