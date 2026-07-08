//! Memory-bandwidth / throughput comparison: SLHA tile vs a bf16 key baseline.
//!
//! Run with:  `cargo run --example bench_vs_fp16 --release`
//!
//! This addresses §6.2 *at the kernel level*: an SLHA tile is 128 B/token,
//! whereas a bf16 key is `d_k · 2 = 256` B/token. Both scorers use AVX2 here, so
//! the comparison isolates the memory-format difference (and the extra popcount
//! work SLHA does) rather than codegen luck.
//!
//! Honesty notes:
//! - Hardware perf counters (§6.1 cache misses) are **unavailable** in this
//!   sandbox (`perf` absent, `perf_event_paranoid=2`). Cache behaviour is shown
//!   *indirectly* by sweeping the working-set size and watching throughput.
//! - Perplexity (§6.3) needs a real model/dataset — out of scope here; see the
//!   score-fidelity proxies in §7.

use std::time::Instant;

use scirust::attention::slha_v2::{SciRustSlhaTile, D_C, FLAG_HOT, LATENT_BYTES, N_GROUPS};
use scirust::rng::Rng;

#[inline]
fn bf16_decode(x: u16) -> f32 {
    f32::from_bits((x as u32) << 16)
}

fn bf16_score_scalar(q: &[f32; D_C], key: &[u16; D_C]) -> f32 {
    let mut s = 0.0f32;
    for d in 0..D_C {
        s += q[d] * bf16_decode(key[d]);
    }
    s
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bf16_score_avx2(q: &[f32; D_C], key: &[u16; D_C]) -> f32 {
    use std::arch::x86_64::*;
    let mut acc = _mm256_setzero_ps();
    let kp = key.as_ptr();
    let qp = q.as_ptr();
    for i in 0..(D_C / 8) {
        let off = i * 8;
        // bf16 -> f32 : widen 8×u16 to u32, shift into the high half, reinterpret.
        let raw = _mm_loadu_si128(kp.add(off) as *const __m128i);
        let widened = _mm256_slli_epi32(_mm256_cvtepu16_epi32(raw), 16);
        let kf = _mm256_castsi256_ps(widened);
        acc = _mm256_add_ps(acc, _mm256_mul_ps(kf, _mm256_loadu_ps(qp.add(off))));
    }
    let mut tmp = [0.0f32; 8];
    _mm256_storeu_ps(tmp.as_mut_ptr(), acc);
    tmp.iter().sum()
}

fn bf16_score(q: &[f32; D_C], key: &[u16; D_C]) -> f32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return unsafe { bf16_score_avx2(q, key) };
        }
    }
    bf16_score_scalar(q, key)
}

fn main() {
    let mut rng = Rng::new(0xBADC0DE);
    let max_l = 1usize << 20; // 1,048,576 tokens

    let mut q = [0.0f32; D_C];
    rng.fill_gaussian(&mut q);
    let q_sign = [
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    ];

    println!("== SLHA (128 o/token) vs référence bf16 (256 o/token) ==\n");
    println!(
        "  Allocation : {max_l} tuiles SLHA ({} Mo) + {max_l} clés bf16 ({} Mo)…",
        max_l * 128 / (1 << 20),
        max_l * 256 / (1 << 20)
    );

    // Values are irrelevant for timing; only the access pattern + work matter.
    let tiles: Vec<SciRustSlhaTile> = (0..max_l)
        .map(|i| {
            let mut latent = [0u8; LATENT_BYTES];
            for b in latent.iter_mut() {
                *b = rng.next_u64() as u8;
            }
            SciRustSlhaTile {
                latent_kv: latent,
                residual_bitmap: [
                    rng.next_u64(),
                    rng.next_u64(),
                    rng.next_u64(),
                    rng.next_u64(),
                ],
                scale: 1.0,
                dynamic_lambda: 0.5,
                residual_sigma: 1.0,
                token_id: i as u32,
                position: i as u32,
                head_id: 0,
                flags: FLAG_HOT,
                group_scales: [200; N_GROUPS],
            }
        })
        .collect();
    let keys: Vec<[u16; D_C]> = (0..max_l)
        .map(|_| {
            let mut k = [0u16; D_C];
            for x in k.iter_mut() {
                *x = rng.next_u64() as u16;
            }
            k
        })
        .collect();

    #[cfg(target_arch = "x86_64")]
    let avx2 = std::is_x86_feature_detected!("avx2");
    #[cfg(not(target_arch = "x86_64"))]
    let avx2 = false;
    println!("  AVX2 = {avx2}  (caches : L1d 48K/cœur, L2 2M/cœur, L3 ~260M partagé)\n");

    println!(
        "  {:>9} {:>7} {:>7} | {:>9} {:>8} | {:>9} {:>8}",
        "contexte", "SLHA Mo", "bf16 Mo", "SLHA M/s", "GB/s", "bf16 M/s", "GB/s"
    );
    println!("  {}", "-".repeat(64));

    for &l in &[8192usize, 65536, 262144, 1_048_576] {
        let reps = (200_000_000 / l).max(2);
        let n = (reps * l) as f64;

        let mut sink = 0.0f32;
        let t = Instant::now();
        for _ in 0..reps {
            for tile in &tiles[..l] {
                sink += tile.compute_score(&q, &q_sign);
            }
        }
        let dt = t.elapsed().as_secs_f64();
        let slha_ms = n / dt / 1e6;
        let slha_gb = n * 128.0 / dt / 1e9;

        let mut sink2 = 0.0f32;
        let t2 = Instant::now();
        for _ in 0..reps {
            for key in &keys[..l] {
                sink2 += bf16_score(&q, key);
            }
        }
        let dt2 = t2.elapsed().as_secs_f64();
        let bf_ms = n / dt2 / 1e6;
        let bf_gb = n * 256.0 / dt2 / 1e9;

        println!(
            "  {:>9} {:>7} {:>7} | {:>9.1} {:>8.1} | {:>9.1} {:>8.1}",
            l,
            l * 128 / (1 << 20),
            l * 256 / (1 << 20),
            slha_ms,
            slha_gb,
            bf_ms,
            bf_gb
        );
        std::hint::black_box((sink, sink2));
    }

    println!(
        "\n  Lecture : SLHA lit 2× moins d'octets/token (128 vs 256). Sur petit\n  \
         contexte (résident L1/L2), la comparaison est dominée par le calcul —\n  \
         SLHA fait en plus le popcount du résidu. Quand le contexte grandit et\n  \
         déborde les caches, l'écart bascule en faveur de SLHA via la bande\n  \
         passante. (Compteurs de cache matériels indisponibles ici — cf. en-tête.)"
    );
}
