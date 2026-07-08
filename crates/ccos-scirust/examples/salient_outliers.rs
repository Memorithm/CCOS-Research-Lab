//! Salient-outlier (BiLLM-style) feasibility study — the honest prerequisite
//! from the roadmap (§ Future Work): *before* spending 16 of the tile's 128
//! bytes on a salient block, measure whether FP-preserving a few salient key
//! dimensions actually helps **when the keys contain activation outliers**.
//!
//! Run with:  `cargo run -p scirust --release --example salient_outliers`
//!
//! Our default benchmark uses Gaussian keys, where §7.8 already showed
//! quantization is *not* the bottleneck (INT8 ≈ INT4). BiLLM targets a different
//! regime: a few **channels** with outlier magnitude that a single INT4 group
//! scale handles badly. So we inject such channels and sweep their strength.
//!
//! For each outlier multiplier we compare WARM-mode (coarse-only — latent
//! quantization in isolation) against the FP truth `<q, k_coarse>`:
//!
//! * **INT4** — group-scaled INT4 over the full key (baseline).
//! * **salient-s** — BiLLM-style: remove the top-`s` |dims| before quantizing
//!   (a tighter scale for the rest), keep those `s` dims in FP32. `s = 2` is the
//!   budget the proposed tile affords (`salient_values: [f32; 2]`); `s = 4`
//!   shows whether 2 is enough.
//!
//! We report latent reconstruction RMSE, score Spearman, and attention-output
//! cosine. **No tile change** — this is a prototype to decide if the trade-off
//! (16 bytes vs. σ_E / `group_scales`, which power CCOS paging + MX) is worth it.

use scirust::attention::slha_v2::{quantize_latent_grouped, SciRustSlhaTile, D_C, FLAG_HOT};
use scirust::metrics::{cosine, dot, softmax_into, spearman};
use scirust::rng::Rng;
use scirust::scenario::{generate, D_K};

/// Group-scaled INT4 round-trip of a latent vector (the kernel's own path).
fn dequant_int4(v: &[f32; D_C]) -> [f32; D_C] {
    let (latent_kv, scale, group_scales) = quantize_latent_grouped(v);
    let tile = SciRustSlhaTile {
        latent_kv,
        residual_bitmap: [0; 4],
        scale,
        dynamic_lambda: 0.0,
        residual_sigma: 0.0,
        token_id: 0,
        position: 0,
        head_id: 0,
        flags: FLAG_HOT,
        group_scales,
    };
    tile.dequant_latent()
}

/// Indices of the `s` largest-magnitude dimensions.
fn topk_abs(v: &[f32; D_C], s: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..D_C).collect();
    idx.sort_by(|&a, &b| v[b].abs().total_cmp(&v[a].abs()));
    idx.truncate(s);
    idx
}

/// BiLLM-style salient reconstruction: pull the top-`s` |dims| out, quantize the
/// remainder in INT4 (now with a tighter scale), then restore the `s` dims in FP.
fn dequant_salient(v: &[f32; D_C], s: usize) -> [f32; D_C] {
    let salient = topk_abs(v, s);
    let mut masked = *v;
    for &d in &salient {
        masked[d] = 0.0;
    }
    let mut out = dequant_int4(&masked);
    for &d in &salient {
        out[d] = v[d]; // high-precision salient value
    }
    out
}

/// softmax(scores · scale) · V.
fn attn_out(scores: &[f32], values: &[Vec<f32>], scale: f32, dv: usize) -> Vec<f32> {
    let mut w = vec![0.0f32; scores.len()];
    softmax_into(scores, scale, &mut w);
    let mut o = vec![0.0f32; dv];
    for (wi, vi) in w.iter().zip(values) {
        for (j, oj) in o.iter_mut().enumerate() {
            *oj += wi * vi[j];
        }
    }
    o
}

fn rmse(a: &[f32; D_C], b: &[f32; D_C]) -> f64 {
    let s: f64 = (0..D_C).map(|d| (a[d] - b[d]).powi(2) as f64).sum();
    (s / D_C as f64).sqrt()
}

fn main() {
    let n = 512usize;
    let dv = 64usize;
    let attn_scale = 1.0 / (D_K as f32).sqrt();
    // A few fixed "outlier channels" (consistent across tokens, as in real LLMs).
    let outlier_dims = [3usize, 37, 70, 101];

    let (q, toks) = generate(7, n, 0.3);
    let mut rngv = Rng::new(11);
    let values: Vec<Vec<f32>> = (0..n)
        .map(|_| {
            let mut v = vec![0.0f32; dv];
            rngv.fill_gaussian(&mut v);
            v
        })
        .collect();

    println!("== BiLLM-style salient-outlier study (WARM / coarse-only) ==");
    println!(
        "  {n} clés · {} canaux outliers {:?} · budget tuile = 2 valeurs FP\n",
        outlier_dims.len(),
        outlier_dims
    );
    println!(
        "  {:>5} | {:>21} | {:>21} | {:>21}",
        "mult", "recon RMSE", "WARM Spearman", "sortie cos"
    );
    println!(
        "  {:>5} | {:>6} {:>6} {:>6} | {:>6} {:>6} {:>6} | {:>6} {:>6} {:>6}",
        "", "INT4", "sal2", "sal4", "INT4", "sal2", "sal4", "INT4", "sal2", "sal4"
    );
    println!("  {}", "-".repeat(78));

    for &mult in &[1.0f32, 2.0, 4.0, 8.0, 16.0, 32.0] {
        let (mut tr, mut b, mut s2, mut s4) =
            (vec![0f32; n], vec![0f32; n], vec![0f32; n], vec![0f32; n]);
        let (mut rb, mut r2, mut r4) = (0f64, 0f64, 0f64);

        for (i, t) in toks.iter().enumerate() {
            let mut k = t.k_coarse;
            for &d in &outlier_dims {
                k[d] *= mult; // inject channel outliers
            }
            let kb = dequant_int4(&k);
            let k2 = dequant_salient(&k, 2);
            let k4 = dequant_salient(&k, 4);
            rb += rmse(&kb, &k);
            r2 += rmse(&k2, &k);
            r4 += rmse(&k4, &k);
            tr[i] = dot(&q, &k); // FP truth (coarse)
            b[i] = dot(&q, &kb);
            s2[i] = dot(&q, &k2);
            s4[i] = dot(&q, &k4);
        }
        let (rb, r2, r4) = (rb / n as f64, r2 / n as f64, r4 / n as f64);
        let ot = attn_out(&tr, &values, attn_scale, dv);
        let cb = cosine(&ot, &attn_out(&b, &values, attn_scale, dv));
        let c2 = cosine(&ot, &attn_out(&s2, &values, attn_scale, dv));
        let c4 = cosine(&ot, &attn_out(&s4, &values, attn_scale, dv));

        println!(
            "  {mult:>5.0} | {rb:>6.3} {r2:>6.3} {r4:>6.3} | {:>6.3} {:>6.3} {:>6.3} | {cb:>6.4} {c2:>6.4} {c4:>6.4}",
            spearman(&b, &tr),
            spearman(&s2, &tr),
            spearman(&s4, &tr),
        );
    }

    println!(
        "\n  Lecture : à mult=1 (clés ~gaussiennes) le salient n'aide pas (cf. §7.8) ;\n  \
         l'écart INT4→salient mesure le gain quand des canaux outliers apparaissent.\n  \
         Si le gain ne se matérialise qu'au-delà d'outliers irréalistes, la tuile BiLLM\n  \
         (16 o pris à σ_E / group_scales) n'en vaut pas le coût — décision *mesurée*."
    );
}
