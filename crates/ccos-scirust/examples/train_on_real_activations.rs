//! Phase 1 (§1.1) — train a **learned** projection on real (or realistic) keys,
//! save it to a portable weights file ([`scirust::weights`]), and reload it to
//! prove the round-trip. The saved `.slhw` file is the reusable projection
//! artifact an LLM integration would ship (train once, load everywhere).
//!
//! Run (realistic synthetic keys):
//! ```text
//! cargo run --release --example train_on_real_activations
//! ```
//! On REAL activations (see `scripts/dump_activations.py`, uses `k.bin`):
//! ```text
//! cargo run --release --example train_on_real_activations -- --dump DIR --rht --out proj.slhw
//! ```

// Numeric loops read closer to the math with indexing.
#![allow(clippy::needless_range_loop)]

use scirust::attention::slha_v2::D_C;
use scirust::learned::{gen_keys, LearnedModel};
use scirust::metrics::{cosine, dot, softmax_into};
use scirust::rng::Rng;
use scirust::weights;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let dump = opt("--dump");
    let rht = args.iter().any(|a| a == "--rht");
    let out = opt("--out").unwrap_or_else(|| {
        std::env::temp_dir()
            .join("slha_projection.slhw")
            .to_string_lossy()
            .into_owned()
    });
    let seed = 0x0000_5107_u64;

    // Training keys: real dump or realistic synthetic (spectral decay + outliers).
    let (keys, d, source) = match &dump {
        Some(dir) => {
            let (k, d) = load_k_bin(&format!("{dir}/k.bin"));
            (k, d, format!("activations RÉELLES {dir}/k.bin"))
        }
        None => {
            let d = 256usize;
            let k = gen_keys(1, 2000, d, d, 0.9, 0.02);
            (k, d, "synthétique réaliste (gen_keys)".to_string())
        }
    };
    assert!(
        d > D_C,
        "SLHA needs a key dim > {D_C}; got d={d} (dump a wider key representation)."
    );

    println!("== Phase 1 — entraînement + sauvegarde d'une projection APPRISE ==\n");
    println!("  clés d'entraînement : {source} — n={}, d={d}", keys.len());
    println!(
        "  incohérence RHT (A2) : {}\n",
        if rht { "activée" } else { "désactivée" }
    );

    // Train (PCA).
    let model = LearnedModel::fit_with(&keys, d, seed, false, rht);
    println!(
        "  énergie captée par le sous-espace top-{D_C} : {:.2}%",
        model.captured_energy * 100.0
    );

    // Save → reload → prove the round-trip is exact.
    weights::save(&out, &model, seed, rht).expect("save weights");
    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    let reloaded = weights::load(&out).expect("load weights");
    let identical = model.projection() == reloaded.projection();
    println!("  poids écrits          : {out}  ({bytes} o)");
    println!(
        "  rechargement          : projection {}\n",
        if identical {
            "identique ✅"
        } else {
            "DIFFÉRENTE ❌"
        }
    );

    // Quick fidelity sanity: attention-output cosine of the trained projection
    // vs full precision, HOT, on a held-out query/value set.
    let (dv, nq, nctx) = (64usize, 32usize, keys.len().min(512));
    let ctx = &keys[..nctx];
    let mut rng = Rng::new(9);
    let values: Vec<Vec<f32>> = (0..nctx)
        .map(|_| {
            let mut v = vec![0.0f32; dv];
            rng.fill_gaussian(&mut v);
            v
        })
        .collect();
    let tiles: Vec<_> = ctx
        .iter()
        .enumerate()
        .map(|(i, k)| model.encode(k, i as u32, false))
        .collect();
    let scale = 1.0 / (d as f32).sqrt();
    let mut cos = 0.0f32;
    for _ in 0..nq {
        let mut q = vec![0.0f32; d];
        rng.fill_gaussian(&mut q);
        let qc = model.query_coarse(&q);
        let qs = model.sign_bits(&q);
        let s_true: Vec<f32> = ctx.iter().map(|k| dot(&q, k)).collect();
        let s_slha: Vec<f32> = tiles.iter().map(|t| t.compute_score(&qc, &qs)).collect();
        cos += cosine(
            &attn(&s_true, &values, scale, dv),
            &attn(&s_slha, &values, scale, dv),
        );
    }
    println!(
        "  fidélité de sortie HOT (cos vs FP32) : {:.4}",
        cos / nq as f32
    );
    println!(
        "\n  → Projection réutilisable prête. Charge-la ailleurs via `scirust::weights::load`\n  \
         (ou lance `offline_validation --dump …` pour le GO/NO-GO complet sur activations réelles)."
    );
}

fn attn(scores: &[f32], values: &[Vec<f32>], scale: f32, dv: usize) -> Vec<f32> {
    let mut w = vec![0.0f32; scores.len()];
    softmax_into(scores, scale, &mut w);
    let mut o = vec![0.0f32; dv];
    for (wi, vi) in w.iter().zip(values) {
        for j in 0..dv {
            o[j] += wi * vi[j];
        }
    }
    o
}

/// Load a `k.bin` matrix (same format as `scripts/dump_activations.py`):
/// `[u32 magic=0x534C4841][u32 rows][u32 cols][f32 rows*cols row-major, LE]`.
fn load_k_bin(path: &str) -> (Vec<Vec<f32>>, usize) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    assert!(bytes.len() >= 12, "{path}: truncated header");
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    assert_eq!(magic, 0x534C_4841, "{path}: bad magic");
    let rows = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let cols = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 12 + rows * cols * 4, "{path}: size mismatch");
    let mut out = Vec::with_capacity(rows);
    let mut off = 12;
    for _ in 0..rows {
        let mut row = vec![0.0f32; cols];
        for c in row.iter_mut() {
            *c = f32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            off += 4;
        }
        out.push(row);
    }
    (out, cols)
}
