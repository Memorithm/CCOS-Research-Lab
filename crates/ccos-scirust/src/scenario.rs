//! Reproducible measurement scenario for SLHA v2.
//!
//! The scientific question this prototype answers is narrow on purpose:
//!
//! > Given a key split into a **captured low-rank part** `k_coarse` (stored as
//! > INT4) and a **residual** `e` of controllable relative energy `rho`, how
//! > well does the SLHA score — coarse dot product **plus** the 1-bit sign-LSH
//! > correction — approximate the true score `<Q, k_coarse + e>`, for ranking
//! > (Spearman / top-k) and for magnitude (Pearson)?
//!
//! To stay self-contained and training-free, we work directly in the key space
//! (`D_K == D_C`): the coarse key *is* the latent, and `Z` is a random Gaussian
//! Johnson–Lindenstrauss projection (exactly as the design prescribes). What is
//! **out of scope** here is the quality of the learned `W_down`/`W_up`
//! projection — that is training-dependent; we assume the low-rank part is
//! captured exactly and measure the quantisation + 1-bit-residual machinery.

use crate::attention::slha_v2::{
    quantize_latent_grouped, SciRustSlhaTile, D_C, D_S, FLAG_HOT, FLAG_WARM, RESIDUAL_WORDS,
};
use crate::metrics::rms;
use crate::rng::Rng;

/// Key dimensionality for the prototype (coarse key == latent space).
pub const D_K: usize = D_C;

/// Analytic λ constant from eq. (3.2): `√(π/(2·D_S))` (≈ 0.0783 at D_S = 256).
/// A function rather than a `const` because `f32::sqrt` is not const-stable.
#[inline]
pub fn analytic_lambda_c() -> f32 {
    (std::f32::consts::PI / (2.0 * D_S as f32)).sqrt()
}

/// Empirically-calibrated λ constant at D_S = 256. The calibration study
/// (`examples/calibrate_lambda.rs`, `tests/calibration.rs`) shows the analytic
/// constant under-weights the 1-bit residual by ~4.2× on the synthetic JL
/// benchmark, so the least-squares-optimal constant is `C_emp ≈ 0.33`.
///
/// Exposed for opt-in use. [`build_tile`] keeps the **analytic** constant by
/// default: the calibration minimises score *magnitude* error (RMSE), which is
/// not the same objective as *ranking* (top-k / Spearman) — over-weighting the
/// directionally-noisy residual can slightly hurt ranking — so the analytic
/// value stays the conservative default and the §7 measurements remain valid.
pub const LAMBDA_C_CALIBRATED: f32 = 0.33;

/// λ for a tile from its residual energy `σ_E`, using the calibrated constant
/// (see [`LAMBDA_C_CALIBRATED`]).
#[inline]
pub fn calibrated_lambda(sigma_e: f32) -> f32 {
    sigma_e * LAMBDA_C_CALIBRATED
}

/// Fixed random sign-LSH projection `Z ∈ ℝ^{D_S × D_K}` (row-major).
pub struct Projection {
    z: Vec<f32>,
}

impl Projection {
    pub fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut z = vec![0.0f32; D_S * D_K];
        rng.fill_gaussian(&mut z);
        Projection { z }
    }

    /// Pack `sign(Z · v)` into `D_S` bits. Convention: **bit = 1 iff the
    /// projection is negative**. With this convention, `popcount(a ^ b)` equals
    /// the number of sign *disagreements* (the Hamming distance), so
    /// `d_s - 2·popcount` is the signed dot product of the two ±1 vectors.
    pub fn sign_bits(&self, v: &[f32; D_K]) -> [u64; RESIDUAL_WORDS] {
        let mut out = [0u64; RESIDUAL_WORDS];
        for s in 0..D_S {
            let row = &self.z[s * D_K..(s + 1) * D_K];
            let mut acc = 0.0f32;
            for k in 0..D_K {
                acc += row[k] * v[k];
            }
            if acc < 0.0 {
                out[s >> 6] |= 1u64 << (s & 63);
            }
        }
        out
    }
}

/// One synthetic context token: the true key and its coarse/residual split.
pub struct ContextToken {
    pub k_coarse: [f32; D_K],
    pub e: [f32; D_K],
    pub k_real: [f32; D_K],
}

/// Build a tile for a context token. `warm = true` marks the residual as paged
/// out (CCOS WARM mode); λ is calibrated per tile from σ_E via eq. (3.2).
pub fn build_tile(proj: &Projection, tok: &ContextToken, pos: u32, warm: bool) -> SciRustSlhaTile {
    let (latent, scale, group_scales) = quantize_latent_grouped(&tok.k_coarse);
    let bitmap = proj.sign_bits(&tok.e);
    let sigma_e = rms(&tok.e);
    // eq. (3.2): λ = σ_E · √(π / (2 · d_s)) — analytic constant (conservative
    // default; see `LAMBDA_C_CALIBRATED` for the opt-in calibrated alternative).
    let lambda = sigma_e * analytic_lambda_c();
    SciRustSlhaTile {
        latent_kv: latent,
        residual_bitmap: bitmap,
        scale,
        dynamic_lambda: lambda,
        residual_sigma: sigma_e,
        token_id: pos,
        position: pos,
        head_id: 0,
        flags: if warm { FLAG_WARM } else { FLAG_HOT },
        group_scales,
    }
}

/// Generate a query and `n` context tokens with residual relative energy `rho`
/// (`rho = ||e|| / ||k_real||`, with `e` independent of `k_coarse`).
pub fn generate(seed: u64, n: usize, rho: f32) -> ([f32; D_K], Vec<ContextToken>) {
    let mut rng = Rng::new(seed);

    let mut q = [0.0f32; D_K];
    rng.fill_gaussian(&mut q);

    // rho = alpha / sqrt(1 + alpha^2)  =>  alpha = rho / sqrt(1 - rho^2),
    // where alpha = ||e|| / ||k_coarse||.
    let rho = rho.clamp(0.0, 0.999);
    let alpha = rho / (1.0 - rho * rho).sqrt();

    let mut tokens = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k_coarse = [0.0f32; D_K];
        rng.fill_gaussian(&mut k_coarse);

        let mut e = [0.0f32; D_K];
        rng.fill_gaussian(&mut e);
        // Scale e so that ||e|| = alpha * ||k_coarse||.
        let nk = norm(&k_coarse);
        let ne = norm(&e).max(1.0e-9);
        let target = alpha * nk;
        let g = target / ne;
        for x in e.iter_mut() {
            *x *= g;
        }

        let mut k_real = [0.0f32; D_K];
        for i in 0..D_K {
            k_real[i] = k_coarse[i] + e[i];
        }
        tokens.push(ContextToken {
            k_coarse,
            e,
            k_real,
        });
    }
    (q, tokens)
}

#[inline]
fn norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}
