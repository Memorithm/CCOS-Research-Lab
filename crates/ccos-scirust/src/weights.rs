//! Portable weights file for a learned projection (plan Phase 1, §1.1).
//!
//! A projection trained once (PCA via [`LearnedModel::fit`], or SGD via
//! [`crate::learned::train_projection`]) can be **saved and reloaded** without
//! re-fitting — the reusable artifact an LLM integration would ship.
//!
//! Zero-dependency, little-endian, self-describing:
//! ```text
//! [u32 magic = 0x534C4857 ("SLHW")]
//! [u32 version = 1]
//! [u32 d]                       key dimension
//! [u64 seed]                    RNG seed for the sign-LSH Z (+ RHT)
//! [u8 rht][u8 pad ×3]           incoherence transform on/off (plan axis A2)
//! [f32 × (D_C·d)]               projection P (D_C × d, row-major)
//! ```
//! The sign-LSH `Z` and the optional RHT are **regenerated from `seed`**
//! ([`LearnedModel::from_projection_with`] seeds them exactly as `fit` does), so
//! only `P` needs storing — the file stays compact. Faithful for non-whitened
//! models (the default; whitening is score-preserving, so it is not persisted).

use crate::attention::slha_v2::D_C;
use crate::learned::LearnedModel;

const MAGIC: u32 = 0x534C_4857; // "SLHW"
const VERSION: u32 = 1;
const HEADER: usize = 4 + 4 + 4 + 8 + 4; // magic, version, d, seed, rht+pad

/// Serialize a fitted model's projection to the weights format.
pub fn to_bytes(model: &LearnedModel, seed: u64, rht: bool) -> Vec<u8> {
    let evec = model.projection(); // D_C × d
    let mut out = Vec::with_capacity(HEADER + evec.len() * 4);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(model.d as u32).to_le_bytes());
    out.extend_from_slice(&seed.to_le_bytes());
    out.push(u8::from(rht));
    out.extend_from_slice(&[0u8; 3]); // pad to 4-byte boundary
    for &f in evec {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

/// Reconstruct a [`LearnedModel`] from the weights format. Scores match the
/// original model exactly (non-whitened case).
pub fn from_bytes(bytes: &[u8]) -> Result<LearnedModel, String> {
    if bytes.len() < HEADER {
        return Err("weights: truncated header".into());
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    if u32_at(0) != MAGIC {
        return Err("weights: bad magic (not an SLHW file)".into());
    }
    let version = u32_at(4);
    if version != VERSION {
        return Err(format!(
            "weights: unsupported version {version} (expected {VERSION})"
        ));
    }
    let d = u32_at(8) as usize;
    let seed = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let rht = bytes[20] != 0;

    let want = HEADER + D_C * d * 4;
    if bytes.len() != want {
        return Err(format!(
            "weights: size mismatch (got {}, expected {want})",
            bytes.len()
        ));
    }
    let mut evec = vec![0.0f32; D_C * d];
    for (i, slot) in evec.iter_mut().enumerate() {
        let o = HEADER + i * 4;
        *slot = f32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    }
    Ok(LearnedModel::from_projection_with(evec, d, seed, rht))
}

/// Write a fitted projection to `path`.
pub fn save(path: &str, model: &LearnedModel, seed: u64, rht: bool) -> std::io::Result<()> {
    std::fs::write(path, to_bytes(model, seed, rht))
}

/// Load a projection from `path`.
pub fn load(path: &str) -> Result<LearnedModel, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("weights: cannot read {path}: {e}"))?;
    from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learned::gen_keys;

    #[test]
    fn roundtrip_preserves_scores() {
        let (d, seed, rht) = (256usize, 0x0000_ABCD_u64, true);
        let keys = gen_keys(1, 300, d, d, 0.9, 0.02);
        let model = LearnedModel::fit_with(&keys, d, seed, false, rht);

        let reloaded = from_bytes(&to_bytes(&model, seed, rht)).expect("roundtrip");
        assert_eq!(
            model.projection(),
            reloaded.projection(),
            "projection differs"
        );

        // Query encoding and a tile score must match bit-for-bit.
        let q = &keys[0];
        assert_eq!(model.query_coarse(q), reloaded.query_coarse(q));
        assert_eq!(model.sign_bits(q), reloaded.sign_bits(q));
        let qc = model.query_coarse(q);
        let qs = model.sign_bits(q);
        let s1 = model.encode(&keys[1], 1, false).compute_score(&qc, &qs);
        let s2 = reloaded.encode(&keys[1], 1, false).compute_score(&qc, &qs);
        assert_eq!(s1, s2, "reloaded score differs");
    }

    #[test]
    fn rejects_malformed() {
        assert!(from_bytes(&[0, 1, 2]).is_err()); // too short
        assert!(from_bytes(&[0; 32]).is_err()); // bad magic
    }
}
