//! Small statistics helpers for validating approximation quality.
//! No external dependencies.

use std::collections::HashSet;

/// Plain dot product — the full-precision ground-truth attention score.
///
/// ```
/// use scirust::metrics::dot;
/// assert!((dot(&[1.0, 2.0, 3.0], &[1.0, 0.0, -1.0]) + 2.0).abs() < 1e-6);
/// ```
#[inline]
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    let mut s = 0.0f32;
    for i in 0..a.len() {
        s += a[i] * b[i];
    }
    s
}

/// Pearson correlation coefficient (linear / magnitude fidelity).
pub fn pearson(x: &[f32], y: &[f32]) -> f32 {
    assert_eq!(x.len(), y.len());
    if x.is_empty() {
        return 0.0;
    }
    let n = x.len() as f32;
    let mx = x.iter().sum::<f32>() / n;
    let my = y.iter().sum::<f32>() / n;
    let (mut sxy, mut sxx, mut syy) = (0.0f32, 0.0f32, 0.0f32);
    for i in 0..x.len() {
        let dx = x[i] - mx;
        let dy = y[i] - my;
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if sxx <= 0.0 || syy <= 0.0 {
        return 0.0;
    }
    sxy / (sxx.sqrt() * syy.sqrt())
}

/// Fractional ranks (0-based), ties broken arbitrarily. Inputs are assumed
/// continuous (no ties) for the synthetic data used here.
pub fn ranks(v: &[f32]) -> Vec<f32> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    idx.sort_by(|&a, &b| v[a].total_cmp(&v[b]));
    let mut r = vec![0.0f32; v.len()];
    for (rank, &i) in idx.iter().enumerate() {
        r[i] = rank as f32;
    }
    r
}

/// Spearman rank correlation (ordering fidelity — what attention top-k cares
/// about most).
pub fn spearman(x: &[f32], y: &[f32]) -> f32 {
    pearson(&ranks(x), &ranks(y))
}

/// Fraction of the top-`k` indices shared between two score vectors.
/// `k == 0` returns `0.0` (rather than `NaN` from dividing by `k`).
pub fn topk_overlap(truth: &[f32], approx: &[f32], k: usize) -> f32 {
    if k == 0 {
        return 0.0;
    }
    let top = |v: &[f32]| -> HashSet<usize> {
        let mut idx: Vec<usize> = (0..v.len()).collect();
        idx.sort_by(|&a, &b| v[b].total_cmp(&v[a]));
        idx.truncate(k);
        idx.into_iter().collect()
    };
    let a = top(truth);
    let b = top(approx);
    a.intersection(&b).count() as f32 / k as f32
}

/// Root-mean-square value of a slice (used as a per-tile sigma_E estimate).
/// Empty input returns `0.0` (rather than `NaN` from `0/0`).
#[inline]
pub fn rms(v: &[f32]) -> f32 {
    if v.is_empty() {
        return 0.0;
    }
    (v.iter().map(|x| x * x).sum::<f32>() / v.len() as f32).sqrt()
}

/// Cosine similarity between two vectors.
///
/// ```
/// use scirust::metrics::cosine;
/// assert!((cosine(&[1.0, 0.0], &[2.0, 0.0]) - 1.0).abs() < 1e-6);
/// assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
/// ```
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let na = dot(a, a).sqrt();
    let nb = dot(b, b).sqrt();
    if na * nb == 0.0 {
        0.0
    } else {
        dot(a, b) / (na * nb)
    }
}

/// Relative L2 error `||a - b|| / ||a||` (a is the reference).
pub fn rel_l2(reference: &[f32], approx: &[f32]) -> f32 {
    let mut nd = 0.0f32;
    let mut na = 0.0f32;
    for i in 0..reference.len() {
        nd += (reference[i] - approx[i]).powi(2);
        na += reference[i] * reference[i];
    }
    (nd / na.max(1e-12)).sqrt()
}

/// Numerically stable softmax of `scores * scale` into `out`.
///
/// ```
/// use scirust::metrics::softmax_into;
/// let mut w = [0.0f32; 3];
/// softmax_into(&[0.0, 0.0, 0.0], 1.0, &mut w);
/// assert!((w.iter().sum::<f32>() - 1.0).abs() < 1e-6);
/// assert!((w[0] - 1.0 / 3.0).abs() < 1e-6);
/// ```
pub fn softmax_into(scores: &[f32], scale: f32, out: &mut [f32]) {
    debug_assert_eq!(scores.len(), out.len());
    let mut m = f32::NEG_INFINITY;
    for &x in scores {
        m = m.max(x * scale);
    }
    let mut sum = 0.0f32;
    for (o, &x) in out.iter_mut().zip(scores) {
        let e = (x * scale - m).exp();
        *o = e;
        sum += e;
    }
    // All-(-inf) (or all-masked) inputs give sum == 0; dividing would yield
    // NaN/Inf. Return a uniform distribution instead, mirroring the
    // "finite 0.0 on degenerate input" contract of the other helpers.
    if !sum.is_finite() || sum <= 0.0 {
        let n = out.len();
        let u = if n == 0 { 0.0 } else { 1.0 / n as f32 };
        for o in out.iter_mut() {
            *o = u;
        }
        return;
    }
    let inv = 1.0 / sum;
    for o in out.iter_mut() {
        *o *= inv;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Degenerate inputs (empty slices, `k == 0`, zero vectors) must return a
    /// finite `0.0` rather than `NaN`/`Inf` from a `0/0` or `x/0`.
    #[test]
    fn degenerate_inputs_stay_finite() {
        let empty: &[f32] = &[];
        assert_eq!(rms(empty), 0.0);
        assert_eq!(dot(empty, empty), 0.0);
        assert_eq!(pearson(empty, empty), 0.0);
        assert_eq!(spearman(empty, empty), 0.0);
        assert_eq!(cosine(empty, empty), 0.0);
        assert_eq!(rel_l2(empty, empty), 0.0);
        assert_eq!(topk_overlap(&[1.0, 2.0], &[2.0, 1.0], 0), 0.0);
        assert_eq!(cosine(&[0.0, 0.0], &[0.0, 0.0]), 0.0); // zero norm

        let mut out: [f32; 0] = [];
        softmax_into(empty, 1.0, &mut out); // must not panic

        // All-(-inf) scores: must not produce NaN/Inf; uniform output instead.
        let mut w = [f32::NAN; 4];
        softmax_into(&[f32::NEG_INFINITY; 4], 1.0, &mut w);
        assert!(w.iter().all(|&x| x.is_finite()), "got {w:?}");
        assert!((w.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!((w[0] - 0.25).abs() < 1e-6);

        for v in [
            rms(empty),
            pearson(empty, empty),
            cosine(empty, empty),
            rel_l2(empty, empty),
            topk_overlap(empty, empty, 0),
        ] {
            assert!(v.is_finite(), "expected finite, got {v}");
        }
    }
}
