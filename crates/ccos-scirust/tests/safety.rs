//! Tests d'intégration pour le filtre de sécurité géométrique.
//!
//! Ces tests vérifient le comportement du [`LatentSafetyGuard`] sur des cas
//! réalistes : vecteurs normaux, vecteurs attaquants, isolation orthogonale, dérive
//! progressive, et analyse directe sur les tuiles compressées INT4.

use scirust::safety::{LatentSafetyGuard, SafetyReason, SafetyResult};

const D: usize = 128;

/// Direction « tous-un » normalisée.
fn ones_unit() -> [f32; D] {
    let n = (D as f32).sqrt();
    core::array::from_fn(|_| 1.0 / n)
}

/// Direction alternée `±1` normalisée, orthogonale à `ones_unit`.
fn alt_unit() -> [f32; D] {
    let n = (D as f32).sqrt();
    core::array::from_fn(|i| if i % 2 == 0 { 1.0 / n } else { -1.0 / n })
}

/// Vecteur unitaire de cosinus `c` connu avec `ones_unit` (mélange orthonormé).
fn with_cosine(c: f32) -> [f32; D] {
    let s = (1.0 - c * c).sqrt();
    let a = ones_unit();
    let b = alt_unit();
    core::array::from_fn(|i| c * a[i] + s * b[i])
}

#[test]
fn test_guard_accepts_normal_vectors() {
    let reference = ones_unit();
    let mut guard = LatentSafetyGuard::new(reference, 0.5);

    // Vecteur identique à la référence : cosinus 1.0 → Safe.
    assert_eq!(guard.analyze_dequantized(&reference), SafetyResult::Safe);

    // Vecteur proche (cosinus 0.95) → Safe.
    let close = with_cosine(0.95);
    assert_eq!(guard.analyze_dequantized(&close), SafetyResult::Safe);
}

#[test]
fn test_guard_detects_attacker_vector() {
    let reference = ones_unit();
    let mut guard = LatentSafetyGuard::new(reference, 0.5);

    // Vecteur opposé (cosinus -1.0) → bien au-dessous du seuil.
    let attacker = with_cosine(-1.0);
    match guard.analyze_dequantized(&attacker) {
        SafetyResult::Anomalous { reason, deviation } => {
            assert_eq!(reason, SafetyReason::DotProductDeviation);
            assert!(deviation > 0.0);
        }
        SafetyResult::Safe => panic!("le vecteur attaquant aurait dû être détecté"),
    }
}

#[test]
fn test_guard_detects_orthogonal_isolation() {
    // reference = tous-un (signal 1 cosinus 1 → passe) ; weights = alterné ±1.
    // Le vecteur tous-un est orthogonal aux weights → score 0 < 0.15 → isolation.
    let reference = ones_unit();
    let weights = core::array::from_fn(|i| if i % 2 == 0 { 1.0 } else { -1.0 });
    let mut guard = LatentSafetyGuard::with_linear_classifier(reference, weights, 0.0, 0.15);

    match guard.analyze_dequantized(&ones_unit()) {
        SafetyResult::Anomalous { reason, .. } => {
            assert_eq!(reason, SafetyReason::OrthogonalIsolation);
        }
        SafetyResult::Safe => panic!("le vecteur isolé aurait dû être détecté"),
    }
}

#[test]
fn test_drift_detection_over_multiple_analyses() {
    // cosinus 0.6 : passe le signal 1 (≥ 0.5) mais moyenne < seuil de dérive 0.8.
    let drifted = with_cosine(0.6);
    let mut guard = LatentSafetyGuard::new(ones_unit(), 0.5);

    // Tant que la fenêtre n'est pas pleine, on reste Safe.
    for _ in 0..3 {
        assert_eq!(guard.analyze_dequantized(&drifted), SafetyResult::Safe);
    }
    // Au 4e appel, la fenêtre est pleine et la moyenne 0.6 < 0.8 → ActivationDrift.
    match guard.analyze_dequantized(&drifted) {
        SafetyResult::Anomalous { reason, .. } => assert_eq!(reason, SafetyReason::ActivationDrift),
        SafetyResult::Safe => panic!("la dérive aurait dû être détectée"),
    }
}

#[test]
fn test_analyze_on_compressed_latent() {
    let mut guard = LatentSafetyGuard::new([1.0f32; D], 0.5);

    // Vecteur latent « normal » : tous les nibbles à 12 (valeur +4) → aligné avec la
    // référence tous-un (cosinus 1.0) → Safe.
    let normal_latent: [u8; 64] = core::array::from_fn(|_| 0xCC); // high=12, low=12
    match guard.analyze(&normal_latent) {
        SafetyResult::Safe => {}
        result => panic!("vecteur normal compressé aurait dû être accepté : {result:?}"),
    }

    // Vecteur latent « attaquant » : tous les nibbles à 0 (valeur -8) → opposé à la
    // référence (cosinus -1.0) → DotProductDeviation.
    let attacker_latent: [u8; 64] = core::array::from_fn(|_| 0x00);
    match guard.analyze(&attacker_latent) {
        SafetyResult::Anomalous { reason, .. } => {
            assert_eq!(reason, SafetyReason::DotProductDeviation);
        }
        SafetyResult::Safe => panic!("vecteur attaquant compressé aurait dû être détecté"),
    }
}

#[test]
fn test_threshold_sensitivity() {
    let reference = ones_unit();
    // cosinus 0.4 : « borderline ».
    let borderline = with_cosine(0.4);

    // Seuil bas (0.1) : 0.4 ≥ 0.1 et fenêtre non pleine au 1er appel → Safe.
    let mut guard_low = LatentSafetyGuard::new(reference, 0.1);
    assert_eq!(
        guard_low.analyze_dequantized(&borderline),
        SafetyResult::Safe
    );

    // Seuil haut (0.9) : 0.4 < 0.9 → Anomalous (DotProductDeviation, signal 1).
    let mut guard_high = LatentSafetyGuard::new(reference, 0.9);
    match guard_high.analyze_dequantized(&borderline) {
        SafetyResult::Anomalous {
            reason: SafetyReason::DotProductDeviation,
            ..
        } => {}
        other => panic!("attendu DotProductDeviation, obtenu {other:?}"),
    }
}

#[test]
fn test_perfect_match_cosine() {
    let reference = ones_unit();
    let mut guard = LatentSafetyGuard::new(reference, 0.5);

    assert_eq!(guard.analyze_dequantized(&reference), SafetyResult::Safe);
    // cos(0°) = 1.0 = alignement parfait.
    assert!((guard.last_cosine() - 1.0).abs() < 1e-6);
}

#[test]
fn test_analyze_uses_canonical_nibble_order() {
    // Verrouille end-to-end l'ordre des nibbles : la référence est la déquant
    // canonique d'un latent asymétrique, donc alignée avec decode_nibbles canonique
    // (cosinus 1.0 → Safe). Un décodage inversé pair-permuterait le vecteur et le
    // cosinus chuterait sous le seuil → Anomalous.
    use scirust::attention::slha_v2::quantize_latent;
    let raw: [f32; D] = core::array::from_fn(|d| ((d as f32 % 7.0) - 3.0) * 0.5);
    let (packed, scale) = quantize_latent(&raw);
    // Déquant canonique = (nibble-8)*scale, dim paire ← nibble bas, impaire ← haut.
    let reference: [f32; D] = core::array::from_fn(|d| {
        let nib = if d & 1 == 0 {
            packed[d >> 1] & 0x0F
        } else {
            (packed[d >> 1] >> 4) & 0x0F
        };
        (nib as f32 - 8.0) * scale
    });
    let mut guard = LatentSafetyGuard::new(reference, 0.99);
    match guard.analyze(&packed) {
        SafetyResult::Safe => {}
        other => panic!("le guard devrait reconnaître le latent canonique : {other:?}"),
    }
}
