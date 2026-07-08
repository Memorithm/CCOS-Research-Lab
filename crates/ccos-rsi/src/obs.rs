//! Observabilité optionnelle — émission d'événements structurés via `tracing`.
//!
//! Sans la feature `observability`, toutes les fonctions sont des **no-ops**
//! `#[inline]` : le cœur reste sans dépendance. Avec la feature, les événements
//! sont émis sur la cible `rsi` et captés par le subscriber `tracing` que l'hôte
//! installe (ex. `tracing_subscriber::fmt`). On instrumente surtout les
//! **événements de sûreté** : adoption/rejet de propositions, disjoncteur, véto.
//!
//! Les **métriques** (compteurs) sont exposées séparément, sans dépendance, par
//! la commande `metrics` de [`crate::api`] au format d'exposition Prometheus.

/// Événement informatif (ex. proposition adoptée). No-op sans `observability`.
#[cfg(feature = "observability")]
#[inline]
pub fn info(event: &str, detail: &str) {
    tracing::info!(target: "rsi", event, detail);
}

/// Événement informatif — no-op (feature `observability` absente).
#[cfg(not(feature = "observability"))]
#[inline]
pub fn info(_event: &str, _detail: &str) {}

/// Événement d'avertissement (garde-fou : rejet de sûreté, disjoncteur, véto).
/// No-op sans `observability`.
#[cfg(feature = "observability")]
#[inline]
pub fn warn(event: &str, detail: &str) {
    tracing::warn!(target: "rsi", event, detail);
}

/// Événement d'avertissement — no-op (feature `observability` absente).
#[cfg(not(feature = "observability"))]
#[inline]
pub fn warn(_event: &str, _detail: &str) {}
