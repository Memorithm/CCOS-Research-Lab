//! **SLHAv2 full-kernel tier** (CCOS_EXTENDED, plan P1) — the premium bridge from
//! CCOS's runtime-neutral [`MemoryProvider`] surface to the REAL `ccos-scirust`
//! attention kernel, behind the off-by-default `slhav2-full` cargo feature and
//! the Pro [`Feature::SlhAv2FullKernel`](crate::license::Feature::SlhAv2FullKernel)
//! runtime gate.
//!
//! ## What this module is, and is not
//!
//! - It is **not** a new core path. The core recall/`MemoryPolicy` path and the
//!   distilled `slhav2` backend (zero-dep, `replay == live`) are untouched and
//!   remain the default. This module is reachable only behind two explicit opt-ins:
//!   the `slhav2-full` cargo feature (compile) **and** the offline license
//!   (runtime, via [`FullSlhaAccess::unlock`]).
//! - It **does** expose the real kernel's two premium capabilities that the
//!   distilled backend cannot provide:
//!   1. [`ScirustBackend`](ccos_memory_runtime::backend::scirust_full::ScirustBackend)
//!      — runtime-dispatched SIMD `compute_score`, `ElasticKvCache` HOT/WARM/COLD
//!      soft-paging with informed (H2O / attention-sink) eviction (plan axis A5),
//!      as a `MemoryProvider` backend the runtime can swap in.
//!   2. [`LatentSafetyGuard`](ccos_scirust::safety::LatentSafetyGuard) — the
//!      geometric latent-injection guard (dot-product deviation / orthogonal
//!      isolation / activation drift), analysable *before* dequantisation.
//!
//! ## Replay boundary (stated plainly)
//!
//! Enabling `slhav2-full` is a **REPLAY-RELAX**: the SIMD accumulation order and
//! the elastic cache's runtime-stateful `observe_scores` / `importance` tracking
//! make bit-exact replay impossible (see `docs/DETERMINISM.md`). The default and
//! `slhav2` builds compile none of this and stay `replay == live`. There is **no
//! silent downgrade**: a community-tier session that calls [`FullSlhaAccess::unlock`]
//! gets the standard refusal (the core and distilled backend keep working), and a
//! Pro session that mixes full-kernel pages into a replay log must opt into the
//! relax explicitly — the distilled backend remains the replay-exact store.

#![cfg(feature = "slhav2-full")]

use crate::license::{Feature, LicenseError, Licensing};

/// Premium construction token for the SLHAv2 full-kernel tier. Only
/// [`FullSlhaAccess::unlock`] produces it, and only on the Pro tier — so every
/// real-kernel entry point is statically reachable solely through a verified
/// license. The token carries no data (the gate is the license, not a secret).
pub struct FullSlhaAccess {
    _gated: (),
}

impl std::fmt::Debug for FullSlhaAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullSlhaAccess").finish()
    }
}

impl FullSlhaAccess {
    /// Unlock the SLHAv2 full-kernel tier from CCOS's `licensing` state at `now`
    /// (unix seconds, supplied by the caller so the verifier reads no clock).
    /// `Ok` only on the Pro tier; otherwise the standard
    /// [`Feature::SlhAv2FullKernel`] refusal (the core + distilled backend stay
    /// usable). Pure, no I/O.
    pub fn unlock(licensing: &Licensing, now: u64) -> Result<Self, LicenseError> {
        licensing.require(Feature::SlhAv2FullKernel, now)?;
        Ok(Self { _gated: () })
    }

    /// Construct a fresh [`ScirustBackend`] (HOT/WARM/COLD elastic arena) sized for
    /// `budget_bytes`, reachable only behind [`Self::unlock`]. The backend speaks
    /// the runtime-neutral [`MemoryProvider`](ccos_memory_runtime::traits::MemoryProvider)
    /// contract, so the runtime can swap it in for the distilled `SlhaAdapter`
    /// without a backend-specific type crossing the API.
    pub fn scirust_backend(
        &self,
        budget_bytes: usize,
    ) -> ccos_memory_runtime::backend::scirust_full::ScirustBackend {
        ccos_memory_runtime::backend::scirust_full::ScirustBackend::with_budget(budget_bytes)
    }

    /// Construct a [`ScirustBackend`] with an explicit informed-eviction policy
    /// (plan axis A5: lowest H2O importance first, attention sinks pinned by
    /// `sink_window`). Reachable only behind [`Self::unlock`].
    pub fn scirust_backend_with_eviction(
        &self,
        budget_bytes: usize,
        eviction: ccos_scirust::ccos::EvictionPolicy,
    ) -> ccos_memory_runtime::backend::scirust_full::ScirustBackend {
        ccos_memory_runtime::backend::scirust_full::ScirustBackend::with_eviction(
            budget_bytes,
            eviction,
        )
    }

    /// Build a [`LatentSafetyGuard`] seeded with a reference direction and a
    /// dot-product threshold (cosine below it ⇒ `DotProductDeviation`). The guard
    /// analyses compressed latents *before* dequantisation, so a CCOS ingestion
    /// path can reject a prompt-injection / drift tile early. Reachable only
    /// behind [`Self::unlock`].
    pub fn safety_guard(
        &self,
        reference: [f32; ccos_scirust::D_C],
        dot_threshold: f32,
    ) -> ccos_scirust::safety::LatentSafetyGuard {
        ccos_scirust::safety::LatentSafetyGuard::new(reference, dot_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::License;
    use ccos_memory_runtime::traits::MemoryProvider;

    const NOW: u64 = 1_000;

    #[test]
    fn community_tier_refuses_full_kernel_without_degrading() {
        let l = Licensing::community();
        let err = FullSlhaAccess::unlock(&l, NOW).unwrap_err();
        assert_eq!(err, LicenseError::FeatureLocked(Feature::SlhAv2FullKernel));
    }

    #[test]
    fn pro_tier_unlocks_and_builds_backend_and_guard() {
        let l = Licensing::licensed(License {
            licensee: "acme".to_string(),
            expires_at: None,
        });
        let access = FullSlhaAccess::unlock(&l, NOW).unwrap();
        let mut be = access.scirust_backend(10 * 128);
        // A default upsert round-trips through the arena.
        be.upsert(ccos_memory_runtime::AlignedMemoryPage::new(7));
        assert_eq!(
            be.state(7).unwrap(),
            ccos_memory_runtime::telemetry::MemoryState::Hot
        );
        let guard = access.safety_guard([1.0; ccos_scirust::D_C], 0.5);
        let _ = guard.last_cosine();
    }

    #[test]
    fn expired_license_refuses() {
        let l = Licensing::licensed(License {
            licensee: "acme".to_string(),
            expires_at: Some(NOW - 1),
        });
        assert!(FullSlhaAccess::unlock(&l, NOW).is_err());
    }
}
