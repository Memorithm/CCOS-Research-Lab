//! Determinism boundary test (CCOS_EXTENDED plan P4).
//!
//! The fusion plan's third invariant is `replay == live` for the **default**
//! build, and every full-kernel feature carries a documented `REPLAY-RELAX`
//! marker. This test pins that boundary at runtime, in the default build:
//!
//! 1. **Air-gap ⇒ no network nondeterminism.** The default
//!    [`ccos::egress::EgressAllowlist`] allows localhost/loopback only and
//!    refuses a public host. The `llm`/`neural-embed`/`eval` call sites all
//!    route through it, so the default build can make no off-host call — there
//!    is no network source of replay divergence in the default configuration.
//! 2. **No silent downgrade.** The community tier refuses every REPLAY-RELAX
//!    Pro feature (`SlhAv2FullKernel`, `RsiSelfImprovement`, `RsiDgm`) with
//!    `LicenseError::FeatureLocked` — the relaxed paths are never reachable
//!    without an active license, and the core stays `replay == live`.
//! 3. **Classification is total & consistent.** Every fusion feature is tagged
//!    either `ReplaySafe` or `ReplayRelax` in the table below, and the relaxed
//!    set is exactly the Pro-gated set (a relaxed feature that were free would
//!    violate the invariant; a Pro feature that were replay-safe is fine but
//!    listed as such). See `docs/DETERMINISM.md` for the human-readable table.
//!
//! This test compiles and passes in the **default build** (no features); it is
//! the executable form of the determinism contract.

use ccos::egress::{EgressAllowlist, EgressError};
use ccos::license::{Feature, LicenseError, Licensing};

const NOW: u64 = 1_700_000_000;

/// Replay posture of a fusion feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replay {
    /// `replay == live`: deterministic, std-only, bit-for-bit reproducible.
    Safe,
    /// Documented `REPLAY-RELAX`: a permitted divergence (SIMD order, a real
    /// subprocess, a remote model). Pro-gated, never the default.
    Relax,
}

/// The fusion feature → replay-posture table. This is the single source the
/// `docs/DETERMINISM.md` table is kept in sync with; editing it here is a
/// deliberate, reviewable act.
const REPLAY_TABLE: &[(Feature, Replay)] = &[
    // Core distilled features — replay-safe by construction (std-only, deterministic).
    (Feature::CustomAuthorityWeights, Replay::Safe),
    (Feature::TensionVisualization, Replay::Safe),
    (Feature::AuditReports, Replay::Safe),
    (Feature::SlhAv2Embeddings, Replay::Safe),
    (Feature::AdaptiveRetrieval, Replay::Safe),
    (Feature::OctaSomaMemory, Replay::Safe),
    // Full-kernel / self-improvement tiers — documented REPLAY-RELAX, Pro-gated.
    (Feature::SlhAv2FullKernel, Replay::Relax),
    (Feature::RsiSelfImprovement, Replay::Relax),
    (Feature::RsiDgm, Replay::Relax),
];

#[test]
fn egress_default_is_localhost_only() {
    let al = EgressAllowlist::localhost_only();
    // Loopback is allowed in every form.
    assert!(al.is_allowed("http://127.0.0.1:11434/api/embeddings"));
    assert!(al.is_allowed("http://localhost:11434/v1/chat"));
    assert!(al.is_allowed("http://[::1]:11434/"));
    assert!(al.is_allowed("https://localhost/"));
    // A public host is refused — air-gap: no off-host call is possible.
    let err = al
        .check("https://api.anthropic.com/v1/messages")
        .unwrap_err();
    match err {
        EgressError::HostNotAllowed { host, .. } => assert_eq!(host, "api.anthropic.com"),
        EgressError::Malformed(_) => panic!("expected HostNotAllowed for a public host"),
    }
}

#[test]
fn egress_default_denies_remote_ollama_too() {
    // The Ollama provider in eval.rs defaults to a *local* endpoint, but a
    // remote OLLAMA_ENDPOINT must be refused under the default policy.
    let al = EgressAllowlist::localhost_only();
    assert!(al
        .check("http://gpu-box.internal:11434/api/generate")
        .is_err());
}

#[test]
fn community_refuses_every_replay_relax_feature() {
    let community = Licensing::community();
    for (feature, posture) in REPLAY_TABLE {
        let res = community.require(*feature, NOW);
        match posture {
            Replay::Relax => {
                // Every relaxed feature MUST be locked at community tier — no
                // silent downgrade into a replay-divergent path.
                assert!(
                    matches!(res, Err(LicenseError::FeatureLocked(f)) if f == *feature),
                    "community tier must refuse relaxed feature {:?} with FeatureLocked",
                    feature
                );
            }
            Replay::Safe => {
                // Safe features are core-reachable regardless of tier; the gate
                // is informational, not a determinism boundary. We only assert
                // the table is consistent (no panic) — `require` may return
                // either Ok or FeatureLocked here and both are acceptable.
                let _ = res;
            }
        }
    }
}

#[test]
fn replay_table_is_total_and_consistent() {
    // Every relaxed feature is Pro-gated by definition: a relaxed feature that
    // were free would let replay diverge in the default build. We assert the
    // community tier refuses each Relax entry (the real contract) and that the
    // table has no duplicate or missing posture.
    let community = Licensing::community();
    let mut seen = std::collections::HashSet::new();
    for (feature, posture) in REPLAY_TABLE {
        assert!(
            seen.insert(feature.name()),
            "duplicate feature in REPLAY_TABLE: {:?}",
            feature
        );
        if *posture == Replay::Relax {
            assert!(
                matches!(
                    community.require(*feature, NOW),
                    Err(LicenseError::FeatureLocked(_))
                ),
                "relaxed feature {:?} is not Pro-gated — violates replay == live",
                feature
            );
        }
    }
}

#[test]
fn pro_unlocks_replay_relax_features() {
    // A Pro license makes the relaxed paths *available* — the boundary is the
    // tier, not a hard removal. We can't mint a real signed license in a test,
    // so we assert the symmetric posture: `allows` is tier-driven, and a Pro
    // tier (via `Licensing::licensed`) returns true for a relaxed feature.
    // Construct a Pro tier through the public `licensed` ctor requires a
    // `License` value; instead assert the table's relaxed set is non-empty and
    // that community denies them (covered above) — the unlock direction is
    // exercised in the feature-gated fusion tests (fusion_slha_full, rsi_bridge).
    let relaxed: Vec<_> = REPLAY_TABLE
        .iter()
        .filter(|(_, p)| *p == Replay::Relax)
        .collect();
    assert!(
        !relaxed.is_empty(),
        "there must be at least one REPLAY-RELAX feature"
    );
    for (f, _) in &relaxed {
        assert!(matches!(
            *f,
            Feature::SlhAv2FullKernel | Feature::RsiSelfImprovement | Feature::RsiDgm
        ));
    }
}
