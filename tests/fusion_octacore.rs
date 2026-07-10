//! CCOS_EXTENDED fusion integration test (plan P2): the OctaCore cascade bridge —
//! the circular-dependency inversion's CCOS-side half.
//!
//! Verifies the fused path: CCOS `ExternalMemory` → `CcosScope` (an
//! `octacore::CausalScope`) → `Cascade` → OctaSoma exact-cosine rerank →
//! token-budgeted window, with the offline license gating it
//! (`Feature::OctaSomaMemory`) and a deterministic `HashEmbedder` keeping the
//! cascade bit-replayable. The default core `Recall::Semantic` path is untouched.
//!
//! Gated by the `octacore` cargo feature. The default build compiles none of this.

#![cfg(feature = "octacore")]

use ccos::external_memory::{CcosMemory, ExternalMemory};
use ccos::license::License;
use ccos::license::{Feature, LicenseError, Licensing, Tier};
use ccos::octacore_bridge::{
    ranked_items, recall_semantic, semantic_cascade, CausalCascadeAccess, CcosScope,
    OfflineEmbedder,
};
use octacore::CausalScope;

const NOW: u64 = 1_000;

fn pro() -> Licensing {
    Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
        machine: None,
    })
}

fn seeded_memory() -> CcosMemory {
    let mut mem = CcosMemory::new();
    // Identifiers carry the query terms (the parser keeps code, drops comments).
    mem.ingest_source(
        "src/db.rs",
        "pub fn open_pooled_database_connection() -> u32 { 30 }\n",
    );
    mem.ingest_source(
        "src/util.rs",
        "pub fn handler_retry_helper() -> u32 { 1 }\n",
    );
    mem.ingest_source("src/log.rs", "pub fn rotate_log_files() -> u32 { 0 }\n");
    mem
}

#[test]
fn octacore_no_longer_depends_on_ccos() {
    // The inversion: `octacore` is a workspace member with no edge on the `ccos`
    // crate. `CcosScope` lives on the CCOS side (this test compiles only because
    // the root `ccos` crate depends on `octacore`, never the reverse).
    let scope = CcosScope::new(seeded_memory());
    let items = scope.scope("open a pooled database connection", 4096);
    assert!(
        items.iter().any(|i| i.uri.contains("db.rs")),
        "scope: {:?}",
        items.iter().map(|i| &i.uri).collect::<Vec<_>>()
    );
}

#[test]
fn community_tier_refuses_cascade_without_degrading_core() {
    let l = Licensing::community();
    assert_eq!(l.tier(NOW), Tier::Community);
    let err = CausalCascadeAccess::unlock(&l, NOW).unwrap_err();
    assert_eq!(err, LicenseError::FeatureLocked(Feature::OctaSomaMemory));

    // The core `Recall::Semantic` path still works on the community tier — the
    // bridge is an opt-in premium alternative, not a replacement.
    let mem = seeded_memory();
    let core_win = mem.recall(
        &ccos::external_memory::Recall::semantic("open_pooled_database_connection"),
        4096,
    );
    assert!(core_win.strategy.contains("semantic"));
}

#[test]
fn pro_unlocks_and_cascade_recalls_deterministically() {
    let access = CausalCascadeAccess::unlock(&pro(), NOW).unwrap();
    let cascade = access.cascade(seeded_memory(), OfflineEmbedder::new(64));

    let win = recall_semantic(&cascade, "open a pooled database connection", 3, 4096).unwrap();
    assert!(!win.items.is_empty(), "window empty");
    assert!(
        win.items[0].uri.contains("db.rs"),
        "top item: {:?}",
        win.items[0].uri
    );

    // Bit-replayable: the same query on a rebuilt cascade yields the same ranking.
    let access2 = CausalCascadeAccess::unlock(&pro(), NOW).unwrap();
    let cascade2 = access2.cascade(seeded_memory(), OfflineEmbedder::new(64));
    let win2 = recall_semantic(&cascade2, "open a pooled database connection", 3, 4096).unwrap();
    assert_eq!(
        win.items.iter().map(|i| i.uri.clone()).collect::<Vec<_>>(),
        win2.items.iter().map(|i| i.uri.clone()).collect::<Vec<_>>(),
        "offline cascade is bit-replayable"
    );
}

#[test]
fn low_level_semantic_cascade_and_ranked_items_helpers() {
    // The lower-level constructor (no license check) is available for code that
    // gates the license itself.
    let cascade = semantic_cascade(seeded_memory(), OfflineEmbedder::new(64));
    let win = recall_semantic(&cascade, "rotate log files", 2, 4096).unwrap();
    let ranked = ranked_items(&win);
    assert!(!ranked.is_empty());
    // Each triple is (uri, content, score).
    let (uri, _content, score) = &ranked[0];
    assert!(uri.contains("log.rs"), "top: {uri}");
    assert!(*score >= 0.0);
}
