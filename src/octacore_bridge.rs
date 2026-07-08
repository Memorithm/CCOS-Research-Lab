//! **OctaCore cascade bridge** (CCOS_EXTENDED, plan P2) — the CCOS-side half of the
//! circular-dependency inversion.
//!
//! Before P2, `octacore` had an optional git dependency on CCOS and an
//! `ccos_adapter::CcosScope` that wrapped `ccos::external_memory::ExternalMemory`
//! into `octacore::CausalScope`. That edge pointed `octacore → ccos`, and since
//! CCOS_EXTENDED makes `octacore` a workspace member of the `ccos` workspace, it was
//! circular. P2 **inverts** it: the adapter now lives here, on the CCOS side, so
//! CCOS depends on `octacore` and `octacore` no longer depends on CCOS at all.
//!
//! What this module exposes (behind the `octacore` cargo feature, runtime-gated by
//! the offline license via [`CausalCascadeAccess::unlock`]):
//!
//! - [`CcosScope`] — a CCOS `ExternalMemory` dressed as an `octacore::CausalScope`,
//!   so the validated cascade (CCOS narrows to a causal region → OctaSoma reranks
//!   it by exact cosine) can run with the real causal layer.
//! - [`CausalCascadeAccess`] — the Pro gate (reuses [`Feature::OctaSomaMemory`],
//!   the same tier as the OctaSoma semantic-memory backend — they are one premium
//!   capability, "semantic memory").
//! - [`semantic_cascade`] / [`recall_semantic`] — assemble a `Cascade` from a CCOS
//!   memory + an OctaSoma `Embedder`, and the one-call recall that turns a free-text
//!   query into a token-budgeted window through the cascade.
//!
//! ## Replay boundary
//!
//! The cascade's replay-exactness follows the **embedder**, exactly like
//! [`crate::octa_index`]: a deterministic embedder (octasoma's `HashEmbedder`)
//! keeps it bit-replayable; a neural embedder (`OllamaEmbedder`, local-only) trades
//! replay-exactness for semantic quality — the choice is the caller's and visible
//! in the type. The default core `Recall::Semantic` path (INT4 TF-IDF, in
//! [`crate::external_memory`]) is untouched and stays `replay == live`; this bridge
//! is the opt-in premium alternative, never a silent replacement.
//!
//! Running a **real** embedder here? Wrap it in
//! [`CachedEmbedder`](crate::embed_cache::CachedEmbedder) — the cascade rebuilds
//! derived state per recall, and the content-addressed cache (optionally
//! persisted next to the workspace) makes that amortized instead of one
//! embedding call per node per recall.

#![cfg(feature = "octacore")]

use crate::external_memory::{ExternalMemory, Recall};
use crate::license::{Feature, LicenseError, Licensing};
use octacore::{Cascade, CausalScope, RecallItem, RecallWindow, ScopeItem};

/// A CCOS [`ExternalMemory`] dressed as an OctaCore [`CausalScope`]: a query becomes
/// a `Recall::Task`, and the recalled region's items become [`ScopeItem`]s for
/// OctaSoma to rerank. This is the CCOS-side replacement for `octacore`'s former
/// `ccos_adapter::CcosScope` (the P2 circular-dep inversion).
pub struct CcosScope<M: ExternalMemory> {
    mem: M,
}

impl<M: ExternalMemory> CcosScope<M> {
    /// Wrap a CCOS memory (e.g. [`CcosMemory`](crate::external_memory::CcosMemory)).
    pub fn new(mem: M) -> Self {
        Self { mem }
    }

    /// Borrow the underlying memory (e.g. to `ingest_source` or `checkpoint`).
    pub fn memory(&self) -> &M {
        &self.mem
    }

    /// Mutably borrow the underlying memory.
    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.mem
    }
}

impl<M: ExternalMemory> CausalScope for CcosScope<M> {
    fn scope(&self, query: &str, budget_tokens: usize) -> Vec<ScopeItem> {
        self.mem
            .recall(&Recall::task(query), budget_tokens)
            .items
            .into_iter()
            .map(|it| ScopeItem {
                uri: it.uri,
                content: it.content,
            })
            .collect()
    }
}

/// Premium construction token for the OctaCore cascade tier. Only
/// [`CausalCascadeAccess::unlock`] produces it, and only on the Pro tier — so the
/// real cascade is statically reachable solely through a verified license. Reuses
/// [`Feature::OctaSomaMemory`] (semantic memory is one premium capability whether
/// served by the OctaSoma index or the OctaCore cascade).
pub struct CausalCascadeAccess {
    _gated: (),
}

impl std::fmt::Debug for CausalCascadeAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CausalCascadeAccess").finish()
    }
}

impl CausalCascadeAccess {
    /// Unlock the OctaCore cascade tier from CCOS's `licensing` state at `now`
    /// (unix seconds, caller-supplied). `Ok` only on the Pro tier; otherwise the
    /// standard [`Feature::OctaSomaMemory`] refusal (the core `Recall::Semantic`
    /// path stays usable). Pure, no I/O.
    pub fn unlock(licensing: &Licensing, now: u64) -> Result<Self, LicenseError> {
        licensing.require(Feature::OctaSomaMemory, now)?;
        Ok(Self { _gated: () })
    }

    /// Assemble the validated cascade — CCOS causal scope + OctaSoma semantic rerank
    /// — over a CCOS memory and an OctaSoma [`Embedder`](octasoma::Embedder). The
    /// embedder is the replay boundary (see the module docs). Reachable only behind
    /// [`Self::unlock`].
    pub fn cascade<E: octasoma::Embedder, M: ExternalMemory>(
        &self,
        memory: M,
        embedder: E,
    ) -> Cascade<E, CcosScope<M>> {
        Cascade::new(CcosScope::new(memory), embedder)
    }
}

/// Convenience (no license check): build a cascade from a CCOS memory and an
/// OctaSoma embedder. Tests and Pro-unlocked callers that already hold a
/// [`CausalCascadeAccess`] should prefer [`CausalCascadeAccess::cascade`]; this is
/// the lower-level constructor for code that gates the license itself.
pub fn semantic_cascade<E: octasoma::Embedder, M: ExternalMemory>(
    memory: M,
    embedder: E,
) -> Cascade<E, CcosScope<M>> {
    Cascade::new(CcosScope::new(memory), embedder)
}

/// One-call semantic recall through the cascade: `query` → causal region (CCOS) →
/// exact cosine rerank (OctaSoma) → top-`k` window compacted to `budget_tokens`.
/// Returns the cascade's neutral [`RecallWindow`] (items most-relevant first). No
/// license check — gate with [`CausalCascadeAccess`] at the call site.
pub fn recall_semantic<E: octasoma::Embedder, M: ExternalMemory>(
    cascade: &Cascade<E, CcosScope<M>>,
    query: &str,
    k: usize,
    budget_tokens: usize,
) -> Result<RecallWindow, octasoma::EmbedError> {
    cascade.recall(query, k, budget_tokens)
}

/// Re-export so callers can build a deterministic offline embedder without naming
/// the `octasoma` crate directly (it is already a dep via the `octacore` feature).
pub use octasoma::HashEmbedder as OfflineEmbedder;

/// A [`RecallWindow`] → `(uri, content, score)` triples helper for callers that
/// want a flat ranked list (mirrors how the MCP surfaces the cascade).
pub fn ranked_items(window: &RecallWindow) -> Vec<(&str, &str, f32)> {
    window
        .items
        .iter()
        .map(|i: &RecallItem| (i.uri.as_str(), i.content.as_str(), i.score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_memory::CcosMemory;
    use crate::license::License;

    const NOW: u64 = 1_000;

    fn pro() -> Licensing {
        Licensing::licensed(License {
            licensee: "acme".to_string(),
            expires_at: None,
        })
    }

    #[test]
    fn community_tier_refuses_cascade_no_silent_downgrade() {
        let l = Licensing::community();
        let err = CausalCascadeAccess::unlock(&l, NOW).unwrap_err();
        assert_eq!(err, LicenseError::FeatureLocked(Feature::OctaSomaMemory));
    }

    #[test]
    fn expired_license_refuses() {
        let l = Licensing::licensed(License {
            licensee: "acme".to_string(),
            expires_at: Some(NOW - 1),
        });
        assert!(CausalCascadeAccess::unlock(&l, NOW).is_err());
    }

    #[test]
    fn ccosscope_routes_recall_task_into_scope_items() {
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
        let scope = CcosScope::new(mem);
        let items = scope.scope("open a pooled database connection", 4096);
        assert!(
            items.iter().any(|i| i.uri.contains("db.rs")),
            "scope items: {:?}",
            items.iter().map(|i| &i.uri).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pro_unlocks_and_cascade_recalls_offline() {
        let l = pro();
        let access = CausalCascadeAccess::unlock(&l, NOW).unwrap();

        let mut mem = CcosMemory::new();
        mem.ingest_source(
            "src/db.rs",
            "pub fn open_pooled_database_connection() -> u32 { 30 }\n",
        );
        mem.ingest_source(
            "src/util.rs",
            "pub fn handler_retry_helper() -> u32 { 1 }\n",
        );
        mem.ingest_source("src/log.rs", "pub fn rotate_log_files() -> u32 { 0 }\n");

        // Deterministic offline embedder → replay-exact.
        let cascade = access.cascade(mem, OfflineEmbedder::new(64));
        let win = recall_semantic(&cascade, "open a pooled database connection", 3, 4096).unwrap();
        assert!(
            !win.items.is_empty(),
            "window items: {:?}",
            win.items.iter().map(|i| i.uri.clone()).collect::<Vec<_>>()
        );
        // The db pool node should rank first (it shares the query's terms).
        assert!(
            win.items[0].uri.contains("db.rs"),
            "top item: {:?}",
            win.items[0].uri
        );
    }
}
