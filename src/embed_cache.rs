//! **Content-addressed embedding cache** (CCOS_EXTENDED) — the follow-up the
//! Pro semantic tier documents: making a REAL (neural, non-replay-exact)
//! embedder practical behind the derived index and the OctaCore cascade.
//!
//! Both premium semantic surfaces rebuild **derived state** from the live graph
//! on every call (`octa_index::SemanticMemoryAccess::sharded_index_from_graph`,
//! the `octa.cascade_recall` tool): with the hash embedder that is microseconds
//! per node, but with a real embedder ([`octasoma::OllamaEmbedder`], local-only)
//! every rebuild would re-embed the whole corpus over HTTP. [`CachedEmbedder`]
//! fixes that at the *embedder* seam, so every consumer of
//! [`octasoma::Embedder`] benefits without new API:
//!
//! ```no_run
//! use ccos_research_lab::embed_cache::CachedEmbedder;
//! use octasoma::HashEmbedder;
//!
//! // Wrap ANY embedder; identical inputs are embedded once.
//! let cached = CachedEmbedder::new(HashEmbedder::new(128), "hash-128");
//! // … use `cached` wherever an `octasoma::Embedder` is expected
//! //   (octa_index, the octacore cascade, …), then optionally persist:
//! cached.save("workspace.ccos.embcache").unwrap();
//! let warm = CachedEmbedder::load("workspace.ccos.embcache",
//!                                 HashEmbedder::new(128), "hash-128").unwrap();
//! # let _ = warm;
//! ```
//!
//! ## Semantics (stated plainly)
//!
//! - **Keyed by content, not by node id**: the key is `sha256(text)`, so a
//!   re-ingested file with identical content is a hit and an edited file is a
//!   miss — exactly the invalidation the derived index needs. Nothing to evict
//!   by hand.
//! - **Fail-closed persistence**: a cache file records the embedder `label` and
//!   `dim` it was built with. Loading it under a different label or dimension is
//!   refused with an explicit error ([`EmbedCacheError::Mismatch`]) — vectors
//!   from one embedder are never silently served to another (that would be a
//!   silent semantic downgrade, the exact failure mode the Pro tier bans).
//! - **Replay posture**: the cache does NOT make a neural embedder replay-exact
//!   (lose the file and the re-embedding may differ — weights/server/hardware
//!   dependent; see `docs/DETERMINISM.md`). What it does guarantee is
//!   **stability**: while a cache entry exists, the same content always maps to
//!   the same vector, within and across sessions. The deterministic
//!   [`octasoma::HashEmbedder`] stays bit-replayable with or without the cache.
//! - **Sensitivity**: the file stores `(sha256(text) → vector)` — no raw text,
//!   but embedding vectors carry semantic information about the corpus. Treat
//!   the cache file with the same sensitivity as the workspace it derives from
//!   (same directory, same permissions is the intended deployment).
//! - **Single-threaded by design** (`RefCell`): index building and the MCP serve
//!   loop are single-threaded; the type is deliberately `!Sync` so misuse fails
//!   at compile time rather than racing.

use crate::util::sha256_hex;
use octasoma::{EmbedError, Embedder};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;

/// Why loading or saving a persisted embedding cache failed. Loading never
/// falls back silently: a bad file is an error, not an empty cache.
#[derive(Debug)]
pub enum EmbedCacheError {
    /// The file could not be read or written.
    Io(std::io::Error),
    /// The file is not a valid cache (wrong JSON shape / version / vector arity).
    Format(String),
    /// The file was built by a different embedder (label or dimension) — serving
    /// its vectors would be a silent semantic downgrade, so it is refused.
    Mismatch {
        expected_label: String,
        found_label: String,
        expected_dim: usize,
        found_dim: usize,
    },
}

impl std::fmt::Display for EmbedCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "embedding cache I/O: {e}"),
            Self::Format(why) => write!(f, "embedding cache format: {why}"),
            Self::Mismatch {
                expected_label,
                found_label,
                expected_dim,
                found_dim,
            } => write!(
                f,
                "embedding cache mismatch: built by '{found_label}' (dim {found_dim}), \
                 refusing to serve it to '{expected_label}' (dim {expected_dim})"
            ),
        }
    }
}

impl std::error::Error for EmbedCacheError {}

impl From<std::io::Error> for EmbedCacheError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// On-disk shape (compact JSON): version + embedder identity + the entries.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheFile {
    version: u32,
    label: String,
    dim: usize,
    entries: HashMap<String, Vec<f32>>,
}

const CACHE_FILE_VERSION: u32 = 1;

/// A content-addressed, optionally-persistent cache around ANY
/// [`octasoma::Embedder`]. See the module docs for the semantics.
pub struct CachedEmbedder<E: Embedder> {
    inner: E,
    /// Embedder identity persisted with the cache — model + dims by convention
    /// (e.g. `"nomic-embed-text-768"`). Guards a saved file against being
    /// reused under a different embedder.
    label: String,
    cache: RefCell<HashMap<String, Vec<f32>>>,
    hits: Cell<u64>,
    misses: Cell<u64>,
}

impl<E: Embedder> CachedEmbedder<E> {
    /// Wrap `inner` with an empty cache. `label` names the embedder identity
    /// for persistence (see the field docs).
    pub fn new(inner: E, label: impl Into<String>) -> Self {
        Self {
            inner,
            label: label.into(),
            cache: RefCell::new(HashMap::new()),
            hits: Cell::new(0),
            misses: Cell::new(0),
        }
    }

    /// Wrap `inner` with a cache warmed from the file at `path`. Fail-closed:
    /// an unreadable / malformed file, a different `label`, or a different
    /// dimension is an explicit [`EmbedCacheError`] — never an empty cache and
    /// never mismatched vectors.
    pub fn load(
        path: impl AsRef<Path>,
        inner: E,
        label: impl Into<String>,
    ) -> Result<Self, EmbedCacheError> {
        let label = label.into();
        let raw = std::fs::read_to_string(path)?;
        let file: CacheFile = serde_json::from_str(&raw)
            .map_err(|e| EmbedCacheError::Format(format!("not a cache file: {e}")))?;
        if file.version != CACHE_FILE_VERSION {
            return Err(EmbedCacheError::Format(format!(
                "unsupported cache version {} (this build reads {CACHE_FILE_VERSION})",
                file.version
            )));
        }
        if file.label != label || file.dim != inner.dim() {
            return Err(EmbedCacheError::Mismatch {
                expected_label: label,
                found_label: file.label,
                expected_dim: inner.dim(),
                found_dim: file.dim,
            });
        }
        if let Some((k, v)) = file.entries.iter().find(|(_, v)| v.len() != file.dim) {
            return Err(EmbedCacheError::Format(format!(
                "entry {k} has {} components, expected {}",
                v.len(),
                file.dim
            )));
        }
        Ok(Self {
            inner,
            label,
            cache: RefCell::new(file.entries),
            hits: Cell::new(0),
            misses: Cell::new(0),
        })
    }

    /// Persist the cache to `path`, durably (temp file + fsync + atomic rename —
    /// the same crash-safety as workspace checkpoints).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), EmbedCacheError> {
        let file = CacheFile {
            version: CACHE_FILE_VERSION,
            label: self.label.clone(),
            dim: self.inner.dim(),
            entries: self.cache.borrow().clone(),
        };
        let json = serde_json::to_string(&file)
            .map_err(|e| EmbedCacheError::Format(format!("serialise: {e}")))?;
        crate::util::write_durable(path.as_ref(), json.as_bytes())?;
        Ok(())
    }

    /// Cached entry count.
    pub fn len(&self) -> usize {
        self.cache.borrow().len()
    }

    /// True when nothing is cached yet.
    pub fn is_empty(&self) -> bool {
        self.cache.borrow().is_empty()
    }

    /// `(hits, misses)` since construction — the observability handle for
    /// deciding when a persistent cache is worth saving.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits.get(), self.misses.get())
    }

    /// Borrow the wrapped embedder.
    pub fn inner(&self) -> &E {
        &self.inner
    }
}

impl<E: Embedder> Embedder for CachedEmbedder<E> {
    fn dim(&self) -> usize {
        self.inner.dim()
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let key = sha256_hex(text);
        if let Some(v) = self.cache.borrow().get(&key) {
            self.hits.set(self.hits.get() + 1);
            return Ok(v.clone());
        }
        // A failed inner embed is NOT cached — the next call retries (a local
        // Ollama that was down comes back; a permanent error keeps surfacing).
        let v = self.inner.embed(text)?;
        self.misses.set(self.misses.get() + 1);
        self.cache.borrow_mut().insert(key, v.clone());
        Ok(v)
    }
}

impl<E: Embedder> std::fmt::Debug for CachedEmbedder<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedEmbedder")
            .field("label", &self.label)
            .field("dim", &self.inner.dim())
            .field("entries", &self.len())
            .field("hits", &self.hits.get())
            .field("misses", &self.misses.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An embedder that counts how many times it is actually asked to embed.
    struct Counting {
        dim: usize,
        calls: Cell<u64>,
    }

    impl Counting {
        fn new(dim: usize) -> Self {
            Self {
                dim,
                calls: Cell::new(0),
            }
        }
    }

    impl Embedder for Counting {
        fn dim(&self) -> usize {
            self.dim
        }
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            self.calls.set(self.calls.get() + 1);
            // Deterministic toy vector derived from the text length.
            Ok((0..self.dim).map(|i| (text.len() + i) as f32).collect())
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ccos-embcache-{}-{name}", std::process::id()));
        p
    }

    #[test]
    fn identical_content_is_embedded_once() {
        let c = CachedEmbedder::new(Counting::new(4), "toy-4");
        let a = c.embed("pub fn q() {}").unwrap();
        let b = c.embed("pub fn q() {}").unwrap();
        let other = c.embed("different").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, other);
        assert_eq!(
            c.inner().calls.get(),
            2,
            "two distinct texts, two real calls"
        );
        assert_eq!(c.stats(), (1, 2), "one hit, two misses");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn save_then_load_serves_hits_without_inner_calls() {
        let path = tmp("roundtrip.json");
        let vec_cold;
        {
            let c = CachedEmbedder::new(Counting::new(4), "toy-4");
            vec_cold = c.embed("alpha").unwrap();
            c.embed("beta").unwrap();
            c.save(&path).unwrap();
        }
        let warm = CachedEmbedder::load(&path, Counting::new(4), "toy-4").unwrap();
        assert_eq!(warm.len(), 2);
        let vec_warm = warm.embed("alpha").unwrap();
        assert_eq!(vec_cold, vec_warm, "persisted vector served verbatim");
        assert_eq!(warm.inner().calls.get(), 0, "no inner call on a warm hit");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mismatched_label_or_dim_is_refused_fail_closed() {
        let path = tmp("mismatch.json");
        let c = CachedEmbedder::new(Counting::new(4), "toy-4");
        c.embed("alpha").unwrap();
        c.save(&path).unwrap();

        // Different label → refused.
        let err = CachedEmbedder::load(&path, Counting::new(4), "other-model").unwrap_err();
        assert!(matches!(err, EmbedCacheError::Mismatch { .. }), "{err}");
        // Different dimension → refused.
        let err = CachedEmbedder::load(&path, Counting::new(8), "toy-4").unwrap_err();
        assert!(matches!(err, EmbedCacheError::Mismatch { .. }), "{err}");
        // Garbage file → format error, not an empty cache.
        std::fs::write(&path, b"not json").unwrap();
        let err = CachedEmbedder::load(&path, Counting::new(4), "toy-4").unwrap_err();
        assert!(matches!(err, EmbedCacheError::Format(_)), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hash_embedder_results_are_identical_with_and_without_cache() {
        use octasoma::HashEmbedder;
        let plain = HashEmbedder::new(64);
        let cached = CachedEmbedder::new(HashEmbedder::new(64), "hash-64");
        for text in ["pub fn a() {}", "open a pooled database connection", ""] {
            assert_eq!(
                plain.embed(text).unwrap(),
                cached.embed(text).unwrap(),
                "cache is transparent for {text:?}"
            );
            // And again, through the cache-hit path.
            assert_eq!(plain.embed(text).unwrap(), cached.embed(text).unwrap());
        }
    }

    /// The cascade seam: a cached embedder drops into `octacore::Cascade`
    /// exactly like the bare one and returns the same ranking.
    #[cfg(feature = "octacore")]
    #[test]
    fn cascade_recall_is_unchanged_under_the_cache() {
        use crate::external_memory::{CcosMemory, ExternalMemory};
        use crate::octacore_bridge::{recall_semantic, semantic_cascade};
        use octasoma::HashEmbedder;

        let mut mem = CcosMemory::new();
        mem.ingest_source(
            "src/db.rs",
            "pub fn open_pooled_database_connection() -> u32 { 30 }\n",
        );
        mem.ingest_source("src/log.rs", "pub fn rotate_log_files() -> u32 { 0 }\n");
        let mut mem2 = CcosMemory::new();
        mem2.ingest_source(
            "src/db.rs",
            "pub fn open_pooled_database_connection() -> u32 { 30 }\n",
        );
        mem2.ingest_source("src/log.rs", "pub fn rotate_log_files() -> u32 { 0 }\n");

        let bare = semantic_cascade(mem, HashEmbedder::new(64));
        let cached = semantic_cascade(mem2, CachedEmbedder::new(HashEmbedder::new(64), "hash-64"));
        let q = "open a pooled database connection";
        let a = recall_semantic(&bare, q, 3, 4096).unwrap();
        let b = recall_semantic(&cached, q, 3, 4096).unwrap();
        let uris =
            |w: &octacore::RecallWindow| w.items.iter().map(|i| i.uri.clone()).collect::<Vec<_>>();
        assert_eq!(uris(&a), uris(&b), "identical ranking under the cache");
        assert!(uris(&a)[0].contains("db.rs"));
    }
}
