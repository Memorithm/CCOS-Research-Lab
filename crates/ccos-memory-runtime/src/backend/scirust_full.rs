//! `ScirustBackend` -- the FULL SLHAv2 kernel as a [`MemoryProvider`] backend.
//!
//! Unlike [`super::slha_adapter::SlhaAdapter`] (which vendors only the minimal
//! grouped-INT4 decode and pulls NO `scirust`), this backend links the real
//! `ccos-scirust` kernel: the runtime-dispatched SIMD [`compute_score`], the
//! [`ElasticKvCache`] with HOT/WARM/COLD soft-paging (`enforce_budget`), and (on
//! the CCOS side, via `src/slha_full.rs`) the [`LatentSafetyGuard`].
//!
//! It is gated by the `slhav2-full` cargo feature -- OFF by default so the
//! default build and the `slhav2` (distilled) build remain `scirust`-free and
//! `replay == live`. Enabling `slhav2-full` is a **REPLAY-RELAX**: the SIMD
//! accumulation order and the elastic cache's runtime-stateful
//! `observe_scores` / `importance` tracking make bit-exact replay impossible
//! (see `docs/DETERMINISM.md`).
//!
//! [`compute_score`]: ccos_scirust::attention::slha_v2::SciRustSlhaTile::compute_score
//! [`ElasticKvCache`]: ccos_scirust::ccos::ElasticKvCache
//! [`LatentSafetyGuard`]: ccos_scirust::safety::LatentSafetyGuard

// REPLAY-RELAX: this backend is only compiled behind `slhav2-full`.

use std::collections::HashMap;

use ccos_scirust::attention::slha_v2::{
    SciRustSlhaTile, D_C, FLAG_WARM, LATENT_BYTES, N_GROUPS, RESIDUAL_WORDS,
};
use ccos_scirust::ccos::{ElasticKvCache, EvictionPolicy, TileState, HOT_BYTES, WARM_BYTES};

use crate::telemetry::{CompressionResult, MemoryBackend, MemoryState};
use crate::traits::{MemoryProvider, MemoryResult, MemoryRuntimeError};
use crate::AlignedMemoryPage;

// SLHAv2 tile ABI byte offsets (mirrors `slha_adapter`; kept here so this module
// is self-contained and does not reach into the distilled adapter).
const OFF_LATENT: usize = 0; // 0..64
const OFF_RESIDUAL: usize = LATENT_BYTES; // 64
const OFF_SCALE: usize = OFF_RESIDUAL + RESIDUAL_WORDS * 8; // 96
const OFF_LAMBDA: usize = OFF_SCALE + 4; // 100
const OFF_SIGMA: usize = OFF_LAMBDA + 4; // 104
const OFF_TOKEN: usize = OFF_SIGMA + 4; // 108
const OFF_POS: usize = OFF_TOKEN + 4; // 112
const OFF_HEAD: usize = OFF_POS + 4; // 116
const OFF_FLAGS: usize = OFF_HEAD + 2; // 118
const OFF_GROUPS: usize = OFF_FLAGS + 2; // 120

/// A CCOS page id's residence in the elastic arena.
#[derive(Debug, Clone, Copy)]
enum SlotEntry {
    /// Live: the page occupies this arena slot (HOT or WARM).
    Live(usize),
    /// Evicted (COLD): the slot was recycled by `ElasticKvCache`; the page is no
    /// longer resident but the id is still tracked so `state()` reports `Cold`.
    Cold,
}

/// Full SLHAv2 memory backend. Owns an [`ElasticKvCache`] and a CCOS page-id →
/// arena-slot map. All SLHAv2 knowledge is confined here; the public surface
/// exposes only runtime-neutral types ([`MemoryState`], [`CompressionResult`],
/// [`MemoryResult`]).
pub struct ScirustBackend {
    cache: ElasticKvCache,
    slots: HashMap<u64, SlotEntry>,
}

impl ScirustBackend {
    /// New backend with the recommended hybrid paging policy and a byte budget.
    pub fn with_budget(budget_bytes: usize) -> Self {
        Self {
            cache: ElasticKvCache::with_budget(budget_bytes),
            slots: HashMap::new(),
        }
    }

    /// New backend with an explicit eviction policy (plan axis A5 -- informed
    /// eviction preserves heavy-hitters and attention sinks).
    pub fn with_eviction(budget_bytes: usize, eviction: EvictionPolicy) -> Self {
        Self {
            cache: ElasticKvCache::with_eviction(budget_bytes, eviction),
            slots: HashMap::new(),
        }
    }

    /// Number of tracked page ids (live + cold).
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the backend tracks no pages.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Producer ingestion path: insert (or replace) a page carrying real tile
    /// bytes. Not part of the hot inference path -- may allocate. A pre-existing
    /// page id is evicted (its old slot recycled) and re-inserted as HOT.
    pub fn upsert(&mut self, page: AlignedMemoryPage) {
        let tile = tile_from_payload(&page.payload.bytes);
        if let Some(SlotEntry::Live(old)) = self.slots.get(&page.page_id).copied() {
            self.cache.evict(old);
        }
        let slot = self.cache.insert(tile);
        self.slots.insert(page.page_id, SlotEntry::Live(slot));
    }

    /// Fused attention score of `q` against every live (non-COLD) tile:
    /// `(page_id, score)`, highest score first. This is the retrieval seam a
    /// CCOS `Recall::Semantic`-style path uses when the KV-cache is the store.
    pub fn score_all(
        &self,
        q_coarse: &[f32; D_C],
        q_sign: &[u64; RESIDUAL_WORDS],
    ) -> Vec<(u64, f32)> {
        let mut out: Vec<(u64, f32)> = self
            .cache
            .score_all(q_coarse, q_sign)
            .into_iter()
            .filter_map(|(slot, score)| {
                // Reverse-lookup the page id owning this slot.
                let id = self.id_of_slot(slot)?;
                Some((id, score))
            })
            .collect();
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    /// Drive the elastic budget enforcer (page HOT→WARM by σ_E, then evict →COLD
    /// per the eviction policy). Call after a batch of `upsert`s.
    pub fn enforce_budget(&mut self) {
        // `ElasticKvCache::evict` recycles slots; reflect any live slot that
        // became COLD back into our map so `state()` stays consistent.
        self.cache.enforce_budget();
        self.reconcile_cold();
    }

    /// Live logical footprint (HOT 128 / WARM 96 / COLD 0) summed over the arena.
    pub fn live_bytes(&self) -> usize {
        self.cache.live_bytes()
    }

    /// `(hot, warm, cold)` slot counts in the arena.
    pub fn counts(&self) -> (usize, usize, usize) {
        self.cache.counts()
    }

    /// Reverse-lookup: which page id owns `slot`, if any live entry points at it.
    fn id_of_slot(&self, slot: usize) -> Option<u64> {
        self.slots.iter().find_map(|(id, e)| match e {
            SlotEntry::Live(s) if *s == slot => Some(*id),
            _ => None,
        })
    }

    /// Mark any `Live(slot)` whose arena state is now `Cold` (recycled by
    /// `enforce_budget`'s eviction phase) as `SlotEntry::Cold`.
    fn reconcile_cold(&mut self) {
        for e in self.slots.values_mut() {
            if let SlotEntry::Live(slot) = e {
                if self.cache.state(*slot) == TileState::Cold {
                    *e = SlotEntry::Cold;
                }
            }
        }
    }

    fn live_slot(&self, id: u64) -> MemoryResult<usize> {
        match self.slots.get(&id) {
            Some(SlotEntry::Live(slot)) => Ok(*slot),
            Some(SlotEntry::Cold) => Err(MemoryRuntimeError::PageNotFound(id)),
            None => Err(MemoryRuntimeError::PageNotFound(id)),
        }
    }

    /// Re-insert the current (WARM) tile as a fresh HOT slot, clearing the WARM
    /// flag. The reclaimed residual is gone -- this is the documented
    /// *approximate* restore (latent-only), mirroring `SlhaAdapter`'s
    /// `RestoreMode::Approximate`.
    fn restore_approximate(&mut self, id: u64, slot: usize) {
        let mut tile = *self.cache.tile(slot);
        tile.residual_bitmap = [0u64; RESIDUAL_WORDS];
        tile.dynamic_lambda = 0.0;
        tile.flags &= !FLAG_WARM;
        self.cache.evict(slot);
        let new_slot = self.cache.insert(tile);
        self.slots.insert(id, SlotEntry::Live(new_slot));
    }
}

impl MemoryProvider for ScirustBackend {
    type PageId = u64;

    fn state(&self, id: u64) -> MemoryResult<MemoryState> {
        match self.slots.get(&id) {
            Some(SlotEntry::Live(slot)) => Ok(self.cache.state(*slot).into()),
            Some(SlotEntry::Cold) => Ok(MemoryState::Cold),
            None => Err(MemoryRuntimeError::PageNotFound(id)),
        }
    }

    fn load_page(&mut self, id: u64) -> MemoryResult<()> {
        match self.slots.get(&id).copied() {
            Some(SlotEntry::Live(_)) => Ok(()), // already resident (HOT or WARM)
            Some(SlotEntry::Cold) | None => {
                // (Re)materialise a default HOT tile. A real host fills it from
                // the external COLD store; here we admit a blank tile so the
                // runtime can page it back in.
                let slot = self.cache.insert(default_tile());
                self.slots.insert(id, SlotEntry::Live(slot));
                Ok(())
            }
        }
    }

    fn evict_page(&mut self, id: u64) -> MemoryResult<()> {
        match self.slots.get(&id).copied() {
            Some(SlotEntry::Live(slot)) => {
                self.cache.evict(slot);
                self.slots.insert(id, SlotEntry::Cold);
                Ok(())
            }
            Some(SlotEntry::Cold) => Ok(()), // already evicted
            None => Err(MemoryRuntimeError::PageNotFound(id)),
        }
    }

    fn compress(&mut self, id: u64) -> MemoryResult<CompressionResult> {
        let slot = self.live_slot(id)?;
        if self.cache.state(slot) != TileState::Hot {
            return Err(MemoryRuntimeError::BackendFailure(format!(
                "page {id} is not HOT; compress is a HOT->WARM transition"
            )));
        }
        let started = std::time::Instant::now();

        // Read the per-tile σ_E (quality proxy) and dequantized latent BEFORE
        // page_out (immutable borrows), then apply the HOT->WARM transition.
        let quality_delta = self.cache.tile(slot).residual_sigma;
        let representation = self.cache.tile(slot).dequant_latent();
        self.cache.page_out(slot);

        Ok(CompressionResult {
            backend: MemoryBackend::SlhaV2,
            previous_state: MemoryState::Hot,
            new_state: MemoryState::Warm,
            bytes_before: HOT_BYTES, // 128
            bytes_after: WARM_BYTES, // 96 -- the 32-byte residual is reclaimed
            quality_delta,
            cpu_cycles: started.elapsed().as_nanos() as u64,
            representation: Some(representation),
        })
    }

    fn restore(&mut self, id: u64) -> MemoryResult<()> {
        let slot = self.live_slot(id)?;
        match self.cache.state(slot) {
            TileState::Hot => Ok(()),
            TileState::Warm => {
                self.restore_approximate(id, slot);
                Ok(())
            }
            TileState::Cold => {
                // Should not happen via `live_slot` (Cold entries are not Live),
                // but guard anyway: re-materialise.
                let new_slot = self.cache.insert(default_tile());
                self.slots.insert(id, SlotEntry::Live(new_slot));
                Ok(())
            }
        }
    }
}

impl From<TileState> for MemoryState {
    fn from(s: TileState) -> Self {
        match s {
            TileState::Hot => MemoryState::Hot,
            TileState::Warm => MemoryState::Warm,
            TileState::Cold => MemoryState::Cold,
        }
    }
}

// ── tile (de)construction from the 128-byte payload ──────────────────────────

fn tile_from_payload(b: &[u8; 128]) -> SciRustSlhaTile {
    let mut latent_kv = [0u8; LATENT_BYTES];
    latent_kv.copy_from_slice(&b[OFF_LATENT..OFF_LATENT + LATENT_BYTES]);
    let mut residual_bitmap = [0u64; RESIDUAL_WORDS];
    for (w, c) in residual_bitmap
        .iter_mut()
        .zip(b[OFF_RESIDUAL..OFF_SCALE].chunks_exact(8))
    {
        *w = u64::from_le_bytes(c.try_into().unwrap());
    }
    let mut group_scales = [0u8; N_GROUPS];
    group_scales.copy_from_slice(&b[OFF_GROUPS..OFF_GROUPS + N_GROUPS]);
    SciRustSlhaTile {
        latent_kv,
        residual_bitmap,
        scale: read_f32(b, OFF_SCALE),
        dynamic_lambda: read_f32(b, OFF_LAMBDA),
        residual_sigma: read_f32(b, OFF_SIGMA),
        token_id: read_u32(b, OFF_TOKEN),
        position: read_u32(b, OFF_POS),
        head_id: read_u16(b, OFF_HEAD),
        flags: read_u16(b, OFF_FLAGS),
        group_scales,
    }
}

fn default_tile() -> SciRustSlhaTile {
    SciRustSlhaTile {
        latent_kv: [0u8; LATENT_BYTES],
        residual_bitmap: [0u64; RESIDUAL_WORDS],
        scale: 1.0,
        dynamic_lambda: 0.0,
        residual_sigma: 0.0,
        token_id: 0,
        position: 0,
        head_id: 0,
        flags: 0,
        group_scales: [0u8; N_GROUPS],
    }
}

#[inline]
fn read_f32(b: &[u8; 128], off: usize) -> f32 {
    f32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline]
fn read_u32(b: &[u8; 128], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline]
fn read_u16(b: &[u8; 128], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AlignedMemoryPage;

    fn tile_page(id: u64, sigma: f32) -> AlignedMemoryPage {
        // Build a real tile via scirust's quantizer, then serialize it into the
        // 128-byte payload so `tile_from_payload` round-trips through the ABI.
        use ccos_scirust::attention::slha_v2::{quantize_latent_grouped, SciRustSlhaTile};
        let mut v = [0.0f32; D_C];
        for (d, value) in v.iter_mut().enumerate() {
            *value = ((id as i32 * 7 + d as i32 * 3) % 11) as f32 - 5.0;
        }
        let (latent_kv, scale, group_scales) = quantize_latent_grouped(&v);
        let tile = SciRustSlhaTile {
            latent_kv,
            residual_bitmap: [0u64; RESIDUAL_WORDS],
            scale,
            dynamic_lambda: 0.5,
            residual_sigma: sigma,
            token_id: id as u32,
            position: id as u32,
            head_id: 0,
            flags: 0,
            group_scales,
        };
        let mut bytes = [0u8; 128];
        bytes[OFF_LATENT..OFF_LATENT + LATENT_BYTES].copy_from_slice(&tile.latent_kv);
        for (i, w) in tile.residual_bitmap.iter().enumerate() {
            bytes[OFF_RESIDUAL + i * 8..OFF_RESIDUAL + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        bytes[OFF_SCALE..OFF_SCALE + 4].copy_from_slice(&tile.scale.to_le_bytes());
        bytes[OFF_LAMBDA..OFF_LAMBDA + 4].copy_from_slice(&tile.dynamic_lambda.to_le_bytes());
        bytes[OFF_SIGMA..OFF_SIGMA + 4].copy_from_slice(&tile.residual_sigma.to_le_bytes());
        bytes[OFF_TOKEN..OFF_TOKEN + 4].copy_from_slice(&tile.token_id.to_le_bytes());
        bytes[OFF_POS..OFF_POS + 4].copy_from_slice(&tile.position.to_le_bytes());
        bytes[OFF_HEAD..OFF_HEAD + 2].copy_from_slice(&tile.head_id.to_le_bytes());
        bytes[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&tile.flags.to_le_bytes());
        bytes[OFF_GROUPS..OFF_GROUPS + N_GROUPS].copy_from_slice(&tile.group_scales);
        AlignedMemoryPage {
            page_id: id,
            state: MemoryState::Hot,
            payload: crate::AlignedPayload { bytes },
        }
    }

    #[test]
    fn compress_hot_to_warm_reclaims_residual() {
        let mut be = ScirustBackend::with_budget(10 * HOT_BYTES);
        be.upsert(tile_page(1, 0.7));
        assert_eq!(be.state(1).unwrap(), MemoryState::Hot);
        let r = be.compress(1).unwrap();
        assert_eq!(r.previous_state, MemoryState::Hot);
        assert_eq!(r.new_state, MemoryState::Warm);
        assert_eq!(r.bytes_before, 128);
        assert_eq!(r.bytes_after, 96);
        assert_eq!(be.state(1).unwrap(), MemoryState::Warm);
        // Representation is the dequantized latent (128 floats).
        assert!(r.representation.is_some());
    }

    #[test]
    fn evict_marks_cold_and_state_reports_cold() {
        let mut be = ScirustBackend::with_budget(10 * HOT_BYTES);
        be.upsert(tile_page(2, 0.1));
        be.evict_page(2).unwrap();
        assert_eq!(be.state(2).unwrap(), MemoryState::Cold);
        // A second eviction is a no-op, not an error.
        be.evict_page(2).unwrap();
    }

    #[test]
    fn enforce_budget_pages_and_evicts_to_respect_budget() {
        // 3 tiles × 128 B = 384 B; budget 160 B ⇒ page 1 HOT→WARM (→96), still
        // 96+128+128=352 > 160 ⇒ page another, ... eventually evict to COLD.
        let mut be = ScirustBackend::with_budget(160);
        for id in 1..=3u64 {
            be.upsert(tile_page(id, id as f32 * 0.1));
        }
        be.enforce_budget();
        assert!(
            be.live_bytes() <= 160,
            "live_bytes={} > budget",
            be.live_bytes()
        );
    }

    #[test]
    fn score_all_returns_sorted_page_ids() {
        let mut be = ScirustBackend::with_budget(10 * HOT_BYTES);
        be.upsert(tile_page(10, 0.5));
        be.upsert(tile_page(11, 0.5));
        let q_coarse = [0.0f32; D_C];
        let q_sign = [0u64; RESIDUAL_WORDS];
        let ranked = be.score_all(&q_coarse, &q_sign);
        assert_eq!(ranked.len(), 2);
        // Scores sorted descending.
        assert!(ranked[0].1 >= ranked[1].1);
    }

    #[test]
    fn restore_approximate_brings_warm_back_to_hot() {
        let mut be = ScirustBackend::with_budget(10 * HOT_BYTES);
        be.upsert(tile_page(3, 0.4));
        be.compress(3).unwrap();
        assert_eq!(be.state(3).unwrap(), MemoryState::Warm);
        be.restore(3).unwrap();
        assert_eq!(be.state(3).unwrap(), MemoryState::Hot);
    }
}
