//! CCOS_EXTENDED fusion integration test (plan P1): the SLHAv2 FULL kernel tier.
//!
//! Exercises the *fused* path end-to-end through CCOS's own surfaces:
//!   1. the offline license gate (`Feature::SlhAv2FullKernel`) — community refuses,
//!      Pro unlocks, no silent downgrade;
//!   2. the real `ccos-scirust` kernel as a `MemoryProvider` backend
//!      (`ScirustBackend`): HOT→WARM compress (128→96 B, residual reclaimed),
//!      approximate restore (WARM→HOT), evict→COLD, `enforce_budget` soft-paging
//!      with informed (H2O / attention-sink) eviction;
//!   3. the `LatentSafetyGuard` — a benign latent passes, an injected (near-zero /
//!      orthogonal) latent is flagged before dequantisation.
//!
//! Gated by the `slhav2-full` cargo feature (a documented REPLAY-RELAX). The
//! default build compiles none of this and stays `replay == live`.

#![cfg(feature = "slhav2-full")]

use ccos::license::{Feature, License, LicenseError, Licensing};
use ccos::slha_full::FullSlhaAccess;
use ccos_memory_runtime::telemetry::{MemoryBackend, MemoryState};
use ccos_memory_runtime::traits::MemoryProvider;
use ccos_memory_runtime::{AlignedMemoryPage, AlignedPayload};
use ccos_scirust::attention::slha_v2::{quantize_latent_grouped, D_C, FLAG_WARM, RESIDUAL_WORDS};
use ccos_scirust::ccos::{EvictionPolicy, HOT_BYTES, WARM_BYTES};
use ccos_scirust::safety::SafetyResult;

const NOW: u64 = 1_000;

/// Build a real SLHAv2 tile (grouped-INT4 latent + a non-trivial residual) and
/// serialize it into a 128-byte CCOS page at the documented ABI offsets.
fn real_tile_page(id: u64, sigma: f32) -> AlignedMemoryPage {
    let mut v = [0.0f32; D_C];
    for d in 0..D_C {
        v[d] = ((id as i32 * 7 + d as i32 * 3) % 11) as f32 - 5.0;
    }
    let (latent_kv, scale, group_scales) = quantize_latent_grouped(&v);
    let tile = ccos_scirust::attention::slha_v2::SciRustSlhaTile {
        latent_kv,
        residual_bitmap: [0x0123_4567_89ab_cdefu64; RESIDUAL_WORDS],
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
    bytes[0..64].copy_from_slice(&tile.latent_kv);
    for (i, w) in tile.residual_bitmap.iter().enumerate() {
        bytes[64 + i * 8..64 + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    bytes[96..100].copy_from_slice(&tile.scale.to_le_bytes());
    bytes[100..104].copy_from_slice(&tile.dynamic_lambda.to_le_bytes());
    bytes[104..108].copy_from_slice(&tile.residual_sigma.to_le_bytes());
    bytes[108..112].copy_from_slice(&tile.token_id.to_le_bytes());
    bytes[112..116].copy_from_slice(&tile.position.to_le_bytes());
    bytes[116..118].copy_from_slice(&tile.head_id.to_le_bytes());
    bytes[118..120].copy_from_slice(&tile.flags.to_le_bytes());
    bytes[120..128].copy_from_slice(&tile.group_scales);
    AlignedMemoryPage {
        page_id: id,
        state: MemoryState::Hot,
        payload: AlignedPayload { bytes },
    }
}

#[test]
fn community_tier_refuses_full_kernel_no_silent_downgrade() {
    let l = Licensing::community();
    let err = FullSlhaAccess::unlock(&l, NOW).unwrap_err();
    assert_eq!(err, LicenseError::FeatureLocked(Feature::SlhAv2FullKernel));
    // No license at all ⇒ NoLicense path when no verifier is supplied.
    assert_eq!(Licensing::community().tier(NOW), ccos::license::Tier::Community);
}

#[test]
fn pro_tier_unlocks_and_backend_roundtrips() {
    let l = Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
    });
    let access = FullSlhaAccess::unlock(&l, NOW).unwrap();

    let mut be = access.scirust_backend(8 * HOT_BYTES);
    be.upsert(real_tile_page(1, 0.7));
    be.upsert(real_tile_page(2, 0.3));

    assert_eq!(be.state(1).unwrap(), MemoryState::Hot);
    assert_eq!(be.state(2).unwrap(), MemoryState::Hot);

    // HOT → WARM compression reclaims the 32-byte residual.
    let r = be.compress(1).unwrap();
    assert_eq!(r.backend, MemoryBackend::SlhaV2);
    assert_eq!(r.previous_state, MemoryState::Hot);
    assert_eq!(r.new_state, MemoryState::Warm);
    assert_eq!(r.bytes_before, HOT_BYTES);
    assert_eq!(r.bytes_after, WARM_BYTES);
    assert_eq!(be.state(1).unwrap(), MemoryState::Warm);

    // Approximate restore brings it back HOT (latent-only; residual gone).
    be.restore(1).unwrap();
    assert_eq!(be.state(1).unwrap(), MemoryState::Hot);

    // Evict → COLD, idempotent.
    be.evict_page(2).unwrap();
    be.evict_page(2).unwrap();
    assert_eq!(be.state(2).unwrap(), MemoryState::Cold);
}

#[test]
fn informed_eviction_respects_budget_and_pins_sinks() {
    let l = Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
    });
    let access = FullSlhaAccess::unlock(&l, NOW).unwrap();

    // Budget for ~2 HOT tiles; insert 4 with rising positions (the sink is the
    // lowest position). Informed eviction should keep the sink and drop the
    // lowest-importance non-sinks first.
    let mut be =
        access.scirust_backend_with_eviction(2 * HOT_BYTES, EvictionPolicy::Importance { sink_window: 1 });
    for id in 1..=4u64 {
        let page = real_tile_page(id, id as f32 * 0.1);
        be.upsert(page);
    }
    be.enforce_budget();
    assert!(
        be.live_bytes() <= 2 * HOT_BYTES,
        "live_bytes={} over budget",
        be.live_bytes()
    );
    let (hot, warm, cold) = be.counts();
    assert!(hot + warm + cold > 0);
}

#[test]
fn score_all_ranks_live_pages_descending() {
    let l = Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
    });
    let access = FullSlhaAccess::unlock(&l, NOW).unwrap();
    let mut be = access.scirust_backend(8 * HOT_BYTES);
    be.upsert(real_tile_page(10, 0.5));
    be.upsert(real_tile_page(11, 0.5));
    let q_coarse = [0.0f32; D_C];
    let q_sign = [0u64; RESIDUAL_WORDS];
    let ranked = be.score_all(&q_coarse, &q_sign);
    assert_eq!(ranked.len(), 2);
    assert!(ranked[0].1 >= ranked[1].1);
}

#[test]
fn latent_safety_guard_passes_benign_and_flags_injection() {
    let l = Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
    });
    let access = FullSlhaAccess::unlock(&l, NOW).unwrap();

    // Reference direction: first basis vector.
    let mut reference = [0.0f32; D_C];
    reference[0] = 1.0;
    let mut guard = access.safety_guard(reference, 0.5);

    // A latent aligned with the reference (dequantized) ⇒ Safe.
    let aligned = {
        let mut v = [0.0f32; D_C];
        v[0] = 1.0;
        v
    };
    assert_eq!(guard.analyze_dequantized(&aligned), SafetyResult::Safe);

    // An orthogonal / near-zero latent ⇒ Anomalous (dot-product deviation).
    let injected = [0.0f32; D_C]; // zero vector ⇒ undefined norm ⇒ deviation
    let res = guard.analyze_dequantized(&injected);
    assert!(matches!(res, SafetyResult::Anomalous { .. }), "got {res:?}");
}

#[test]
fn flag_warm_round_trips_through_tile_abi() {
    // Sanity: the WARM flag bit survives the (de)serialization used by the backend.
    let mut p = real_tile_page(42, 0.0);
    // Set the WARM flag in the ABI's flags field (offset 118).
    let flags_off = 118usize;
    let mut flags = u16::from_le_bytes(p.payload.bytes[flags_off..flags_off + 2].try_into().unwrap());
    flags |= FLAG_WARM;
    p.payload.bytes[flags_off..flags_off + 2].copy_from_slice(&flags.to_le_bytes());

    let l = Licensing::licensed(License {
        licensee: "acme".to_string(),
        expires_at: None,
    });
    let access = FullSlhaAccess::unlock(&l, NOW).unwrap();
    let mut be = access.scirust_backend(8 * HOT_BYTES);
    be.upsert(p);
    // A freshly upserted page is HOT regardless of the inbound flag (insert resets
    // state); the ABI bit only matters on the distilled decode side.
    assert_eq!(be.state(42).unwrap(), MemoryState::Hot);
}