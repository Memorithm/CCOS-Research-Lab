# P3 Handoff — RSI vendor + sandbox (`rsi` / `rsi-dgm`)

> **STATUS: ✅ CLOSED 2026-07-07.** P3 is complete and verified. The sections
> below are kept as the history of the in-progress state + the fixes applied;
> read "Final verified state" first. Next phase is **P4** (security hardening).
>
> Companion: `docs/FUSION_PLAN.md` §F (phasing, P3 now ✅) and §C (RSI wiring).

## Final verified state (2026-07-07, post-fix)

All P3 gates green:
- `cargo check` (default) → green, byte-identical (`cargo tree` shows no `rsi`
  crate — the `dep:rsi` is optional and off by default).
- `cargo check --features rsi` → green.
- `cargo check --features rsi-dgm` → green.
- `cargo check --features pro-default` → green (rsi composes with octacore/etc.).
- `cargo test --features rsi --lib` → **601/601 pass** (5 new bridge tests + 596).
- `cargo tree -p rsi | grep ccos` → empty (circular-dep inversion holds).

What was wired this session (finishing P3):
1. **Root `Cargo.toml`**: added `rsi = { path = "crates/ccos-rsi", optional =
   true }` dep (extern name `rsi`, the `dep:` pattern like `octasoma`), and
   features `rsi = ["dep:rsi"]`, `rsi-dgm = ["rsi"]` (the `ccos-rsi/dgm`
   sub-feature in the plan is stale — `pub mod dgm;` is unconditional), `rsi-full
   = ["rsi","rsi/llm-ollama"]`, `pro-default = […]` (includes `rsi`), `all-full =
   ["pro-default","slhav2-full","rsi-full","rsi-dgm"]`.
2. **`src/lib.rs`**: `#[cfg(feature = "rsi")] pub mod rsi_bridge;`.
3. **`src/license.rs`**: added `Feature::RsiSelfImprovement` + `Feature::RsiDgm`
   (with `name()` arms + `ALL` array → size 9).
4. **`src/event_log.rs`**: added `EventType::SelfModify` +
   `EventPayload::RsiMutation{variant_id,parent_id,patch_target,patch_find_hash,
   patch_replace_hash,compiles,tests_passed,tests_failed,score,accepted,promoted}`
   (fitness as primitives — `event_log` is in the default build and must not
   depend on `ccos-rsi`), + `ReplayStatistics.rsi_mutations` counter + match arm.
5. **`src/rsi_bridge.rs`** fixes: `GuardedDgm` gained `live_root: PathBuf`
   (captured from `DgmConfig.workspace_root`, pub) — replaced the
   `unreachable!()` `config_ref()` stub; `run_step` now emits
   `SelfModify`/`RsiMutation` per step + `GraphMutation` on promote (fixed the
   `edge_kind` typo → `edges_before`/`edges_after`); `CcosAudit::record` returns
   the chain head (was the event UUID — an `AuditLog::record` contract bug); test
   `OnceProposer` uses `&self` + `Cell` (the `Proposer::propose` trait takes
   `&self`, not `&mut self`); removed the dead `DgmConfigRef` trait; cleaned
   test-only imports (`ClosureEvaluator`/`Patch`/`GuardConfig`) + the
   `timed_out` unused-assignment.

## TL;DR (historical — pre-fix in-progress state, kept for context)

- **Crate surgery (`crates/ccos-rsi`): DONE & green.** The `ccos` git dep and the
  `ccos_audit` module are gone; the `CcosAudit` adapter was *moved* to the CCOS
  side; `AuditEvent::payload()` is `pub`. `cargo check -p rsi` is green and
  `cargo tree -p rsi | grep ccos` is empty → the circular-dep inversion holds.
- **Bridge file (`src/rsi_bridge.rs`): WRITTEN but was NOT WIRED** (now wired).
- **One latent panic in `GuardedDgm::run_step`** (now fixed via `live_root`).
- **Default build: green & byte-identical** (P0 invariant holds).

## What is DONE (verified 2026-07-07)

### `crates/ccos-rsi` — circular-dep inversion (the crate side)
- `crates/ccos-rsi/Cargo.toml`: the `ccos = { git = … }` dependency is **removed**.
  No feature pulls `ccos`. `cargo tree -p rsi` shows no `ccos` edge.
- `crates/ccos-rsi/src/lib.rs`: the `ccos_audit` module is gone (see the comment
  block at `lib.rs:49-54`). `pub mod dgm;` is unconditional.
- `crates/ccos-rsi/src/audit.rs`: `AuditEvent::payload()` promoted from
  `pub(crate)` to `pub` (`audit.rs:30-49`) so the moved CCOS-side adapter can
  rebuild the canonical link-payload string. Format unchanged → chain hashes
  identical to the old in-crate path.
- `crates/ccos-rsi/src/bin/rsi_full.rs`: updated to use the in-crate
  `HashChainLog` instead of the removed `CcosAudit` (no `ccos` edge from the bin).
- **Build gate:** `cargo check -p rsi` → exit 0.

### `src/rsi_bridge.rs` — the CCOS-side adapter + hard-sandbox DGM (written)
Behind `#![cfg(feature = "rsi")]`. Public surface:
- `CcosAudit` — `rsi::AuditLog` over CCOS's hash-chained `EventLog`. `record`
  appends `EventType::AgentAction` + `EventPayload::Custom{key:"rsi_step", …}`;
  `head()`/`verify()` delegate to the `EventLog`. Debug-printable.
- `RsiAccess::unlock(&Licensing, now)` — Pro gate for `Feature::RsiSelfImprovement`;
  `RsiAccess::audit(session_id) -> Box<dyn AuditLog>`.
- `DgmAccess::unlock(&Licensing, now)` — Pro gate for `Feature::RsiDgm`;
  `DgmAccess::guarded_dgm(...)` assembles a `GuardedDgm`.
- `GuardedDgmConfig { editable_allowlist, backup_dir }` — the editable-file
  allowlist is the **primary security control** (`is_editable` normalises `./`).
- `GuardedProposer<P>` — refuses proposals whose `target` is not allowlisted
  (returns `DgmError::PathNotAllowed`), and routes the proposer `rationale`
  through `GuardLayer::validate_and_sanitize`.
- `GuardedDgm<P,E>` — wraps `DgmEngine<GuardedProposer<P>, E>`; `run_step`
  records every step in the CCOS `EventLog` and, on an accepted+allowlisted
  patch, calls `rsi::dgm::promote_to_live` and records a `GraphMutation` event
  (refused/blocked promotes are recorded too — never silent).
- `GuardedCargoEvaluator` — air-gapped real cargo evaluator: `cargo build
  --offline --frozen` then `cargo test --offline --frozen`, with
  `CARGO_NET_OFFLINE=true`, bounded by timeout (300s) + per-stream output cap
  (4 MiB), `kill()` on deadline. `run_bounded` + `parse_test_counts` helpers.
- **Tests (5, in-module `#[cfg(test)]`):** `community_tier_refuses_rsi_and_dgm`,
  `ccosaudit_records_into_ccos_hashchain_and_verifies`, `pro_unlocks_rsi_audit`,
  `guarded_dgm_promotes_allowlisted_patch_and_records_to_eventlog`,
  `guarded_dgm_refuses_non_allowlisted_target`. **The last two currently panic**
  (see §Open work #2).

## Open work to FINISH P3

### 1. Wire the bridge into the root crate (`Cargo.toml` + `src/lib.rs`)
The root `Cargo.toml` `[features]` block ends at `octacore` (line ~179). Add:

```toml
# (in [dependencies])
ccos-rsi = { path = "crates/ccos-rsi", package = "rsi", optional = true }

# (in [features], after octacore)
# CERVO/RSI vendor (plan P3): the deterministic std-only RSI core (step + audit
# bridge). `replay == live` (no LLM, no subprocess). Off by default → byte-identical.
rsi = ["dep:ccos-rsi"]
# DGM self-improvement loop. Pulls the guarded sandbox + GuardedCargoEvaluator.
# REPLAY-RELAX: the evaluator runs a real `cargo` subprocess. Off by default.
rsi-dgm = ["rsi"]
# RSI + LLM proposer backend (Ollama/Claude). REPLAY-RELAX (LLM non-replayable).
rsi-full = ["rsi", "ccos-rsi/llm-ollama"]   # adjust if a root-side LLM wire is needed
# Pro bundle: every deterministic premium tier, no full-kernel replay relax.
pro-default = ["license","license-pq","signed-sync","slhav2","octasoma","octacore","rsi","learned-embed"]
# Test-only: every full-kernel / replay-relax feature at once.
all-full = ["pro-default","slhav2-full","rsi-full","rsi-dgm"]
```

> Note: `FUSION_PLAN.md` §B lists `rsi-dgm = ["rsi", "ccos-rsi/dgm"]`, but the
> vendored `crates/ccos-rsi` has **no `dgm` cargo feature** — `pub mod dgm;` is
> unconditional. So `rsi-dgm = ["rsi"]` is correct as-is; the `ccos-rsi/dgm`
> sub-feature in the plan is stale. (Optionally add a `dgm` cargo feature to
> `ccos-rsi` gating `pub mod dgm;` behind `#[cfg(feature="dgm")]` if you want the
> plan's exact dependency shape — not required for green.)

Then in `src/lib.rs`, declare the module (gated, mirroring `octacore_bridge`):
```rust
// CCOS_EXTENDED (plan P3): the RSI circular-dep inversion + hard-sandbox DGM.
// CCOS depends on `ccos-rsi` (the vendored CERVO/RSI core); `ccos-rsi` has no
// edge on `ccos`. The `CcosAudit` adapter + `GuardedDgm` live here, behind `rsi`.
#[cfg(feature = "rsi")]
pub mod rsi_bridge;
```
Place it near `pub mod octacore_bridge;` (`src/lib.rs:148`) / `pub mod slha_full;`
(`src/lib.rs:157`).

### 2. Fix the `GuardedDgm::run_step` panic (BLOCKING for the 2 DGM tests)
`src/rsi_bridge.rs:321` does:
```rust
let live_root = self.engine.config_ref().workspace_root.clone();
```
`DgmEngine` does **not** expose `config` (private field, `dgm.rs:1439`) and has
no `config_ref()` accessor. The bridge defines a private trait `DgmConfigRef`
with an impl that does `unreachable!()` (`rsi_bridge.rs:569-579`) — a placeholder.
So `run_step` panics on every call. The code comment already states the intended
fix ("store the live root on the wrapper instead") — apply it:

```rust
pub struct GuardedDgm<P: Proposer, E: Evaluator> {
    engine: DgmEngine<GuardedProposer<P>, E>,
    sandbox: GuardedDgmConfig,
    guard: GuardLayer,
    live_root: PathBuf,   // ← add
}

impl<P: Proposer, E: Evaluator> GuardedDgm<P, E> {
    pub fn new(archive, proposer, evaluator, config: DgmConfig, seed, sandbox, guard) -> Self {
        let live_root = config.workspace_root.clone();      // DgmConfig.workspace_root is pub (dgm.rs:1377)
        let gp = GuardedProposer::new(proposer, sandbox.clone(), guard.clone());
        let engine = DgmEngine::new(archive, gp, evaluator, config, seed);
        Self { engine, sandbox, guard, live_root }
    }
    pub fn run_step(&mut self, audit: &mut EventLog) -> rsi::dgm::Result<GuardedStepOutcome> {
        let live_root = self.live_root.clone();   // ← was: self.engine.config_ref()…
        // …rest unchanged
    }
}
```
`DgmAccess::guarded_dgm` passes `config` through, so `live_root` is captured at
construction. Delete the dead `DgmConfigRef` trait + impl. Re-run the 2 DGM
tests; they should then pass (allowlist allow → promote + audit; allowlist
refuse → `PathNotAllowed`, secret untouched).

### 3. Decide the audit-event taxonomy (non-blocking, optional polish)
`FUSION_PLAN.md` §C/§D specify dedicated `EventType::SelfModify` +
`EventPayload::RsiMutation{variant_id,parent_id,patch_target,patch_find_hash,
patch_replace_hash,fitness,accepted}`. The written bridge instead reuses the
existing `EventType::GraphMutation` / `EventType::AgentAction` +
`EventPayload::Custom{key:"rsi_dgm_*"}`. Both are tamper-evident; the dedicated
variants give structured audit queries. **Decision:** either (a) keep `Custom`
(document the keys in `docs/SECURITY.md`), or (b) add the dedicated variants to
`src/event_log.rs` and switch the bridge. Recommended: (b) for a clean
tamper-evident timeline, matching the plan. Either way, record the choice in
the FUSION_PLAN P3 close-out.

### 4. P3 close-out gates (from FUSION_PLAN §F)
- `cargo check` (default) green ✅ (already).
- `cargo check --features rsi` green.
- `cargo test --features rsi` green: the 5 bridge tests + ccos-rsi's own tests.
- `cargo tree --features rsi | grep ccos-rsi` shows the dep; `cargo tree -p rsi
  | grep ccos` still empty.
- Step-determinism + DGM-sandbox + hashchain tests pass (the 5 bridge tests).
- Default build still byte-identical (`cargo tree` default shows no `ccos-rsi`).
- Then mark P3 ✅ in `docs/FUSION_PLAN.md` §F and update this file to "CLOSED".

## Resume recipe (copy-paste)

```bash
cd /root/CCOS_EXTENDED
# 1. apply Open work #1 (Cargo.toml + src/lib.rs), #2 (run_step fix), #3 (audit taxonomy)
# 2. build:
cargo check                       # default — must stay green
cargo check --features rsi         # bridge compiles
cargo test  --features rsi -p ccos --lib   # 5 bridge tests
# 3. verify invariants:
cargo tree -p rsi | grep ccos      # empty
cargo tree --features rsi | grep ccos-rsi  # present
cargo tree | grep ccos-rsi         # empty (default byte-identity)
```

## Files touched this session (P3, as of the crash)

- `crates/ccos-rsi/Cargo.toml` — `ccos` git dep removed; inversion comment added.
- `crates/ccos-rsi/src/lib.rs` — `ccos_audit` module removed; comment block.
- `crates/ccos-rsi/src/audit.rs` — `AuditEvent::payload()` → `pub`.
- `crates/ccos-rsi/src/bin/rsi_full.rs` — uses `HashChainLog` (no `ccos` edge).
- `src/rsi_bridge.rs` — NEW (772 lines): adapter + gates + guarded DGM + tests.
- `docs/FUSION_PLAN.md` — P3 line still reads "in progress" (update on close).
- `docs/P3_HANDOFF.md` — THIS file.

## Not yet started (P4+)

- **P4** Security hardening pass (NUMA audit, FFI alignment, egress allowlist,
  determinism-boundary table + `docs/DETERMINISM.md`, PQ-default).
- **P5** Unified MCP/CLI multiplexing `ccos.*`+`slha.*`+`octa.*`+`rsi.*`;
  Pro-default surface.
- **P6** Massive test suite + CI matrix (`default` | `pro-default` | `all-full`
  × build/clippy/test/doc; weekly `cargo audit`; criterion benches).