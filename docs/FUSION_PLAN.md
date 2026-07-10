# CCOS_EXTENDED — Fusion Plan (Premium)

A single Rust product at `/root/CCOS_EXTENDED` fusing **CCOS** (hub) + **CERVO/RSI** + **SLHAv2** + **OctaSoma**, behind a **DUAL determinism posture** and a **Pro-by-default commercial license**.

> Source repos (all same org Memorithm/Memorithm, all dual-licensed PolyForm-Noncommercial/commercial — mutually compatible):
> CCOS `/root/CCOS` v0.3.0 · CERVO/RSI `/root/CERVO/RSI` v0.10.0 · SLHAv2 `/root/SLHAv2` v0.2.0 · OctaSoma `/root/octasoma` v0.4.0

## Guiding invariants (non-negotiable)

1. **Default build is byte-identical to CCOS today** (`default = ["syn-parser"]`). The four repos' real kernels enter ONLY behind opt-in features.
2. **No `scirust` in the default runtime** ("distill-don't-link"). `cargo tree | grep scirust` empty; `cargo tree --features slhav2-full | grep scirust` shows `ccos-scirust`.
3. **`replay == live`** for the default build; every full-kernel feature carries a `REPLAY-RELAX:` marker + documented divergence.
4. **No new network egress by default** — air-gap posture preserved.
5. **Pro-by-default + commercial gate**; community tier reachable via features.

## User-confirmed decisions

- **Determinism posture**: DUAL — default déterministe (distillé) + features full-kernel opt-in.
- **RSI/DGM safety**: hard sandbox + allowlists + audit hash-chain + GuardLayer.
- **License**: Pro par défaut + commercial gate.

## A. Workspace layout

```
/root/CCOS_EXTENDED/
├─ Cargo.toml                  # root package `ccos` 0.4.0 + workspace (resolver 2, MSRV 1.89)
├─ src/                        # CCOS hub (surface unchanged; additions behind features)
├─ crates/
│  ├─ ccos-memory-runtime/     # existing; expanded (slhav2-full backend)
│  ├─ ccos-rsi/                # ← CERVO/RSI   (drop parent cervo scaffold — no license)
│  ├─ ccos-scirust/            # ← SLHAv2/scirust   (lib name stays "scirust")
│  ├─ ccos-scirust-mcp/        # ← SLHAv2/slha-mcp
│  ├─ ccos-scirust-c/          # ← SLHAv2/slha-c   (output FFI only)
│  ├─ ccos-scirust-python/     # ← SLHAv2/slha-python
│  ├─ ccos-octasoma/           # ← octasoma  (separate, #![forbid(unsafe_code)] quarantine)
│  └─ ccos-octacore/           # ← octasoma/octacore  (CausalScope/Cascade)
└─ tests/ benches/ docs/ examples/ scripts/ .github/   # from CCOS, expanded
```

### Critical manifest surgeries
- **RSI circular dep inversion**: RSI's `ccos = { git=… }` → REMOVE; delete `RSI/src/ccos_audit.rs` and its exports (`lib.rs:103-104`); move `CcosAudit` to CCOS side as `src/rsi/audit_bridge.rs` (behind `rsi`). `ccos-rsi` becomes a pure leaf; `ccos` depends on `ccos-rsi`.
- **Octacore circular dep**: same pattern — drop octacore's `ccos` git dep + `ccos_adapter` module; move `CcosScope<M: ExternalMemory>` to `src/substrate/mod.rs` on CCOS side.
- **OctaSoma git→path**: `octasoma = { path = "crates/ccos-octasoma", optional = true }` (single v0.4.0 pin).
- **Crate name collision**: SLHAv2's `scirust` → package name `ccos-scirust`, `[lib] name = "scirust"` (imports unchanged). RSI's `scirust-rsi` feature DROPPED. OctaSoma's `scirust-simd/evo` stay optional git (off by default).
- **License**: every member `license = "LicenseRef-TarekZekriti-Dual"`. Drop the no-license `cervo` scaffold.
- **Edition**: `ccos` stays 2021 (`octa_index.rs:1-12` let-chain note); `ccos-octasoma` stays 2024; workspace mixes editions freely.

## B. Feature gate architecture (DUAL)

Existing (unchanged semantics): `default=["syn-parser"]`, `llm`, `syn-parser`, `mimalloc`, `learned-embed`, `license`, `license-pq`, `signed-sync`, `slhav2`, `neural-embed`, `octasoma`.

| New feature | Pulls | Breaks replay? |
|---|---|---|
| `slhav2-full` | `slhav2`, `ccos-memory-runtime/slhav2-full` → `ccos-scirust` | **Yes** (SIMD float order) |
| `rsi` | `dep:ccos-rsi` | No (std-only deterministic) |
| `rsi-full` | `rsi` + LLM backend | **Yes** (LLM non-replayable) |
| `rsi-dgm` | `rsi`, `ccos-rsi/dgm` (gate `dgm` module) | **Yes** (subprocess) |
| `rsi-wasm` | `ccos-rsi/wasm` | No (wasmi fuel-bounded) |
| `octacore` | `dep:ccos-octacore` | No w/ HashEmbedder |
| `pro-default` | `license,license-pq,signed-sync,slhav2,octasoma,octacore,rsi,learned-embed` | No |
| `all-full` | `pro-default` + all full-kernel | **Yes** (test-only) |

Runtime `Feature` enum (`src/license.rs:29`) gains: `SlhAv2FullKernel`, `RsiSelfImprovement`, `RsiDgm`, `OctaCoreCascade`. Each new entry point calls `Licensing::require(Feature::X, now)` mirroring `SemanticMemoryAccess::unlock` (`octa_index.rs:445`).

## C. Trait wiring (the actual fusion)

### SLHAv2 (`slhav2-full`)
- `ElasticKvCache` (`SLHAv2/scirust/src/ccos.rs:79`) → `MemoryProvider` backend via `crates/ccos-memory-runtime/src/backend/scirust_full.rs` (`ScirustBackend`). NOT `ExternalMemory` directly (it's a KV-cache, not a graph). A `KvCacheExternalMemory` adapter in `src/slha_full.rs` exposes `recall(Recall::Semantic)` → `ElasticKvCache::score_all` top-k.
- `LatentSafetyGuard` (`safety.rs`) composes BEFORE decompression; CCOS `GuardLayer`/`sanitizer`/`injection_classifier` AFTER. `GuardedKvCache`.
- `scirust::audit` → `ScirustAuditHandler: ReplayHandler` writing `EventPayload::Custom{key:"slha_audit"}` to hash chain.
- `compute_score` → retrieval backend `SemanticRetriever::Backend::Slha` + `SlhaEncoder: Encoder`.
- MCP: `slha.*` tools multiplexed under `src/mcp.rs`.

### OctaSoma (`octacore`)
- `ccos-octasoma` stays a separate `#![forbid(unsafe_code)]` quarantine crate (path dep).
- Promote `ccos-octacore::{CausalScope, Cascade}` → `ccos::substrate` module (behind `octacore`). `CcosScope<M: ExternalMemory>` moved to CCOS side.
- `Recall::Semantic` routes through `Cascade` under Pro + `octacore`; else existing INT4 path unchanged.

### CERVO/RSI (`rsi`/`rsi-dgm`)
- Vendor `RSI/` as `crates/ccos-rsi`. Trait mapping:
  - `MetaSearch`/`RSIAgent::step` → CCOS `Agent` impl `RsiAgent` (`src/rsi/agent_bridge.rs`); `StepReport` → `EventPayload::Custom{key:"rsi_step"}` via `Agent::emit_event`.
  - `ContextMemory` → `CcosContextMemory` over `ExternalMemory`.
  - `AuditLog` → `CcosAudit` (moved to `src/rsi/audit_bridge.rs`).
  - `SubstrateImprover`/`KnowledgeSource`/`LoopObserver` → CCOS runtime/`AgentExecutor`/`GuardLayer`.
  - DGM `Proposer`/`Evaluator`/`CodeModel` → CCOS plan steps + `eval.rs`; every accepted mutation → `EventPayload::RsiMutation` + `EventType::SelfModify`.
- Module collisions (`memory`/`audit`/`llm`/`json`) handled by crate-level namespacing; RSI lib name stays `rsi`.

### Unified premium surface
- Single MCP server multiplexing `ccos.*` (14) + `slha.*` + `octa.*` + `rsi.*`.
- Unified CLI: `ccos slha|octa|rsi <sub>` behind features.

## D. Security hardening (sécurité absolue)

- **DGM hard sandbox**: `WorkspaceSnapshot` temp copy (skips symlinks), `cargo --offline` + `CARGO_NET_OFFLINE=true` (egress allowlist `CCOS_EGRESS_ALLOW`), editable-path canonicalization (refuse `../`/symlink escape), bounded output (4MiB) + timeout (300s) + `kill()`, `promote_to_live` all-at-once re-eval, per-run total budget, `GuardedProposer` sanitizes rationale via `GuardLayer`. New `EventPayload::RsiMutation{variant_id,parent_id,patch_target,patch_find_hash,patch_replace_hash,fitness,accepted}` + `EventType::SelfModify` → tamper-evident timeline.
- **NUMA unsafe** (`ccos-scirust/numa.rs`): gate behind `numa` (default off); `#![forbid(unsafe_code)]` at crate root, `allow` only inside gated `numa.rs`; add `// SAFETY:` justifications for `unsafe impl Send/Sync`; or split `ccos-scirust-numa-sys` sub-crate.
- **FFI** (`ccos-scirust-c`): output boundary only; header documents 128-align + `slha_tile_free` (dealloc w/ same Layout); debug `assert!(ptr % 128 == 0)`.
- **Egress**: `ureq`/`reqwest` consult `EgressAllowlist`; default localhost only.
- **Determinism boundary**: `tests/determinism_boundary.rs` + `docs/DETERMINISM.md` table; default build `#![deny(unsafe_code)]`-clean where possible.
- **License**: zero-knowledge offline; `license-pq` (SLH-DSA FIPS 205) in `pro-default`; no silent downgrade.

## E. Massive test strategy

- **Regression gate**: `tests/regression_default_byte_identical.rs` — default session → snapshot → replay identical; `pro-default` chain head still identical; `slhav2-full` documented divergence.
- **Existing CCOS tests** (20 integration + inline + proptest + criterion) pass unchanged in default build (P0 gate).
- **Per-crate**: SLHAv2 SIMD≡scalar + replay-divergence + NUMA stress; OctaSoma kNN≡bruteforce (exists) + cascade routing + scope adapter; RSI step determinism + agent bridge + DGM sandbox escape (path traversal, command injection, timeout, egress) + DGM hashchain.
- **Cross-crate fusion**: recall-through-cascade, rsi-as-agent, elastickv-as-memory, unified-mcp tools/list (4 namespaces).
- **Security fuzz**: dgm escape, sanitizer roundtrip, numa unsafe, ffi alignment (ASAN).
- **Property**: proptest over feature combos → expected replay-safe vs replay-relaxed.
- **CI matrix** (extend `.github/workflows/ci.yml`): `default` | `pro-default` | `all-full` × build/clippy/test/doc; weekly `cargo audit`.
- **Benchmarks** (criterion, `benches/delta_bench.rs`): cascade_recall, slha_full_score, rsi_step, unified_mcp_tools_list.

## F. Phasing (each phase gated by "default build green & byte-identical")

- **P0** ✅ DONE — Workspace skeleton + manifest surgery + green default build. Gate met: `cargo check` default green; `cargo tree|grep -E 'scirust|ccos-rsi|octacore|octasoma|ccos-memory-runtime'` empty (byte-identity preserved via `default-members = ["."]`).
- **P1** ✅ DONE — SLHAv2 full kernel (`slhav2-full`). `ScirustBackend: MemoryProvider` (`crates/ccos-memory-runtime/src/backend/scirust_full.rs`) wraps `ElasticKvCache` (HOT/WARM/COLD soft-paging, informed H2O/sink eviction, SIMD `compute_score`); CCOS-side premium gate `FullSlhaAccess::unlock` (`src/slha_full.rs`, `Feature::SlhAv2FullKernel`) also exposes the `LatentSafetyGuard`. Gate met: default unchanged + `--features slhav2-full` builds; 5 backend unit + 3 gate + 6 fusion integration tests green; `cargo tree --features slhav2-full|grep scirust` shows scirust, default shows none.
- **P2** ✅ DONE — OctaSoma/octacore promotion (`octacore`). **Circular-dep inversion**: removed `octacore`'s `ccos` git dep + `ccos_adapter` module; `CcosScope` now lives on the CCOS side (`src/octacore_bridge.rs`) implementing `octacore::CausalScope` over a CCOS `ExternalMemory`, so CCOS depends on `octacore`, never the reverse (`cargo tree -p octacore|grep ccos` empty). Premium gate `CausalCascadeAccess::unlock` (reuses `Feature::OctaSomaMemory`); `semantic_cascade`/`recall_semantic` helpers; deterministic `HashEmbedder` keeps the cascade bit-replayable. The core `Recall::Semantic` path is untouched. Gate met: 4 bridge unit + 4 fusion integration tests green; default + `--features octacore` + combo builds green; `octacore` self doctests pass.
- **P3** ✅ DONE (2026-07-07) — RSI vendor + sandbox (`rsi`/`rsi-dgm`). **Crate side**: `ccos-rsi` has no `ccos` edge (`cargo tree -p rsi | grep ccos` empty), `AuditEvent::payload()` is `pub`, `ccos_audit` module gone. **Bridge wired** (`src/rsi_bridge.rs`, behind root `rsi` feature): `CcosAudit` (rsi `AuditLog` → CCOS hash-chained `EventLog`, returns the chain head not the event id), `RsiAccess`/`DgmAccess` Pro gates (`Feature::RsiSelfImprovement`/`RsiDgm` added to `src/license.rs`), `GuardedDgm` (editable-file allowlist + `GuardLayer` + air-gapped `cargo --offline --frozen` evaluator + hash-chain-audited `promote_to_live`) emitting the dedicated `EventType::SelfModify` + `EventPayload::RsiMutation{…}` (added to `src/event_log.rs`). Root `Cargo.toml` gains `rsi`/`rsi-dgm`/`rsi-full`/`pro-default`/`all-full` features + the `rsi` dep; `src/lib.rs` declares `#[cfg(feature="rsi")] pub mod rsi_bridge;`. Three latent bugs from the pre-crash draft fixed: the `run_step` `unreachable!()` panic (added `live_root` to the wrapper), the `GraphMutation` `edge_kind` typo (→ `edges_before/edges_after`), and the `Proposer::propose` `&mut self` test stub (→ `&self` + `Cell`). Gate met: `cargo check` default green & byte-identical (no `rsi` in tree); `cargo check --features rsi`/`rsi-dgm`/`pro-default` green; `cargo test --features rsi --lib` → 601/601 (5 new bridge tests: license refusal, CcosAudit hashchain, Pro unlock, allowlisted promote+audit, non-allowlisted refuse). `cargo tree -p rsi | grep ccos` empty. Close-out: **`docs/P3_HANDOFF.md`** (CLOSED).
- **P4** ✅ DONE (2026-07-07) — Security hardening pass (NUMA audit, FFI, egress, determinism boundary; PQ default already wired in P1). **NUMA**: `ccos-scirust` now `#![deny(unsafe_code)]` at the crate root, with `#![allow(unsafe_code)]` zones only in the two audited modules — `numa.rs` (gated `#[cfg(all(feature="numa", target_os="linux"))]`, default off; `// SAFETY:` justifications on the `Send`/`Sync` impls for `AlignedBuffer`/`NumaBuffer`) and `attention/slha_v2.rs` (x86_64 `#[target_feature]`-gated SIMD, runtime `is_x86_feature_detected!`, scalar-equivalence-checked reference path). **FFI** (`slha-c`): output-boundary-only — `slha_process_tile` borrows a caller-owned tile (no `slha_tile_free`), `debug_assert!`s the `SLHA_TILE_ALIGN` (64/128) alignment on entry; `include/slha.h` documents the ownership + alignment contract. **Egress** (`src/egress.rs`, default-compiled, pure `std`): `EgressAllowlist` (default localhost/loopback only — `localhost`/`127.0.0.1`/`::1`/`[::1]`/`0.0.0.0`; `CCOS_EGRESS_ALLOW` comma-separated expansion; **fail-closed** `EgressError::{Malformed,HostNotAllowed}`) gates the three network call sites — `llm::query_as` (→ fallback `ValidatedResponse`, no call), `neural_embed::NeuralEncoder::try_new` (→ `NeuralEmbedError::EgressDenied`), `eval::ask` Anthropic/OpenAI/Ollama branches (→ `None`). **Determinism boundary**: `docs/DETERMINISM.md` (the feature→replay-posture table + air-gap + `unsafe` boundary) and `tests/determinism_boundary.rs` (5 tests: egress localhost-only + remote-ollama refusal, community refuses every REPLAY-RELAX feature, table total & consistent, relaxed set = Pro-gated set). Gate met: `cargo check` default + `--features slhav2-full` + `--features pro-default` + `--features llm,neural-embed` all green; default `cargo tree` shows no scirust/rsi (byte-identity preserved); `cargo check -p slha-c` green; `cargo test --test determinism_boundary` → 5/5; egress lib unit → 5/5; `cargo test --features slhav2-full --lib` → 604/604 (no regression). Close-out: **`docs/DETERMINISM.md`**.
- **P5** ✅ DONE (2026-07-08) — Unified MCP/CLI. **One server, four namespaces**:
  `src/mcp_ext.rs` (gated `any(slhav2-full, octacore, rsi)`) multiplexes
  `slha.{explain,audit,compress,score,benchmark}` (codec-parameterised incl. TQ3,
  mirroring the standalone `slha-mcp` contract), `octa.{explain,cascade_recall}`
  (read-only cascade over the live session graph, deterministic `HashEmbedder`),
  and `rsi.{explain,status}` into `src/mcp.rs` via two small hooks (catalogue
  append + prefix dispatch). Every kernel-touching tool goes through its bridge's
  Pro gate (visible `isError` refusal); the `explain` tools are free prose.
  **Security stance: DGM execution is unreachable over MCP *and* the CLI** — only
  the typed `GuardedDgm` API (which forces an explicit allowlist) can run it; the
  MCP surface exposes status/documentation only. Unified CLI (`src/main.rs`,
  thin wrappers over `mcp_ext::call_tool` so CLI and MCP share one
  implementation/gate/refusal): `ccos slha explain|audit|benchmark`,
  `ccos octa recall <text> --workspace <ws> [--k|--budget]`, `ccos rsi
  status|explain`; refusals exit 3; help advertises only compiled namespaces.
  Gate met: `tests/fusion_unified_mcp.rs` → 6/6 (4-namespace catalogue,
  community visible-refusals + working core, Pro slha kernel incl. TQ3 compress,
  cascade rerank over live content, rsi gates + no-self-modification posture,
  free explains); `mcp_ext` unit tests green across feature combos; default
  build untouched (no premium feature ⇒ module not compiled).
- **P6** ✅ DONE (2026-07-08) — Test suite + CI matrix. `.github/workflows/ci.yml`
  gains the fused profiles folded into the consolidated job: a **byte-identity
  guard** (default `cargo tree` must pull no scirust/octasoma/octacore/rsi),
  `cargo test --features pro-default` (deterministic premium bundle),
  `cargo test --features all-full` (every REPLAY-RELAX kernel), per-member tests
  (`-p scirust -p slha-mcp -p slha-c -p ccos-memory-runtime -p octasoma
  -p octacore -p rsi`), and a community-tier CLI smoke pinning the visible
  refusal (exit 3). Weekly `cargo audit` already runs in `audit.yml`.

### Vendored-source refresh (2026-07-08 audit)

The scirust family was re-based onto SLHAv2 HEAD (`0ba1991`), ingesting the
whole TurboQuant series that had landed upstream after the P1 vendor (PR #52 +
phase-0/1 precursors): the MIXED/TQ3/MIX3 latent codecs + their AVX2/AVX-512/NEON
score paths (`slha_v2.rs` 805→3002 lines), `fit_joint` query-aware projection,
COLD→EventLog persistence (`src/eventlog.rs`, std-only deterministic), the
`slha.compress` codec parameter (slha-mcp), and the llama.cpp Phase-2 codec FFI
bridge (`slha_weights_load`/`slha_encode_key`/`slha_decode_latent`, slha-c). The
P4 hardening was re-applied on top (crate-root `#![deny(unsafe_code)]` with the
two audited allow-zones, `// SAFETY:` justifications, slha-c debug alignment
guard + header ownership contract — updated for the model handle the codec FFI
introduces). `ccos-octasoma`/`ccos-octacore`/`ccos-scirust-python` were verified
in sync (intentional manifest/dep-inversion surgery only). The CCOS base was
caught up with upstream #151 (`ccos.recall` OpenClaw contract + `get`/`sync`
tools). **cervo**: the vendored `ccos-rsi` (CERVO/RSI v0.10.0 engine) remains
the fusion's RSI source; the `memorithm/cervo` scaffold repo has since evolved
into an independent structural fork (own cortex/evolution/pipeline loop, still
no LICENSE file) — per the §A decision it stays excluded; revisit only if it
gains a license and converges with the engine.

## G. Risks & mitigations

1. Circular deps (RSI/octacore `ccos` git dep) → invert, adapters on CCOS side.
2. `replay==live` breakage → DUAL posture + regression gate; `pro-default` excludes full kernels.
3. MSRV 1.89 bump → `workspace.package.rust-version=1.89`; document.
4. `cervo` no-license → drop scaffold, keep only `RSI/` (dual-licensed).
5. RSI subprocess safety → hard sandbox (§D).
6. OctaSoma git→path pin unification → single v0.4.0; optional `scirust-simd/evo` stay off.
7. Module name collisions → crate-level namespacing, no glob re-exports.
8. `scirust` vs `scirust-rsi` → only `ccos-scirust` vendored; `scirust-rsi` dropped.
9. Edition mismatch (2021 vs 2024) → workspace mixes per-crate.
10. Pro-default UX → no-silent-downgrade error with rebuild hint.

## Critical wiring files (target tree)
- `Cargo.toml` — workspace members, feature table, path-dep replacements, MSRV 1.89
- `src/license.rs` — `Feature` enum extension (4 new variants)
- `src/substrate/mod.rs` — `CausalScope`/`Cascade`/`CcosScope` (octacore)
- `src/rsi/{mod,agent_bridge,memory_bridge,audit_bridge,knowledge_bridge,loop_bridge,dgm_bridge}.rs`
- `src/slha_full.rs` — `KvCacheExternalMemory`, `GuardedKvCache`, `ScirustAuditHandler`, `SlhaEncoder`
- `src/event_log.rs` — `EventPayload::RsiMutation`, `EventType::SelfModify`
- `crates/ccos-memory-runtime/src/backend/scirust_full.rs` — `ScirustBackend: MemoryProvider`
- `crates/ccos-rsi/Cargo.toml` + `src/lib.rs` — ccos dep removed, `dgm` gated, octasoma→path
- `crates/ccos-octacore/Cargo.toml` + `src/lib.rs` — ccos dep + `ccos_adapter` removed
- `src/mcp.rs` — multiplex `slha.*`/`octa.*`/`rsi.*`
- `.github/workflows/ci.yml` — 3-profile matrix