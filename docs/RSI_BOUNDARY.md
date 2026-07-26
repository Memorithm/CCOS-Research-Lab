# RSI Boundary

## What RSI is here

`crates/ccos-rsi` (package `rsi`): a recursive self-improvement research
stack — deterministic agent core, DGM loop with sandboxed evaluation, optional
local LLM proposers. Every step is audit-journaled (`CcosAudit` over the
hash-chained event log).

## Hard boundaries

1. **RSI never runs in CCOS Core or CCOS Enterprise.** Those products contain
   no `rsi`/`forge` code, dependency, feature, MCP namespace, or test
   (enforced there by `scripts/check-no-research-components.sh`).
2. **RSI execution is license-gated and approval-gated** here
   (`Feature::RsiSelfImprovement`, `Feature::RsiDgm`; HUMAN_APPROVAL_GATE.md).
3. **The `rsi.*` MCP namespace is status-and-documentation only** in the
   default posture; live runs go through the guarded CLI/API, never through
   an unauthenticated server (§31 of the charter).
4. **No self-modification of this repository by RSI itself** without the
   promotion path (PATCH_PROMOTION_POLICY.md): allowlist + sandbox + human
   approval + journaled `GraphMutation`.
5. **Air-gap**: evaluators run `cargo --offline --frozen` with
   `CARGO_NET_OFFLINE=true`.
