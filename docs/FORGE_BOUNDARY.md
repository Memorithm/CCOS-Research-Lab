# Forge Boundary

## What Forge is here

`crates/forge/forge-core` (+ `forge-bridge`, `forge-cli`): candidate
generation, mutation, evaluation and patch-promotion machinery used by the
RSI/DGM stack (the `forge` feature of the `rsi` crate).

## Hard boundaries

1. **Forge is Research-Lab-only.** CCOS Core and CCOS Enterprise forbid
   `forge-core`/`forge-bridge`/`forge-cli` by name in their dependency graphs
   (CI guardrail).
2. **Candidate execution is sandboxed and fail-closed** (`ccos-sandbox`;
   PR #12/#13 hardening: unified fail-closed generated-code execution,
   elite injection tests).
3. **No promotion without the gate** (PATCH_PROMOTION_POLICY.md,
   HUMAN_APPROVAL_GATE.md).
4. **Forge output is data, not authority**: a produced patch is a *proposal*
   — it gains effect only through the promotion path or, for Core-bound
   ideas, through EXPERIMENT_TO_CORE_PROMOTION.md.
