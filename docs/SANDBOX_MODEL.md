# Sandbox Model

(Complements the historical `SANDBOX.md` with the current, post-hardening model.)

## Layers

| Layer | Mechanism |
|---|---|
| Proposer-side | editable-file allowlist enforced at the proposer — a patch to a non-allowlisted target never reaches evaluation |
| Evaluation | `rsi::WorkspaceSnapshot` — isolated temp copy, `Drop`-cleaned, bounded time + bounded output |
| Evaluator | `GuardedCargoEvaluator`: `cargo --offline --frozen`, `CARGO_NET_OFFLINE=true` (air-gap) |
| OS confinement | `ccos-sandbox`: OS-level restrictions for generated-code execution (fail-closed; bubblewrap where available) |
| Audit | every evaluated step recorded in the hash-chained `EventLog`; every accepted patch promotion records a `GraphMutation` event |
| Promotion | `promote_to_live` is the single live-tree writer; re-checks the allowlist; requires the human approval gate |

## Guarantees and non-guarantees

Guaranteed: no execution of non-allowlisted code paths; no silent mutation;
auditable steps; bounded resources.

**Not** guaranteed: hardware/kernel-level isolation strength of a production
sandbox. This is a research sandbox — treat every candidate as hostile, and
run it only on throwaway infrastructure (EXPERIMENT_SAFETY.md rule 1).
