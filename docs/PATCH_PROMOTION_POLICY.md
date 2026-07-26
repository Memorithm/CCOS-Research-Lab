# Patch Promotion Policy

Promotion means: a generated patch leaves the sandbox and touches a live tree.

## Rules

1. **Single writer.** `promote_to_live` (see `src/rsi_bridge.rs`, `GuardedDgm`)
   is the only path. There is no other live-tree writer.
2. **Double allowlist check.** The editable-file allowlist is checked at the
   proposer AND re-checked at promotion time.
3. **Recorded.** Every promotion writes a `GraphMutation` event into the
   hash-chained journal — tamper-evident, replayable.
4. **Atomic.** A promotion applies completely or not at all; the CI
   `atomic-promotion` test covers partial-failure rollback.
5. **Gated.** Promotion requires the human approval gate
   (HUMAN_APPROVAL_GATE.md). An unattended promotion is a security incident.
6. **Never cross-product.** Research Lab patches never target CCOS Core or
   CCOS Enterprise trees. For candidate improvements to Core, see
   EXPERIMENT_TO_CORE_PROMOTION.md (pull request + full Core CI + owner
   approval).
