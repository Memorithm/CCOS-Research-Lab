# Experiment Safety

## Absolute rules

1. **Never execute an untrusted candidate on a runner containing** API keys,
   GitHub write tokens, SSH keys, Docker socket access, production
   repositories, or Enterprise secrets (§42 of the product charter).
2. **Fail-closed everywhere.** Generated-code execution goes through
   `ccos-sandbox` only; a sandbox failure denies execution (PR #13:
   "unify fail-closed generated code execution").
3. **Air-gap by default.** Evaluators pin `cargo --offline --frozen`
   (`CARGO_NET_OFFLINE=true`); network egress during a build/test cycle is
   refused (see `src/rsi_bridge.rs`, `GuardedCargoEvaluator`).
4. **Editable-file allowlist.** A patch targeting a non-allowlisted file is
   refused *before* any evaluation, and again before any promotion.
5. **Human approval gate.** No patch is promoted to a live tree without the
   recorded human approval flow (HUMAN_APPROVAL_GATE.md).
6. **No automatic cross-product effects.** Research Lab may only: generate a
   proposal, generate a patch, run isolated tests, produce a report, and
   prepare a pull request after human approval (§28).

## Runner checklist (CI)

See `.github/workflows/security.yml`: sandbox tests, no-network tests,
no-secret tests, timeout tests, descendant-process termination, memory/CPU/
process/output limits, symlink and path-traversal tests, evaluator- and
test-modification detection, Docker/SSH access denial, exfiltration tests,
atomic-promotion tests.
