# Research Scope

⚠️ Experimental research environment — outside the certifiable CCOS Core and
CCOS Enterprise product boundary. / Environnement de recherche expérimental —
hors du périmètre certifiable de CCOS Core et CCOS Enterprise.

## In scope

- **RSI** (`crates/ccos-rsi`, package `rsi`): recursive self-improvement —
  deterministic std-only agent core, DGM (Darwin–Gödel Machine) loop, LLM
  proposers (local only).
- **Forge** (`crates/forge/forge-core`, `-bridge`, `-cli`): candidate
  generation, mutation, evaluation and patch promotion machinery.
- **Sandbox** (`crates/ccos-sandbox`): OS-level confinement for generated-code
  execution (fail-closed).
- **scirust / SLHAv2** (`crates/ccos-scirust` + `-mcp`, `-c`, `-python`):
  real SIMD kernels — REPLAY-RELAX, documented in DETERMINISM.md.
- **OctaSoma / OctaCore** (`crates/ccos-octasoma`, `crates/ccos-octacore`):
  fractal memory and the causal-narrow → semantic-rerank cascade.
- **Experimental cognition**: embed cache, fusion MCP namespaces
  (`slha.*`, `octa.*`, `rsi.*`), advanced Q-Page variants.
- **Benchmarks, simulators, evaluators**, adversarial suites.

## Out of scope (by construction)

- Any guarantee of stability, determinism, or certifiability.
- Any automatic promotion of changes into CCOS Core or CCOS Enterprise
  (see EXPERIMENT_TO_CORE_PROMOTION.md — human approval only).
- Any claim that results here evidence Core/Enterprise properties (§6 of the
  product charter).

## Relationship to Core

The hub crate (`ccos-research-lab`) currently vendors the full CCOS 0.3-era
core. Progressively, stable capabilities will be consumed from
`ccos-core` (exact `rev` dependency) instead of the vendored copy, keeping
here only the experimental extensions (compatibility-tested at each step).
