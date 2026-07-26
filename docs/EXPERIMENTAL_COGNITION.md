# Experimental Cognition

Experimental cognitive mechanisms that live here — and ONLY here until
promoted (EXPERIMENT_TO_CORE_PROMOTION.md):

| Mechanism | Where | Status |
|---|---|---|
| Advanced / hierarchical Q-Page variants | hub + `octacore` cascade | experimental |
| Content-addressed embedding cache | `src/embed_cache.rs` | validated locally (tests green); promotion candidate |
| OctaSoma fractal memory (vendored) | `crates/ccos-octasoma` | experimental |
| OctaCore cascade (causal-narrow → semantic-rerank) | `crates/ccos-octacore` | experimental |
| SLHAv2 full kernel (SIMD, elastic KV cache) | `crates/ccos-scirust`, `src/slha_full.rs` | REPLAY-RELAX, license-gated |
| RSI agent + DGM self-improvement loop | `crates/ccos-rsi`, `src/rsi_bridge.rs` | sandboxed, approval-gated |
| Premium MCP namespaces (`slha.*`, `octa.*`, `rsi.*`) | `src/mcp_ext.rs` | read-only status/docs by default |
| Experimental causality / metacognition / adaptive planning | various | exploratory |

## Rules

- Every experimental mechanism documents its determinism posture (see
  DETERMINISM.md relaxations) and its safety posture (EXPERIMENT_SAFETY.md).
- An experimental result is never evidence for a Core claim (§6 charter).
- Negative results are preserved (NEGATIVE_RESULTS_POLICY.md).
