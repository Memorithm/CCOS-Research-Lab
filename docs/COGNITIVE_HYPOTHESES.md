# Cognitive Hypotheses (Research Lab)

The canonical hypothesis registry is maintained in **CCOS Core**:
`docs/research/CCOS_COGNITIVE_HYPOTHESES.md` (H1–H7, protocol v0.1).

## Research Lab role

- Research Lab may explore **additional, experimental** hypotheses (H-X
  series below) and may attempt to **refute** H1–H7. Refutations are first-
  class results (NEGATIVE_RESULTS_POLICY.md).
- Research Lab results are **never** evidence for Core/Enterprise claims
  (§6 charter). A H1–H7 evaluation here is marked `research-only` and must be
  replicated inside Core's boundary to count for Core.

## Experimental hypotheses (H-X series)

| ID | Hypothesis | Status |
|---|---|---|
| H-X1 | The OctaCore cascade (causal-narrow → semantic-rerank) improves precision at fixed latency vs single-stage retrieval | exploratory |
| H-X2 | The content-addressed embedding cache preserves ranking exactly while reducing embedder calls | locally validated (tests green); pending promotion review |
| H-X3 | Sandboxed DGM iterations can improve a bounded objective on allowlisted code without sandbox violations | exploratory, safety-gated |

Classifications follow the same scale: confirmed · partially confirmed ·
not confirmed · refuted.
