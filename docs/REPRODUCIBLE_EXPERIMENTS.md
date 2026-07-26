# Reproducible Experiments

## Minimum standard

An experiment is reportable only with:

1. **exact commit** of this repository (and of `ccos-core` when depended on);
2. **toolchain** (`rust-toolchain.toml`) and feature set;
3. **seed(s)** for every randomized component;
4. **model identity + version** for every LLM-backed step (and provider);
5. **dataset / corpus identity** (hash when possible);
6. **environment** (OS, arch, sandbox backend);
7. **raw outputs** retained under version control or content-addressed storage.

## Determinism classes

| Class | Meaning | Examples |
|---|---|---|
| D0 | bit-reproducible offline | hub default build, replay vectors |
| D1 | reproducible modulo documented relax | slhav2-full SIMD accumulation order |
| D2 | stochastic, seed-recorded | LLM proposer runs, mutation searches |
| D3 | non-reproducible (exploratory) | live external services |

Classes D1–D3 must say so in their report header. A D2/D3 result can motivate
a Core promotion only after a D0 replication of the underlying mechanism
(EXPERIMENT_TO_CORE_PROMOTION.md).

## Canonical replay

Use `scripts/benchmark_repro.sh` and `src/bin/ccos-bench-repro.rs`; results go
to `benchmark-results/<commit>-cycles-N/` (git-ignored artifacts — regenerate,
never migrate).
