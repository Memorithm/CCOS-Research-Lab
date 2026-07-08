# A Geometric Dynamical Model of Recursive Self-Improvement with Stability Guarantees

**Version 0.9 — RSI working paper**

---

## Abstract

We present a unified geometric formulation of *recursive self-improvement*
(RSI) for a cognitive agent, together with a self-contained, dependency-free
Rust implementation. The model represents an agent's competence as a
**surface of intelligence** `Σ_I(t)`, a graph over a probability space of
tasks `(Ω, 𝒜, μ)`. The agent's competence on each task is the minimum of a
*cognitive* term `Φ_x(S)` — a function of an extended cognitive state vector
`S = (D, M, R, A, C, V)` — and a *physical* ceiling `g_x(P_eff)` set by a
multiplicative hardware/software substrate. A continuous dynamical law evolves
`S` under three driving terms (learning, exploration, substrate uplift) and a
dissipative penalty, subject to two stability safeguards: a bounded step
`‖ΔS‖ < λ` and a non-regression guarantee `SI_global(t+1) ≥ SI_global(t) − ε`.
A recursive meta-revision `ℳ_{t+1} = argmax_ℳ SI_global(ℳ(S_t))` lets the agent
improve *the way it improves*, including rewriting its own software substrate.
We prove (by construction and verify empirically) that the global intelligence
functional is monotone within tolerance, and we show experimentally that the
system converges to a **substrate-limited attractor**: competence saturates
the cognitive dimension first, after which the physical substrate becomes the
binding constraint. We discuss the model as a sandbox for studying RSI safety
properties — in particular, how hard stability constraints prevent runaway
divergence while still permitting large competence gains (+360–440% in our
runs).

---

## 1. Introduction

Recursive self-improvement — an agent that improves not only its competence but
the very process by which it becomes more competent — is central to debates on
advanced AI. Most treatments are either informal or restricted to narrow
optimization loops. This paper offers a compact, fully specified **dynamical
systems** model that (i) makes the geometry of an agent's competence explicit,
(ii) couples cognition to a physical substrate via a multiplicative efficiency
term, and (iii) embeds the recursive meta-loop under explicit stability
safeguards.

Our contributions are:

1. A **geometric formalization** of competence as a deformable surface
   `Σ_I(t)` over a task space, with a scalar functional `SI_global(t)` (the
   volume under the surface) as the global objective.
2. A **continuous-time dynamics** for the extended cognitive state with three
   interpretable driving terms and a dissipative penalty, discretized under two
   stability constraints.
3. A **recursive meta-optimizer** that selects the self-modification policy
   maximizing projected global intelligence, including self-rewrite of the
   software substrate.
4. A **reference implementation** in dependency-free Rust, with two meta-search
   back-ends (random neighborhood search and separable CMA-ES), JSON/CSV
   trajectory export, a Model Context Protocol (MCP) server, and an
   auto-registration mechanism for autonomous agent runtimes.

---

## 2. The model

### 2.1 Surface of intelligence (§1)

Let `(Ω, 𝒜, μ)` be a probability space of tasks/contexts. The **surface of
intelligence** at time `t` is the graph

```
Σ_I(t) = { (x, C_real(x, t)) : x ∈ Ω } ⊂ Ω × [0, 1],
```

where the **real competence** on task `x` is the bottleneck

```
C_real(x, t) = min( Φ_x(S(t)),  g_x(P_eff) ).
```

`Φ_x(S)` is the *cognitive* competence (what the agent knows how to do) and
`g_x(P_eff)` is the *physical ceiling* imposed by the substrate (what the
hardware/software permits). The **global intelligence** is the volume under the
surface,

```
SI_global(t) = ∫_Ω C_real(x, t) dμ(x),
```

estimated by a fixed Monte-Carlo sample `{x_i} ~ μ` with weights `w_i`. Using a
*fixed* sample makes `SI_global` comparable across steps — essential for the
non-regression safeguard (§2.4) and the meta-`argmax` (§2.5).

In the reference implementation, each task `x` is a profile of demands over the
six cognitive components (a Dirichlet draw), `Φ_x(S) = σ((⟨x, caps(S)⟩ − b)·k)`
is a shifted logistic of the projection of capabilities onto task demands, and
`g_x(P_eff) = P_eff^{demand(x)}` so that heavier tasks are throttled more by a
weak substrate. Both `Φ` and `g` are pluggable via traits.

### 2.2 Extended cognitive state (§2)

The agent state is the six-tuple

```
S = (D, M, R, A, C, V),
```

with `D` knowledge, `M` model (parameters + architecture), `R` reasoning,
`A` autonomy, `C` context memory, `V` values/goals. Each component is a real
vector; the concatenation is the flat state manipulated by the dynamics.

### 2.3 Physical & software substrate (§3)

Let `H ∈ ℝ^{n_H}` (hardware) and `O ∈ ℝ^{n_O}` (software). The **effective
power** is *multiplicative*:

```
P_eff = σ(Hᵀ A H) · σ(Oᵀ B O) · σ(Hᵀ C O),     σ(x) = 1/(1 + e^{−x}),
```

with `A, B` internal-efficiency matrices and `C` the hardware↔software coupling.
Multiplicativity encodes the intuition that powerful hardware is useless without
software able to exploit it; the coupling term `σ(Hᵀ C O)` captures HW/SW
synergy. `P_eff ∈ (0, 1)`.

### 2.4 Continuous dynamics with stability constraints (§4)

The state evolves according to

```
dS/dt = η(S, H, O) · [ L(D) + E(A, V) + U(H, O) ] − P(S),
```

where:

- `η(S, H, O)` is an effective learning rate, increasing in `P_eff` and context
  memory `C`, decreasing as competences saturate;
- `L(D)` is learning drawn from knowledge (feeds `D, M, R`);
- `E(A, V)` is exploration driven by autonomy and *aligned* by values (the
  product `A·V` ensures autonomy without values yields no useful exploration);
- `U(H, O)` is the uplift contributed by the substrate (feeds `M, D`);
- `P(S)` is a dissipative penalty (forgetting / maintenance cost), proportional
  to the current state.

At the discrete step, two **stability safeguards** apply:

```
(C1)  ‖ΔS‖ < λ                          (bounded step)
(C2)  SI_global(t+1) ≥ SI_global(t) − ε  (non-regression)
```

`(C1)` is enforced by radial projection of the raw step; `(C2)` by a
backtracking line search that shrinks the step until the global objective does
not regress beyond `ε` (and, in the limit, holds the state in place). Together
they prevent runaway divergence while still permitting monotone improvement.

### 2.5 Discrete loop and recursive meta-function (§5–§6)

The discrete update couples a self-modification proposal `ℳ` with the learning
increment:

```
S_{t+1}  = S_t + ℳ(S_t, V_t, H, O) + ΔS_appr,
ℳ_{t+1}  = argmax_ℳ  SI_global( ℳ(S_t) ).      (meta-revision)
```

`ℳ` is a *self-modification policy*: it allocates improvement effort across the
six components (`focus`), and rewrites the software substrate `O` (bounded by
autonomy `A` and aligned by values `V`). The meta-revision searches a
neighborhood of policies and keeps the one maximizing the *projected*
`SI_global` — never returning a policy worse than the current one. This is the
recursive core: the agent improves the procedure that improves it.

The compact "wave equation" of the surface (§6) summarizes one step:

```
Σ_I(t+1) = Σ_I(t) + η · ℳ(Σ_I, S, H, O, V) − P.
```

---

## 3. Implementation

The model is implemented in ~2,000 lines of **dependency-free Rust** (standard
library only, including a `xoshiro256**` PRNG and a small dense-matrix module).
Modules map one-to-one to the equations:

| Module          | Equation set | Contents |
|-----------------|--------------|----------|
| `surface.rs`    | §1           | `Σ_I`, `C_real`, `SI_global`, pluggable `Φ`/`g` traits |
| `state.rs`      | §2           | `S = (D,M,R,A,C,V)`, flatten/reconstruct |
| `substrate.rs`  | §3           | `P_eff` with SPD efficiency matrices |
| `dynamics.rs`   | §4           | `dS/dt`, constrained step (projection + line search) |
| `meta.rs`       | §5           | `MetaStrategy`, `MetaSearch` trait, random + CMA-ES |
| `cma.rs`        | §5           | separable CMA-ES (diagonal covariance) |
| `agent.rs`      | §5–§6        | discrete RSI loop |

Two meta-search back-ends implement the `MetaSearch` trait: a **random
neighborhood search** and a **separable CMA-ES** (Ros & Hansen, 2008) — a
diagonal-covariance evolution strategy that avoids any eigendecomposition,
keeping the build dependency-free. Trajectories export to CSV/JSON. An MCP
server (`rsi-mcp`) exposes the system as tools for LLM agents, and `rsi-connect`
auto-registers it with agent runtimes.

All invariants of §2.4 are checked by an automated test suite (34 tests):
`‖ΔS‖ ≤ λ` and `SI_global(t+1) ≥ SI_global(t) − ε` are asserted at every step
of long trajectories; the separable CMA-ES is validated against a quadratic
objective; the JSON parser/serializer round-trips; and the API/MCP layers are
exercised end-to-end.

---

## 4. Experiments

We run the reference agent for 150 discrete steps with `|Ω| = 1024` tasks,
six-dimensional components, a 4×4 hardware/software substrate, `λ = 0.5`,
`ε = 10⁻³`. We compare the two meta-search back-ends across five random seeds.

### 4.1 Global trajectory

A representative run (seed 2026, random search) over 120 steps:

| t | SI_global | P_eff | ‖ΔS‖ | % substrate-limited | capabilities (D M R A C V) |
|---|-----------|-------|------|---------------------|----------------------------|
| 1 | 0.141 | 0.156 | 0.009 | 0% | 0.02 0.04 0.05 0.06 0.04 0.08 |
| 21 | 0.280 | 0.168 | 0.027 | 50% | 0.64 0.21 0.24 0.26 0.17 0.39 |
| 46 | 0.494 | 0.311 | 0.085 | 100% | 0.99 0.73 0.96 0.93 0.70 0.92 |
| 120 | 0.676 | 0.530 | 0.103 | 100% | 0.98 0.88 0.95 0.94 0.98 0.98 |

`SI_global` rises from 0.139 to 0.676 (**+388%**). Crucially, the
**bottleneck migrates**: early on, no task is substrate-limited (competence is
gated by cognition); by step ~46 *every* task is substrate-limited. This is the
signature of an agent that has saturated its cognitive dimension and is now
bound by its physical substrate — at which point the self-rewrite of `O` (which
raises `P_eff` from 0.156 to 0.530) becomes the only avenue for further gains.

### 4.2 Cross-seed summary

Final `SI_global` and convergence metrics over 150 steps:

| seed | SI_end | t@90% | t@99% | mean SI (AUC) |
|------|--------|-------|-------|---------------|
| 1    | 0.714  | 39–40 | 44–46 | 0.616–0.629 |
| 42   | 0.772  | 39–57 | 45–64 | 0.640–0.659 |
| 2026 | 0.676  | 45–60 | 51–78 | 0.553–0.581 |
| 9001 | 0.689  | 34–44 | 39–50 | 0.594–0.606 |

### 4.3 Attractor and the role of the meta-optimizer

Across all seeds, **both meta-search back-ends converge to the identical final
`SI_global`** (and `P_eff`). The system possesses a **substrate-limited
attractor**: a stable equilibrium set by the substrate ceiling that both search
strategies reach. The choice of meta-optimizer affects only the *transient*
(time-to-threshold and area under the curve), and neither dominates across
seeds — separable CMA-ES converges faster on seeds 1 and 2026, random search on
seeds 42 and 9001. In other words, in this model the *existence and location* of
the improvement ceiling is a property of the substrate and the stability
constraints, not of the search heuristic.

---

## 5. Discussion

**Stability vs. capability.** The two safeguards `(C1)`–`(C2)` are the
load-bearing safety mechanism. `(C2)` makes `SI_global` monotone within `ε`, so
the agent never trades a large competence loss for a speculative gain; `(C1)`
caps per-step change, preventing discontinuous jumps. Yet within these limits
the agent still achieves +360–440% competence gains, illustrating that hard
non-regression constraints are compatible with rapid improvement.

**Substrate as the binding constraint.** The migration of the bottleneck from
cognition to substrate is a robust, seed-independent phenomenon. It suggests
that, in a balanced agent, *sustained* recursive improvement eventually depends
on improving the physical/computational substrate — the cognitive dimension
saturates first. The multiplicative form of `P_eff` makes the substrate a
genuine ceiling rather than an additive contributor.

**Recursion without divergence.** Because the meta-revision optimizes the *same*
fixed functional `SI_global` that the safeguards protect, the recursive loop
inherits the stability guarantees. There is no separate, unconstrained
meta-objective that could be gamed.

---

## 6. Limitations and future work

- The task space `Ω`, the competence model `Φ_x`, and the ceiling `g_x` are
  stylized; richer, learned task distributions would test generality (the
  trait-based design already supports swapping them).
- The substrate self-rewrite is constrained to the software vector `O`; a fuller
  model would let `ℳ` edit `A`, `B`, `C` and the hardware `H`.
- `SI_global` is a Monte-Carlo estimate; very small `ε` interacts with sampling
  noise and would benefit from variance reduction or common random numbers.
- The attractor analysis is empirical; a formal characterization of the
  equilibrium set and its dependence on `(A, B, C)` is open.

---

## 7. Failure modes and criticality (FMECA)

Because recursive self-improvement *amplifies* failures, a safety-critical RSI
model needs more than the pointwise safeguards of §2.4: it needs an explicit
theory of failure modes, their **criticality**, and a **risk-adjusted**
objective.

For each failure mode `f` we score three factors in `[0,1]` — severity `S_f`,
occurrence `O_f` (a function of the live signals), and detection difficulty
`D_f` — and form the Risk Priority Number

```
RPN_f = S_f · O_f · D_f.
```

The principal RSI failure modes, with state-dependent occurrence and the
mechanism that detects them:

| Mode | Occurrence | Detector |
|------|-----------|----------|
| competence regression | `−ΔSI / ε` | ε safeguard |
| instability / divergence | `‖ΔS‖ / λ` | λ safeguard |
| value drift | `A − V` | (FMECA) |
| substrate collapse | `(1 − P_eff)·frac_substrate` | bottleneck |
| Goodhart / overfitting | `backtracks / 5` | line search |
| memory poisoning | base, if memory active | (CCOS, future) |
| wireheading | `max(0, measured − analytic)` | Forge `verify` |

Aggregating, `Risk_global(t) = mean_f RPN_f`, and the **risk-adjusted
intelligence** is

```
SI_safe(t) = SI_global(t) − κ · Risk_global(t).
```

The meta-revision can then optimize `SI_safe` instead of `SI_global`, subject to
a **criticality safeguard** `max_f RPN_f < RPN_max` (when violated, the agent
takes a conservative step by damping the gain of `ℳ`). The λ/ε safeguards of
§2.4 are recovered as special cases (the regression and instability modes), so
FMECA *subsumes and generalizes* the original stability theory. Operationally,
the most-critical mode drives **criticality routing** (a generalization of the
bottleneck routing of §4): improvement effort is allocated where the criticality
is highest. CCOS, with its hash-chained event log and deterministic replay, is
the natural detector/forensics layer raising detectability for the hardest modes
(memory poisoning, wireheading).

---

## 8. Conclusion

We gave a compact, fully specified geometric model of recursive
self-improvement in which an agent's competence surface deforms under learning,
a multiplicative substrate, and a recursive meta-optimizer, all under explicit
stability safeguards. The accompanying dependency-free implementation makes the
model executable, inspectable, and directly drivable by autonomous LLM agents
via MCP. Empirically, the system improves rapidly yet provably never regresses
beyond tolerance, and converges to a substrate-limited attractor — a concrete,
reproducible illustration of how stability constraints shape the trajectory and
the ceiling of recursive self-improvement.

---

## Reproducibility

```bash
cargo test                                   # 34 tests (invariants incl.)
cargo run --release --bin rsi-demo -- 120 2026 random
cargo run --release --bin rsi-demo -- 150 42 cma --csv traj.csv --json traj.json
```

All runs are deterministic given the seed. Source:
`src/{surface,state,substrate,dynamics,meta,cma,agent}.rs`.

## References

- N. Hansen, *The CMA Evolution Strategy: A Tutorial*, 2016.
- R. Ros, N. Hansen, *A Simple Modification in CMA-ES Achieving Linear Time and
  Space Complexity* (separable CMA-ES), PPSN 2008.
- Model Context Protocol specification, 2024.
