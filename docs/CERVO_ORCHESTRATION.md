# CERVO → CCOS Research Lab: orchestration boundary

## Status

This document records the first production-facing extraction from the former
`Memorithm/cervo` concept bench.  CERVO remains useful as an architectural
prototype, but its original RSI objective, memory and sandbox are **not** copied
into the certifiable CCOS core.

The reusable idea is the control plane:

- long-lived cognitive units;
- health exchange;
- deterministic supervision;
- horizontal transfer of a better strategy;
- explicit lifecycle events.

The implementation starts in `crates/ccos-rsi/src/orchestrator.rs` because this
is an experimental RSI capability and therefore belongs in CCOS Research Lab,
not CCOS Core.

## Boundary

```text
CCOS Core
  deterministic memory / provenance / event log
                    ^
                    | next: mirror canonical swarm audit
                    |
CCOS Research Lab
  SwarmAuditLog (portable SHA-256 chain)
                    ^
                    |
  CervoOrchestrator
      |      |      |
      v      v      v
   RSIAgent RSIAgent RSIAgent
      |      |      |
      +------+------+
             |
       candidate/evaluator
             |
        ccos-sandbox
```

`CervoOrchestrator` is deliberately transport-neutral and std-only.  It does
not execute generated code and it does not implement a security sandbox.
Anything that evaluates generated code must cross `ccos-sandbox` (or an
equivalent fail-closed host boundary) before promotion.

## Determinism changes versus CERVO

The original prototype used UUID v4, `thread_rng()` and broadcast scheduling.
The extracted control plane instead uses:

- caller-supplied `UnitId(u64)`;
- `BTreeMap` unit ordering;
- a monotone logical `seq` for every swarm event;
- the seeded deterministic `RSIAgent` implementation already present in RSI;
- stable tie-breaking by the smallest `UnitId`.

The same seeds, unit IDs and configuration therefore reproduce the same control
plane event stream.

## Ranking and horizontal transfer

CERVO's shared `EvolutionTracker` mixed local and peer accounting and could
multiply a physical mutation when reports were aggregated.  The new
orchestrator owns `total_steps` and `total_adoptions`; one `RSIAgent::step()`
adds exactly one physical step.

Peer ranking uses the existing RSI safety-adjusted objective `SI_safe` rather
than CERVO's success ratio.  A source strategy is not copied merely because its
source scored higher.  Transfer requires all of the following:

1. source `SI_safe` exceeds target `SI_safe` by `adoption_margin`;
2. source risk is within `risk_slack` and below `max_source_rpn`;
3. the strategy has a compatible software-edit dimension;
4. applying that strategy to the **target's own** state has projected
   `SI_global >= current + min_projected_gain`.

Only the `MetaStrategy` is transferred.  State, memory, audit state and
substrate measurements are not overwritten.

## Swarm protocol P1

The logical protocol currently records:

- `Health`;
- `StrategyOffer`;
- `StrategyAdopted`;
- `StrategyRejected` with an explicit reason;
- `Shutdown`.

Each message is wrapped in a `SwarmEvent { seq, message }`.  The event journal
is intentionally transport-neutral so later phases may carry the same messages
over Tokio actors or process/network transports without making scheduling order
part of the decision semantics.

`strategy_digest()` is only a compact deterministic observability fingerprint.
It is **not** a security digest.

## Portable hash-chain audit implemented

`orchestrator_audit.rs` adds `SwarmAuditLog`. It incrementally consumes
`SwarmEvent`s and seals their canonical payloads into RSI's std-only SHA-256
`HashChainLog` under event type `rsi_swarm`.

Important properties:

- duplicate synchronization is idempotent;
- missing/reordered logical sequence numbers fail closed;
- the same swarm replay produces the same chain head;
- the chain is independently integrity-verifiable;
- `to_ccos_json()` already provides the portable CCOS-ingestable representation.

`HashChainLog::record_custom()` was added so control-plane events can share the
same link-hash contract as RSI step events without widening the `AuditLog` trait
or introducing a dependency on CCOS.

This portable chain is **not a replacement for CCOS `EventLog`**. The next
bridge mirrors the same canonical `rsi_swarm` payloads into the CCOS-side log,
where product-wide provenance and replay live.

## Tests introduced

The modules assert:

- duplicate IDs are rejected;
- physical RSI steps are counted exactly once;
- event sequences are monotone and gap-free;
- identical seeds/topology replay the same control-plane stream;
- exact score ties use stable unit-ID ordering;
- unit shutdown is observable;
- strategy fingerprints are deterministic and sensitive to changes;
- custom events share RSI's SHA-256 hash-chain contract;
- swarm audit synchronization is incremental;
- sequence gaps fail closed;
- identical swarm replay produces an identical audit head.

## Next phases

### P2 — CCOS EventLog mirror

Mirror every canonical `rsi_swarm` payload into the existing CCOS-side
hash-chained `EventLog`, without adding a dependency from `rsi` back to CCOS.
The portable `SwarmAuditLog` remains the deterministic producer-side proof.

### P3 — guarded candidate evaluation

Add an orchestration adapter for DGM/Forge/SciRust candidates.  Generated code
must be evaluated through `ccos-sandbox`; the orchestrator receives only a
sealed evaluation result and never executes candidate code itself.

### P4 — memory integration

Use CCOS/OctaSoma as shared/semantic memory providers.  Do not port CERVO's
payload-equality active/long-term memory.

### P5 — transport

Add a Tokio actor transport as an optional outer layer.  Message processing
must feed the same deterministic reducer so replay decisions do not depend on
wall-clock arrival order.

### P6 — COGNO-1 proposal adapter

CERVO-derived orchestration may fan out candidate proposals, but COGNO-1 hard
gates remain the sole authority for promotion, persistence and tool effects.