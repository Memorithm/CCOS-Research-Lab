# Candidate Execution Protocol v1

> Experimental Research-Lab contract. This protocol is intentionally outside
> the certifiable CCOS Core boundary.

## Purpose

The candidate protocol closes the evidence path between proposal engines
(Forge/RSI), the fail-closed generated-code sandbox, SciRust execution evidence,
promotion policy, and CCOS's primary hash-chained `EventLog`.

```text
Forge / RSI / external proposer
          |
          v
 CandidateEnvelope
          |
          v
 SealedCandidateEvaluator
          |
          v
    ccos-sandbox
          |
          +---- optional verified SciRust ExecutionAttestation fingerprint
          |
          v
 EvaluationReceipt
          |
          v
 ChampionChallengerPolicy
          |
          v
  AdoptionReceipt
          |
          v
 CCOS primary EventLog
```

The LLM/proposer is never the authority for a score or a promotion. Executed
and verified evidence is the authority, and a promotion is a separate policy
decision bound to one exact evaluation receipt.

## CandidateEnvelope

`rsi::CandidateEnvelope` is the portable proposal identity.

The stable `candidate_id` is content-addressed from:

- origin (`Forge`, `Rsi`, `SciRust`, or `External`);
- domain;
- SHA-256 of the candidate source/representation.

The envelope fingerprint additionally binds the trial seed, producer-native id,
parent identity, and optional proposal digest. This separation means the same
source retains one content identity while two experimental trials remain distinct
receipts.

## EvaluationReceipt

A sealed evaluation receipt binds:

- the exact candidate-envelope fingerprint;
- evaluator semantic id;
- sandbox-policy semantic id;
- trial seed;
- typed objectives and optimization direction;
- stdout/stderr content hashes;
- timeout and output-truncation state;
- optional verifier digest;
- optional SciRust architecture-neutral execution-profile fingerprint.

Fitness values must be finite. A failed candidate or infrastructure failure
carries no fitness objectives. This prevents an execution failure from being
mistaken for a very good score.

### SciRust boundary

`execution_profile_sha256` is deliberately an opaque digest in Research-Lab.
Its semantic source of truth is **SciRust `ExecutionAttestation v1`**, not a
second locally invented hardware schema.

SciRust's v1 execution profile binds backend/device, architecture family,
capability/topology fingerprints, caller memory budget, numeric mode,
reproducibility level, kernel/sampler semantic versions, model digest, and
tokenizer digest. Research-Lab requires only the verified canonical profile
fingerprint in the candidate receipt.

The public SciRust golden v1 profile fingerprint currently used by its protocol
test is:

```text
f0423da9a3c6c2e43f6e75acd4cd017bd020a0f21d65112a73d1076026c10826
```

That golden value is an interoperability test vector, not a trusted-machine id.
The digest detects mutation but is not itself a digital signature. Producer
authenticity remains a transport/identity concern.

## Sandbox boundary

`rsi::SandboxCandidateEvaluator` is the concrete implementation of
`SealedCandidateEvaluator` for a `ccos-sandbox` runner and a trusted harness.

It validates the candidate before execution, delegates execution only to the
sandbox runner, and validates the resulting receipt before releasing it to CCOS.
There is no direct-process fallback.

For generated candidates the higher-level evaluator additionally requires
`NetworkPolicy::Deny`. A harness requesting loopback/network access is rejected
before execution.

The Linux Bubblewrap backend applies requested address-space, file-size,
process-count, and CPU-time limits via `prlimit(1)` inside the sandbox. If a
resource ceiling is requested but `prlimit` is unavailable, execution fails
closed rather than silently dropping the limit.

## AdoptionReceipt

Promotion is a separate receipt bound to the exact evaluation fingerprint.

`Promote` is invalid unless:

- the referenced evaluation succeeded;
- the promoted artifact has a content SHA-256;
- the adoption receipt passes protocol validation.

Reject and quarantine decisions remain auditable without fabricating a promoted
artifact.

## Champion / Challenger v1

`ChampionChallengerPolicy` compares two successful receipts only when they were
measured under the same:

- evaluator id;
- sandbox policy id;
- SciRust execution-profile fingerprint;
- verifier fingerprint;
- objective names and optimization directions.

The policy has two explicit thresholds:

- minimum relative improvement on the primary objective;
- maximum tolerated relative regression on each secondary objective.

This is the first policy, not the final statistical promotion gate. Future
versions should add repeated seeds, confidence intervals, holdouts,
cross-hardware evidence, and regression suites without weakening the v1
comparability requirements.

## CCOS audit mirror

`CcosCandidateAudit` owns the CCOS-side dependency inversion. RSI never depends
on CCOS.

The mirror records, in order:

1. `candidate_envelope_v1`;
2. `candidate_evaluation_v1`;
3. `candidate_adoption_v1`.

Every transition is validated before the primary EventLog is mutated. Evaluation
before candidate, or adoption before evaluation, fails closed. Repeated sync of
an identical fingerprint is idempotent. The resulting CCOS chain remains
integrity-checkable and deterministic for identical canonical receipt streams.

## Forge integration boundary

The portable protocol does **not** require the full `forge-core` dependency.
Forge candidates already expose the data needed by the envelope: producer id and
source representation. A typed `forge_core::Candidate` convenience adapter remains
behind `ccos-rsi`'s optional `forge` feature, but the deterministic RSI tier does
not force Forge's larger dependency graph into its locked build.

The next integration step is a small shared wire/protocol crate or equivalent
versioned transport so canonical Forge and Research-Lab can exchange this envelope
without vendoring either engine into the other.

## Non-goals

v1 does not claim:

- remote-worker authentication or TLS;
- hardware TEE/TPM attestation;
- bit-exact reproducibility of LLM proposal generation;
- statistical proof that a promoted candidate is globally optimal;
- a complete hostile-code sandbox on every operating system.

Those are explicit later layers. The v1 invariant is narrower: **no candidate is
promoted without a canonical, validated chain linking proposal identity,
fail-closed execution evidence, and an explicit adoption policy decision.**
