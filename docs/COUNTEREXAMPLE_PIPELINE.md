# Counterexample pipeline v1

This phase sits **after** the sealed candidate/evaluation boundary and **before** final promotion authority.

## Contract

A counterexample is not a model critique or a failed infrastructure run. It is a reproducible input for which a trusted oracle returns a semantic failure against one exact `CandidateEnvelope`.

The v1 pipeline is:

```text
seeded generator
  -> canonical input bytes
  -> trusted oracle
  -> first semantic failure
  -> deterministic shrink candidates
  -> oracle-preserving minimization
  -> CounterexampleReceipt
  -> CCOS primary EventLog
  -> promotion hard gate
```

## Determinism

- generation is indexed by `(seed, ordinal)`;
- duplicate generated cases are skipped by SHA-256;
- shrink candidates are normalized by `(byte length, lexical bytes)` before testing;
- a shrink step is accepted only when it is strictly smaller in that total order and preserves the same failure kind;
- infrastructure failures never count as counterexamples;
- all oracle calls consume an explicit query budget;
- the receipt binds original/minimized bytes by SHA-256 and length, plus generator/oracle/shrinker identities and the oracle execution-contract digest.

## Security boundary

The generic engine never executes generated candidate code directly. A production oracle must sit on top of the existing sealed/sandboxed evaluation boundary. The oracle contract digest is required so a witness cannot be compared or replayed under an untracked verifier/execution environment.

## Promotion rule

A minimized counterexample is negative evidence. Once mirrored into the CCOS primary log for a challenger candidate, promotion of that candidate must fail closed until a later candidate identity is evaluated. Counterexamples are content-addressed evidence, not mutable annotations.
