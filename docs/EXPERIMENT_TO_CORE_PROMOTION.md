# Experiment → Core Promotion (§47 of the charter)

An experimental capability may enter CCOS Core only when ALL are true:

1. independent from RSI;
2. independent from Forge;
3. does not execute generated code;
4. has a specification;
5. has deterministic tests;
6. has non-regression tests;
7. has an error policy;
8. has a versioned format;
9. does not reduce auditability;
10. demonstrates measurable improvement;
11. creates no unjustified cost or latency regression;
12. is approved by ZEKRITI Tarek;
13. enters through a dedicated pull request;
14. passes the full Core CI.

## Process

1. Write the specification and the determinism evidence (class D0 replication).
2. Extract the capability cleanly (no contaminated cherry-picks — §24).
3. Open the dedicated PR against `Memorithm/CCOS-Core` referencing this file
   and the experiment registry entry.
4. Owner review against the 14 rules; merge only on explicit approval.

## Current candidates (registered, NOT promoted)

| Candidate | Evidence so far | Missing |
|---|---|---|
| content-addressed embedding cache (`src/embed_cache.rs`) | ranking-equality tests green here | D0 spec, Core-side PR, rules 4–14 |
