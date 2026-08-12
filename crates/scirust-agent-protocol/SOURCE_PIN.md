# SciRust execution-attestation source pin

This Research-Lab crate mirrors only SciRust's canonical execution-attestation module so the candidate-evaluation boundary can verify the exact same execution-profile fingerprint without adding a network dependency.

- upstream repository: `Memorithm/scirust`
- upstream commit: `6a1a594843a02392f69da740ede649a0592a7af9`
- upstream path: `scirust-agent-protocol/src/execution_attestation.rs`
- upstream blob SHA: `660f35bcc9ee299b4e8881ce9597aefb33cc5817`
- schema: `EXECUTION_PROFILE_SCHEMA_VERSION = 1`

`src/execution_attestation.rs` must remain byte-for-byte synchronized with that upstream blob. Changes to the schema are made upstream first and imported here with a new explicit source pin and compatibility review.
