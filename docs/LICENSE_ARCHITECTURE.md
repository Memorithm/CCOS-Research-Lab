# License Architecture

Tokens are versioned `ccoslic1` records with explicit algorithm and key ID. Ed25519 and SLH-DSA keyrings are separate and bounded; unknown IDs, algorithms, duplicate fields, malformed keys, expiry, machine mismatch, and oversized input fail closed. Offline revocation lists are signed `ccosrev1` records and are never trusted merely because a local file exists. Test keys are rejected for release builds.
