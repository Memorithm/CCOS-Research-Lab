# Threat Model

Assets include agent state, source-derived embeddings, license metadata, and audit logs. Threats include malicious plugins/DGM patches, hostile local inputs, SSRF, corrupted persistence, and compromised dependencies. The community profile assumes an untrusted candidate and no network; premium licensing is fail-closed. Host root, a compromised kernel, and stolen at-rest keys are outside the application boundary.
