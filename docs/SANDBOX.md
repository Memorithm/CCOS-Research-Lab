# DGM Sandbox

DGM evaluation requires `/usr/bin/bwrap` and `/usr/bin/prlimit`; absence fails closed. Evaluation uses a disposable snapshot, read-only system mounts, an isolated network namespace, private home/tmp, bounded CPU/address-space/process/file/output limits, and process-group termination. Only a successful evaluation with unchanged source digests can be promoted. This is Linux-specific rootless isolation, not a substitute for an independent host hardening review.
