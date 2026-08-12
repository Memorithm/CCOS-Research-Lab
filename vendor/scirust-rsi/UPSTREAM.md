# Vendored scirust-rsi provenance

This directory contains the build-relevant `scirust-rsi` library source vendored for offline CI and sandbox validation.

- Upstream repository: `https://github.com/Memorithm/scirust`
- Upstream crate: `scirust-rsi`
- Pinned upstream commit: `5c7e43b399d3247d68a957faf5e13f147e48a7ef`
- Vendored runtime source: every module declared by upstream `src/lib.rs` at that commit.
- Source integrity: each file under `src/` is copied byte-for-byte; therefore its Git blob SHA matches the upstream tree at the pinned commit.
- License: `LICENSE.md` is copied byte-for-byte from the upstream repository, including the Required Notice.

## Local manifest adaptation

`Cargo.toml` is intentionally local rather than byte-identical to the upstream manifest. Runtime dependencies and features are retained. Upstream development-only path dependencies and executable/example auto-discovery are omitted because this repository consumes `scirust-rsi` only as a library and the vendored dependency must resolve without reaching outside this snapshot. `license-file` points at the copied local `LICENSE.md`, and an empty `[workspace]` prevents the vendor package from joining the parent workspace.

No runtime Rust source is modified by the vendoring process.
