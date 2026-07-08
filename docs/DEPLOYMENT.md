# Deploying CCOS

CCOS ships as a single Rust binary (`ccos`) that also hosts the MCP server. This is the recommended
path for running it on a server, behind an AI agent.

> **First command on any new host:** `ccos doctor` — it reports the build profile, compiled features,
> active parser, license status, and any deployment warnings.

## 1. Build

The `ccos` binary **requires the `llm` feature** (it drives the async MCP server + runtime), so a bare
`cargo build --release` produces **no binary at all**. Build with the deployment features:

```sh
# Community / core deployment:
cargo build --release --features llm,license

# CCOS_EXTENDED premium deployment — every deterministic Pro tier, replay-safe:
cargo build --release --features llm,pro-default

# Everything incl. the REPLAY-RELAX full kernels (test/CI; see docs/DETERMINISM.md):
cargo build --release --features llm,all-full
```

| feature | gives you | default |
|---|---|---|
| `syn-parser` | the accurate `syn` AST parser | **on** |
| `llm` | the `ccos` binary itself + MCP server + Ollama backend | required for the bin |
| `license` | the offline ed25519 Pro-license verifier (`tensions` / `audit` + a Pro tier) | recommended |
| `license-pq` | the offline **post-quantum** (SLH-DSA, FIPS 205) Pro-license verifier — composes with `license` (§4b) | recommended |
| `signed-sync` | per-workspace ed25519 identities for `ccos sync` (signed, TOFU-pinned bundles) | optional |
| `learned-embed` | the LSA semantic re-ranker | optional |
| `mimalloc` | a faster allocator (benchmarking only) | optional |
| `neural-embed` | quarantined **local** neural embedder (Ollama `/api/embeddings`; REPLAY-RELAX) | optional |
| `slhav2` | the distilled zero-dep SLHAv2 tile backend (`replay == live`) | optional |
| `slhav2-full` | the REAL `ccos-scirust` kernel — SIMD scoring, `ElasticKvCache`, `LatentSafetyGuard`, the `slha.*` MCP tools + `ccos slha` (Pro-gated; REPLAY-RELAX) | optional |
| `octasoma` | the OctaSoma semantic-memory backend + the `octa-semantic` recall strategy (Pro-gated) | optional |
| `octacore` | the causal-narrow → cosine-rerank cascade — the `octa.*` MCP tools + `ccos octa` (Pro-gated; implies `octasoma`) | optional |
| `rsi` | the CERVO/RSI self-improvement core — the `rsi.*` MCP status tools + `ccos rsi` (Pro-gated) | optional |
| `rsi-dgm` | the hard-sandboxed Darwin–Gödel Machine loop (typed API only; Pro-gated; REPLAY-RELAX) | optional |
| `rsi-full` | RSI + a local LLM proposer backend (REPLAY-RELAX) | optional |
| `pro-default` | **bundle**: every deterministic premium tier (`license`, `license-pq`, `signed-sync`, `slhav2`, `octasoma`, `octacore`, `rsi`, `learned-embed`) — replays bit-identically | premium |
| `all-full` | **bundle**: `pro-default` + every REPLAY-RELAX full kernel | test/CI |

The **default build** (nothing beyond `syn-parser`) compiles none of the premium crates — its
dependency tree is byte-identical to core CCOS, and the CI's byte-identity guard enforces that.

## 2. Install

```sh
install -m 755 target/release/ccos /usr/local/bin/ccos
ccos doctor
```

`ccos doctor` (or `ccos doctor --json` for machines) prints, e.g.:

```
ccos doctor — deployment self-check

  version      0.4.0
  build        release
  target       x86_64-linux
  parser       syn AST (accurate)
  features     llm=yes license=yes license-pq=yes syn-parser=yes learned-embed=no mimalloc=no signed-sync=no
  premium      slhav2=no slhav2-full=no octasoma=no octacore=no rsi=no rsi-dgm=no
  mcp          ready  (ccos mcp <workspace>)

  license
    verifier   slh-dsa (SLH-DSA-128s) + ed25519 (both compiled in)
    ed25519 key placeholder (fail-closed)
    slh-dsa key placeholder (fail-closed)
    tier       community
    token      none

  ⚠ 1 warning(s):
    - no vendor public key is set (both embedded keys are the all-zero placeholder) — Pro is fail-closed until a vendor key is set …
```

## 3. MCP server

Point your MCP gateway at the **installed release** binary and a workspace path:

```
/usr/local/bin/ccos mcp /var/lib/ccos/workspace.ccos
```

> ⚠️ Do **not** point the gateway at `target/debug/ccos`: a debug build is slower and may diverge from
> your installed release. `ccos doctor` flags a debug build. Keep the MCP command and your install on
> the same release binary.

The workspace is one `.ccos` snapshot + a `.oplog` timeline sidecar, shared with the CLI.

## 4. Pro license (optional)

The public key shipped in the source tree is an **all-zero placeholder**, so the build is
**fail-closed** — it licenses nothing — until you bake in your own vendor key:

```sh
# 1. Generate a keypair (keep the seed SECRET; it never goes in the repo).
cargo run --features license --example license_sign -- keygen
#    → paste the printed LICENSE_PUBLIC_KEY into src/license.rs, then rebuild.

# 2. Sign a license for a customer (perpetual = omit --days).
CCOS_LICENSE_SIGNING_SEED=<64-hex-seed> \
  cargo run --features license --example license_sign -- sign --licensee "Acme Corp" --days 365

# 3. Install the token on the host — env var, explicit file, or the XDG default.
export CCOS_LICENSE="<token>"                 # inline (containers / CI), or:
export CCOS_LICENSE_FILE=/etc/ccos/license    # an explicit path, or:
#     write it to ~/.config/ccos/license      # ($XDG_CONFIG_HOME/ccos/license)
ccos doctor                                   # tier should now read: PRO
```

Resolution order: `$CCOS_LICENSE` (token text inline) → `$CCOS_LICENSE_FILE` → the XDG default.

Verification is **fully offline** — no network, no telemetry — so a customer can run air-gapped.

### 4b. Post-quantum licenses (SLH-DSA / FIPS 205, optional)

For deployments that want a license signature that is conjectured secure against a large-scale
quantum computer, CCOS ships a **second**, independent offline verifier based on **SLH-DSA**
(NIST FIPS 205, formerly SPHINCS+) behind the `license-pq` cargo feature. It is orthogonal to the
ed25519 `license` feature — a build may compile in one, the other, or both
(`--features llm,license,license-pq`). A token's `slhdsa.` scheme tag dispatches it to the SLH-DSA
verifier; an untagged token still goes to ed25519. The tag is also bound into the signed message,
so a signature made under one scheme can never be replayed as the other.

Parameter set **SLH-DSA-SHAKE-128s**: 32-byte public key, 64-byte secret key, **7,856-byte
signature** (~10.5 KB base64url) — the smallest FIPS 205 signature, NIST PQ category 1 (~128-bit
post-quantum), a like-for-like PQ upgrade of ed25519's classical 128-bit. Signing is deterministic;
verification is fast (it runs on every `ccos` invocation that reads the license).

```sh
# 1. Generate a post-quantum keypair (keep the 64-byte SECRET; it never goes in the repo).
cargo run --features license-pq --example license_sign_pq -- keygen
#    → paste the printed LICENSE_SLH_DSA_PUBLIC_KEY into src/license.rs, then rebuild.

# 2. Sign a license (perpetual = omit --days). The token is ~10.5 KB — prefer the file over the env var.
CCOS_LICENSE_PQ_SIGNING_SEED=<128-hex-secret-key> \
  cargo run --features license-pq --example license_sign_pq -- sign --licensee "Acme Corp" --days 365 \
  > /tmp/acme.pqlicense
mkdir -p ~/.config/ccos && cp /tmp/acme.pqlicense ~/.config/ccos/license

# 3. Verify on the host (build with the feature that matches the token's scheme).
cargo run --features llm,license-pq -- doctor    # verifier: slh-dsa; tier: PRO
```

> ⚠️ **Unaudited cryptography.** The `lattice-slh-dsa` crate is pure Rust
> (`#![forbid(unsafe_code)]`, `zeroize`-backed) but **not independently audited**. It was chosen over
> RustCrypto's `slh-dsa` because the latter pins a pre-release `signature` crate that cannot coexist
> with `ed25519-dalek` in a single build (it would break `--all-features`). Treat the PQ verifier as
> defence-in-depth or an opt-in for post-quantum-readiness, not a drop-in replacement for an audited
> ed25519 stack, until an independent audit of `lattice-slh-dsa` exists.

### 4c. Pro features

The Pro license unlocks, all verified locally and gated through `Licensing::require` (the core
causal graph, Q-Page, and recall are **never** gated):

- **custom-authority-weights** — per-source authority weighting (vs. the uniform default).
- **tension-visualization** — cognitive-tension rendering in the logs.
- **audit-reports** — belief / conflict / provenance audit-report generation.
- **slhav2-embeddings** — the adaptive **grouped** INT4 quantization (group size 16) for the
  semantic embedding store. A community session falls back to **uniform** INT4 (a single per-vector
  scale); the core recall path is unchanged, only the embedding precision reflects the tier.
- **adaptive-retrieval** — the `ccos::retrieval` self-improving feedback loop (`ImprovementLoop`).
  The core retrieval (dense / BM25 / hybrid + metrics) is free and fully functional; only the
  continuous-improvement tier is gated.
- **octasoma-memory** — the OctaSoma-backed, region-sharded semantic-anchor index
  (`ccos::octa_index`, compiled behind the `octasoma` cargo feature). The free core recall
  strategies (working-set / around / task / INT4 TF-IDF semantic / hybrid) are untouched; only the
  true-embedding OctaSoma backend is Pro. The tier includes the **explicit relevance-feedback
  channel** (`SemanticFeedback`, and the `octa_feedback` MCP tool): labels from the agent loop
  certify a conformal anchor-score floor (miscoverage ≤ α), and `recall_semantic_calibrated` /
  the MCP `octa-semantic` strategy then trust an anchor only when it clears the floor — refusals
  are visible (`octa-semantic-below-floor-fallback-task`), never a silent downgrade, and with too
  few labels no floor is fabricated.
- **slhav2-full-kernel** *(CCOS_EXTENDED, `slhav2-full` cargo feature)* — the REAL `ccos-scirust`
  attention kernel as a `MemoryProvider` backend: runtime-dispatched SIMD scoring, `ElasticKvCache`
  HOT/WARM/COLD soft-paging with informed eviction, the `LatentSafetyGuard`, and the `slha.*` MCP
  tools / `ccos slha` CLI. A documented REPLAY-RELAX (see `docs/DETERMINISM.md`); the distilled
  `slhav2` backend stays the replay-exact store.
- **rsi-self-improvement** *(CCOS_EXTENDED, `rsi` cargo feature)* — running the CERVO/RSI agent
  with CCOS audit (`CcosAudit`: rsi's audit log over CCOS's hash-chained `EventLog`), plus the
  `rsi.*` MCP status tools / `ccos rsi` CLI. The std-only core keeps `replay == live`.
- **rsi-dgm** *(CCOS_EXTENDED, `rsi-dgm` cargo feature)* — the hard-sandboxed Darwin–Gödel Machine
  loop (`GuardedDgm`: editable-file allowlist, GuardLayer sanitation, air-gapped
  `cargo --offline --frozen` evaluator, hash-chain-audited promotion). Deliberately reachable
  **only** through the typed API — no MCP tool and no CLI one-liner can trigger self-modification.
  A documented REPLAY-RELAX.

`ccos license` enumerates the active set; `ccos doctor` reports the compiled verifier scheme(s).

## 5. Durability (what survives a crash / power cut)

Every checkpoint is **crash- and power-safe**. `util::write_durable` writes a temp file, `fsync`s it,
**atomically renames** it into place, then `fsync`s the parent directory — the snapshot is never left
half-written, and the hash-chained event log detects any tampering on reload. Durability is at
**checkpoint granularity**: the agent / MCP flow checkpoints to the workspace, so both the causal
memory and the replayable timeline survive a restart or a sudden power loss.

## One-shot

`scripts/install.sh` does build → install → `ccos doctor` in one step
(`PREFIX=/usr/local/bin CCOS_FEATURES=llm,license sh scripts/install.sh`; add `,license-pq` to also
compile the post-quantum SLH-DSA verifier — see §4b).
