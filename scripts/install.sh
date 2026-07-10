#!/usr/bin/env sh
# One-shot build + install + wire + self-test for CCOS.
#
# Builds the release binary with the deployment features, installs it to PREFIX
# (default /usr/local/bin), runs `ccos doctor`, then `ccos setup --yes`: probe
# the host, register the MCP server in this project's .mcp.json, run the
# deterministic first-run self-test battery, and seal the verdict into
# setup_report.json (an MCP agent relays it via ccos://setup/report — see
# docs/SETUP.md). Override with env vars:
#
#   PREFIX=/opt/bin CCOS_FEATURES=llm,license,learned-embed sh scripts/install.sh
#   CCOS_SETUP=0 sh scripts/install.sh    # skip the setup pass (doctor only)
#
# The `ccos` binary REQUIRES the `llm` feature, so `llm` must stay in CCOS_FEATURES.
set -eu

PREFIX="${PREFIX:-/usr/local/bin}"
FEATURES="${CCOS_FEATURES:-llm,license}"
BIN="target/release/ccos"

echo "==> building ccos (release, --features ${FEATURES})"
cargo build --release --features "${FEATURES}"

if [ ! -x "${BIN}" ]; then
  echo "error: build produced no binary at ${BIN}" >&2
  echo "       the 'ccos' bin requires the 'llm' feature — keep 'llm' in CCOS_FEATURES." >&2
  exit 1
fi

echo "==> installing to ${PREFIX}/ccos"
if [ -w "${PREFIX}" ]; then
  install -m 755 "${BIN}" "${PREFIX}/ccos"
else
  sudo install -m 755 "${BIN}" "${PREFIX}/ccos"
fi

echo "==> ccos doctor"
"${PREFIX}/ccos" doctor

if [ "${CCOS_SETUP:-1}" = "1" ]; then
  echo "==> ccos setup (agent wiring + first-run self-test)"
  "${PREFIX}/ccos" setup --yes
else
  echo "==> ccos setup skipped (CCOS_SETUP=0) — run '${PREFIX}/ccos setup' to wire an agent host"
fi
