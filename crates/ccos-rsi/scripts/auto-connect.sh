#!/usr/bin/env bash
# Auto-connexion du serveur MCP RSI aux runtimes d'agents (openclaw,
# hermes-agent, …) — SANS intervention humaine.
#
# Idempotent : compile le binaire MCP en release puis enregistre le
# descripteur dans les configs des runtimes cibles. Conçu pour être lancé
# au démarrage d'un conteneur / d'une session (hook SessionStart, entrypoint
# Docker, systemd, cron @reboot, …).
#
# Variables d'environnement reconnues (optionnelles) :
#   OPENCLAW_CONFIG, HERMES_AGENT_CONFIG, MCP_CONFIG  → chemins de config
#   RSI_MCP_BIN                                        → binaire MCP explicite
#
# Usage : scripts/auto-connect.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[rsi] compilation des binaires (release)…"
cargo build --release --bins

export RSI_MCP_BIN="${RSI_MCP_BIN:-$ROOT/target/release/rsi-mcp}"

echo "[rsi] enregistrement MCP auprès des runtimes…"
"$ROOT/target/release/rsi-connect" "$@"

echo "[rsi] prêt. Le serveur MCP RSI est connecté automatiquement."
