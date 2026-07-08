#!/usr/bin/env bash
# Hook SessionStart — auto-connecte le serveur MCP RSI au démarrage d'une
# session/d'un conteneur, EN LOCAL (transport stdio, aucun port réseau ouvert :
# c'est l'option la plus sûre).
#
# Léger et idempotent : ne recompile que si les binaires manquent, puis
# enregistre le descripteur MCP. Échoue toujours « en douceur » (|| true) pour
# ne jamais bloquer le démarrage de l'hôte.
#
# Câblage (opt-in explicite — voir docs/INTEGRATION.md) :
#   - Claude Code   : "hooks.SessionStart" dans .claude/settings.json
#   - Docker        : ENTRYPOINT / CMD
#   - systemd       : ExecStartPre
#   - cron          : @reboot
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/rsi-mcp"
CONNECT="$ROOT/target/release/rsi-connect"

# (re)compile uniquement si nécessaire — garde le démarrage rapide
if [[ ! -x "$BIN" || ! -x "$CONNECT" ]]; then
  cargo build --release --bins --manifest-path "$ROOT/Cargo.toml" >/dev/null 2>&1 || exit 0
fi

# enregistrement MCP local (fichiers de config en 0600)
RSI_MCP_BIN="$BIN" "$CONNECT" >/dev/null 2>&1 || true
