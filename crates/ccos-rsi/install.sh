#!/usr/bin/env bash
#
#  RSI — installation en UNE commande.
#
#  Compile le serveur MCP puis le connecte automatiquement à ton agent IA
#  (openclaw, hermes-agent, ou tout client MCP). Aucune configuration manuelle.
#
#  Usage :
#     ./install.sh                 # installe et connecte tout
#     ./install.sh --name monrsi   # nom de l'outil côté agent (défaut: rsi)
#
#  Variables d'env optionnelles (chemins de config des agents) :
#     OPENCLAW_CONFIG, HERMES_AGENT_CONFIG, MCP_CONFIG
#
set -euo pipefail

# --- jolis messages (dégradent proprement sans couleurs) -------------------- #
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=""; G=""; Y=""; R=""; N=""; fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

say ""
say "${B}┌──────────────────────────────────────────────┐${N}"
say "${B}│   Installation de RSI  →  agent IA (MCP)      │${N}"
say "${B}└──────────────────────────────────────────────┘${N}"
say ""

# --- 1. pré-requis ---------------------------------------------------------- #
if ! command -v cargo >/dev/null 2>&1; then
  die "Rust/cargo introuvable. Installe-le en 1 ligne :
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  puis relance ./install.sh"
fi
ok "Rust détecté : $(cargo --version)"

# --- 2. compilation --------------------------------------------------------- #
say "→ Compilation (cela peut prendre une minute la 1re fois)…"
cargo build --release --bin rsi-mcp --bin rsi-connect >/dev/null 2>&1 \
  || die "La compilation a échoué. Lance 'cargo build --release' pour voir le détail."
ok "Binaires compilés : rsi-mcp, rsi-connect"

# --- 3. connexion automatique à l'agent ------------------------------------- #
say "→ Connexion au(x) agent(s)…"
export RSI_MCP_BIN="$ROOT/target/release/rsi-mcp"
"$ROOT/target/release/rsi-connect" "$@"

# --- 4. fini ! -------------------------------------------------------------- #
say ""
ok "${B}Terminé.${N} RSI est connecté à ton agent."
say ""
say "  Au prochain démarrage de ton agent (openclaw / hermes-agent), les outils"
say "  ${B}rsi_*${N} (rsi_create, rsi_run, rsi_state, …) seront disponibles."
say ""
say "  Pour tester tout de suite le moteur sans agent :"
say "     ${B}cargo run --release --bin rsi-demo${N}"
say ""
