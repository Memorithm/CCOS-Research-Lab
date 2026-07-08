#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Setup script pour Claude Code on the web (environnement à accès réseau
# « Trusted »). À coller dans le champ "Setup script" de l'environnement, OU
# référencé depuis là. Pré-chauffe le cache cargo pour des démarrages rapides
# (le résultat est mis en cache par l'environnement).
#
# Sûr par construction : ne bloque jamais le démarrage de la session
# (chaque étape tolère l'échec ; le script se termine par exit 0).
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo /home/user/RSI)"
cd "$ROOT" 2>/dev/null || exit 0

echo ">> RSI web setup : pré-chauffage cargo dans $ROOT"

# Récupère les dépendances (registry crates.io + git-deps GitHub).
# Nécessite l'accès réseau « Trusted » (crates.io + github.com sont autorisés).
cargo fetch || true

# Pré-compile le cœur (cache d'artefacts) — accélère le 1er build de la session.
cargo build --quiet || true

echo ">> RSI web setup terminé"
exit 0
