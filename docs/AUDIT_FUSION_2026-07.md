# CCOS_EXTENDED — Audit complet de fusion & sécurité (2026-07-08)

> Livrable de l'audit demandé : « CCOS_EXTENDED se veut la fusion, autour de
> CCOS, de CCOS + SLHAv2 + OctaSoma + CERVO — la version premium de CCOS. »
> Ce rapport vérifie que la fusion est **complète**, **à jour**, et **sécurisée**,
> et consigne ce qui a été corrigé pendant l'audit. Compagnon de
> `docs/FUSION_PLAN.md` (l'architecture et le phasage P0–P6, tous ✅) et de
> `docs/DETERMINISM.md` (la frontière replay).

## 1. Verdict

**CCOS_EXTENDED est la fusion effective des quatre sources, sur base CCOS à
jour, avec les invariants de sécurité et de déterminisme tenus.**

| Source | Ingestion | État à l'audit | Action menée |
|---|---|---|---|
| **CCOS** (hub) | base du produit (`src/`, 50 commits) | 1 commit en retard (#151) | **Porté** : `ccos.recall` aligné contrat OpenClaw + outils MCP `get`/`sync` (`src/mcp.rs`, `src/external_memory.rs:source_for`) |
| **SLHAv2** | `crates/ccos-scirust{,-mcp,-c,-python}` | famille scirust **périmée** (série TurboQuant absente, PR #52 + phase 0/1) | **Re-basée sur HEAD amont** : codecs MIXED/TQ3/MIX3 + SIMD (805→3002 lignes `slha_v2.rs`), `fit_joint`, persistance COLD→EventLog (`eventlog.rs`), paramètre `codec` de `slha.compress`, pont FFI llama.cpp (`slha_weights_load`/`slha_encode_key`/`slha_decode_latent`) ; durcissement P4 ré-appliqué par-dessus |
| **OctaSoma** | `crates/ccos-octasoma` + `crates/ccos-octacore` | **à jour** (`src/` identique octet-à-octet à l'amont ; seules divergences = chirurgie de manifeste + inversion de dépendance P2, intentionnelles) | vérifié, aucun port nécessaire |
| **CERVO/RSI** | `crates/ccos-rsi` (moteur RSI v0.10.0, ~40 modules) | moteur ingéré et **en avance** sur le dépôt `memorithm/cervo` | décision documentée (§4) : le scaffold cervo reste exclu |

Les gates du plan tiennent après l'audit :

- `cargo tree` (default) ne référence **aucune** crate premium (byte-identity P0) —
  désormais verrouillé en CI (« Byte-identity guard »).
- Tests : default lib **608/608** ; pro-default lib **651/651** ; scirust
  **143 verts** (dont les nouveaux tests codec TQ3/MIX3) ; slha-mcp 10/10 (dont
  codec) ; fusion : `fusion_slha_full` 6/6, `fusion_octacore` 4/4 (via
  pro-default), `fusion_unified_mcp` **6/6** (nouveau, P5),
  `determinism_boundary` 5/5.
- `cargo check` vert sur : default, `slhav2-full`, `octacore`, `rsi`, `rsi-dgm`,
  `pro-default`, `all-full`, binaire `llm,all-full`, `-p scirust -p slha-c
  -p slha-mcp -p ccos-memory-runtime`.

## 2. Complétude de la fusion (détail)

### 2.1 Base CCOS
`diff -r` contre `memorithm/ccos@3b407c1` : hors ajouts de fusion, **seul le
changeset #151 manquait** ; il a été porté tel quel (aucun conflit — les deux
fichiers touchés ne portaient aucune modification de fusion). #149 (index
d'adjacence causal_flash) et #150 (worldsim/migrate `--extend`) étaient déjà
présents octet-à-octet.

### 2.2 Famille SLHAv2 (le vrai trou, comblé)
La base de vendoring était le commit amont `fd7d1dd` ; l'amont a ensuite reçu
9 commits fonctionnels (série TurboQuant). Méthode de ré-ingestion :
1. délta P4 extrait = `diff(amont@fd7d1dd, vendored)` → 4 fichiers, ~110 lignes
   (postures `deny/allow(unsafe_code)`, `// SAFETY:`, accesseur `tile()` —
   ce dernier repris entre-temps par l'amont) ;
2. copie de l'amont HEAD (`git archive`), chirurgie de manifeste ré-appliquée
   (`scirust = { path = "../ccos-scirust" }`) ;
3. délta P4 ré-appliqué et **adapté** : le contrat d'ownership du header C
   documente désormais le handle de modèle alloué par le nouveau pont codec
   (`slha_weights_free`), et la note SIMD couvre les nouveaux noyaux
   TQ3/NF4/Mixed/MIX3 (chaque `unsafe fn` porte un contrat `# Safety`, chaque
   site un `// SAFETY:` ou un garde de détection runtime).

### 2.3 OctaSoma / OctaCore
`ccos-octasoma/src` et `ccos-octacore/src/{mcp.rs,bin}` identiques à l'amont ;
les seules divergences sont la chirurgie voulue : suppression du
`[profile.release]` non-racine, licence `LicenseRef-CheckupAuto-Dual`,
et l'inversion P2 (le module `ccos_adapter` amont supprimé, l'adaptateur
`CcosScope` vivant côté CCOS dans `src/octacore_bridge.rs` — `cargo tree -p
octacore | grep ccos` vide).

### 2.4 CERVO
Voir §4 (décision).

## 3. Audit sécurité

### 3.1 Surface `unsafe` (mémoire)
- Racine `ccos`, `ccos-memory-runtime`, `ccos-octasoma`, `ccos-octacore`,
  `ccos-rsi` : **zéro `unsafe`** (`forbid(unsafe_code)` sur les crates
  quarantaine ; les hits grep restants sont des littéraux de chaîne/tests).
- `ccos-scirust` : `#![deny(unsafe_code)]` à la racine, deux zones d'allow
  auditées — `numa.rs` (allocateur aligné + politique NUMA derrière la feature
  `numa`, off par défaut, Linux-only) et `attention/slha_v2.rs` (SIMD
  runtime-dispatché, chemin scalaire de référence prouvé équivalent par tests).
- `slha-c` : frontière FFI *sortie uniquement* — la bibliothèque n'alloue
  jamais de tuile ; garde d'alignement `debug_assert!` à l'entrée ; panics
  confinés par `catch_unwind` (codes -2) ; le nouveau pont codec introduit un
  handle opaque documenté (paire `slha_weights_load`/`slha_weights_free`).

### 3.2 Egress réseau (exfiltration)
- Posture air-gap par défaut **fail-closed** : `src/egress.rs`
  (`EgressAllowlist`, loopback uniquement, extension explicite via
  `CCOS_EGRESS_ALLOW`, refus `Malformed`/`HostNotAllowed`) garde les trois
  sites d'appel du hub (`llm::query_as`, `neural_embed`, `eval::ask`).
- `ccos-rsi` : le client LLM est **local par défaut** (`127.0.0.1:11434`,
  std-only) et n'est compilé que derrière `llm-ollama` (tiré uniquement par
  `rsi-full`, REPLAY-RELAX documenté) ; le backend Claude est opt-in séparé.
- Le sandbox DGM force `cargo --offline --frozen` + `CARGO_NET_OFFLINE=true`.

### 3.3 Sous-processus
| Site | Garde |
|---|---|
| `src/rsi_bridge.rs` (`GuardedCargoEvaluator`) | air-gap (`--offline --frozen`), timeout 300 s, sortie bornée 4 Mio, `kill()` au deadline, jamais atteignable sans le gate Pro `RsiDgm` |
| `ccos-rsi/{addons,knowledge}.rs` (binaire `papers`) | intégration opérateur opt-in (env `RSI_PAPERS_BIN`/PATH), timeout 30 s, sortie bornée 8 Mio, dégradation propre si absent |

### 3.4 Auto-modification (DGM) — défense en profondeur
1. compile-time : feature `rsi-dgm` off par défaut ;
2. runtime : gate licence `Feature::RsiDgm` (refus visible) ;
3. **API only** : aucune exposition MCP ni CLI (décision P5, testée par
   `fusion_unified_mcp::rsi_status_…` — le catalogue n'advertise que
   `rsi.explain`/`rsi.status`) ;
4. allowlist de fichiers éditables obligatoire (`GuardedDgmConfig`), rationale
   assaini par `GuardLayer`, promotion auditée ;
5. chaque étape (acceptée/refusée/bloquée) émet `EventType::SelfModify` +
   `EventPayload::RsiMutation` dans l'EventLog hash-chaîné (inviolabilité).

### 3.5 Licence & gating commercial
- Vérification **hors-ligne** (ed25519 + SLH-DSA post-quantique en option) ;
  aucun downgrade silencieux : chaque refus nomme le tier et laisse le cœur
  fonctionner (testé aux trois niveaux : unité, fusion, smoke CLI exit 3).
- Les 9 `Feature` runtime couvrent les 4 kernels premium ; MCP et CLI
  partagent la même implémentation de gate (`mcp_ext::call_tool`).

### 3.6 Chaîne d'approvisionnement
- `cargo audit` hebdomadaire (`audit.yml`) ; workspace `--locked` en CI ;
  vendoring par copie (pas de dépendance git flottante) ; les features
  optionnelles amont d'OctaSoma (`scirust-simd`/`evo`) restent off.

### 3.7 Points relevés, non bloquants
- `key_sidecar` (src/agent_session.rs:1837) : warning `dead_code` en build
  default — **préexistant dans CCOS amont** (la fonction ne sert qu'aux builds
  `signed-sync` et aux tests) ; laissé intact pour préserver l'identité
  octet-à-octet avec l'amont ; à corriger côté CCOS.
- `slha.benchmark` (MCP/CLI) rapporte des durées wall-clock : sortie
  non-déterministe par nature (mesure, pas état mémoire) — lecture seule,
  documenté dans `src/mcp_ext.rs`.

## 4. Décision CERVO (consignée)

Le plan (§A, décision utilisateur) vend le **moteur** CERVO/RSI v0.10.0 en
`crates/ccos-rsi` et exclut le scaffold parent `cervo` (sans LICENSE). L'audit
confirme que cette décision reste la bonne : le dépôt `memorithm/cervo` a
depuis évolué en **fork structurel indépendant** (boucle
cortex/évolution/pipeline/stability propre, ~5 modules réécrits, toujours
aucune LICENSE), sans relation de vendoring exploitable avec `ccos-rsi` (qui
lui est très en avance : dgm, meta-search, wasm sandbox, audit, ~40 modules).
**La contribution CERVO à la fusion est donc le moteur RSI, déjà ingéré.**
À revisiter uniquement si cervo obtient une licence et converge avec le moteur.

## 5. Récapitulatif des changements de cet audit

1. Port CCOS #151 (`src/mcp.rs`, `src/external_memory.rs`).
2. Re-base famille scirust sur SLHAv2 HEAD (TurboQuant complet) + P4 ré-appliqué.
3. **P5** : `src/mcp_ext.rs` (namespaces `slha.*`/`octa.*`/`rsi.*` multiplexés,
   gates Pro, refus visibles) + CLI unifiée (`ccos slha|octa|rsi`) + doc.
4. **P6** : `tests/fusion_unified_mcp.rs` (6 tests) + matrice CI
   default|pro-default|all-full + garde byte-identity + tests des membres
   fusionnés + smoke refus CLI.
5. Docs : `FUSION_PLAN.md` (P5/P6 ✅ + refresh vendored), `CHANGELOG.md`,
   ce rapport.
