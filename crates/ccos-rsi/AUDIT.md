# Audit complet de RSI (v0.10.0)

Audit du code source du projet RSI — Recursive Self-Improvement (Rust),
réalisé après une vague de changements substantiels (pull de `origin/main` :
commits `8f938d4` → `a0ec011`, passage v0.9.0 → v0.10.0).

Lecture exhaustive de **35 fichiers Rust** (~5 000 LOC cœur + vendor),
**5 binaires**, **2 examples**, exécution de `cargo build` (cœur + feature
`scirust`), `cargo clippy --all-targets` (+ `--features scirust`), `cargo test`
(lib + intégration + doctests), et smoke-tests des binaires `rsi-ablate` et
`rsi-loopbench`.

Date : 2026-06-22
Auditeur : opencode (glm-5.2:cloud)
Cible : `/root/rsi` (commit `a0ec011`, v0.10.0)
Audit précédent : v0.9.0 (commit `fc8ce0d`) — voir section 10 pour le diff.

---

## 1. État global

| Aspect | Verdict | vs v0.9.0 |
|---|---|---|
| Compilation (release, cœur) | ✅ propre, 0 warning | = |
| Compilation (release, `--features scirust`) | ✅ propre | nouveau |
| Tests lib | ✅ 89/89 passent (était 54) | +35 tests |
| Tests intégration | ✅ 3/3 passent | = |
| Doctests | ✅ 1/1 (+1 ignored sous `scirust`) | = |
| Clippy (`--all-targets`) | ✅ **0 warning** (était 7) | corrigé ✅ |
| Architecture | ✅ propre, modulaire, cœur std-only | = |
| Sécurité mémoire | ✅ aucun `unsafe` (sauf `PermissionsExt`) | = |
| Déterminisme | ✅ testé et vérifié | = |

Le code reste de **très bonne qualité** et a même gagné en maturité : les 7
warnings Clippy de v0.9.0 ont été éliminés, la suite de tests a presque doublé
(54 → 89), et l'ajout de la feature `scirust` (moteur réel vendorisé) se
compile et passe ses tests. Le cœur reste std-only.

---

## 2. Nouveautés v0.10.0 (depuis l'audit précédent)

Le dépôt a grossi de ~11 commits structurants autour de trois axes :

### 2.1 De-stylisation & robustesse (commit `8f938d4`)
- **`tasks.rs`** (268 LOC) — corpus de tâches **ancré** (Ω réel) remplaçant
  les profils Dirichlet synthétiques. `TaskCorpus::builtin()` (10 archétypes)
  et `extended()` (40 tâches). `GroundedCapability` implémente la **loi de
  Liebig** (Φ = min des marges sur les composantes requises) — plus fidèle
  qu'un produit scalaire lissé.
- **`knowledge.rs`** (290 LOC) — source de connaissances réelle alimentant
  la composante `D` : `CorpusKnowledge` (textes/répertoire), `PapersKnowledge`
  (sous-processus `papers extract` avec dégradation gracieuse),
  `StaticKnowledge` (calibration). Niveau saturant `1 − exp(−n/scale)`.
- **`measured_substrate.rs`** (166 LOC) — `SubstrateImprover` natif std-only
  (kernel matmul CPU chronométré, balaye une grille de tuilages). Alternative
  portable à `ForgeSubstrate` (qui exige Forge).
- **ε adaptatif** (`dynamics.rs`) — `adaptive_epsilon` rend la tolérance de
  non-régression sensible au bruit Monte-Carlo : `ε_eff = ε + z·stderr(SI)`,
  via `IntelligenceSurface::si_global_stats` (variance pondérée + taille
  effective de Kish).

### 2.2 Loop Engineering — epic L1→L9 (commits `1c97724`→`bed94c5`)
- **`convergence.rs`** (121 LOC, L2) — détecteur de tendance par régression
  linéaire sur fenêtre glissante (`Trend::Improving|Plateau|Diverging`).
- **`loop_ctrl.rs`** (256 LOC, L1/L4/L6) — pilote `run_until` avec critères
  d'arrêt motivés (budget, cible, plateau, divergence, timeout,
  **disjoncteur de criticité** avec rollback, **véto HITL** via
  `LoopObserver`).
- **`schedule.rs`** (107 LOC, L3) — cadences multi-échelles
  (`meta_every`, `substrate_every`) + `MetaMeta` (boucle méta-méta qui adapte
  les cadences selon la tendance : ralentit sur plateau, accélère en
  divergence).
- **`checkpoint.rs`** (231 LOC, L5) — instantané reprenable de l'état macro
  (S, substrat, stratégie, t) en JSON, pour reprise et rollback.
- **`swarm.rs`** (95 LOC, L8) — portefeuille d'agents en parallèle
  (`std::thread::scope`, sélection par `SI_safe`), déterministe par graine.
- **`api.rs`** — commande `run_until` exposée via MCP (L7).
- **`bin/rsi_ablate.rs`** (175 LOC) — banc d'ablation (7 configs on/off × N
  graines, agrégats SI/SI_safe/risque/AUC/t@90/interventions/régressions).
- **`bin/rsi_loopbench.rs`** (80 LOC) — banc d'essai des cadences (L9) +
  comparaison swarm vs agent unique.

### 2.3 Pont `scirust-rsi` (commits `6e3a9fe`→`a0ec011`)
- **`ascent.rs`** (211 LOC) — stand-in local du contrat `scirust-rsi`
  (`RefineTask` + `Guard` + `ascend`, élitiste borné, `Report::is_monotone`).
- **`synthesis.rs`** (308 LOC) — domaine de **synthèse symbolique** : AST
  `Expr` évalué en sandbox (interpréteur maison, jamais exécuté), mutations
  déterministes (grow/replace/perturb), 1+λ.
- **`scirust_bridge.rs`** (228 LOC, feature `scirust`) — pont vers le **vrai**
  moteur `scirust-rsi` (`SelfRefiner::run`), API-compatible avec `ascent`.
- **`vendor/scirust-rsi/`** (699 LOC) — reconstruction API-compatible du
  crate amont, vendorisée en `path` dep (hors-ligne, ne tire que `rand`).
  Inclut `refine`, `star` (Self-Taught Reasoner), `expert_iteration`, `pbt`
  (Population-Based Training), `evo` (1+λ-ES avec règle du 1/5).
- **`vendor_scirust_rsi.sh`** — installeur offline auto-extractible
  (archive base64 + checksum SHA-256).
- **`SCIRUST_ACTIVATION.md`** — guide d'activation (stand-in vs moteur réel).
- **2 examples** : `self_improve.rs` (stand-in), `self_improve_real.rs`
  (moteur réel, feature-gated).

---

## 3. Bugs et problèmes réels (par ordre de gravité)

### 🟠 Bug A — `dynamics.rs:85` « saturation » mal définie [NON CORRIGÉ]

```rust
let saturation = (1.0 - mean(&state.to_vector())).clamp(0.0, 1.0);
```

**Statut : inchangé depuis v0.9.0.** La doc dit « saturation des compétences
freine l'apprentissage », mais `mean(&state.to_vector())` calcule la moyenne
de **tout l'état** (D,M,R,A,C,V) — or V (valeurs) et A (autonomie) ne sont
pas des « compétences saturantes ». L'effet : η diminue quand l'état global
moyen augmente, ce qui inclut A et V. Effet de bord : un agent très autonome
mais peu compétent voit son η artificiellement réduit. De plus, `to_vector()`
alloue un `Vec<f64>` à **chaque appel de `eta`** (et `eta` est appelé dans
`velocity` → `constrained_step`, lui-même dans une boucle de line search
jusqu'à 20×). Coût O(N) par pas.

**Recommandation** : utiliser `state.capability_array()` (déjà `[f64;6]`,
stack), ou moyenne de D,M,R seulement. Alloue 0. *(Recommandation inchangée.)*

### 🟠 Bug B — Garde-fou de non-régression contournable par ℳ [NON CORRIGÉ]

`agent.rs:277-383` : le `line search` de non-régression (§4) ne s'applique
qu'à l'étape d'apprentissage `ΔS_appr`, **pas** au `meta_delta` de ℳ. Or ℳ
peut faire régresser SI si le substrat change (improver refusé) ou si la
mitigation anti-wireheading baisse `P_eff` (ligne 373-379, « override assumé »).
Le test `si_is_monotone_within_epsilon` ne vérifie que
`appr.si_after ≥ appr.si_before`, pas `delta_si ≥ -ε`. Un
`StepReport.delta_si` négatif est possible.

**Le banc d'ablation le confirme empiriquement** : la colonne « régr » reste à
0.0 sur les 30 pas × 3 graines testées, mais l'invariant n'est pas formellement
garanti — c'est une propriété émergente de la dynamique, pas un garde-fou.

**Recommandation** : soit documenter explicitement que `delta_si` n'est pas
garanti (actuellement le README §3 promet `SI(t+1) ≥ SI(t) − ε` comme
invariant global), soit étendre le line search au pas combiné `meta + appr`.
*(Recommandation inchangée.)*

### 🟢 Bug C — `meta.rs:127` encode/decode non-roundtrip aux bornes [CORRIGÉ]

```rust
let x = self.gain.clamp(GAIN_LO + 1e-6, GAIN_HI - 1e-6);
theta.push(((x - GAIN_LO) / (GAIN_HI - x)).ln());
```

Encode clamp à `GAIN_LO + 1e-6`, mais `decode` fait
`GAIN_LO + (GAIN_HI-GAIN_LO)*sigmoid(θ)` qui peut rendre des valeurs dans
`[GAIN_LO, GAIN_LO+1e-6)`. Le test `encode_decode_roundtrip` évite les bornes
donc ne le détecte pas. Effet mineur (stratégie légèrement décalée) mais
viole l'invariant de roundtrip. **Statut : CORRIGÉ** — `decode` applique les
**bornes identiques** à `encode` (`meta.rs`, « roundtrip idempotent jusqu'aux
extrêmes ») et le test `encode_decode_roundtrip` couvre désormais des θ extrêmes.

### 🟢 Bug D — `json.rs:293` échappement `\u` non conforme RFC 8259 [CORRIGÉ]

Pas de gestion des surrogate pairs UTF-16 : un caractère hors BMP (ex. emoji)
est encodé en un seul `\uXXXX` par `write_escaped` côté sérialisation, mais
le parseur interprète `\uXXXX` comme un seul codepoint. Pour `char::from_u32`
avec `code > 0xFFFF`, Rust accepte (Unicode scalaire) — donc côté parsing ça
marche, mais la sérialisation n'est pas strictement RFC 8259 (devrait émettre
surrogate pairs). Aucun impact pratique ici (pas d'emoji dans les payloads).
**Statut : CORRIGÉ** — le parseur gère les **paires de surrogates UTF-16**
(RFC 8259) et rejette proprement un surrogate isolé/invalide (erreur, pas de
panic) ; test `parses_utf16_surrogate_pairs` (caractère hors-BMP 😀).

### 🟢 Bug E — `api.rs:59` `as_u64` silent sur négatifs/NaN [CORRIGÉ]

```rust
pub fn as_u64(&self) -> Option<u64> { self.as_f64().map(|n| n as u64) }
```

`-1.0 as u64` → `0` (saturation silencieuse), `NaN as u64` → `0`. Une config
`{"steps": -5}` devient silencieusement 0 pas. `bounded()` clamping compense
pour `steps` (borne `[0, MAX_STEPS]`) mais pas pour `seed`. Mineur mais à
corriger pour robustesse API. **Statut : CORRIGÉ** — `as_u64`/`as_usize`
rejettent désormais NaN, ±∞ et négatifs (`filter(|n| n.is_finite() && *n >= 0.0)`
⇒ `None` au lieu d'une saturation silencieuse à 0).

### 🟡 Bug F — `swarm.rs:53` `h.join().unwrap()` [NOUVEAU]

```rust
handles.into_iter().map(|h| h.join().unwrap()).collect()
```

Si un thread panic (par ex. un `RSIAgent` configuré avec des dimensions
incohérentes), `join().unwrap()` propage le panic dans le thread appelant —
le swarm entier s'effondre au lieu d'isoler le membre défaillant.

**Recommandation** : soit `join().unwrap_or_else(|_| SwarmMember{seed, si_global: 0, si_safe: f64::NEG_INFINITY})` pour marquer le membre comme
invalide et le exclure de la sélection, soit documenter que `build(seed)` doit
être infaillible.

### 🟡 Bug G — `knowledge.rs:175` `PapersKnowledge::run_papers` sous-processus non limité [NOUVEAU]

```rust
match cmd.output() { ... }
```

L'appel à `papers` (binaire externe) n'a **pas de timeout** ni de limite sur
la taille de la sortie capturée. Un binaire `papers` hostile ou bogué pourrait
bloquer indéfiniment ou remplir la mémoire. La `String::from_utf8_lossy(&out.stdout)`
charge toute la sortie en RAM.

**Recommandation** : ajouter `std::process::Command::stdout(Stdio::piped())`
+ lecture bornée, ou un `wait_timeout` (p. ex. 30 s). Mineur vu l'usage
(dégradation gracieuse si binaire absent), mais à savoir si on branche un vrai
`papers` en production.

### 🟡 Bug H — `checkpoint.rs:140` validation de dimensions insuffisante [NOUVEAU]

```rust
let _ = Dims { d: state.d.len(), m: ..., r: ..., a: ..., c: ..., v: ... };
```

La reconstruction depuis JSON construit un `Dims` mais **ne valide pas** que
les dimensions sont cohérentes avec le reste de l'agent (surface, substrat).
Restaurer un checkpoint aux dimensions incohérentes avec la surface courante
→ panic ultérieur (ex. dans `si_global` quand `caps[i]` accède un indice
invalide). Le `_` supprime même l'avertissement.

**Recommandation** : exposer `Dims` dans l'erreur ou valider contre la surface
attendue au moment du `restore`.

---

## 4. Sécurité & robustesse

### Serveur MCP (`rsi_mcp.rs`)
- ✅ Parseur JSON limite la profondeur à 128 (anti stack-overflow, testé).
- ✅ API borne les ressources (`MAX_SESSIONS=64`, `MAX_TASKS=50_000`,
  `MAX_DIM=1024`, `MAX_STEPS=100_000`, `MAX_SUBSTRATE=256`).
- ✅ Nouvelle commande `run_until` expose le pilote L1 (cible, plateau,
  disjoncteur) via MCP — pilotable par un LLM.
- ⚠️ **Pas de limite de taille sur stdin** (inchangé) : un client hostile
  peut envoyer une ligne JSON de plusieurs Go → OOM.
- ⚠️ Pas de timeout sur la lecture stdin. Acceptable pour stdio.

### `install.sh` / `rsi-connect`
- ✅ `set -euo pipefail`, permissions `0600` sur les configs MCP.
- ⚠️ `install.sh` exécute `cargo build` sans vérifier la version de la
  toolchain (inchangé).

### SHA-256 maison (`sha256.rs`)
- ✅ Vecteurs FIPS 180-4 / NIST validés (inchangé).
- ⚠️ `msg = data.to_vec()` alloue une copie complète de l'entrée (inchangé,
  acceptable vu la taille des payloads).

### Nouveau : `vendor_scirust_rsi.sh`
- ✅ Vérification SHA-256 de l'archive extraite (constante `EXPECT_SHA`).
- ✅ Archive base64 + tar, auto-extractible, `set -euo pipefail`.
- ⚠️ Le script est un polyglotte bash+archive : l'exécution d'un script
  téléchargé sans inspection est intrinsèquement risquée, mais le checksum
  protège contre l'altération.

### Nouveau : `PapersKnowledge` (knowledge.rs)
- ⚠️ Appel sous-processus sans timeout ni limite de sortie (cf. bug G).
- ✅ Dégradation gracieuse testée (`papers_degrades_gracefully_when_absent`).
- ✅ Binaire résolu via `--bin`, `RSI_PAPERS_BIN`, ou `papers` (défaut).

---

## 5. Avertissements Clippy

**Statut : 0 warning** (était 7 en v0.9.0). Tous les warnings de style
(`field_reassign_with_default`, `needless_range_loop`,
`inherent_to_string_shadow`, `empty_format_string`,
`unwrap_used_after_is_some`, `is_multiple_of` manuel) ont été corrigés —
le dernier via `#[allow(clippy::inherent_to_string)]` documenté (json.rs:82).

`cargo clippy --all-targets --features scirust` : 0 warning également.

---

## 6. Cohérence licence

**Statut : inchangé (toujours incohérent).**
- `Cargo.toml:6` : `license = "PolyForm-Noncommercial-1.0.0"` (une seule
  licence).
- `README.md:222` et `LICENSING.md` : « Double licence » (non-commercial
  gratuit + commercial séparée).
- `vendor/scirust-rsi/Cargo.toml:6` : même licence unique.

Pour crates.io, soit déclarer `PolyForm-Noncommercial-1.0.0` seul (et
documenter la licence commerciale ailleurs), soit utiliser `license-file`.
Actuellement `cargo publish` serait cohérent mais le README peut induire en
erreur.

---

## 7. Points forts notables (nouveautés v0.10.0)

- **Loop Engineering complet (L1→L9)** : un epic structuré qui transforme
  `RSIAgent::run` (boucle aveugle de N pas) en un système de pilotage motivé
  — arrêt sur plateau/divergence/cible/timeout/disjoncteur/véto HITL, rollback,
  checkpoint/reprise, cadences multi-échelles auto-adaptatives, parallélisme
  par portefeuille. C'est un saut de maturité opérationnel.
- **Disjoncteur de criticité (L4)** : `breaker_rpn` arrête la boucle et
  restaure le dernier état sain si `max_rpn` dépasse un seuil — généralise le
  garde-fou de stabilité en garde-fou de sûreté. Testé
  (`circuit_breaker_trips_and_rolls_back`).
- **Observateur HITL (L6)** : `LoopObserver::on_step` peut vétoer la
  poursuite — human-in-the-loop propre, testé (`observer_veto_stops_loop`).
- **Checkpoint/reprise (L5)** : sérialisation JSON std-only de l'état macro,
  roundtrip testé, reprise testée (`resume_continues_improving`).
- **Corpus de tâches ancré** : `TaskCorpus::builtin()` et `extended()`
  remplacent les profils Dirichlet synthétiques par des archétypes réels
  (rappel_factuel, raisonnement_multi_etapes, planification_autonome, …).
  `GroundedCapability` (loi de Liebig) est plus fidèle qu'un produit scalaire.
- **ε adaptatif** : rend le garde-fou de non-régression sensible au bruit
  Monte-Carlo via `si_global_stats` (variance pondérée + taille effective de
  Kish). Évite les faux backtracks sous le bruit d'échantillonnage.
- **Stand-in `scirust-rsi` + pont réel** : `ascent.rs` reproduit le contrat du
  moteur réel en std-only, `scirust_bridge.rs` bascule vers le vrai moteur
  via une feature. Sandbox par AST interprété (jamais d'exécution de code
  généré). Vendorisation propre (path dep, checksum, hors-ligne).
- **Banc d'ablation** : `rsi-ablate` quantifie l'apport de chaque facteur
  (mémoire, substrat, connaissances, réponse active, ε adaptatif) sur le
  corpus élargi — démarche scientifique solide. Vérifie empiriquement
  « régressions notables = 0 ».
- **Banc de boucle** : `rsi-loopbench` mesure l'effet des cadences
  multi-échelles sur le coût (méta-évaluations) vs la convergence — valide
  l'efficacité de calcul de la boucle méta-méta.
- **Swarm** : parallélisme `std::thread::scope` propre, sélection par
  `SI_safe`, déterministe par graine. Testé (`swarm_is_deterministic`).

---

## 8. Recommandations prioritaires

1. **Bug A** (`dynamics.rs:85`) : remplacer `mean(&state.to_vector())` par
   `mean(&state.capability_array())` ou moyenne de D,M,R — corrige perf +
   sémantique. *(Recommandation inchangée de v0.9.0.)*
2. **Bug B** (`agent.rs`) : étendre le line search de non-régression au pas
   combiné (meta + apprentissage), ou clarifier dans le README que l'invariant
   ne couvre que l'étape d'apprentissage.
3. **Bug G** (`knowledge.rs:175`) : ajouter un timeout et une limite de sortie
   au sous-processus `papers`.
4. **Bug H** (`checkpoint.rs:140`) : valider les dimensions du checkpoint
   contre la surface attendue au `restore`.
5. **Bug F** (`swarm.rs:53`) : isoler les panics de membres (`join().ok()`
   + marquage invalide) au lieu de propager.
6. **MCP stdin** : ajouter un plafond de taille de ligne (ex. 16 MB) dans
   `rsi_mcp.rs` avant `Json::parse`. *(Inchangé.)*
7. **Licence** : aligner `Cargo.toml` avec la double licence déclarée ou
   corriger le README. *(Inchangé.)*

---

## 9. Verdict global

**Code de qualité supérieure, en progression nette.** L'epic « Loop
Engineering » transforme un prototype de recherche en un système pilotable
avec arrêts motivés, rollback, checkpoint, parallélisme — le saut de
maturité opérationnel le plus significatif depuis la v0.9.0. La dé-stylisation
(tâches ancrées, loi de Liebig, ε adaptatif, connaissances réelles) ancre le
modèle dans le concret sans trahir les garde-fous. Le pont `scirust-rsi`
est proprement isolé (sandbox AST, feature gate, vendorisation checksummée).

Les 8 problèmes identifiés sont tous mineurs à modérés (1 perf/sémantique, 1
invariant à étendre, 2 robustesse API, 2 robustesse sous-processus/thread, 2
cohérence licence/roundtrip) et **aucun n'est un bug critique de sécurité ou
de logique**. Les 5 bugs hérités de v0.9.0 (A-E) n'ont pas été corrigés mais
n'ont pas empiré non plus ; les 3 nouveaux (F-H) sont liés aux nouvelles
fonctionnalités et sont localisés. Le projet reste **publiable en l'état**
après correction du bug A (le plus impactant en perf) et de préférence du
bug G (sous-processus non borné).

---

## 10. Diff avec l'audit précédent (v0.9.0 → v0.10.0)

| Dimension | v0.9.0 | v0.10.0 | Δ |
|---|---|---|---|
| LOC cœur (src/) | ~3 200 | ~5 000 | +56 % |
| Modules src/ | 24 | 35 | +11 (ascent, checkpoint, convergence, knowledge, loop_ctrl, measured_substrate, schedule, scirust_bridge, swarm, synthesis, tasks) |
| Binaires | 4 | 5 | +1 (rsi_ablate, rsi_loopbench ; rsi_full inchangé) |
| Examples | 0 | 2 | +2 (self_improve, self_improve_real) |
| Tests lib | 54 | 89 | +35 |
| Warnings Clippy | 7 | 0 | corrigé ✅ |
| Features | 3 (forge, octasoma, ccos) | 4 (+scirust) | +1 |
| Bugs identifiés | 5 (A-E) | 8 (A-H) | +3 nouveaux, 0 corrigé |
| Features vendoring | non | scirust-rsi (path dep) | nouveau |

> **Mise à jour post-audit.** Les chiffres ci-dessus sont le **constat au moment
> de l'audit**. Depuis, **les 8 bugs A–H ont été corrigés** (correctifs validés,
> property tests, clippy 0 warning, et désormais une CI qui le verrouille). Le
> statut à jour est ci-dessous.

### Statut des bugs hérités (à jour)
- **Bug A** (dynamics.rs:85 saturation) — ✅ corrigé (saturation = moyenne D,M,R)
- **Bug B** (line search pas combiné) — ✅ corrigé (garde-fou §4bis combiné)
- **Bug C** (encode/decode bornes) — ✅ corrigé (bornes `decode` = `encode`, test étendu)
- **Bug D** (échappement `\u`) — ✅ corrigé (paires de surrogates UTF-16, RFC 8259)
- **Bug E** (`as_u64` silencieux) — ✅ corrigé (rejet NaN/∞/négatifs)

### Nouveaux bugs
- **Bug F** (swarm join unwrap) — ✅ corrigé (isolation des panics, `si_safe = −∞`)
- **Bug G** (PapersKnowledge sous-processus non borné) — ✅ corrigé (timeout 30 s / 8 MiB)
- **Bug H** (checkpoint validation dims) — ✅ corrigé (validation dimensionnelle au restore)

### Améliorations notables
- ✅ Clippy : 7 warnings → 0
- ✅ Tests : 54 → 89 (+35)
- ✅ Loop Engineering L1→L9 (pilotage motivé, disjoncteur, checkpoint, swarm)
- ✅ De-stylisation (corpus réel, loi de Liebig, ε adaptatif, connaissances)
- ✅ Pont scirust-rsi (sandbox AST, vendorisation, feature gate)
- ✅ Banc d'ablation + banc de boucle (validation empirique)

---

## 11. Nature du projet (mise à jour)

RSI reste un **cadre formel de sûreté pour l'auto-amélioration récursive
d'agents cognitifs** — un modèle mathématique exécutable qui formalise
*comment un agent peut s'améliorer lui-même sans diverger*. La v0.10.0
l'élargit dans trois directions :

1. **Ancrage réel** : Ω n'est plus synthétique (corpus de tâches ancrées),
  D est alimentée par de vraies sources (textes/PAPERS), P_eff est mesurée
  sur un vrai kernel CPU. Le modèle reste un modèle, mais ses entrées sont
  ancrées dans des données réelles plutôt que des Dirichlet abstraites.

2. **Pilotage opérationnel** : `run(N)` (boucle aveugle) devient `run_until`
  (arrêt motivé par plateau/cible/disjoncteur/véto), avec checkpoint/reprise,
  cadences auto-adaptatives et parallélisme. C'est le passage du « moteur de
  simulation » au « système pilotable ».

3. **Auto-amélioration bidirectionnelle** : le pont `scirust-rsi` ouvre la
  porte à un **vrai** moteur d'ascension élitiste (propose → évalue → garde
  si meilleur) sur un domaine de synthèse symbolique, en sandbox. L'agent
  génère et améliore des expressions arithmétiques — un cas d'usage concret
  (quoique jouet) d'auto-amélioration, au-delà de la dynamique abstraite.

### En une phrase (mise à jour)

> **Un laboratoire numérique std-only qui démontre, trajectoire reproductible
> à l'appui, comment encadrer par garde-fous mathématiques une boucle
> d'auto-amélioration récursive — désormais pilotable (arrêts motivés,
> checkpoint, swarm), ancrée sur des tâches/connaissances réelles, et ouverte
> à un moteur d'ascension réel via scirust-rsi.**

Le projet confirme son positionnement de **recherche en alignment / AI safety
formalisée en code**, avec une maturité opérationnelle en progression nette.
La double licence et l'orientation « contact@checkupauto.fr » suggèrent
toujours un positionnement à la fois académique et commercial discret.

---

*Fin du rapport — v0.10.0.*