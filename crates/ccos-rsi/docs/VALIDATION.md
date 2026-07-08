# Validation empirique — ablations & substrat GPU/temps réel

## Étude d'ablation des garde-fous & intégrations

Banc reproductible **cœur pur** (aucune feature) : `cargo run --release --bin
rsi-ablate -- [pas] [graines]`. Chaque configuration active/désactive un facteur,
sur le **corpus élargi** (Ω = 40 tâches ancrées), moyenné sur plusieurs graines.

Résultat (45 pas, 6 graines, graines 1000–1005) :

| configuration     |   SI   | SI_safe | risk_moy | risk_max | t@90 |  AUC   | interv | régr |
|-------------------|--------|---------|----------|----------|------|--------|--------|------|
| baseline (nu)     | 0.5666 | 0.5505  | 0.0238   | 0.0503   | 40.3 | 0.3303 |  0.0   | 0.0  |
| + mémoire         | 0.5635 | 0.5443  | 0.0256   | 0.0506   | 40.3 | 0.3296 |  0.0   | 0.0  |
| + substrat        | 0.5539 | 0.5303  | 0.0446   | 0.0840   | 35.3 | 0.3513 |  0.0   | 0.0  |
| + connaissances   | 0.5904 | 0.5739  | 0.0270   | 0.0502   | 37.7 | 0.3659 |  0.0   | 0.0  |
| + réponse active  | 0.5666 | 0.5505  | 0.0238   | 0.0503   | 40.3 | 0.3303 |  0.0   | 0.0  |
| + ε adaptatif     | 0.5605 | 0.5434  | 0.0162   | 0.0436   | 40.5 | 0.3228 |  0.0   | 0.0  |
| FULL (tout)       | 0.5587 | 0.5343  | 0.0419   | 0.0730   | 34.7 | 0.3752 |  1.3   | 0.0  |

### Lecture (constats honnêtes)
- **Non-régression préservée** : `régr = 0` partout → le garde-fou de
  non-régression tient quelle que soit la configuration (résultat le plus
  important côté sûreté).
- **Connaissances** : font monter la compétence (`SI` 0.567 → 0.590) — `D` réelle
  nourrit `L(D)`.
- **Substrat mesuré** : **accélère** la convergence (`t@90` 40 → 35, `AUC` ↑) mais
  **augmente le risque mesuré** (`risk_max` 0.050 → 0.084) car la mesure réelle
  active le détecteur *wireheading* (l'agent ne se ment pas sur son substrat).
- **ε adaptatif** : trajectoire plus **lisse** (`risk` moyen/max les plus bas) —
  on ne sur-réagit pas au bruit Monte-Carlo.
- **Réponse active** : ne se déclenche **que** lorsque le RPN franchit le seuil
  (ici uniquement en `FULL`, où le substrat pousse le risque) — coût en
  interventions, **zéro régression** induite.

> Ces chiffres ne « survendent » pas les intégrations : sur le SI brut on reste
> proche de l'attracteur substrate-limited ; la valeur ajoutée est la **vitesse**
> (substrat), la **compétence** (connaissances), la **stabilité** (ε adaptatif)
> et la **détection/maîtrise du risque** (réponse active), sans jamais régresser.

Pour rejouer / exporter : `cargo run --release --bin rsi-ablate -- 60 10 > ablation.txt`.

## Substrat GPU / temps réel

État : **hors périmètre de l'environnement de CI** (pas de GPU, pas de
toolchain CUDA), mais le chemin est clair et déjà cablé côté code :

| Niveau | Implémentation | Disponibilité |
|--------|----------------|---------------|
| CPU portable | `MeasuredSubstrate` (cœur, std-only) — kernel matmul chronométré | partout ✅ |
| CPU/SIMD & GPU évolués | **Forge** domaines `simd_gemm` / `cuda_kernel` (via `ForgeSubstrate`) | runtime : nécessite `cargo`/`rustc` (SIMD) ou `nvcc` + GPU (CUDA) |

- Le `SubstrateImprover` est un **trait** : brancher un améliorateur GPU revient
  à fournir une implémentation qui mesure un kernel sur accélérateur et renvoie
  l'efficience — sans toucher au cœur.
- Forge gère déjà l'évolution de kernels **SIMD/CUDA** quand la toolchain est
  présente ; `ForgeSubstrate` y donne accès. En CI (sans GPU), on s'appuie sur
  `MeasuredSubstrate` (CPU), d'où sa présence native.
- **Temps réel** : non visé à ce stade (la boucle est discrète et déterministe) ;
  ce serait un objectif distinct, dépendant d'un ordonnanceur temps réel.

Conclusion : la **dépendance au GPU n'est pas un blocage de conception** (seam
par trait + Forge), seulement une indisponibilité d'environnement. Le banc CPU
reste pleinement représentatif des dynamiques de substrat.
