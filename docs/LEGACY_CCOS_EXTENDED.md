# Legacy: CCOS_EXTENDED

CCOS Research Lab is the continuation of the historical `Memorithm/CCOS_EXTENDED`
repository (v0.4.0 "premium fusion").

## Provenance

| Item | Value |
|---|---|
| Historical repo | Memorithm/CCOS_EXTENDED (private; retained, NOT archived by the migration) |
| Historical HEAD at migration | `47e0889bd5bda5d77f92d091e31140053adaf7ca` (2026-07-19, PR #13) |
| Tags carried over | `v0.3.0` (b57ae6b9), `v0.4.0` (8fa68bb6 / release "ccos 0.4.0 — CCOS_EXTENDED premium fusion") |
| Branches carried over | `main`, `codex/full-security-hardening` |
| Relationship to CCOS | content superset of CCOS 0.3: 245/245 paths, 195 byte-identical, 50 modified, 375 added (migration report 05) |

## Migration notes

- All commit authorship was normalized to the sole human owner
  (migration report 03): AI systems that participated as tools were removed
  from author/committer fields and trailers. SHAs therefore differ from the
  historical repository.
- The hub package was renamed `ccos` → `ccos-research-lab` (lib
  `ccos_research_lab`); member crates keep their names (`rsi`, `forge-core`,
  `ccos-sandbox`, `scirust`, `octasoma`, `octacore`, …).
- Two environment-sensitive tests were fixed post-migration (egress port-1
  policy assertion; redirect-test server `Connection: close` header).

## Archival

The historical repository is archived manually by ZEKRITI Tarek only after the
complete migration is validated. This repository must never trigger that
archival automatically.
