# OctaSoma canonical source

Research Lab consumes OctaSoma from the canonical `Memorithm/octasoma` repository at an immutable reviewed Git revision.

For the v0.5 integration, every active OctaSoma dependency in the Research workspace resolves to:

`145761aeb52ef8ded85dcf2b8c97690005284926`

The root Research package, OctaCore, and RSI integration must use the same Cargo source identity. CI and lockfile review must reject stale vendor revisions or multiple `octasoma` package identities.

Historical local copies may not be reintroduced into the active dependency graph.
