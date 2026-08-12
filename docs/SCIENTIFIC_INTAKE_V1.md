# Scientific Intake v1

CCOS Research Lab accepts the PAPERS scientific interchange as **untrusted research data** and commits its provenance to the canonical hash-chained `EventLog`.

Supported schemas:

- `memorithm.science/bundle-v1`
- `memorithm.science/claim-v1`
- `memorithm.science/experiment-proposal-v1`
- `memorithm.science/experiment-result-v1`

Implementation: `src/scientific_intake.rs`.

## Bundle / claim intake

`import_scientific_bundle(raw, event_log)` validates schema tags, identifiers, paper/provenance consistency and SHA-256 fields before writing anything.

The event log does not copy paper/model prose. Titles, source strings, claim statements and evidence locators are represented by hashes. Stable typed identifiers and controlled enum values remain visible for audit.

Embedded experiment proposals are attested but are **not executed**.

## Experiment proposal

`import_experiment_proposal(raw, event_log)` validates and attests a standalone proposal. Required fields include a hypothesis, target component, intervention, baseline and `repetitions >= 1`.

`resource_limits` are part of the validated/audited policy envelope:

- `timeout_seconds`
- `max_memory_bytes`
- `max_output_bytes`

When present, each must be greater than zero. Importing the proposal never schedules the intervention or turns its free-form text into a command. An explicit sandbox/evaluator must still decide how a typed experiment is executed.

## Experiment result

`import_experiment_result(raw, event_log)` records empirical result status and finite metric values. Metric labels, units, artifact paths and timestamps are hashed before entering the event log; measured numeric values and uncertainty/sample counts remain available for evidence processing.

A `passed` experiment result does **not** automatically rewrite a paper claim to `reproduced`. Claim-state promotion needs an explicit policy tying the proposal's acceptance criteria, baseline and metrics to the observed result.

## Replay and integrity

CCOS `EventLog` excludes random event ids and wall-clock timestamps from its link hash. Therefore the same validated scientific payload sequence produces the same chain head across sessions while the stored trace events can still have unique ids/timestamps.

## Security boundary

Scientific intake is data ingestion, not instruction execution. Prompt-like text embedded in a paper or model output is hashed/audited and kept outside the executable control path. Execution belongs to an explicitly configured Research Lab sandbox or RSI `GuardedDgm` flow.
