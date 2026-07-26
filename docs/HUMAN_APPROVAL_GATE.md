# Human Approval Gate

The only authorized approver is **ZEKRITI Tarek**.

## What requires approval

- any patch promotion to a live tree (PATCH_PROMOTION_POLICY.md);
- any experiment leaving the sandbox boundary (network, filesystem outside
  the workspace snapshot, processes outside the cgroup/limits);
- any research-to-Core promotion (EXPERIMENT_TO_CORE_PROMOTION.md);
- any publication of results (benchmark or otherwise) naming CCOS products;
- any release artifact from this repository.

## How approval is recorded

- In the journal: a dedicated approval event (custom payload naming the
  approver, the artifact hash, and the decision).
- In git: the approving human signs the merge/commit through the normal
  single-maintainer flow (GOVERNANCE.md).

## What the gate is NOT

Not a rubber stamp: an approval records *informed* consent with the
experiment's report (including negative results — NEGATIVE_RESULTS_POLICY.md)
available to the approver.
