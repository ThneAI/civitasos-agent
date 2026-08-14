# V1-A2 Offline Cost Intake

This package converts reviewed cost-source declarations and Runtime cost requests into
a deterministic, append-disabled Fact batch and reconciliation Gate.

It is an offline preparation boundary. It never reads provider credentials, calls a
model, executes a participant or Agent, appends Backend Facts, appends the Evidence
Ledger, or performs payment. A passing real-input Gate still requires a separately
reviewed, single-use append authorization.

## Input Contract

The source manifest binds every cost category to:

- a provenance class and measurement scope;
- a content-addressed Evidence reference;
- explicit `real_external_source` and `independently_reviewed` declarations;
- a Runtime `rate_published` request using the same Evidence reference.

Every cohort entry binds one `source_id` to one reservation and exactly one terminal
state: `reconciled`, `unknown`, or `waived`. Reconciled entries require a measurement.
Unknown entries retain a positive conservative upper bound. Multi-currency totals stay
separate and are never converted implicitly.

Real input collection needs the following source artifacts. Values may remain unknown
until these artifacts exist; estimated values must not be labelled as observed.

| Category | Minimum source artifact | Measurement scope |
| --- | --- | --- |
| Storage | provider invoice/export or host meter snapshot | allocated byte-seconds retained during the cohort window |
| Network | provider invoice/export or transport meter receipt | application payload bytes, with the accounting layer stated |
| Operator time | signed operator policy plus activity attestations | active review/recovery seconds by role and activity code |

The artifact records hashes and sanitized accounting fields, not invoice payloads,
credentials, participant content, or provider response content.

## Dry Run

Run the deterministic five-task fixture from the Agent virtual environment:

```bash
.venv/bin/python -m benchmarks.v1a_cost.offline fixture \
  --output-root ~/.civitasos/private/v1a-cost-dry-run-20260814
```

The output directory is mode `0700`; JSON artifacts are mode `0600`. The expected
decision is `offline_dry_run_passed_real_source_review_required`. Fixture Evidence can
never pass the real-source Gate.

For separately prepared private inputs, execute the stages in order:

```bash
.venv/bin/python -m benchmarks.v1a_cost.offline preflight \
  --source-manifest SOURCE.json \
  --cohort-plan PLAN.json \
  --output PREFLIGHT.json

.venv/bin/python -m benchmarks.v1a_cost.offline batch \
  --source-manifest SOURCE.json \
  --cohort-plan PLAN.json \
  --preflight PREFLIGHT.json \
  --entry-set ENTRIES.json \
  --output FACT-BATCH.json

.venv/bin/python -m benchmarks.v1a_cost.offline gate \
  --source-manifest SOURCE.json \
  --cohort-plan PLAN.json \
  --preflight PREFLIGHT.json \
  --entry-set ENTRIES.json \
  --fact-batch FACT-BATCH.json \
  --output GATE.json
```

Source manifests, cohort plans, and entry sets should be built with
`build_source_manifest`, `build_cohort_plan`, and `build_entry_set`; these builders use
the existing `civitasos-runtime` cost request schemas and reject incomplete bindings.

## Gate Semantics

`offline_structural_passed` proves schema, self-hash, lineage, rate, source, terminal,
coverage, arithmetic, and currency consistency for the supplied artifacts.

`real_cohort_gate_passed` additionally requires every declared source to be real and
independently reviewed, every reservation to have a terminal state, and zero unknown
cost entries. It does not authorize append or a VMV maturity claim.
