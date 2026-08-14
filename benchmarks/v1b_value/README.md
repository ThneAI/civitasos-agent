# V1-B Offline External Value Receipt

This package builds a deterministic, append-disabled contract, receipt, preflight,
and Gate for one bounded external task/value case.

It separates four claims that must not be conflated:

- a real independent counterparty case reached a terminal outcome;
- independently verified external monetary or non-monetary value was received;
- external revenue was received through an allowed real-value environment;
- repeated market demand and sustainable unit economics were demonstrated.

One case can prove only the first three, depending on its Evidence. This Gate always
keeps market-demand and unit-economics claims false. Self-payment, affiliate payment,
test funds, internal CIV, fixture Evidence, refunds, and nonpayment cannot become
external revenue.

## Inputs

The contract binds distinct requester/provider identities, beneficial-control review,
consideration, requester consent, deliverable commitment, acceptance, dispute/refund
terms, and payment environment. The receipt binds the stable Backend-style task
receipt to acceptance, dispute, and an independently verifiable terminal value outcome.

Artifacts record hashes and sanitized accounting fields. They do not record raw
identity attestations, payment payloads, deliverables, credentials, or participant
content.

## Dry Run

Run the deterministic self-controlled test-funds fixture:

```bash
.venv/bin/python -m benchmarks.v1b_value.offline fixture \
  --output-root ~/.civitasos/private/v1b-value-dry-run-20260814
```

The directory is mode `0700` and JSON artifacts are mode `0600`. Expected decision:
`offline_dry_run_passed_real_counterparty_evidence_required`.

For private reviewed inputs, execute the two offline stages:

```bash
.venv/bin/python -m benchmarks.v1b_value.offline preflight \
  --contract CONTRACT.json \
  --receipt RECEIPT.json \
  --output PREFLIGHT.json

.venv/bin/python -m benchmarks.v1b_value.offline gate \
  --contract CONTRACT.json \
  --receipt RECEIPT.json \
  --preflight PREFLIGHT.json \
  --output GATE.json
```

Creating a real task, contacting a counterparty, executing work, moving funds, or
appending Backend Fact/Evidence Ledger entries remains outside this package and
requires separately reviewed authorization.
