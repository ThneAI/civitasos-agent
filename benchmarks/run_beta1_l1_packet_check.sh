#!/usr/bin/env bash
# Beta-1 L1 evidence packet closure check.
#
# This uses fixture proposal content. It validates that a Beta-1
# proposal/receipt/audit byproduct can become an importable L1 packet.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if [ -x "./.venv/bin/python" ]; then
    PYTHON="./.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
  else
    PYTHON="python"
  fi
fi

RUN_TS="${RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
CHECK_ROOT="${BETA1_L1_PACKET_CHECK_ROOT:-runs/beta1_l1_packet_check_${RUN_TS}}"
RUN_ROOT="$CHECK_ROOT/source_run"
PACKET_ROOT="$CHECK_ROOT/packet"
IMPORTED_RUN_ROOT="$CHECK_ROOT/imported_run"
REPORT_ROOT="$CHECK_ROOT/reports"
LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
GOAL_ID="${BETA1_L1_PACKET_GOAL_ID:-h3-draft-goal:beta1-repo-review:l1-packet-check}"

run_ledger() {
  if [ -x "$LEDGER_ROOT/.venv/bin/civitasos-evidence-ledger" ]; then
    "$LEDGER_ROOT/.venv/bin/civitasos-evidence-ledger" "$@"
  elif command -v civitasos-evidence-ledger >/dev/null 2>&1; then
    civitasos-evidence-ledger "$@"
  elif [ -f "$LEDGER_ROOT/pyproject.toml" ] && command -v uv >/dev/null 2>&1; then
    (cd "$LEDGER_ROOT" && uv run civitasos-evidence-ledger "$@")
  else
    echo "civitasos-evidence-ledger is unavailable; set CIVITASOS_EVIDENCE_LEDGER_ROOT" >&2
    exit 127
  fi
}

rm -rf "$CHECK_ROOT"
mkdir -p "$RUN_ROOT" "$REPORT_ROOT"

TMP_REPO="$CHECK_ROOT/review_repo"
mkdir -p "$TMP_REPO"
git -C "$TMP_REPO" init >/dev/null
git -C "$TMP_REPO" config user.email "beta1@example.com"
git -C "$TMP_REPO" config user.name "Beta1 L1 Packet Check"
printf 'initial\n' > "$TMP_REPO/README.md"
git -C "$TMP_REPO" add README.md
git -C "$TMP_REPO" commit -m "initial" >/dev/null
printf 'initial\nreview target\n' > "$TMP_REPO/README.md"

"$PYTHON" scripts/beta1_repo_review_proposal.py prepare \
  --repo "$TMP_REPO" \
  --output-root "$RUN_ROOT" \
  --request-id beta1-l1-packet-check \
  --request-text "Review this repository state and produce a proposal only." \
  --operator-id l1-controlled-pilot-operator \
  --target-agent external-model-reviewer >"$REPORT_ROOT/prepare.json"

cat > "$RUN_ROOT/proposal.md" <<'EOF'
# Proposal

## Scope
Proposal-only repository review.

## Repository Evidence
README.md has a controlled review-target change.

## Findings
No repository mutation was performed by the reviewer.

## Proposal
Keep this as a manual operator decision candidate.

## Risks
The proposal must not be treated as merge, push, deploy, or production authorization.

## Operator Decision Required
An operator receipt is required before any manual follow-up.

## H3 Boundary
H.3 remains blocked; no production runtime execution; no production receipt writes.
EOF

cat > "$RUN_ROOT/external_model_summary.json" <<'EOF'
{
  "schema_version": "beta1-external-model-proposal-run-summary:v1",
  "model": "fixture-external-reviewer",
  "boundary": "proposal_only; H.3 remains blocked",
  "non_claims": [
    "fixture_is_for_l1_packet_check_only",
    "fixture_does_not_claim_h3_production_readiness"
  ]
}
EOF

"$PYTHON" scripts/beta1_repo_review_proposal.py receipt \
  --request "$RUN_ROOT/beta1_repo_review_proposal_request.json" \
  --proposal "$RUN_ROOT/proposal.md" \
  --output "$RUN_ROOT/operator_decision_receipt.json" \
  --decision deferred \
  --operator-id l1-controlled-pilot-operator \
  --reason "packet check only" \
  --audit-output "$RUN_ROOT/sinks/audit-events.jsonl" >"$REPORT_ROOT/receipt.json"

"$PYTHON" scripts/beta1_repo_review_proposal.py validate \
  --receipt "$RUN_ROOT/operator_decision_receipt.json" \
  --output "$RUN_ROOT/operator_decision_receipt_validation.json" >"$REPORT_ROOT/receipt_validation_stdout.json"

"$PYTHON" scripts/beta1_export_l1_packet.py \
  --run-root "$RUN_ROOT" \
  --packet-root "$PACKET_ROOT" \
  --overwrite >"$REPORT_ROOT/packet_export.json"

read_manifest_time() {
  "$PYTHON" - "$1" <<'PY'
import sys
from datetime import datetime, timedelta, timezone

kind = sys.argv[1]
now = datetime.now(timezone.utc)
if kind == "started_at":
    value = now - timedelta(seconds=60)
elif kind == "ended_at":
    value = now + timedelta(seconds=60)
else:
    value = now
print(value.isoformat().replace("+00:00", "Z"))
PY
}

run_ledger write-l1-pilot-packet-manifest \
  --input-root "$PACKET_ROOT" \
  --packet-id "packet:${RUN_TS}:beta1-l1-packet-check" \
  --prepared-by-actor-id audit-owner-001 \
  --prepared-at "$(read_manifest_time prepared_at)" \
  --collection-window-started-at "$(read_manifest_time started_at)" \
  --collection-window-ended-at "$(read_manifest_time ended_at)" \
  --operator-attestation-ref "operator-attestation:${RUN_TS}:beta1-l1-packet-check" \
  --overwrite >"$REPORT_ROOT/manifest_write.json"

run_ledger validate-l1-pilot-input \
  --input-root "$PACKET_ROOT" \
  --output "$REPORT_ROOT/validation.json"

run_ledger run-l1-pilot-input \
  --input-root "$PACKET_ROOT" \
  --run-root "$IMPORTED_RUN_ROOT" \
  --goal-id "$GOAL_ID" >"$REPORT_ROOT/import.json"

run_ledger review-l1-controlled-packet-run \
  --packet-root "$PACKET_ROOT" \
  --run-root "$IMPORTED_RUN_ROOT" \
  --validation-report "$REPORT_ROOT/validation.json" \
  --output "$REPORT_ROOT/review.json"

"$PYTHON" - "$REPORT_ROOT" "$PACKET_ROOT" "$IMPORTED_RUN_ROOT" <<'PY'
import json
import sys
from pathlib import Path

reports = Path(sys.argv[1])
packet = Path(sys.argv[2])
run = Path(sys.argv[3])
validation = json.loads((reports / "validation.json").read_text(encoding="utf-8"))
review = json.loads((reports / "review.json").read_text(encoding="utf-8"))
export = json.loads((reports / "packet_export.json").read_text(encoding="utf-8"))
if validation.get("passed") is not True:
    raise SystemExit(f"Beta-1 L1 packet validation failed: {validation.get('failure_reasons')}")
if review.get("passed") is not True:
    raise SystemExit(f"Beta-1 L1 packet review failed: {review.get('failure_reasons')}")
summary = {
    "schema_version": "beta1-l1-packet-check-summary:v1",
    "packet_root": str(packet),
    "imported_run_root": str(run),
    "validation_passed": validation.get("passed"),
    "review_passed": review.get("passed"),
    "exported": export.get("exported"),
    "request_id": export.get("request_id"),
    "decision": export.get("decision"),
    "source_record_count": validation.get("metrics", {}).get("source_record_count"),
    "boundary": "proposal_only; H.3 remains blocked",
}
(reports / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "Beta-1 L1 packet closure check passed: $CHECK_ROOT"
