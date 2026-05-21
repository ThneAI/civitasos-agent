#!/usr/bin/env bash
# Beta-2 manual operator apply evidence packet closure check.
#
# The only patch application here is a fixture git apply inside a temporary
# repository. Production Beta-2 still requires a human operator apply action.
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
CHECK_ROOT="${BETA2_OPERATOR_APPLY_PACKET_CHECK_ROOT:-runs/beta2_operator_apply_packet_check_${RUN_TS}}"
RUN_ROOT="$CHECK_ROOT/source_run"
PACKET_ROOT="$CHECK_ROOT/packet"
IMPORTED_RUN_ROOT="$CHECK_ROOT/imported_run"
REPORT_ROOT="$CHECK_ROOT/reports"
LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
GOAL_ID="${BETA2_OPERATOR_APPLY_PACKET_GOAL_ID:-h3-draft-goal:beta2-operator-apply:l1-packet-check}"

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

rm -rf "$CHECK_ROOT"
mkdir -p "$RUN_ROOT" "$REPORT_ROOT"

TMP_REPO="$CHECK_ROOT/review_repo"
mkdir -p "$TMP_REPO"
git -C "$TMP_REPO" init >/dev/null
git -C "$TMP_REPO" config user.email "beta2-apply@example.com"
git -C "$TMP_REPO" config user.name "Beta2 Operator Apply Check"
printf 'initial\n' > "$TMP_REPO/README.md"
git -C "$TMP_REPO" add README.md
git -C "$TMP_REPO" commit -m "initial" >/dev/null

"$PYTHON" scripts/beta1_repo_review_proposal.py prepare \
  --repo "$TMP_REPO" \
  --output-root "$RUN_ROOT" \
  --request-id beta2-operator-apply-check \
  --request-text "Generate a patch proposal only; operator may manually apply after approval." \
  --operator-id l1-controlled-pilot-operator \
  --target-agent external-model-reviewer >"$REPORT_ROOT/prepare.json"

cat > "$RUN_ROOT/patch_proposal.patch" <<'EOF'
diff --git a/README.md b/README.md
index e79c5e8..3e8c4e9 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 initial
+operator manually applied fixture proposal
EOF

"$PYTHON" scripts/beta2_patch_proposal.py validate \
  --repo "$TMP_REPO" \
  --request "$RUN_ROOT/beta1_repo_review_proposal_request.json" \
  --patch "$RUN_ROOT/patch_proposal.patch" \
  --allow-path-prefix README.md \
  --output "$RUN_ROOT/beta2_patch_proposal_validation.json" >"$REPORT_ROOT/patch_validation_stdout.json"

cat > "$RUN_ROOT/external_model_summary.json" <<'EOF'
{
  "schema_version": "beta2-external-model-patch-proposal-run-summary:v1",
  "model": "fixture-external-patch-proposer",
  "output_kind": "patch_proposal",
  "boundary": "patch proposal only; H.3 remains blocked"
}
EOF

"$PYTHON" scripts/beta1_repo_review_proposal.py receipt \
  --request "$RUN_ROOT/beta1_repo_review_proposal_request.json" \
  --proposal "$RUN_ROOT/patch_proposal.patch" \
  --output "$RUN_ROOT/operator_decision_receipt.json" \
  --decision approved \
  --operator-id l1-controlled-pilot-operator \
  --reason "approved for fixture manual apply only" \
  --audit-output "$RUN_ROOT/sinks/audit-events.jsonl" >"$REPORT_ROOT/proposal_receipt.json"

"$PYTHON" scripts/beta1_repo_review_proposal.py validate \
  --receipt "$RUN_ROOT/operator_decision_receipt.json" \
  --output "$RUN_ROOT/operator_decision_receipt_validation.json" >"$REPORT_ROOT/proposal_receipt_validation_stdout.json"

"$PYTHON" scripts/beta1_export_l1_packet.py \
  --run-root "$RUN_ROOT" \
  --packet-root "$PACKET_ROOT" \
  --overwrite >"$REPORT_ROOT/packet_export.json"

# Fixture-only manual apply simulation in a temporary repository.
git -C "$TMP_REPO" apply "$RUN_ROOT/patch_proposal.patch"
git -C "$TMP_REPO" diff > "$RUN_ROOT/applied_diff.patch"

"$PYTHON" scripts/beta2_operator_apply_receipt.py record \
  --repo "$TMP_REPO" \
  --patch-validation "$RUN_ROOT/beta2_patch_proposal_validation.json" \
  --proposal-receipt "$RUN_ROOT/operator_decision_receipt.json" \
  --applied-diff "$RUN_ROOT/applied_diff.patch" \
  --output "$RUN_ROOT/beta2_operator_apply_receipt.json" \
  --operator-id l1-controlled-pilot-operator \
  --reason "fixture operator manually applied approved patch proposal" \
  --tests-status passed \
  --tests-ref "tests:beta2-operator-apply-fixture:passed" \
  --manual-apply-confirmed \
  --audit-output "$PACKET_ROOT/sinks/audit-events.jsonl" \
  --append >"$REPORT_ROOT/operator_apply_receipt.json"

"$PYTHON" scripts/beta2_operator_apply_receipt.py validate \
  --receipt "$RUN_ROOT/beta2_operator_apply_receipt.json" \
  --output "$RUN_ROOT/beta2_operator_apply_receipt_validation.json" >"$REPORT_ROOT/operator_apply_validation_stdout.json"

run_ledger write-l1-pilot-packet-manifest \
  --input-root "$PACKET_ROOT" \
  --packet-id "packet:${RUN_TS}:beta2-operator-apply-check" \
  --prepared-by-actor-id audit-owner-001 \
  --prepared-at "$(read_manifest_time prepared_at)" \
  --collection-window-started-at "$(read_manifest_time started_at)" \
  --collection-window-ended-at "$(read_manifest_time ended_at)" \
  --operator-attestation-ref "operator-attestation:${RUN_TS}:beta2-operator-apply-check" \
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

"$PYTHON" - "$RUN_ROOT" "$REPORT_ROOT" "$PACKET_ROOT" "$IMPORTED_RUN_ROOT" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
reports = Path(sys.argv[2])
packet = Path(sys.argv[3])
run = Path(sys.argv[4])
packet_validation = json.loads((reports / "validation.json").read_text(encoding="utf-8"))
review = json.loads((reports / "review.json").read_text(encoding="utf-8"))
apply_validation = json.loads((source / "beta2_operator_apply_receipt_validation.json").read_text(encoding="utf-8"))
apply_receipt = json.loads((source / "beta2_operator_apply_receipt.json").read_text(encoding="utf-8"))
if packet_validation.get("passed") is not True:
    raise SystemExit(f"Beta-2 operator apply packet validation failed: {packet_validation.get('failure_reasons')}")
if review.get("passed") is not True:
    raise SystemExit(f"Beta-2 operator apply packet review failed: {review.get('failure_reasons')}")
if apply_validation.get("passed") is not True:
    raise SystemExit(f"Beta-2 operator apply receipt validation failed: {apply_validation.get('failure_reasons')}")
summary = {
    "schema_version": "beta2-operator-apply-packet-check-summary:v1",
    "packet_root": str(packet),
    "imported_run_root": str(run),
    "validation_passed": packet_validation.get("passed"),
    "review_passed": review.get("passed"),
    "apply_receipt_validation_passed": apply_validation.get("passed"),
    "manual_apply_confirmed": apply_receipt.get("manual_apply_confirmed"),
    "applied_target_paths": apply_receipt.get("applied_diff", {}).get("target_paths"),
    "tests": apply_receipt.get("tests"),
    "source_record_count": packet_validation.get("metrics", {}).get("source_record_count"),
    "auto_apply_performed": False,
    "commit_created_by_tool": False,
    "push_performed_by_tool": False,
    "merge_performed_by_tool": False,
    "deploy_performed_by_tool": False,
    "boundary": "operator manual L1 apply receipt only; H.3 remains blocked",
}
(reports / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "Beta-2 operator apply packet closure check passed: $CHECK_ROOT"
