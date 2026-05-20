#!/usr/bin/env bash
# Beta-2 patch-proposal packet closure check.
#
# This uses a fixture patch proposal. It verifies that patch artifacts can be
# validated, receipt-bound, and imported as L1 evidence without applying them.
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
CHECK_ROOT="${BETA2_PATCH_PROPOSAL_PACKET_CHECK_ROOT:-runs/beta2_patch_proposal_packet_check_${RUN_TS}}"
RUN_ROOT="$CHECK_ROOT/source_run"
PACKET_ROOT="$CHECK_ROOT/packet"
IMPORTED_RUN_ROOT="$CHECK_ROOT/imported_run"
REPORT_ROOT="$CHECK_ROOT/reports"
LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
GOAL_ID="${BETA2_PATCH_PROPOSAL_PACKET_GOAL_ID:-h3-draft-goal:beta2-patch-proposal:l1-packet-check}"

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
git -C "$TMP_REPO" config user.email "beta2@example.com"
git -C "$TMP_REPO" config user.name "Beta2 Patch Proposal Check"
printf 'initial\n' > "$TMP_REPO/README.md"
git -C "$TMP_REPO" add README.md
git -C "$TMP_REPO" commit -m "initial" >/dev/null

"$PYTHON" scripts/beta1_repo_review_proposal.py prepare \
  --repo "$TMP_REPO" \
  --output-root "$RUN_ROOT" \
  --request-id beta2-patch-proposal-check \
  --request-text "Generate a patch proposal only. Do not apply, commit, push, merge, or deploy." \
  --operator-id l1-controlled-pilot-operator \
  --target-agent external-model-reviewer >"$REPORT_ROOT/prepare.json"

cat > "$RUN_ROOT/patch_proposal.patch" <<'EOF'
diff --git a/README.md b/README.md
index e79c5e8..2a9f8c1 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 initial
+proposed beta2 change
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
  "boundary": "patch proposal only; H.3 remains blocked",
  "non_claims": [
    "fixture_is_for_l1_packet_check_only",
    "fixture_does_not_apply_patch",
    "fixture_does_not_claim_h3_production_readiness"
  ]
}
EOF

"$PYTHON" scripts/beta1_repo_review_proposal.py receipt \
  --request "$RUN_ROOT/beta1_repo_review_proposal_request.json" \
  --proposal "$RUN_ROOT/patch_proposal.patch" \
  --output "$RUN_ROOT/operator_decision_receipt.json" \
  --decision deferred \
  --operator-id l1-controlled-pilot-operator \
  --reason "patch proposal packet check only; patch not applied" \
  --audit-output "$RUN_ROOT/sinks/audit-events.jsonl" >"$REPORT_ROOT/receipt.json"

"$PYTHON" scripts/beta1_repo_review_proposal.py validate \
  --receipt "$RUN_ROOT/operator_decision_receipt.json" \
  --output "$RUN_ROOT/operator_decision_receipt_validation.json" >"$REPORT_ROOT/receipt_validation_stdout.json"

"$PYTHON" scripts/beta1_export_l1_packet.py \
  --run-root "$RUN_ROOT" \
  --packet-root "$PACKET_ROOT" \
  --overwrite >"$REPORT_ROOT/packet_export.json"

"$PYTHON" - "$RUN_ROOT" "$PACKET_ROOT" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

run_root = Path(sys.argv[1])
packet = Path(sys.argv[2])
receipt = json.loads((run_root / "operator_decision_receipt.json").read_text(encoding="utf-8"))
validation = json.loads((run_root / "beta2_patch_proposal_validation.json").read_text(encoding="utf-8"))
if validation.get("passed") is not True:
    raise SystemExit(f"Beta-2 patch validation failed: {validation}")
record = {
    "type": "audit_event_recorded",
    "actor_id": "audit-owner-001",
    "status": "recorded",
    "audit_event_ref": f"beta2-patch-validation:{receipt['request_id']}",
    "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "source_evidence_ref": str((run_root / "beta2_patch_proposal_validation.json").resolve()),
    "audit_ref_kind": "beta2_patch_proposal_validation",
    "request_id": receipt["request_id"],
    "patch_validation_passed": True,
    "patch_target_paths": validation.get("target_paths", []),
    "patch_applied": False,
    "commit_created": False,
    "push_performed": False,
    "merge_performed": False,
    "deploy_performed": False,
    "production_runtime_execution_allowed": False,
    "production_receipt_write_allowed": False,
    "non_claims": validation.get("non_claims", []),
}
with (packet / "sinks" / "audit-events.jsonl").open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
PY

run_ledger write-l1-pilot-packet-manifest \
  --input-root "$PACKET_ROOT" \
  --packet-id "packet:${RUN_TS}:beta2-patch-proposal-check" \
  --prepared-by-actor-id audit-owner-001 \
  --prepared-at "$(read_manifest_time prepared_at)" \
  --collection-window-started-at "$(read_manifest_time started_at)" \
  --collection-window-ended-at "$(read_manifest_time ended_at)" \
  --operator-attestation-ref "operator-attestation:${RUN_TS}:beta2-patch-proposal-check" \
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

"$PYTHON" - "$REPORT_ROOT" "$PACKET_ROOT" "$IMPORTED_RUN_ROOT" "$RUN_ROOT" <<'PY'
import json
import sys
from pathlib import Path

reports = Path(sys.argv[1])
packet = Path(sys.argv[2])
run = Path(sys.argv[3])
source = Path(sys.argv[4])
validation = json.loads((reports / "validation.json").read_text(encoding="utf-8"))
review = json.loads((reports / "review.json").read_text(encoding="utf-8"))
patch_validation = json.loads((source / "beta2_patch_proposal_validation.json").read_text(encoding="utf-8"))
receipt = json.loads((source / "operator_decision_receipt.json").read_text(encoding="utf-8"))
if validation.get("passed") is not True:
    raise SystemExit(f"Beta-2 L1 packet validation failed: {validation.get('failure_reasons')}")
if review.get("passed") is not True:
    raise SystemExit(f"Beta-2 L1 packet review failed: {review.get('failure_reasons')}")
summary = {
    "schema_version": "beta2-patch-proposal-packet-check-summary:v1",
    "packet_root": str(packet),
    "imported_run_root": str(run),
    "validation_passed": validation.get("passed"),
    "review_passed": review.get("passed"),
    "patch_validation_passed": patch_validation.get("passed"),
    "target_paths": patch_validation.get("target_paths"),
    "decision": receipt.get("decision"),
    "source_record_count": validation.get("metrics", {}).get("source_record_count"),
    "patch_applied": False,
    "commit_created": False,
    "push_performed": False,
    "merge_performed": False,
    "deploy_performed": False,
    "boundary": "patch proposal only; H.3 remains blocked",
}
(reports / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "Beta-2 patch proposal packet closure check passed: $CHECK_ROOT"
