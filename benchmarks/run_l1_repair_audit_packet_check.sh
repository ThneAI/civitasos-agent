#!/usr/bin/env bash
# Lightweight L1 repair-audit packet closure check.
#
# This check does not start backend, agents, or an LLM. It creates a minimal
# controlled L1 packet, appends repair audit refs exported from contract-runner
# evidence, refreshes the packet manifest, and verifies validate -> import ->
# review as one closed loop.
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
CHECK_ROOT="${L1_REPAIR_AUDIT_PACKET_CHECK_ROOT:-runs/l1_repair_audit_packet_check_${RUN_TS}}"
PACKET_ROOT="$CHECK_ROOT/packet"
RUN_ROOT="$CHECK_ROOT/imported_run"
REPORT_ROOT="$CHECK_ROOT/reports"
CONTRACT_EVIDENCE="$CHECK_ROOT/source/contract_runner_evidence.json"
LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
GOAL_ID="${L1_REPAIR_AUDIT_PACKET_GOAL_ID:-h3-draft-goal:post_delivery_failure:l1-repair-audit-packet-check}"

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
mkdir -p "$PACKET_ROOT/identities" "$PACKET_ROOT/monitoring" "$PACKET_ROOT/sinks" "$REPORT_ROOT" "$(dirname "$CONTRACT_EVIDENCE")"

"$PYTHON" - "$PACKET_ROOT" "$CONTRACT_EVIDENCE" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

packet_root = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
now = datetime.now(timezone.utc)
ts = now.isoformat()

actors = [
    {
        "actor_id": "observer-001",
        "actor_role": "observability_owner",
        "display_name": "L1 Observability Owner",
        "signature_ref": "sigref:observer-001:l1-repair-audit-check",
        "accountability_ref": "accountability:observer-001",
    },
    {
        "actor_id": "agent-registrar-001",
        "actor_role": "external_agent_registrar",
        "display_name": "L1 External Agent Registrar",
        "signature_ref": "sigref:agent-registrar-001:l1-repair-audit-check",
        "accountability_ref": "accountability:agent-registrar-001",
    },
    {
        "actor_id": "agent-observer-001",
        "actor_role": "external_agent_observer",
        "display_name": "L1 External Agent Observer",
        "signature_ref": "sigref:agent-observer-001:l1-repair-audit-check",
        "accountability_ref": "accountability:agent-observer-001",
    },
    {
        "actor_id": "audit-owner-001",
        "actor_role": "audit_owner",
        "display_name": "L1 Audit Owner",
        "signature_ref": "sigref:audit-owner-001:l1-repair-audit-check",
        "accountability_ref": "accountability:audit-owner-001",
    },
]
(packet_root / "identities" / "operator_registry.json").write_text(
    json.dumps(actors, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(packet_root / "identities" / "external_agent_registry.json").write_text(
    json.dumps(
        [
            {
                "agent_id": "external-agent-001",
                "agent_role": "pilot_worker",
                "registration_ref": "agent-reg:l1-repair-audit-check:001",
            }
        ],
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)

probe_records = [
    {
        "type": "monitoring_green",
        "actor_id": "observer-001",
        "status": "green",
        "live_monitoring_ref": "lm:l1-repair-audit-check:001",
        "checked_at": ts,
    },
    {
        "type": "backend_health_probe_green",
        "actor_id": "observer-001",
        "status": "green",
        "backend_health_ref": "backend-health:l1-repair-audit-check:001",
        "checked_at": ts,
    },
]
(packet_root / "monitoring" / "probe-events.jsonl").write_text(
    "".join(json.dumps(record, sort_keys=True) + "\n" for record in probe_records),
    encoding="utf-8",
)

external_records = [
    {
        "type": "external_agent_registered",
        "actor_id": "agent-registrar-001",
        "status": "registered",
        "agent_id": "external-agent-001",
        "agent_role": "pilot_worker",
        "registration_ref": "agent-reg:l1-repair-audit-check:001",
        "registered_at": ts,
    },
    {
        "type": "external_agent_message_observed",
        "actor_id": "agent-observer-001",
        "status": "observed",
        "agent_id": "external-agent-001",
        "message_ref": "agent-msg:l1-repair-audit-check:001",
        "observed_at": ts,
    },
]
(packet_root / "sinks" / "external-agent-events.jsonl").write_text(
    "".join(json.dumps(record, sort_keys=True) + "\n" for record in external_records),
    encoding="utf-8",
)

audit_records = [
    {
        "type": "audit_event_recorded",
        "actor_id": "audit-owner-001",
        "status": "recorded",
        "audit_event_ref": "audit:l1-repair-audit-check:bootstrap",
        "recorded_at": ts,
    }
]
(packet_root / "sinks" / "audit-events.jsonl").write_text(
    "".join(json.dumps(record, sort_keys=True) + "\n" for record in audit_records),
    encoding="utf-8",
)

receipt_records = [
    {
        "type": "receipt_sink_ready",
        "actor_id": "audit-owner-001",
        "status": "ready",
        "receipt_sink_ref": "receipt-sink:l1-repair-audit-check:001",
        "ready_at": ts,
    }
]
(packet_root / "sinks" / "receipt-events.jsonl").write_text(
    "".join(json.dumps(record, sort_keys=True) + "\n" for record in receipt_records),
    encoding="utf-8",
)

evidence = {
    "schema_version": "l1-contract-runner-evidence-fixture:v1",
    "tasks": {
        "beta_task_id": {
            "id": "task-beta",
            "status": "Failed",
            "failure_reason": "worker_failed",
        }
    },
    "contract_log_hits": [
        {
            "log": "runs/l1-fixture/logs/beta.log",
            "line": "Delivery contract blocked task_execute for task-beta: output makes a positive H3/production authorization claim",
        }
    ],
    "non_claims": [
        "fixture_is_for_l1_smoke_packet_check_only",
        "fixture_does_not_claim_real_production_evidence",
    ],
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

window = {
    "prepared_at": ts,
    "started_at": (now - timedelta(minutes=5)).isoformat(),
    "ended_at": (now + timedelta(minutes=5)).isoformat(),
}
(packet_root.parent / "collection_window.json").write_text(
    json.dumps(window, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

"$PYTHON" scripts/l1_export_contract_audit_refs.py \
  --evidence "$CONTRACT_EVIDENCE" \
  --output "$PACKET_ROOT/sinks/audit-events.jsonl" \
  --actor-id audit-owner-001 \
  --audit-ref-prefix "audit:l1-repair-audit-check:repair" \
  --append >"$REPORT_ROOT/audit_ref_export.json"

read_manifest_time() {
  "$PYTHON" - "$CHECK_ROOT/collection_window.json" "$1" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data[sys.argv[2]])
PY
}

run_ledger write-l1-pilot-packet-manifest \
  --input-root "$PACKET_ROOT" \
  --packet-id "packet:${RUN_TS}:l1-repair-audit-check" \
  --prepared-by-actor-id audit-owner-001 \
  --prepared-at "$(read_manifest_time prepared_at)" \
  --collection-window-started-at "$(read_manifest_time started_at)" \
  --collection-window-ended-at "$(read_manifest_time ended_at)" \
  --operator-attestation-ref "operator-attestation:${RUN_TS}:l1-repair-audit-check" \
  --overwrite >"$REPORT_ROOT/manifest_write.json"

run_ledger validate-l1-pilot-input \
  --input-root "$PACKET_ROOT" \
  --output "$REPORT_ROOT/validation.json"

run_ledger run-l1-pilot-input \
  --input-root "$PACKET_ROOT" \
  --run-root "$RUN_ROOT" \
  --goal-id "$GOAL_ID" >"$REPORT_ROOT/import.json"

run_ledger review-l1-controlled-packet-run \
  --packet-root "$PACKET_ROOT" \
  --run-root "$RUN_ROOT" \
  --validation-report "$REPORT_ROOT/validation.json" \
  --output "$REPORT_ROOT/review.json"

"$PYTHON" - "$REPORT_ROOT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

reports = Path(sys.argv[1])
validation = json.loads((reports / "validation.json").read_text(encoding="utf-8"))
review = json.loads((reports / "review.json").read_text(encoding="utf-8"))
export = json.loads((reports / "audit_ref_export.json").read_text(encoding="utf-8"))
if validation.get("passed") is not True:
    raise SystemExit(f"L1 repair audit packet validation failed: {validation.get('failure_reasons')}")
if review.get("passed") is not True:
    raise SystemExit(f"L1 repair audit packet review failed: {review.get('failure_reasons')}")
if int(export.get("record_count") or 0) < 1:
    raise SystemExit("L1 repair audit packet check exported no audit ref records")
summary = {
    "schema_version": "l1-repair-audit-packet-check-summary:v1",
    "validation_passed": validation.get("passed"),
    "review_passed": review.get("passed"),
    "audit_ref_record_count": export.get("record_count"),
    "packet_root": str(reports.parent / "packet"),
    "run_root": str(reports.parent / "imported_run"),
}
(reports.parent / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "L1 repair audit packet closure check passed: $CHECK_ROOT"
