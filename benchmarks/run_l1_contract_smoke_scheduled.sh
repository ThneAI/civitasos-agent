#!/usr/bin/env bash
# Scheduled strict L1 contract smoke wrapper.
#
# Intended for a backend/LLM/GPU-capable runner. It runs the strict smoke and
# appends a compact evidence index so operators can track run roots over time.
set -euo pipefail

cd "$(dirname "$0")/.."

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
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
BACKEND_URL="${BACKEND_URL:-http://localhost:8099}"
LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:11434/v1}"
L1_PILOT_001_CONTRACT_ROOT="${L1_PILOT_001_CONTRACT_ROOT:-runs/l1_contract_smoke_scheduled_${RUN_TS}}"
L1_CONTRACT_SMOKE_INDEX="${L1_CONTRACT_SMOKE_INDEX:-runs/l1_contract_smoke_index.jsonl}"
L1_CONTRACT_SMOKE_LATEST="${L1_CONTRACT_SMOKE_LATEST:-runs/l1_contract_smoke_latest.json}"

if [[ "$PYTHON" == */* ]]; then
  if [ ! -x "$PYTHON" ]; then
    echo "python not executable: $PYTHON" >&2
    exit 1
  fi
elif ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python command not found: $PYTHON" >&2
  exit 1
fi

curl -fsS "$BACKEND_URL/healthz" >/dev/null
if [ -n "${LLM_API_KEY:-}" ]; then
  curl -fsS "$LLM_BASE_URL/models" -H "Authorization: Bearer $LLM_API_KEY" >/dev/null
else
  curl -fsS "$LLM_BASE_URL/models" >/dev/null
fi

export BACKEND_URL
export LLM_BASE_URL
export L1_PILOT_001_CONTRACT_ROOT
export PYTHON

benchmarks/run_l1_contract_smoke.sh

EVIDENCE="$L1_PILOT_001_CONTRACT_ROOT/contract_runner_evidence.json"
"$PYTHON" - "$EVIDENCE" "$L1_CONTRACT_SMOKE_INDEX" "$L1_CONTRACT_SMOKE_LATEST" <<'PY'
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
index_path = Path(sys.argv[2])
latest_path = Path(sys.argv[3])

report = json.loads(evidence_path.read_text(encoding="utf-8"))
event_wake = report.get("event_wake_evidence") or {}
logs_dir = evidence_path.parent / "logs"
logs = ""
if logs_dir.exists():
    logs = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(logs_dir.glob("*.log"))
    )
entry = {
    "schema_version": "l1-contract-smoke-scheduled-index-entry:v1",
    "generated_at": report.get("generated_at"),
    "root": report.get("root"),
    "evidence_path": str(evidence_path),
    "chain_passed": report.get("chain_passed"),
    "stage_count": len(report.get("stage_reports", [])),
    "auth_method": (report.get("auth_context") or {}).get("auth_method"),
    "service_id": (report.get("auth_context") or {}).get("service_id"),
    "require_signed_wake": (report.get("wake_security") or {}).get("require_signed_wake"),
    "fallback_used": [
        (stage.get("wake") or {}).get("fallback_used")
        for stage in report.get("stage_reports", [])
    ],
    "wake_event_counts": event_wake.get("wake_event_counts") or {
        "task_posted": logs.count("WAKE received: event=task.posted"),
        "task_claimed": logs.count("WAKE received: event=task.claimed"),
        "task_delivered": logs.count("WAKE received: event=task.delivered"),
    },
    "rule_pool_claim_count": event_wake.get("rule_pool_claim_count", logs.count("Rule 'auto_claim_matching' fired: pool_claim")),
    "wake_action_bias_pool_claim_count": event_wake.get("wake_action_bias_pool_claim_count", logs.count("Wake action bias accepted: action=pool_claim")),
    "service_token_bootstrap_count": event_wake.get("service_token_bootstrap_count", logs.count("Service-token bootstrap token acquired")),
    "did_auth_bootstrap_count": event_wake.get("did_auth_bootstrap_count", logs.count("DID auth token bootstrapped")),
    "non_claims": [
        "scheduled_smoke_is_l1_controlled_pilot_only",
        "scheduled_smoke_does_not_claim_h3_production_readiness",
    ],
}
if entry["chain_passed"] is not True:
    raise SystemExit(f"cannot index failed L1 contract smoke: {evidence_path}")
if (report.get("wake_security") or {}).get("wake_mode") == "event":
    if entry["wake_action_bias_pool_claim_count"] < entry["stage_count"]:
        raise SystemExit(
            "cannot index L1 event wake smoke without wake action bias evidence "
            f"for every stage: {entry['wake_action_bias_pool_claim_count']}/{entry['stage_count']}"
        )
    missing = [
        stage.get("role")
        for stage in event_wake.get("stage_evidence", [])
        if stage.get("wake_action_bias_pool_claim_observed") is not True
    ]
    if missing:
        raise SystemExit(
            "cannot index L1 event wake smoke with missing per-stage wake action bias evidence: "
            + ", ".join(str(role) for role in missing)
        )

index_path.parent.mkdir(parents=True, exist_ok=True)
with index_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
latest_path.write_text(
    json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(f"L1 contract smoke indexed: {latest_path}")
PY
