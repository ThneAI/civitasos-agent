#!/usr/bin/env bash
# Beta-0 real-model controlled pilot wrapper.
#
# This is the first safe entry point for external LLM-backed CivitasOS usage.
# It runs the existing strict L1 alpha -> beta -> gamma contract chain with:
# - non-Ollama model by default
# - service-token auth
# - signed event wake
# - no production/H.3 readiness claims
# - optional L1 packet byproduct check
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

BACKEND_URL="${BACKEND_URL:-${CIVITASOS_URL:-http://localhost:8099}}"
AGENT_LLM="${AGENT_LLM:-}"
LLM_BASE_URL="${LLM_BASE_URL:-}"
LLM_API_KEY="${LLM_API_KEY:-}"
BETA0_REQUIRE_EXTERNAL_MODEL="${BETA0_REQUIRE_EXTERNAL_MODEL:-1}"
BETA0_RUN_ROOT="${BETA0_RUN_ROOT:-runs/beta0_real_model_pilot_${RUN_TS}}"
BETA0_SUMMARY="${BETA0_SUMMARY:-$BETA0_RUN_ROOT/beta0_real_model_pilot_summary.json}"
BETA0_RUN_PACKET_CHECK="${BETA0_RUN_PACKET_CHECK:-auto}"
BETA0_PACKET_CHECK_ROOT="${BETA0_PACKET_CHECK_ROOT:-$BETA0_RUN_ROOT/l1_repair_audit_packet_check}"

if [[ "$PYTHON" == */* ]]; then
  if [ ! -x "$PYTHON" ]; then
    echo "python not executable: $PYTHON" >&2
    exit 1
  fi
elif ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python command not found: $PYTHON" >&2
  exit 1
fi

if [ -z "$AGENT_LLM" ]; then
  echo "Beta-0 requires AGENT_LLM, for example openai:<model> or anthropic:<model>" >&2
  exit 1
fi
if [ -z "$LLM_API_KEY" ]; then
  echo "Beta-0 requires LLM_API_KEY for the external model provider" >&2
  exit 1
fi
if [ "$BETA0_REQUIRE_EXTERNAL_MODEL" = "1" ]; then
  if [[ "$AGENT_LLM" == ollama:* ]]; then
    echo "Beta-0 requires an external model; AGENT_LLM must not use ollama:*" >&2
    exit 1
  fi
  if [[ "$LLM_BASE_URL" == *"11434"* ]]; then
    echo "Beta-0 requires an external model endpoint; LLM_BASE_URL must not point to local Ollama" >&2
    exit 1
  fi
fi

if [ -z "${L1_PILOT_001_WAKE_CALLBACK_SECRET:-${CIVITASOS_WAKE_CALLBACK_SECRET:-}}" ]; then
  echo "Beta-0 requires signed wake; set L1_PILOT_001_WAKE_CALLBACK_SECRET or CIVITASOS_WAKE_CALLBACK_SECRET" >&2
  exit 1
fi
if [ -z "${L1_PILOT_001_SERVICE_TOKEN_SECRET:-${CIVITASOS_SERVICE_TOKEN_SECRET:-}}" ]; then
  echo "Beta-0 requires service-token auth; set L1_PILOT_001_SERVICE_TOKEN_SECRET or CIVITASOS_SERVICE_TOKEN_SECRET" >&2
  exit 1
fi

curl -fsS "$BACKEND_URL/healthz" >/dev/null

export BACKEND_URL
export AGENT_LLM
export LLM_BASE_URL
export LLM_API_KEY
export PYTHON
export L1_PILOT_001_CONTRACT_ROOT="$BETA0_RUN_ROOT/contract_smoke"
export L1_PILOT_001_WAKE_MODE="${L1_PILOT_001_WAKE_MODE:-event}"
export L1_PILOT_001_REQUIRE_SIGNED_WAKE=1
export L1_PILOT_001_REQUIRE_SERVICE_TOKEN=1
export L1_PILOT_001_EVENT_WAKE_GRACE="${L1_PILOT_001_EVENT_WAKE_GRACE:-25}"
export L1_PILOT_001_STAGE_TIMEOUT="${L1_PILOT_001_STAGE_TIMEOUT:-360}"
export L1_PILOT_001_POLL_INTERVAL="${L1_PILOT_001_POLL_INTERVAL:-5}"

mkdir -p "$BETA0_RUN_ROOT"
benchmarks/run_l1_contract_smoke.sh

PACKET_CHECK_STATUS="skipped"
LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
if [ "$BETA0_RUN_PACKET_CHECK" != "0" ]; then
  if [ -d "$LEDGER_ROOT" ]; then
    CIVITASOS_EVIDENCE_LEDGER_ROOT="$LEDGER_ROOT" \
    L1_REPAIR_AUDIT_PACKET_CHECK_ROOT="$BETA0_PACKET_CHECK_ROOT" \
    PYTHON="$PYTHON" \
      benchmarks/run_l1_repair_audit_packet_check.sh
    PACKET_CHECK_STATUS="passed"
  elif [ "$BETA0_RUN_PACKET_CHECK" = "1" ]; then
    echo "BETA0_RUN_PACKET_CHECK=1 but ledger repo not found: $LEDGER_ROOT" >&2
    exit 1
  fi
fi

"$PYTHON" - "$BETA0_RUN_ROOT" "$BETA0_SUMMARY" "$PACKET_CHECK_STATUS" "$AGENT_LLM" "$LLM_BASE_URL" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
packet_check_status = sys.argv[3]
agent_llm = sys.argv[4]
llm_base_url = sys.argv[5]
evidence_path = root / "contract_smoke" / "contract_runner_evidence.json"
evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
summary = {
    "schema_version": "beta0-real-model-pilot-summary:v1",
    "run_root": str(root),
    "evidence_path": str(evidence_path),
    "chain_passed": evidence.get("chain_passed"),
    "stage_count": len(evidence.get("stage_reports", [])),
    "auth_method": (evidence.get("auth_context") or {}).get("auth_method"),
    "service_id": (evidence.get("auth_context") or {}).get("service_id"),
    "wake_mode": (evidence.get("wake_security") or {}).get("wake_mode"),
    "require_signed_wake": (evidence.get("wake_security") or {}).get("require_signed_wake"),
    "agent_llm": agent_llm,
    "llm_base_url_configured": bool(llm_base_url),
    "packet_check_status": packet_check_status,
    "boundary": "L1 controlled pilot only; H.3 remains blocked.",
    "non_claims": [
        "beta0_real_model_pilot_does_not_claim_h3_production_readiness",
        "beta0_real_model_pilot_does_not_authorize_production_runtime_execution",
        "beta0_real_model_pilot_does_not_write_production_receipts",
    ],
}
if summary["chain_passed"] is not True:
    raise SystemExit(f"Beta-0 real model pilot failed: {evidence_path}")
if summary["auth_method"] != "service_token":
    raise SystemExit(f"Beta-0 requires service_token auth_context: {summary['auth_method']}")
if summary["require_signed_wake"] is not True:
    raise SystemExit("Beta-0 requires signed wake evidence")
summary_path.write_text(
    json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
PY

echo "Beta-0 real-model controlled pilot passed: $BETA0_SUMMARY"
