#!/usr/bin/env bash
# Strict L1 Pilot 001 contract smoke.
#
# This runs only the L1 alpha -> beta -> gamma contract chain. Unlike the full
# nightly wrapper, it does not execute the broader F/G/H regression gates.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-./.venv/bin/python}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8099}"
LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:11434/v1}"
AGENT_LLM="${AGENT_LLM:-ollama:qwen3:latest}"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
L1_PILOT_001_CONTRACT_ROOT="${L1_PILOT_001_CONTRACT_ROOT:-runs/l1_contract_smoke_${RUN_TS}}"
L1_PILOT_001_WAKE_MODE="${L1_PILOT_001_WAKE_MODE:-event}"
L1_PILOT_001_EVENT_WAKE_GRACE="${L1_PILOT_001_EVENT_WAKE_GRACE:-25}"
L1_PILOT_001_STAGE_TIMEOUT="${L1_PILOT_001_STAGE_TIMEOUT:-240}"
L1_PILOT_001_POLL_INTERVAL="${L1_PILOT_001_POLL_INTERVAL:-5}"
L1_PILOT_001_ENABLE_EVENT_WAKE="${L1_PILOT_001_ENABLE_EVENT_WAKE:-1}"
L1_PILOT_001_GATEWAY_BASE_PORT="${L1_PILOT_001_GATEWAY_BASE_PORT:-18710}"
L1_PILOT_001_AGENT_HOST="${L1_PILOT_001_AGENT_HOST:-127.0.0.1}"
L1_PILOT_001_REQUIRE_SIGNED_WAKE="${L1_PILOT_001_REQUIRE_SIGNED_WAKE:-1}"
L1_PILOT_001_REQUIRE_SERVICE_TOKEN="${L1_PILOT_001_REQUIRE_SERVICE_TOKEN:-1}"
L1_PILOT_001_WAKE_CALLBACK_SECRET="${L1_PILOT_001_WAKE_CALLBACK_SECRET:-${CIVITASOS_WAKE_CALLBACK_SECRET:-}}"
L1_PILOT_001_SERVICE_TOKEN_SECRET="${L1_PILOT_001_SERVICE_TOKEN_SECRET:-${CIVITASOS_SERVICE_TOKEN_SECRET:-}}"
L1_PILOT_001_SERVICE_ID="${L1_PILOT_001_SERVICE_ID:-l1_contract_runner}"
L1_PILOT_001_SERVICE_SCOPES="${L1_PILOT_001_SERVICE_SCOPES:-agents:read,agents:write,pool:post,pool:read,pool:claim,pool:write,webhooks:write}"

l1_service_scope_present() {
  local required="$1"
  local scope_domain="${required%%:*}"
  local compact_scopes="${L1_PILOT_001_SERVICE_SCOPES//[[:space:]]/}"
  case ",$compact_scopes," in
    *,"$required",*|*,"$scope_domain:*",*|*,\*,*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$L1_PILOT_001_REQUIRE_SIGNED_WAKE" = "1" ] && [ -z "$L1_PILOT_001_WAKE_CALLBACK_SECRET" ]; then
  echo "L1 contract smoke requires signed wake; set L1_PILOT_001_WAKE_CALLBACK_SECRET or CIVITASOS_WAKE_CALLBACK_SECRET" >&2
  exit 1
fi

if [ "$L1_PILOT_001_REQUIRE_SERVICE_TOKEN" = "1" ]; then
  if [ -z "$L1_PILOT_001_SERVICE_TOKEN_SECRET" ]; then
    echo "L1 contract smoke requires service token auth; set L1_PILOT_001_SERVICE_TOKEN_SECRET or CIVITASOS_SERVICE_TOKEN_SECRET" >&2
    exit 1
  fi
  for required_scope in agents:read agents:write pool:post pool:read pool:claim pool:write webhooks:write; do
    if ! l1_service_scope_present "$required_scope"; then
      echo "L1 contract smoke service token scopes missing required scope: $required_scope" >&2
      echo "Configured scopes: $L1_PILOT_001_SERVICE_SCOPES" >&2
      exit 1
    fi
  done
fi

RUNNER_ARGS=(
  --base-url "$BACKEND_URL"
  --root "$L1_PILOT_001_CONTRACT_ROOT"
  --python "$PYTHON"
  --wake-mode "$L1_PILOT_001_WAKE_MODE"
  --event-wake-grace "$L1_PILOT_001_EVENT_WAKE_GRACE"
  --stage-timeout "$L1_PILOT_001_STAGE_TIMEOUT"
  --poll-interval "$L1_PILOT_001_POLL_INTERVAL"
)

if [ "$L1_PILOT_001_REQUIRE_SIGNED_WAKE" = "1" ]; then
  RUNNER_ARGS+=(--require-signed-wake)
fi

L1_PILOT_ROOT="$L1_PILOT_001_CONTRACT_ROOT" \
CIVITASOS_URL="$BACKEND_URL" \
AGENT_LLM="$AGENT_LLM" \
LLM_BASE_URL="$LLM_BASE_URL" \
L1_ENABLE_EVENT_WAKE="$L1_PILOT_001_ENABLE_EVENT_WAKE" \
L1_GATEWAY_BASE_PORT="$L1_PILOT_001_GATEWAY_BASE_PORT" \
L1_AGENT_HOST="$L1_PILOT_001_AGENT_HOST" \
L1_REQUIRE_SIGNED_WAKE="$L1_PILOT_001_REQUIRE_SIGNED_WAKE" \
L1_REQUIRE_SERVICE_TOKEN="$L1_PILOT_001_REQUIRE_SERVICE_TOKEN" \
CIVITASOS_WAKE_CALLBACK_SECRET="$L1_PILOT_001_WAKE_CALLBACK_SECRET" \
L1_SERVICE_TOKEN_SECRET="$L1_PILOT_001_SERVICE_TOKEN_SECRET" \
L1_SERVICE_ID="$L1_PILOT_001_SERVICE_ID" \
L1_SERVICE_TOKEN_SCOPES="$L1_PILOT_001_SERVICE_SCOPES" \
"$PYTHON" scripts/l1_pilot_001_contract_runner.py "${RUNNER_ARGS[@]}"

"$PYTHON" - "$L1_PILOT_001_CONTRACT_ROOT/contract_runner_evidence.json" <<'PY'
import json
import sys
from pathlib import Path

path = sys.argv[1]
report = json.load(open(path, encoding="utf-8"))
if report.get("chain_passed") is not True:
    raise SystemExit(f"L1 contract smoke failed: {path}")
auth = report.get("auth_context") or {}
if auth.get("auth_method") != "service_token":
    raise SystemExit(f"L1 contract smoke requires service_token auth_context: {auth}")
wake = report.get("wake_security") or {}
if wake.get("require_signed_wake") is not True:
    raise SystemExit(f"L1 contract smoke requires signed wake evidence: {wake}")
if any((stage.get("wake") or {}).get("fallback_used") for stage in report.get("stage_reports", [])):
    raise SystemExit("L1 contract smoke requires event wake without restart fallback")
logs_dir = Path(path).parent / "logs"
logs = "\n".join(
    log_path.read_text(encoding="utf-8", errors="replace")
    for log_path in sorted(logs_dir.glob("*.log"))
)
if "Demo-login token bootstrapped" in logs:
    raise SystemExit("L1 contract smoke must not use demo-login bootstrap")
service_bootstrap_count = logs.count("Service-token bootstrap token acquired")
did_bootstrap_count = logs.count("DID auth token bootstrapped")
if service_bootstrap_count < 3:
    raise SystemExit(
        "L1 contract smoke requires service-token bootstrap evidence for all agents; "
        f"found {service_bootstrap_count}"
    )
if did_bootstrap_count < 3:
    raise SystemExit(
        "L1 contract smoke requires DID challenge bootstrap evidence after registration; "
        f"found {did_bootstrap_count}"
    )
stage_count = len(report.get("stage_reports", []))
event_wake = report.get("event_wake_evidence") or {}
if wake.get("wake_mode") == "event":
    wake_bias_count = int(event_wake.get("wake_action_bias_pool_claim_count") or 0)
    if wake_bias_count < stage_count:
        raise SystemExit(
            "L1 event wake hard gate requires wake action bias pool_claim evidence "
            f"for every stage; found {wake_bias_count}/{stage_count}"
        )
    missing = [
        stage.get("role")
        for stage in event_wake.get("stage_evidence", [])
        if stage.get("wake_action_bias_pool_claim_observed") is not True
    ]
    if missing:
        raise SystemExit(
            "L1 event wake hard gate missing per-stage wake action bias evidence: "
            + ", ".join(str(role) for role in missing)
        )
print(f"L1 contract smoke passed: {path}")
PY
