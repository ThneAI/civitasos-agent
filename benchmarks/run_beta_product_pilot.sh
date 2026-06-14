#!/usr/bin/env bash
# Canonical single-command Beta product pilot.
#
# This wrapper owns the strict local backend lifecycle and delegates the real
# Agent task chain to run_beta0_real_model_pilot.sh. Runtime execution does not
# require Evidence Ledger; ledger checks are an explicit optional byproduct.
set -euo pipefail

cd "$(dirname "$0")/.."

COMMAND="${1:-run}"
ENV_FILE="${BETA_PRODUCT_ENV_FILE:-.env.beta0.local}"
BACKEND_ROOT="${BETA_PRODUCT_BACKEND_ROOT:-../civitasos-backend}"
BACKEND_BIN="${BETA_PRODUCT_BACKEND_BIN:-target/debug/api_only}"
BACKEND_PORT="${BETA_PRODUCT_BACKEND_PORT:-8099}"
BETA_PRODUCT_BACKEND_URL="${BETA_PRODUCT_BACKEND_URL:-http://127.0.0.1:$BACKEND_PORT}"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
BETA_PRODUCT_RUN_ROOT="${BETA_PRODUCT_RUN_ROOT:-runs/beta_product_pilot_${RUN_TS}}"
BETA_PRODUCT_RUN_LEDGER_CHECK="${BETA_PRODUCT_RUN_LEDGER_CHECK:-0}"
BETA_PRODUCT_KEEP_BACKEND="${BETA_PRODUCT_KEEP_BACKEND:-0}"
BACKEND_PID=""

usage() {
  cat <<USAGE
Usage: $0 [preflight|run]

Environment:
  BETA_PRODUCT_ENV_FILE=$ENV_FILE
  BETA_PRODUCT_BACKEND_ROOT=$BACKEND_ROOT
  BETA_PRODUCT_BACKEND_BIN=$BACKEND_BIN
  BETA_PRODUCT_BACKEND_PORT=$BACKEND_PORT
  BETA_PRODUCT_BACKEND_URL=$BETA_PRODUCT_BACKEND_URL
  BETA_PRODUCT_RUN_ROOT=$BETA_PRODUCT_RUN_ROOT
  BETA_PRODUCT_RUN_LEDGER_CHECK=$BETA_PRODUCT_RUN_LEDGER_CHECK
  BETA_PRODUCT_KEEP_BACKEND=$BETA_PRODUCT_KEEP_BACKEND
USAGE
}

load_env() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "Beta product pilot env file not found: $ENV_FILE" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

backend_bin_path() {
  if [[ "$BACKEND_BIN" = /* ]]; then
    printf '%s\n' "$BACKEND_BIN"
  else
    printf '%s\n' "$BACKEND_ROOT/$BACKEND_BIN"
  fi
}

preflight() {
  load_env

  local backend_path
  backend_path="$(backend_bin_path)"
  if [ ! -x "$backend_path" ]; then
    echo "Beta product backend binary is not executable: $backend_path" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "Beta product pilot requires curl" >&2
    exit 1
  fi
  if [ -z "${AGENT_LLM:-}" ]; then
    echo "Beta product pilot requires AGENT_LLM" >&2
    exit 1
  fi
  if [ -z "${LLM_BASE_URL:-}" ]; then
    echo "Beta product pilot requires LLM_BASE_URL" >&2
    exit 1
  fi
  if [ -z "${LLM_API_KEY:-}" ]; then
    echo "Beta product pilot requires LLM_API_KEY" >&2
    exit 1
  fi
  if [[ "${AGENT_LLM}" == ollama:* ]] || [[ "${LLM_BASE_URL}" == *"11434"* ]]; then
    echo "Beta product pilot requires an external model provider" >&2
    exit 1
  fi
  if [ -z "${CIVITASOS_SERVICE_TOKEN_SECRET:-}" ]; then
    echo "Beta product pilot requires CIVITASOS_SERVICE_TOKEN_SECRET" >&2
    exit 1
  fi
  if [ -z "${CIVITASOS_WAKE_CALLBACK_SECRET:-}" ]; then
    echo "Beta product pilot requires CIVITASOS_WAKE_CALLBACK_SECRET" >&2
    exit 1
  fi
  if curl -fsS "$BETA_PRODUCT_BACKEND_URL/healthz" >/dev/null 2>&1; then
    echo "Beta product pilot refuses an existing backend at $BETA_PRODUCT_BACKEND_URL; strict startup ownership is required" >&2
    exit 1
  fi

  echo "Beta product pilot preflight passed"
  echo "  backend=$backend_path"
  echo "  backend_url=$BETA_PRODUCT_BACKEND_URL"
  echo "  agent_llm=$AGENT_LLM"
  echo "  ledger_check=$BETA_PRODUCT_RUN_LEDGER_CHECK"
}

cleanup() {
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    if [ "$BETA_PRODUCT_KEEP_BACKEND" = "1" ]; then
      echo "Beta product backend kept running: pid=$BACKEND_PID"
      return
    fi
    kill "$BACKEND_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
      if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
      kill -KILL "$BACKEND_PID" 2>/dev/null || true
    fi
  fi
}

wait_for_backend() {
  for _ in $(seq 1 120); do
    if curl -fsS "$BETA_PRODUCT_BACKEND_URL/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
      echo "Beta product backend exited during startup" >&2
      tail -80 "$BETA_PRODUCT_RUN_ROOT/backend.log" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "Beta product backend health check timed out: $BETA_PRODUCT_BACKEND_URL" >&2
  tail -80 "$BETA_PRODUCT_RUN_ROOT/backend.log" >&2 || true
  return 1
}

run() {
  preflight
  mkdir -p "$BETA_PRODUCT_RUN_ROOT/backend_data/storage"

  local backend_path
  backend_path="$(backend_bin_path)"
  trap cleanup EXIT INT TERM

  CIVITASOS_DATA_DIR="$BETA_PRODUCT_RUN_ROOT/backend_data" \
  CIVITASOS_STORAGE_DATA_DIR="$BETA_PRODUCT_RUN_ROOT/backend_data/storage" \
  CIVITASOS_NODE_ID="beta-product-local" \
  CIVITASOS_BOOT_NODES= \
  CIVITASOS_JWT_SECRET="${CIVITASOS_JWT_SECRET:-${CIVITASOS_SERVICE_TOKEN_SECRET}-jwt-beta-local}" \
  CIVITASOS_SERVICE_TOKEN_SECRET="$CIVITASOS_SERVICE_TOKEN_SECRET" \
  CIVITASOS_WAKE_CALLBACK_SECRET="$CIVITASOS_WAKE_CALLBACK_SECRET" \
  CIVITASOS_A2A_ALLOW_PRIVATE_CALLBACKS=true \
  CIVITASOS_AUTH_MODE=production \
  CIVITASOS_DEMO_LOGIN_ENABLED=false \
  CIVITASOS_DEMO_AUTO_REGISTER=false \
  CIVITASOS_A2A_SEED_TASKS=false \
  CIVITASOS_EPOCH_AUTO_ENABLED=false \
  CIVITASOS_POOL_SWEEP_AUTO_ENABLED=true \
  CIVITASOS_POOL_SWEEP_INTERVAL_SECS=1 \
  CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED=true \
  CIVITASOS_TASK_CHALLENGE_WINDOW_SECS="${CIVITASOS_TASK_CHALLENGE_WINDOW_SECS:-60}" \
  CIVITASOS_POOL_SWEEP_SETTLE_CHALLENGE_ENABLED=true \
    "$backend_path" --api-port "$BACKEND_PORT" \
    >"$BETA_PRODUCT_RUN_ROOT/backend.log" 2>&1 &
  BACKEND_PID="$!"
  echo "$BACKEND_PID" >"$BETA_PRODUCT_RUN_ROOT/backend.pid"
  wait_for_backend

  BACKEND_URL="$BETA_PRODUCT_BACKEND_URL" \
  CIVITASOS_URL="$BETA_PRODUCT_BACKEND_URL" \
  BETA0_RUN_ROOT="$BETA_PRODUCT_RUN_ROOT/pilot" \
  BETA0_RUN_PACKET_CHECK="$BETA_PRODUCT_RUN_LEDGER_CHECK" \
  L1_PILOT_001_SERVICE_TOKEN_SECRET="$CIVITASOS_SERVICE_TOKEN_SECRET" \
  L1_PILOT_001_WAKE_CALLBACK_SECRET="$CIVITASOS_WAKE_CALLBACK_SECRET" \
    benchmarks/run_beta0_real_model_pilot.sh

  echo "Beta product pilot passed: $BETA_PRODUCT_RUN_ROOT/pilot/beta0_real_model_pilot_summary.json"
}

case "$COMMAND" in
  preflight) preflight ;;
  run) run ;;
  -h|--help|help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
