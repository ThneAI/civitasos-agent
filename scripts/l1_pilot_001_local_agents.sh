#!/usr/bin/env bash
set -euo pipefail

# Local L1 Pilot 001 agent launcher.
# This starts controlled local Agent identities only. It does not claim H.3
# production readiness, external independence, actuation, or production receipt.

CMD="${1:-check}"
if [ "$#" -gt 0 ]; then
  shift
fi
ROOT="${L1_PILOT_ROOT:-runs/l1_pilot_001}"
PYTHON_BIN="${PYTHON:-./.venv/bin/python}"
CIVITASOS_URL="${CIVITASOS_URL:-http://localhost:8099}"
AGENT_LLM_VALUE="${AGENT_LLM:-ollama:qwen3:latest}"
LLM_BASE_URL_VALUE="${LLM_BASE_URL:-http://localhost:11434/v1}"
LOG_LEVEL_VALUE="${LOG_LEVEL:-INFO}"
BIRTH_SPONSOR_VALUE="${CIVITASOS_BIRTH_SPONSOR:-pilot_guardian}"
EVENT_WAKE_VALUE="${L1_ENABLE_EVENT_WAKE:-1}"
GATEWAY_BASE_PORT_VALUE="${L1_GATEWAY_BASE_PORT:-18710}"
AGENT_HOST_VALUE="${L1_AGENT_HOST:-127.0.0.1}"
SIGNED_WAKE_REQUIRED_VALUE="${L1_REQUIRE_SIGNED_WAKE:-0}"

roles=(alpha_planner beta_implementer gamma_reviewer)
capabilities=(
  "planning,documentation,boundary_analysis"
  "implementation,documentation,repair"
  "review,boundary_check,audit"
)

usage() {
  cat <<USAGE
Usage: $0 [check|print|start|status|stop|resolve-agents|post-alpha|post-beta|post-gamma|post-next|post-repair|task-status|export-audit-refs|run-chain]

Environment overrides:
  L1_PILOT_ROOT=$ROOT
  CIVITASOS_URL=$CIVITASOS_URL
  AGENT_LLM=$AGENT_LLM_VALUE
  LLM_BASE_URL=$LLM_BASE_URL_VALUE
  CIVITASOS_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE
  L1_ENABLE_EVENT_WAKE=$EVENT_WAKE_VALUE
  L1_GATEWAY_BASE_PORT=$GATEWAY_BASE_PORT_VALUE
  L1_AGENT_HOST=$AGENT_HOST_VALUE
  L1_REQUIRE_SIGNED_WAKE=$SIGNED_WAKE_REQUIRED_VALUE
  CIVITASOS_WAKE_CALLBACK_SECRET=${CIVITASOS_WAKE_CALLBACK_SECRET:+<configured>}
  PYTHON=$PYTHON_BIN

Commands:
  check   Validate local Python, backend health, and Ollama model endpoint.
  print   Print the three local Agent commands without running them.
  start   Start alpha_planner, beta_implementer, gamma_reviewer in background.
  status  Show recorded background process status.
  stop    Stop recorded background processes.
  resolve-agents  Resolve pilot requester/alpha/beta/gamma DIDs for contract tasks.
  post-alpha      Post alpha planner task with structured delivery_contract.
  post-beta       Post beta implementer task after alpha is Delivered/Completed.
  post-gamma      Post gamma reviewer task after beta is Delivered/Completed.
  post-next       Post the next missing task in the alpha→beta→gamma chain.
  post-repair     Post an explicit operator-approved repair task for a failed task.
  task-status     Show posted contract task state.
  export-audit-refs  Export repair suggestions as L1 packet audit-events JSONL.
  run-chain       Run the full alpha→beta→gamma controlled pilot chain.
USAGE
}

probe_url() {
  local label="$1"
  local url="$2"
  "$PYTHON_BIN" - "$label" "$url" <<'PY'
import sys
import urllib.request

label, url = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(url, timeout=3) as resp:
        print(f"[ok] {label}: HTTP {resp.status} {url}")
except Exception as exc:
    print(f"[fail] {label}: {type(exc).__name__}: {exc}")
    raise SystemExit(1)
PY
}

check() {
  if [ ! -x "$PYTHON_BIN" ]; then
    echo "[fail] python not executable: $PYTHON_BIN" >&2
    exit 1
  fi
  "$PYTHON_BIN" --version
  probe_url "ollama-openai-models" "$LLM_BASE_URL_VALUE/models"
  if ! probe_url "backend-healthz" "$CIVITASOS_URL/healthz"; then
    echo "[hint] Start civitasos backend before running Pilot 001 agents." >&2
    exit 1
  fi
}

print_commands() {
  for i in "${!roles[@]}"; do
    local role="${roles[$i]}"
    local caps="${capabilities[$i]}"
    local gateway_port
    gateway_port="$(role_gateway_port "$i")"
    cat <<CMD
CIVITASOS_URL=$CIVITASOS_URL \\
CIVITASOS_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE \\
BENCHMARK_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE \\
AGENT_NAME=$role \\
AGENT_CAPABILITIES=$caps \\
GATEWAY_PORT=$gateway_port \\
AGENT_ENDPOINT=http://$AGENT_HOST_VALUE:$gateway_port \\
AGENT_LLM=$AGENT_LLM_VALUE \\
LLM_BASE_URL=$LLM_BASE_URL_VALUE \\
AGENT_IDENTITY=$ROOT/identity/$role.key \\
AGENT_DATA_DIR=$ROOT/data/$role \\
LOG_LEVEL=$LOG_LEVEL_VALUE \\
$PYTHON_BIN agent.py

CMD
  done
}

role_gateway_port() {
  local role_index="$1"
  echo $((GATEWAY_BASE_PORT_VALUE + role_index + 1))
}

start_agents() {
  check
  mkdir -p "$ROOT/identity" "$ROOT/data" "$ROOT/logs" "$ROOT/pids"
  for i in "${!roles[@]}"; do
    local role="${roles[$i]}"
    local caps="${capabilities[$i]}"
    local gateway_port="0"
    local agent_endpoint=""
    if [ "$EVENT_WAKE_VALUE" = "1" ]; then
      gateway_port="$(role_gateway_port "$i")"
      agent_endpoint="http://$AGENT_HOST_VALUE:$gateway_port"
    fi
    local pid_file="$ROOT/pids/$role.pid"
    if [ -s "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      echo "[skip] $role already running pid=$(cat "$pid_file")"
      continue
    fi
    CIVITASOS_URL="$CIVITASOS_URL" \
    CIVITASOS_BIRTH_SPONSOR="$BIRTH_SPONSOR_VALUE" \
    BENCHMARK_BIRTH_SPONSOR="$BIRTH_SPONSOR_VALUE" \
    AGENT_NAME="$role" \
    AGENT_CAPABILITIES="$caps" \
    GATEWAY_PORT="$gateway_port" \
    AGENT_ENDPOINT="$agent_endpoint" \
    AGENT_LLM="$AGENT_LLM_VALUE" \
    LLM_BASE_URL="$LLM_BASE_URL_VALUE" \
    AGENT_IDENTITY="$ROOT/identity/$role.key" \
    AGENT_DATA_DIR="$ROOT/data/$role" \
    LOG_LEVEL="$LOG_LEVEL_VALUE" \
    nohup setsid "$PYTHON_BIN" agent.py > "$ROOT/logs/$role.log" 2>&1 < /dev/null &
    echo "$!" > "$pid_file"
    echo "[started] $role pid=$! log=$ROOT/logs/$role.log"
  done
}

status_agents() {
  for role in "${roles[@]}"; do
    local pid_file="$ROOT/pids/$role.pid"
    if [ -s "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      echo "[running] $role pid=$(cat "$pid_file")"
    else
      echo "[stopped] $role"
    fi
  done
}

stop_agents() {
  for role in "${roles[@]}"; do
    local pid_file="$ROOT/pids/$role.pid"
    if [ -s "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      local pid
      pid="$(cat "$pid_file")"
      kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 120); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.25
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      fi
      echo "[stopped] $role pid=$pid"
    else
      echo "[skip] $role not running"
    fi
    rm -f "$pid_file"
  done
}

contract_tasks() {
  "$PYTHON_BIN" scripts/l1_pilot_001_contract_tasks.py \
    --base-url "$CIVITASOS_URL" \
    --root "$ROOT" \
    "$@"
}

contract_runner() {
  "$PYTHON_BIN" scripts/l1_pilot_001_contract_runner.py \
    --base-url "$CIVITASOS_URL" \
    --root "$ROOT" \
    --python "$PYTHON_BIN" \
    "$@"
}

export_audit_refs() {
  local output="$ROOT/packet_input/sinks/audit-events.jsonl"
  if [ "$#" -gt 0 ] && [[ "$1" != --* ]]; then
    output="$1"
    shift
  fi
  "$PYTHON_BIN" scripts/l1_export_contract_audit_refs.py \
    --evidence "$ROOT/contract_runner_evidence.json" \
    --output "$output" \
    "$@"
}

case "$CMD" in
  check) check ;;
  print) print_commands ;;
  start) start_agents ;;
  status) status_agents ;;
  stop) stop_agents ;;
  resolve-agents) contract_tasks resolve-agents "$@" ;;
  post-alpha) contract_tasks post-alpha "$@" ;;
  post-beta) contract_tasks post-beta "$@" ;;
  post-gamma) contract_tasks post-gamma "$@" ;;
  post-next) contract_tasks post-next "$@" ;;
  post-repair) contract_tasks post-repair "$@" ;;
  task-status) contract_tasks status "$@" ;;
  export-audit-refs) export_audit_refs "$@" ;;
  run-chain) contract_runner "$@" ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
