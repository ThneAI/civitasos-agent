#!/usr/bin/env bash
set -euo pipefail

# Local L1 Pilot 001 agent launcher.
# This starts controlled local Agent identities only. It does not claim H.3
# production readiness, external independence, actuation, or production receipt.

CMD="${1:-check}"
ROOT="${L1_PILOT_ROOT:-runs/l1_pilot_001}"
PYTHON_BIN="${PYTHON:-./.venv/bin/python}"
CIVITASOS_URL="${CIVITASOS_URL:-http://localhost:8099}"
AGENT_LLM_VALUE="${AGENT_LLM:-ollama:qwen3:latest}"
LLM_BASE_URL_VALUE="${LLM_BASE_URL:-http://localhost:11434/v1}"
LOG_LEVEL_VALUE="${LOG_LEVEL:-INFO}"
BIRTH_SPONSOR_VALUE="${CIVITASOS_BIRTH_SPONSOR:-pilot_guardian}"

roles=(alpha_planner beta_implementer gamma_reviewer)
capabilities=(
  "planning,documentation,boundary_analysis"
  "implementation,documentation,repair"
  "review,boundary_check,audit"
)

usage() {
  cat <<USAGE
Usage: $0 [check|print|start|status|stop]

Environment overrides:
  L1_PILOT_ROOT=$ROOT
  CIVITASOS_URL=$CIVITASOS_URL
  AGENT_LLM=$AGENT_LLM_VALUE
  LLM_BASE_URL=$LLM_BASE_URL_VALUE
  CIVITASOS_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE
  PYTHON=$PYTHON_BIN

Commands:
  check   Validate local Python, backend health, and Ollama model endpoint.
  print   Print the three local Agent commands without running them.
  start   Start alpha_planner, beta_implementer, gamma_reviewer in background.
  status  Show recorded background process status.
  stop    Stop recorded background processes.
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
    cat <<CMD
CIVITASOS_URL=$CIVITASOS_URL \\
CIVITASOS_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE \\
BENCHMARK_BIRTH_SPONSOR=$BIRTH_SPONSOR_VALUE \\
AGENT_NAME=$role \\
AGENT_CAPABILITIES=$caps \\
AGENT_LLM=$AGENT_LLM_VALUE \\
LLM_BASE_URL=$LLM_BASE_URL_VALUE \\
AGENT_IDENTITY=$ROOT/identity/$role.key \\
AGENT_DATA_DIR=$ROOT/data/$role \\
LOG_LEVEL=$LOG_LEVEL_VALUE \\
$PYTHON_BIN agent.py

CMD
  done
}

start_agents() {
  check
  mkdir -p "$ROOT/identity" "$ROOT/data" "$ROOT/logs" "$ROOT/pids"
  for i in "${!roles[@]}"; do
    local role="${roles[$i]}"
    local caps="${capabilities[$i]}"
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
    AGENT_LLM="$AGENT_LLM_VALUE" \
    LLM_BASE_URL="$LLM_BASE_URL_VALUE" \
    AGENT_IDENTITY="$ROOT/identity/$role.key" \
    AGENT_DATA_DIR="$ROOT/data/$role" \
    LOG_LEVEL="$LOG_LEVEL_VALUE" \
    nohup "$PYTHON_BIN" agent.py > "$ROOT/logs/$role.log" 2>&1 &
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
      kill "$(cat "$pid_file")"
      echo "[stopped] $role pid=$(cat "$pid_file")"
    else
      echo "[skip] $role not running"
    fi
    rm -f "$pid_file"
  done
}

case "$CMD" in
  check) check ;;
  print) print_commands ;;
  start) start_agents ;;
  status) status_agents ;;
  stop) stop_agents ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
