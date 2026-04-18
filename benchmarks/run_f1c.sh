#!/usr/bin/env bash
# benchmarks/run_f1c.sh — F.1.c serial 3-agent × 60-task baseline launcher.
#
# Per F1_BASELINE_DESIGN §4.1 + §7 R9: agents run SERIALLY (not concurrently)
# to avoid ollama-single-instance contention polluting m5_tick_latency.
#
# Pre-conditions (validated by f1c_check.sh — run that first):
#   - backend listening on $BACKEND_URL (default http://localhost:8099)
#   - ollama listening on $LLM_BASE_URL with qwen3:latest pulled
#   - benchmarks/v1/agent_ids.json exists (from f1c_preflight.py)
#
# Usage:
#   ./benchmarks/run_f1c.sh                  # full 3-agent × 60-task run (~9h)
#   SMOKE=1 ./benchmarks/run_f1c.sh          # 1 agent × 1 task (~3min)
#   AGENTS="alpha" ./benchmarks/run_f1c.sh   # subset of agents
#   TASKS="R01_happy_01 V04_adversarial_01" ./benchmarks/run_f1c.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

PYTHON="${PYTHON:-./.venv/bin/python}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8099}"
LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:11434/v1}"
AGENT_LLM="${AGENT_LLM:-ollama:qwen3:latest}"
RUNS_ROOT="${RUNS_ROOT:-runs/F1c}"
MANIFEST="${MANIFEST:-benchmarks/v1/manifest.yaml}"
WALL_CLOCK_PER_TICK_S="${WALL_CLOCK_PER_TICK_S:-60}"
AGENT_IDS_FILE="$RUNS_ROOT/agent_ids.json"

# Speed knobs (benchmark-only; production agents unaffected):
#   LLM_DISABLE_THINKING=1  → ollama qwen3/deepseek-r1 skip <think> chain
#                             (default OFF: F.1.c baseline needs reasoning to
#                              expose disease-③ aspect_gap signal; A/B showed
#                              ON is actually ~2s/tick faster on qwen3:8B Q4
#                              because it answers more concisely after thinking)
#   BENCHMARK_TICK_INTERVAL_S=0.1  → inter-tick sleep (default ACTIVE=10s)
#   BENCHMARK_IDLE_INTERVAL_S=1.0  → inter-tick sleep when IDLE (default 45s)
export LLM_DISABLE_THINKING="${LLM_DISABLE_THINKING:-0}"
export BENCHMARK_TICK_INTERVAL_S="${BENCHMARK_TICK_INTERVAL_S:-0.1}"
export BENCHMARK_IDLE_INTERVAL_S="${BENCHMARK_IDLE_INTERVAL_S:-1.0}"

# Smoke knobs
SMOKE="${SMOKE:-0}"
AGENTS_DEFAULT="alpha beta gamma"
[ "$SMOKE" = "1" ] && AGENTS_DEFAULT="alpha"
AGENTS="${AGENTS:-$AGENTS_DEFAULT}"
TASKS_DEFAULT=""
[ "$SMOKE" = "1" ] && TASKS_DEFAULT="R01_happy_01"
TASKS="${TASKS:-$TASKS_DEFAULT}"

mkdir -p "$RUNS_ROOT"

if [ ! -f "$AGENT_IDS_FILE" ]; then
    echo "ERROR: $AGENT_IDS_FILE not found — run f1c_preflight first:" >&2
    echo "  $PYTHON -m benchmarks.f1c_preflight --backend-url $BACKEND_URL --runs-root $RUNS_ROOT" >&2
    exit 1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
LAUNCHER_LOG="$RUNS_ROOT/launcher_${TS}.log"
exec > >(tee -a "$LAUNCHER_LOG") 2>&1

echo "════════════════════════════════════════════════════════════════════════"
echo "F.1.c launcher started at $TS"
echo "  backend       : $BACKEND_URL"
echo "  ollama        : $LLM_BASE_URL  ($AGENT_LLM)"
echo "  manifest      : $MANIFEST"
echo "  runs_root     : $RUNS_ROOT"
echo "  agents        : $AGENTS"
echo "  tasks         : ${TASKS:-<all 60>}"
echo "  smoke mode    : $SMOKE"
echo "  wall_clock/tick: ${WALL_CLOCK_PER_TICK_S}s"
echo "════════════════════════════════════════════════════════════════════════"

# Build --task flags from $TASKS (space-separated)
task_flags=""
if [ -n "$TASKS" ]; then
    for t in $TASKS; do
        task_flags="$task_flags --task $t"
    done
fi

orch_failures=0
AGENT_TOTAL=$(echo $AGENTS | wc -w)
AGENT_IDX=0

for AGENT in $AGENTS; do
    AGENT_IDX=$((AGENT_IDX + 1))
    echo
    echo "── [$AGENT] (agent $AGENT_IDX/$AGENT_TOTAL) starting ──────────────"
    REC="$($PYTHON -c "
import json, sys
recs = json.load(open('$AGENT_IDS_FILE'))
for r in recs:
    if r['alias'] == '$AGENT':
        print(json.dumps(r))
        break
else:
    sys.exit(1)
")"
    if [ -z "$REC" ]; then
        echo "ERROR: agent alias $AGENT not in $AGENT_IDS_FILE" >&2
        orch_failures=$((orch_failures + 1))
        continue
    fi

    AGENT_NAME="$($PYTHON -c "import json; print(json.loads('''$REC''')['name'])")"
    AGENT_DID="$($PYTHON -c "import json; print(json.loads('''$REC''')['did'])")"
    AGENT_IDENTITY="$($PYTHON -c "import json; print(json.loads('''$REC''')['identity_file'])")"
    AGENT_CAPS="$($PYTHON -c "import json; print(','.join(json.loads('''$REC''')['capabilities']))")"

    echo "  name=$AGENT_NAME did=$AGENT_DID caps=$AGENT_CAPS"
    echo "  identity=$AGENT_IDENTITY"

    AGENT_DATA_DIR="$RUNS_ROOT/agent_data/$AGENT"
    mkdir -p "$AGENT_DATA_DIR"

    # The agent subprocess inherits these via os.environ in orchestrator.
    export AGENT_NAME AGENT_IDENTITY AGENT_DATA_DIR
    export AGENT_CAPABILITIES="$AGENT_CAPS"
    export AGENT_LLM LLM_BASE_URL
    export CIVITASOS_URL="$BACKEND_URL"
    # GATEWAY_PORT=0 → no gateway server (benchmarks don't need inbound)
    export GATEWAY_PORT=0

    RUN_ID="baseline-${AGENT}-${TS}"
    RESUME_FLAG=""
    if [ "${RESUME:-0}" = "1" ]; then
        # Reuse the most-recent existing baseline-<alias>-* run dir for this agent.
        EXISTING="$(ls -dt "$RUNS_ROOT"/baseline-"${AGENT}"-*/ 2>/dev/null | head -1)"
        if [ -n "$EXISTING" ]; then
            RUN_ID="$(basename "${EXISTING%/}")"
            RESUME_FLAG="--resume"
            echo "  RESUME: reusing $RUN_ID"
        else
            echo "  RESUME=1 but no prior run for $AGENT — starting fresh"
        fi
    fi
    echo "  run_id=$RUN_ID"

    set +e
    $PYTHON -m benchmarks.orchestrator \
        --manifest "$MANIFEST" \
        --agent-command "$PYTHON $ROOT/agent.py" \
        --runs-root "$RUNS_ROOT" \
        --run-id "$RUN_ID" \
        $RESUME_FLAG \
        --wall-clock-per-tick-s "$WALL_CLOCK_PER_TICK_S" \
        --backend-mode backend-tasks \
        --backend-url "$BACKEND_URL" \
        --orch-agent-id "f1c_orchestrator" \
        --orch-agent-name "f1c-orchestrator" \
        --orch-identity "$RUNS_ROOT/identity/orchestrator.key" \
        --target-agent-id "$AGENT_DID" \
        $task_flags
    rc=$?
    set -e
    if [ $rc -ne 0 ]; then
        echo "  WARN: orchestrator for $AGENT exited non-zero ($rc)"
        orch_failures=$((orch_failures + 1))
    fi
done

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "All agents done. Failures: $orch_failures"
echo "Next: $PYTHON -m benchmarks.f1c_merge --runs-root $RUNS_ROOT"
echo "════════════════════════════════════════════════════════════════════════"

exit $orch_failures
