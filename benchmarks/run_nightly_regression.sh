#!/usr/bin/env bash
# benchmarks/run_nightly_regression.sh
#
# Nightly regression launcher:
# - Institutional Identity ON
# - Identity Emergence ON
# - F.1.c run + merge
# - hard-check integrity/sentinel/ii2/g2/g3 gates
#
# Optional:
#   BASELINE_RUNS_ROOT=runs/F1c_m2_full_2026-04-23 \
#   ./benchmarks/run_nightly_regression.sh
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-./.venv/bin/python}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8099}"
LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:11434/v1}"
AGENT_LLM="${AGENT_LLM:-ollama:qwen3:latest}"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUNS_ROOT="${RUNS_ROOT:-runs/nightly_${RUN_TS}}"
MANIFEST="${MANIFEST:-benchmarks/v1/manifest.yaml}"
AGENTS="${AGENTS:-alpha beta gamma}"
TASKS="${TASKS:-}"
WALL_CLOCK_PER_TICK_S="${WALL_CLOCK_PER_TICK_S:-60}"
REQUIRE_PRECHECK="${REQUIRE_PRECHECK:-1}"
BASELINE_RUNS_ROOT="${BASELINE_RUNS_ROOT:-}"
GATE_MIN_COMMON_TASKS="${GATE_MIN_COMMON_TASKS:-}"
if [ -z "$GATE_MIN_COMMON_TASKS" ]; then
  MANIFEST_TASK_COUNT="$("$PYTHON" - <<'PY' "$MANIFEST"
import sys
from benchmarks.task_loader import load_manifest
print(len(load_manifest(sys.argv[1]).tasks))
PY
)"
  if [ "$MANIFEST_TASK_COUNT" -lt 30 ]; then
    GATE_MIN_COMMON_TASKS="$MANIFEST_TASK_COUNT"
  else
    GATE_MIN_COMMON_TASKS="30"
  fi
fi
if [ -z "${REQUIRE_G3_ACTIVE:-}" ]; then
  case "$MANIFEST" in
    benchmarks/v2/*|*/benchmarks/v2/*) REQUIRE_G3_ACTIVE=1 ;;
    *) REQUIRE_G3_ACTIVE=0 ;;
  esac
fi

export CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED="${CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED:-1}"
export CIVITASOS_IDENTITY_EMERGENCE_ENABLED="${CIVITASOS_IDENTITY_EMERGENCE_ENABLED:-1}"
export CIVITASOS_BIRTH_SPONSOR="${CIVITASOS_BIRTH_SPONSOR:-${BENCHMARK_BIRTH_SPONSOR:-@guardian}}"
export BENCHMARK_BIRTH_SPONSOR="${BENCHMARK_BIRTH_SPONSOR:-$CIVITASOS_BIRTH_SPONSOR}"
# For newly created benchmark identities, keep provisional window long enough
# to avoid mid-run liquidation.
export BENCHMARK_BIRTH_INCUBATION_EPOCHS="${BENCHMARK_BIRTH_INCUBATION_EPOCHS:-240}"

mkdir -p "$RUNS_ROOT"

echo "════════════════════════════════════════════════════════════════"
echo "Nightly regression run"
echo "  runs_root        : $RUNS_ROOT"
echo "  backend          : $BACKEND_URL"
echo "  llm              : $AGENT_LLM ($LLM_BASE_URL)"
echo "  agents           : $AGENTS"
echo "  tasks            : ${TASKS:-<all>}"
echo "  manifest         : $MANIFEST"
echo "  min_common_tasks : $GATE_MIN_COMMON_TASKS"
echo "  require_g3_active: $REQUIRE_G3_ACTIVE"
echo "  institutional_on : $CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED"
echo "  identity_on      : $CIVITASOS_IDENTITY_EMERGENCE_ENABLED"
echo "  birth_sponsor    : $CIVITASOS_BIRTH_SPONSOR"
echo "  birth_incubation : ${BENCHMARK_BIRTH_INCUBATION_EPOCHS} epochs"
echo "════════════════════════════════════════════════════════════════"

# Bootstrap identities first so f1c_check doesn't fail on missing agent_ids.json.
if [ ! -f "$RUNS_ROOT/agent_ids.json" ]; then
  "$PYTHON" -m benchmarks.f1c_preflight \
    --backend-url "$BACKEND_URL" \
    --runs-root "$RUNS_ROOT"
fi

if [ "$REQUIRE_PRECHECK" = "1" ]; then
  RUNS_ROOT="$RUNS_ROOT" BACKEND_URL="$BACKEND_URL" ./benchmarks/f1c_check.sh
fi

RUNS_ROOT="$RUNS_ROOT" \
BACKEND_URL="$BACKEND_URL" \
LLM_BASE_URL="$LLM_BASE_URL" \
AGENT_LLM="$AGENT_LLM" \
MANIFEST="$MANIFEST" \
AGENTS="$AGENTS" \
TASKS="$TASKS" \
WALL_CLOCK_PER_TICK_S="$WALL_CLOCK_PER_TICK_S" \
./benchmarks/run_f1c.sh

"$PYTHON" -m benchmarks.f1c_merge \
  --runs-root "$RUNS_ROOT" \
  --manifest "$MANIFEST" \
  --gate-min-common-tasks "$GATE_MIN_COMMON_TASKS"

"$PYTHON" - <<'PY' "$RUNS_ROOT" "$REQUIRE_G3_ACTIVE"
import json
import sys
from pathlib import Path

runs_root = Path(sys.argv[1])
require_g3_active = sys.argv[2] == "1"
summary_path = runs_root / "merge_summary.json"
if not summary_path.exists():
    raise SystemExit(f"merge summary missing: {summary_path}")
summary = json.loads(summary_path.read_text(encoding="utf-8"))

integrity_ok = bool(summary.get("integrity_gate", {}).get("passed", False))
sentinel_ok = bool(summary.get("sentinel_gate", {}).get("passed", False))
ii2_ok = bool(summary.get("ii2_gate", {}).get("passed", False))
g2_ok = bool(summary.get("g2_gate", {}).get("passed", False))
g3_gate = summary.get("g3_gate", {})
g3_ok = bool(g3_gate.get("passed", False))
g3_active_ok = (not require_g3_active) or (not bool(g3_gate.get("skipped", False)))
if not (integrity_ok and sentinel_ok and ii2_ok and g2_ok and g3_ok and g3_active_ok):
    print(json.dumps(
        {
            "passed": False,
            "integrity_gate": summary.get("integrity_gate"),
            "sentinel_gate": summary.get("sentinel_gate"),
            "ii2_gate": summary.get("ii2_gate"),
            "g2_gate": summary.get("g2_gate"),
            "g3_gate": summary.get("g3_gate"),
            "require_g3_active": require_g3_active,
            "g3_active_ok": g3_active_ok,
        },
        indent=2,
    ))
    raise SystemExit(5)
print(json.dumps(
    {
        "passed": True,
        "integrity_gate": summary.get("integrity_gate"),
        "sentinel_gate": summary.get("sentinel_gate"),
        "ii2_gate": summary.get("ii2_gate"),
        "g2_gate": summary.get("g2_gate"),
        "g3_gate": summary.get("g3_gate"),
        "require_g3_active": require_g3_active,
    },
    indent=2,
))
PY

if [ -n "$BASELINE_RUNS_ROOT" ]; then
  "$PYTHON" -m benchmarks.h1_compare \
    --baseline-runs-root "$BASELINE_RUNS_ROOT" \
    --candidate-runs-root "$RUNS_ROOT"
fi

echo "Nightly regression completed: $RUNS_ROOT"
