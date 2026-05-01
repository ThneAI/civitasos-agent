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
if [ -z "${G3_MIN_BACKEND_SOURCE_RATIO:-}" ]; then
  case "$MANIFEST" in
    benchmarks/v2/*|*/benchmarks/v2/*) G3_MIN_BACKEND_SOURCE_RATIO=1.0 ;;
    *) G3_MIN_BACKEND_SOURCE_RATIO="" ;;
  esac
fi
if [ -z "${G3_MIN_R2R_RELATION_ID_RATIO:-}" ]; then
  case "$MANIFEST" in
    benchmarks/v2/*|*/benchmarks/v2/*) G3_MIN_R2R_RELATION_ID_RATIO=1.0 ;;
    *) G3_MIN_R2R_RELATION_ID_RATIO="" ;;
  esac
fi
if [ -z "${G3_MIN_RELATION_PAIR_CONTEXT_RATIO:-}" ]; then
  case "$MANIFEST" in
    benchmarks/v2/*|*/benchmarks/v2/*) G3_MIN_RELATION_PAIR_CONTEXT_RATIO=1.0 ;;
    *) G3_MIN_RELATION_PAIR_CONTEXT_RATIO="" ;;
  esac
fi
G3_MIN_RELATION_PAIR_FAILURE_REF_RATIO="${G3_MIN_RELATION_PAIR_FAILURE_REF_RATIO:-}"
REQUIRE_H0_ACTIVE="${REQUIRE_H0_ACTIVE:-0}"
H0_MIN_RELATION_FAILURE_TRACE_RATIO="${H0_MIN_RELATION_FAILURE_TRACE_RATIO:-1.0}"
H0_MIN_IEM_UPDATE_LOG_RATIO="${H0_MIN_IEM_UPDATE_LOG_RATIO:-1.0}"
H0_MIN_RELATION_ACTION_BIAS_RATIO="${H0_MIN_RELATION_ACTION_BIAS_RATIO:-1.0}"
H0_MIN_NORMATIVE_GUARD_RATIO="${H0_MIN_NORMATIVE_GUARD_RATIO:-1.0}"
H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO="${H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO:-1.0}"
H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO="${H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO:-1.0}"
H0_MIN_IDENTITY_ACTION_BIAS_RATIO="${H0_MIN_IDENTITY_ACTION_BIAS_RATIO:-1.0}"
H0_MIN_PREDICTED_UPDATE_RATIO="${H0_MIN_PREDICTED_UPDATE_RATIO:-1.0}"
H0_MIN_DESIRED_SLOW_DRIFT_RATIO="${H0_MIN_DESIRED_SLOW_DRIFT_RATIO:-0.0}"
H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO="${H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO:-1.0}"

export CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED="${CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED:-1}"
export CIVITASOS_IDENTITY_EMERGENCE_ENABLED="${CIVITASOS_IDENTITY_EMERGENCE_ENABLED:-1}"
export CIVITASOS_BIRTH_SPONSOR="${CIVITASOS_BIRTH_SPONSOR:-${BENCHMARK_BIRTH_SPONSOR:-@guardian}}"
export BENCHMARK_BIRTH_SPONSOR="${BENCHMARK_BIRTH_SPONSOR:-$CIVITASOS_BIRTH_SPONSOR}"
# For newly created benchmark identities, keep provisional window long enough
# to avoid mid-run liquidation.
export BENCHMARK_BIRTH_INCUBATION_EPOCHS="${BENCHMARK_BIRTH_INCUBATION_EPOCHS:-240}"
export CIVITASOS_BIRTH_INCUBATION_EPOCHS="${CIVITASOS_BIRTH_INCUBATION_EPOCHS:-$BENCHMARK_BIRTH_INCUBATION_EPOCHS}"

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
echo "  g3_backend_source: ${G3_MIN_BACKEND_SOURCE_RATIO:-<not required>}"
echo "  g3_r2r_relation : ${G3_MIN_R2R_RELATION_ID_RATIO:-<not required>}"
echo "  g3_relation_pair: ${G3_MIN_RELATION_PAIR_CONTEXT_RATIO:-<not required>}"
echo "  g3_pair_fail_ref: ${G3_MIN_RELATION_PAIR_FAILURE_REF_RATIO:-<not required>}"
echo "  require_h0_active: $REQUIRE_H0_ACTIVE"
if [ "$REQUIRE_H0_ACTIVE" = "1" ]; then
  echo "  h0_failure_trace: $H0_MIN_RELATION_FAILURE_TRACE_RATIO"
  echo "  h0_update_log   : $H0_MIN_IEM_UPDATE_LOG_RATIO"
  echo "  h0_action_bias  : $H0_MIN_RELATION_ACTION_BIAS_RATIO"
  echo "  h0_norm_guard   : $H0_MIN_NORMATIVE_GUARD_RATIO"
  echo "  h0_id_domains   : $H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO"
  echo "  h0_exp_domains  : $H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO"
  echo "  h0_id_bias      : $H0_MIN_IDENTITY_ACTION_BIAS_RATIO"
  echo "  h0_pred_update  : $H0_MIN_PREDICTED_UPDATE_RATIO"
  echo "  h0_desired_drift: $H0_MIN_DESIRED_SLOW_DRIFT_RATIO"
  echo "  h0_gov_trigger  : $H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO"
fi
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

MERGE_ARGS=(
  --runs-root "$RUNS_ROOT"
  --manifest "$MANIFEST"
  --gate-min-common-tasks "$GATE_MIN_COMMON_TASKS"
)
if [ -n "$G3_MIN_BACKEND_SOURCE_RATIO" ]; then
  MERGE_ARGS+=(--g3-min-backend-source-ratio "$G3_MIN_BACKEND_SOURCE_RATIO")
fi
if [ -n "$G3_MIN_R2R_RELATION_ID_RATIO" ]; then
  MERGE_ARGS+=(--g3-min-r2r-relation-id-ratio "$G3_MIN_R2R_RELATION_ID_RATIO")
fi
if [ -n "$G3_MIN_RELATION_PAIR_CONTEXT_RATIO" ]; then
  MERGE_ARGS+=(--g3-min-relation-pair-context-ratio "$G3_MIN_RELATION_PAIR_CONTEXT_RATIO")
fi
if [ -n "$G3_MIN_RELATION_PAIR_FAILURE_REF_RATIO" ]; then
  MERGE_ARGS+=(--g3-min-relation-pair-failure-ref-ratio "$G3_MIN_RELATION_PAIR_FAILURE_REF_RATIO")
fi
if [ "$REQUIRE_H0_ACTIVE" = "1" ]; then
  MERGE_ARGS+=(--require-h0-active)
  MERGE_ARGS+=(--h0-min-relation-failure-trace-ratio "$H0_MIN_RELATION_FAILURE_TRACE_RATIO")
  MERGE_ARGS+=(--h0-min-iem-update-log-ratio "$H0_MIN_IEM_UPDATE_LOG_RATIO")
  MERGE_ARGS+=(--h0-min-relation-action-bias-ratio "$H0_MIN_RELATION_ACTION_BIAS_RATIO")
  MERGE_ARGS+=(--h0-min-normative-guard-ratio "$H0_MIN_NORMATIVE_GUARD_RATIO")
  MERGE_ARGS+=(--h0-min-identity-domain-trace-ratio "$H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO")
  MERGE_ARGS+=(--h0-min-expanded-domain-trace-ratio "$H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO")
  MERGE_ARGS+=(--h0-min-identity-action-bias-ratio "$H0_MIN_IDENTITY_ACTION_BIAS_RATIO")
  MERGE_ARGS+=(--h0-min-predicted-update-ratio "$H0_MIN_PREDICTED_UPDATE_RATIO")
  MERGE_ARGS+=(--h0-min-desired-slow-drift-ratio "$H0_MIN_DESIRED_SLOW_DRIFT_RATIO")
  MERGE_ARGS+=(--h0-min-normative-governance-trigger-ratio "$H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO")
fi
"$PYTHON" -m benchmarks.f1c_merge "${MERGE_ARGS[@]}"

"$PYTHON" - <<'PY' "$RUNS_ROOT" "$REQUIRE_G3_ACTIVE" "$REQUIRE_H0_ACTIVE"
import json
import sys
from pathlib import Path

runs_root = Path(sys.argv[1])
require_g3_active = sys.argv[2] == "1"
require_h0_active = sys.argv[3] == "1"
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
h0_gate = summary.get("h0_gate", {})
h0_ok = bool(h0_gate.get("passed", False))
h0_active_ok = (not require_h0_active) or (not bool(h0_gate.get("skipped", False)))
if not (
  integrity_ok
  and sentinel_ok
  and ii2_ok
  and g2_ok
  and g3_ok
  and g3_active_ok
  and h0_ok
  and h0_active_ok
):
    print(json.dumps(
        {
            "passed": False,
            "integrity_gate": summary.get("integrity_gate"),
            "sentinel_gate": summary.get("sentinel_gate"),
            "ii2_gate": summary.get("ii2_gate"),
            "g2_gate": summary.get("g2_gate"),
            "g3_gate": summary.get("g3_gate"),
            "h0_gate": summary.get("h0_gate"),
            "require_g3_active": require_g3_active,
            "g3_active_ok": g3_active_ok,
            "require_h0_active": require_h0_active,
            "h0_active_ok": h0_active_ok,
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
        "h0_gate": summary.get("h0_gate"),
        "require_g3_active": require_g3_active,
        "require_h0_active": require_h0_active,
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
