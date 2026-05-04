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
#   ENABLE_H1_LLM_JUDGE=1 \
#   H1_JUDGE_CALIBRATION_REPORT=runs/H1C_gemma4_calibration_20260502_r2.json \
#   CIVITASOS_H1_JUDGE_ENABLED=1 \
#   CIVITASOS_H1_JUDGE_BACKEND=openai-compatible \
#   CIVITASOS_H1_JUDGE_BASE_URL=http://localhost:11434/v1 \
#   CIVITASOS_H1_JUDGE_MODEL=gemma4:26b \
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
H0_MIN_RELATION_TRAINING_SAMPLE_RATIO="${H0_MIN_RELATION_TRAINING_SAMPLE_RATIO:-1.0}"
H0_MIN_RELATION_NEGATIVE_FAST_LEARNING_RATIO="${H0_MIN_RELATION_NEGATIVE_FAST_LEARNING_RATIO:-1.0}"
H0_MIN_RELATION_REPAIR_SLOW_RECOVERY_RATIO="${H0_MIN_RELATION_REPAIR_SLOW_RECOVERY_RATIO:-1.0}"
H0_MIN_RELATION_HISTORY_PRESERVED_RATIO="${H0_MIN_RELATION_HISTORY_PRESERVED_RATIO:-1.0}"
H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO="${H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO:-1.0}"
H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO="${H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO:-1.0}"
H0_MIN_IDENTITY_ACTION_BIAS_RATIO="${H0_MIN_IDENTITY_ACTION_BIAS_RATIO:-1.0}"
H0_MIN_PREDICTED_UPDATE_RATIO="${H0_MIN_PREDICTED_UPDATE_RATIO:-1.0}"
H0_MIN_DESIRED_SLOW_DRIFT_RATIO="${H0_MIN_DESIRED_SLOW_DRIFT_RATIO:-0.0}"
H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO="${H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO:-1.0}"
H0_MIN_GOVERNED_REVISION_RATIO="${H0_MIN_GOVERNED_REVISION_RATIO:-1.0}"
H0_MIN_DECISION_PROOF_HASH_RATIO="${H0_MIN_DECISION_PROOF_HASH_RATIO:-1.0}"
H0_MIN_IEM_ANCHOR_REPLAY_RATIO="${H0_MIN_IEM_ANCHOR_REPLAY_RATIO:-1.0}"
H0_MIN_IEM_ANCHOR_REPLAY_EMBEDDED_RATIO="${H0_MIN_IEM_ANCHOR_REPLAY_EMBEDDED_RATIO:-1.0}"
H0_MAX_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_RATIO="${H0_MAX_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_RATIO:-0.0}"
H0_MIN_RUNTIME_IEM_AUDIT_RATIO="${H0_MIN_RUNTIME_IEM_AUDIT_RATIO:-1.0}"
H0_MIN_VOTE_REFS_RATIO="${H0_MIN_VOTE_REFS_RATIO:-1.0}"
H0_MIN_AUTHORITY_KIND_COUNT="${H0_MIN_AUTHORITY_KIND_COUNT:-1}"
REQUIRE_H1_ACTIVE="${REQUIRE_H1_ACTIVE:-0}"
H1_MIN_SERVED_INTENT_LAYER_COVERAGE_RATIO="${H1_MIN_SERVED_INTENT_LAYER_COVERAGE_RATIO:-1.0}"
H1_MIN_VERIFIER_BEFORE_DELIVERY_RATIO="${H1_MIN_VERIFIER_BEFORE_DELIVERY_RATIO:-1.0}"
ENABLE_H1_LLM_JUDGE="${ENABLE_H1_LLM_JUDGE:-0}"
H1_JUDGE_CALIBRATION_REPORT="${H1_JUDGE_CALIBRATION_REPORT:-}"
H1_LLM_JUDGE_REPORT="${H1_LLM_JUDGE_REPORT:-$RUNS_ROOT/h1_llm_judge_report.json}"
H1_MIN_LLM_JUDGE_PASS_RATE="${H1_MIN_LLM_JUDGE_PASS_RATE:-1.0}"
REQUIRE_H2_ACTIVE="${REQUIRE_H2_ACTIVE:-0}"
H2_OUTCOME_REPORT="${H2_OUTCOME_REPORT:-$RUNS_ROOT/h2_outcome_report.json}"
H2_DELAYED_OUTCOMES="${H2_DELAYED_OUTCOMES:-}"
H2_BACKEND_OUTCOME_EVENTS="${H2_BACKEND_OUTCOME_EVENTS:-}"
EXPORT_H2_BACKEND_OUTCOME_EVENTS="${EXPORT_H2_BACKEND_OUTCOME_EVENTS:-0}"
if [ "$EXPORT_H2_BACKEND_OUTCOME_EVENTS" = "1" ] && [ -z "$H2_BACKEND_OUTCOME_EVENTS" ]; then
  H2_BACKEND_OUTCOME_EVENTS="$RUNS_ROOT/backend_outcome_events.json"
fi
H2_BACKEND_OUTCOME_EVENTS_LIMIT="${H2_BACKEND_OUTCOME_EVENTS_LIMIT:-500}"
H2_BACKEND_OUTCOME_EVENTS_SINCE="${H2_BACKEND_OUTCOME_EVENTS_SINCE:-}"
H2_ALLOW_TRUNCATED_BACKEND_OUTCOME_EVENTS="${H2_ALLOW_TRUNCATED_BACKEND_OUTCOME_EVENTS:-0}"
H2_MIN_OUTCOME_LEDGER_COVERAGE_RATIO="${H2_MIN_OUTCOME_LEDGER_COVERAGE_RATIO:-1.0}"
H2_MIN_H1_EVIDENCE_REF_RATIO="${H2_MIN_H1_EVIDENCE_REF_RATIO:-1.0}"
H2_MIN_NORMATIVE_LOCAL_UPDATE_BLOCKED_RATIO="${H2_MIN_NORMATIVE_LOCAL_UPDATE_BLOCKED_RATIO:-1.0}"
H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO="${H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO:-}"
RUN_H2_RELEASE_CHECK="${RUN_H2_RELEASE_CHECK:-$REQUIRE_H2_ACTIVE}"
H2_RELEASE_CHECK_REPORT="${H2_RELEASE_CHECK_REPORT:-$RUNS_ROOT/h2_release_check.json}"
H2_REQUIRE_BACKEND_OUTCOME_EVENTS="${H2_REQUIRE_BACKEND_OUTCOME_EVENTS:-$EXPORT_H2_BACKEND_OUTCOME_EVENTS}"
H2_RELEASE_MIN_OUTCOME_RECORD_COUNT="${H2_RELEASE_MIN_OUTCOME_RECORD_COUNT:-1}"
if [ -z "${H2_RELEASE_MIN_DELAYED_EVENT_COUNT:-}" ]; then
  if [ "$H2_REQUIRE_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    H2_RELEASE_MIN_DELAYED_EVENT_COUNT="1"
  else
    H2_RELEASE_MIN_DELAYED_EVENT_COUNT="0"
  fi
fi
if [ -z "${H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO+x}" ]; then
  if [ -n "$H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO" ]; then
    H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO="$H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO"
  elif [ "$H2_REQUIRE_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO="1.0"
  else
    H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO=""
  fi
fi

export CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED="${CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED:-1}"
export CIVITASOS_IDENTITY_EMERGENCE_ENABLED="${CIVITASOS_IDENTITY_EMERGENCE_ENABLED:-1}"
if [ "$REQUIRE_H1_ACTIVE" = "1" ]; then
  export CIVITASOS_H1_TELOS_ENABLED="${CIVITASOS_H1_TELOS_ENABLED:-1}"
fi
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
  echo "  h0_train_sample : $H0_MIN_RELATION_TRAINING_SAMPLE_RATIO"
  echo "  h0_neg_learning : $H0_MIN_RELATION_NEGATIVE_FAST_LEARNING_RATIO"
  echo "  h0_repair_slow  : $H0_MIN_RELATION_REPAIR_SLOW_RECOVERY_RATIO"
  echo "  h0_hist_preserve: $H0_MIN_RELATION_HISTORY_PRESERVED_RATIO"
  echo "  h0_id_domains   : $H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO"
  echo "  h0_exp_domains  : $H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO"
  echo "  h0_id_bias      : $H0_MIN_IDENTITY_ACTION_BIAS_RATIO"
  echo "  h0_pred_update  : $H0_MIN_PREDICTED_UPDATE_RATIO"
  echo "  h0_desired_drift: $H0_MIN_DESIRED_SLOW_DRIFT_RATIO"
  echo "  h0_gov_trigger  : $H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO"
  echo "  h0_gov_revision : $H0_MIN_GOVERNED_REVISION_RATIO"
  echo "  h0_proof_hash   : $H0_MIN_DECISION_PROOF_HASH_RATIO"
  echo "  h0_anchor_replay: $H0_MIN_IEM_ANCHOR_REPLAY_RATIO"
  echo "  h0_anchor_embed : $H0_MIN_IEM_ANCHOR_REPLAY_EMBEDDED_RATIO"
  echo "  h0_legacy_sidecar: $H0_MAX_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_RATIO"
  echo "  h0_runtime_iem  : $H0_MIN_RUNTIME_IEM_AUDIT_RATIO"
  echo "  h0_vote_refs    : $H0_MIN_VOTE_REFS_RATIO"
  echo "  h0_authorities  : $H0_MIN_AUTHORITY_KIND_COUNT"
fi
echo "  require_h1_active: $REQUIRE_H1_ACTIVE"
if [ "$REQUIRE_H1_ACTIVE" = "1" ]; then
  echo "  h1_telos_enabled: ${CIVITASOS_H1_TELOS_ENABLED:-0}"
  echo "  h1_served_layer : $H1_MIN_SERVED_INTENT_LAYER_COVERAGE_RATIO"
  echo "  h1_verifier_pre : $H1_MIN_VERIFIER_BEFORE_DELIVERY_RATIO"
fi
echo "  h1_llm_judge   : $ENABLE_H1_LLM_JUDGE"
if [ "$ENABLE_H1_LLM_JUDGE" = "1" ]; then
  echo "  h1_judge_model : ${CIVITASOS_H1_JUDGE_MODEL:-<unset>}"
  echo "  h1_judge_url   : ${CIVITASOS_H1_JUDGE_BASE_URL:-<unset>}"
  echo "  h1_calibration : ${H1_JUDGE_CALIBRATION_REPORT:-<missing>}"
  echo "  h1_judge_report: $H1_LLM_JUDGE_REPORT"
  echo "  h1_judge_rate  : $H1_MIN_LLM_JUDGE_PASS_RATE"
fi
echo "  require_h2_active: $REQUIRE_H2_ACTIVE"
if [ "$REQUIRE_H2_ACTIVE" = "1" ]; then
  echo "  h2_report       : $H2_OUTCOME_REPORT"
  echo "  h2_delayed_seed : ${H2_DELAYED_OUTCOMES:-<none>}"
  echo "  h2_backend_events: ${H2_BACKEND_OUTCOME_EVENTS:-<none>}"
  echo "  h2_export_backend: $EXPORT_H2_BACKEND_OUTCOME_EVENTS"
  if [ "$EXPORT_H2_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    echo "  h2_backend_limit : $H2_BACKEND_OUTCOME_EVENTS_LIMIT"
    echo "  h2_backend_since : ${H2_BACKEND_OUTCOME_EVENTS_SINCE:-<none>}"
    echo "  h2_allow_trunc   : $H2_ALLOW_TRUNCATED_BACKEND_OUTCOME_EVENTS"
  fi
  echo "  h2_ledger_ratio : $H2_MIN_OUTCOME_LEDGER_COVERAGE_RATIO"
  echo "  h2_h1_ref_ratio : $H2_MIN_H1_EVIDENCE_REF_RATIO"
  echo "  h2_norm_blocked : $H2_MIN_NORMATIVE_LOCAL_UPDATE_BLOCKED_RATIO"
  echo "  h2_delayed_cover: ${H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO:-<not required>}"
  echo "  h2_release_check: $RUN_H2_RELEASE_CHECK"
  if [ "$RUN_H2_RELEASE_CHECK" = "1" ]; then
    echo "  h2_release_report: $H2_RELEASE_CHECK_REPORT"
    echo "  h2_release_backend_required: $H2_REQUIRE_BACKEND_OUTCOME_EVENTS"
    echo "  h2_release_min_records: $H2_RELEASE_MIN_OUTCOME_RECORD_COUNT"
    echo "  h2_release_min_delayed: $H2_RELEASE_MIN_DELAYED_EVENT_COUNT"
    echo "  h2_release_delayed_cover: ${H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO:-<not required>}"
  fi
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

if [ "$EXPORT_H2_BACKEND_OUTCOME_EVENTS" = "1" ]; then
  H2_EXPORT_ARGS=(
    --backend-url "$BACKEND_URL"
    --output "$H2_BACKEND_OUTCOME_EVENTS"
    --limit "$H2_BACKEND_OUTCOME_EVENTS_LIMIT"
  )
  if [ -n "$H2_BACKEND_OUTCOME_EVENTS_SINCE" ]; then
    H2_EXPORT_ARGS+=(--since "$H2_BACKEND_OUTCOME_EVENTS_SINCE")
  fi
  if [ "$H2_ALLOW_TRUNCATED_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    H2_EXPORT_ARGS+=(--allow-truncated)
  fi
  "$PYTHON" -m benchmarks.h2_backend_outcome_export "${H2_EXPORT_ARGS[@]}"
fi

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
  MERGE_ARGS+=(--h0-min-relation-training-sample-ratio "$H0_MIN_RELATION_TRAINING_SAMPLE_RATIO")
  MERGE_ARGS+=(--h0-min-relation-negative-fast-learning-ratio "$H0_MIN_RELATION_NEGATIVE_FAST_LEARNING_RATIO")
  MERGE_ARGS+=(--h0-min-relation-repair-slow-recovery-ratio "$H0_MIN_RELATION_REPAIR_SLOW_RECOVERY_RATIO")
  MERGE_ARGS+=(--h0-min-relation-history-preserved-ratio "$H0_MIN_RELATION_HISTORY_PRESERVED_RATIO")
  MERGE_ARGS+=(--h0-min-identity-domain-trace-ratio "$H0_MIN_IDENTITY_DOMAIN_TRACE_RATIO")
  MERGE_ARGS+=(--h0-min-expanded-domain-trace-ratio "$H0_MIN_EXPANDED_DOMAIN_TRACE_RATIO")
  MERGE_ARGS+=(--h0-min-identity-action-bias-ratio "$H0_MIN_IDENTITY_ACTION_BIAS_RATIO")
  MERGE_ARGS+=(--h0-min-predicted-update-ratio "$H0_MIN_PREDICTED_UPDATE_RATIO")
  MERGE_ARGS+=(--h0-min-desired-slow-drift-ratio "$H0_MIN_DESIRED_SLOW_DRIFT_RATIO")
  MERGE_ARGS+=(--h0-min-normative-governance-trigger-ratio "$H0_MIN_NORMATIVE_GOVERNANCE_TRIGGER_RATIO")
  MERGE_ARGS+=(--h0-min-governed-revision-ratio "$H0_MIN_GOVERNED_REVISION_RATIO")
  MERGE_ARGS+=(--h0-min-decision-proof-hash-ratio "$H0_MIN_DECISION_PROOF_HASH_RATIO")
  MERGE_ARGS+=(--h0-min-iem-anchor-replay-ratio "$H0_MIN_IEM_ANCHOR_REPLAY_RATIO")
  MERGE_ARGS+=(--h0-min-iem-anchor-replay-embedded-ratio "$H0_MIN_IEM_ANCHOR_REPLAY_EMBEDDED_RATIO")
  MERGE_ARGS+=(--h0-max-iem-anchor-replay-legacy-sidecar-ratio "$H0_MAX_IEM_ANCHOR_REPLAY_LEGACY_SIDECAR_RATIO")
  MERGE_ARGS+=(--h0-min-runtime-iem-audit-ratio "$H0_MIN_RUNTIME_IEM_AUDIT_RATIO")
  MERGE_ARGS+=(--h0-min-vote-refs-ratio "$H0_MIN_VOTE_REFS_RATIO")
  MERGE_ARGS+=(--h0-min-authority-kind-count "$H0_MIN_AUTHORITY_KIND_COUNT")
fi
if [ "$REQUIRE_H1_ACTIVE" = "1" ]; then
  MERGE_ARGS+=(--enable-h1-gate)
  MERGE_ARGS+=(--h1-min-served-intent-layer-coverage-ratio "$H1_MIN_SERVED_INTENT_LAYER_COVERAGE_RATIO")
  MERGE_ARGS+=(--h1-min-verifier-before-delivery-ratio "$H1_MIN_VERIFIER_BEFORE_DELIVERY_RATIO")
fi
if [ "$ENABLE_H1_LLM_JUDGE" = "1" ]; then
  if [ "$REQUIRE_H1_ACTIVE" != "1" ]; then
    MERGE_ARGS+=(--enable-h1-gate)
  fi
  MERGE_ARGS+=(--enable-h1-llm-judge)
  MERGE_ARGS+=(--h1-judge-calibration-report "$H1_JUDGE_CALIBRATION_REPORT")
  MERGE_ARGS+=(--h1-llm-judge-report "$H1_LLM_JUDGE_REPORT")
  MERGE_ARGS+=(--h1-min-llm-judge-pass-rate "$H1_MIN_LLM_JUDGE_PASS_RATE")
fi
if [ "$REQUIRE_H2_ACTIVE" = "1" ]; then
  if [ "$REQUIRE_H1_ACTIVE" != "1" ]; then
    MERGE_ARGS+=(--enable-h1-gate)
  fi
  MERGE_ARGS+=(--enable-h2-gate)
  MERGE_ARGS+=(--h2-outcome-report "$H2_OUTCOME_REPORT")
  MERGE_ARGS+=(--h2-min-outcome-ledger-coverage-ratio "$H2_MIN_OUTCOME_LEDGER_COVERAGE_RATIO")
  MERGE_ARGS+=(--h2-min-h1-evidence-ref-ratio "$H2_MIN_H1_EVIDENCE_REF_RATIO")
  MERGE_ARGS+=(--h2-min-normative-local-update-blocked-ratio "$H2_MIN_NORMATIVE_LOCAL_UPDATE_BLOCKED_RATIO")
  if [ -n "$H2_DELAYED_OUTCOMES" ]; then
    MERGE_ARGS+=(--h2-delayed-outcomes "$H2_DELAYED_OUTCOMES")
  fi
  if [ -n "$H2_BACKEND_OUTCOME_EVENTS" ]; then
    MERGE_ARGS+=(--h2-backend-outcome-events "$H2_BACKEND_OUTCOME_EVENTS")
  fi
  if [ -n "$H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO" ]; then
    MERGE_ARGS+=(--h2-min-delayed-verifier-coverage-ratio "$H2_MIN_DELAYED_VERIFIER_COVERAGE_RATIO")
  fi
fi
"$PYTHON" -m benchmarks.f1c_merge "${MERGE_ARGS[@]}"

"$PYTHON" - <<'PY' "$RUNS_ROOT" "$REQUIRE_G3_ACTIVE" "$REQUIRE_H0_ACTIVE" "$REQUIRE_H1_ACTIVE" "$REQUIRE_H2_ACTIVE"
import json
import sys
from pathlib import Path

runs_root = Path(sys.argv[1])
require_g3_active = sys.argv[2] == "1"
require_h0_active = sys.argv[3] == "1"
require_h1_active = sys.argv[4] == "1"
require_h2_active = sys.argv[5] == "1"
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
h1_gate = summary.get("h1_gate", {})
h1_ok = bool(h1_gate.get("passed", False))
h1_active_ok = (not require_h1_active) or (not bool(h1_gate.get("skipped", False)))
h2_gate = summary.get("h2_gate", {})
h2_ok = bool(h2_gate.get("passed", False))
h2_active_ok = (not require_h2_active) or (not bool(h2_gate.get("skipped", False)))
if not (
  integrity_ok
  and sentinel_ok
  and ii2_ok
  and g2_ok
  and g3_ok
  and g3_active_ok
  and h0_ok
  and h0_active_ok
  and h1_ok
  and h1_active_ok
  and h2_ok
  and h2_active_ok
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
            "h1_gate": summary.get("h1_gate"),
            "h2_gate": summary.get("h2_gate"),
            "require_g3_active": require_g3_active,
            "g3_active_ok": g3_active_ok,
            "require_h0_active": require_h0_active,
            "h0_active_ok": h0_active_ok,
            "require_h1_active": require_h1_active,
            "h1_active_ok": h1_active_ok,
            "require_h2_active": require_h2_active,
            "h2_active_ok": h2_active_ok,
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
        "h1_gate": summary.get("h1_gate"),
        "h2_gate": summary.get("h2_gate"),
        "require_g3_active": require_g3_active,
        "require_h0_active": require_h0_active,
        "require_h1_active": require_h1_active,
        "require_h2_active": require_h2_active,
    },
    indent=2,
))
PY

if [ "$RUN_H2_RELEASE_CHECK" = "1" ]; then
  H2_RELEASE_ARGS=(
    --run-root "$RUNS_ROOT"
    --outcome-report "$H2_OUTCOME_REPORT"
    --output "$H2_RELEASE_CHECK_REPORT"
    --min-outcome-record-count "$H2_RELEASE_MIN_OUTCOME_RECORD_COUNT"
    --min-delayed-event-count "$H2_RELEASE_MIN_DELAYED_EVENT_COUNT"
    --min-outcome-ledger-coverage-ratio "$H2_MIN_OUTCOME_LEDGER_COVERAGE_RATIO"
    --min-h1-evidence-ref-ratio "$H2_MIN_H1_EVIDENCE_REF_RATIO"
    --min-normative-local-update-blocked-ratio "$H2_MIN_NORMATIVE_LOCAL_UPDATE_BLOCKED_RATIO"
  )
  if [ -n "$H2_BACKEND_OUTCOME_EVENTS" ]; then
    H2_RELEASE_ARGS+=(--backend-outcome-events "$H2_BACKEND_OUTCOME_EVENTS")
  fi
  if [ -n "$H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO" ]; then
    H2_RELEASE_ARGS+=(--min-delayed-verifier-coverage-ratio "$H2_RELEASE_MIN_DELAYED_VERIFIER_COVERAGE_RATIO")
  fi
  if [ "$H2_REQUIRE_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    H2_RELEASE_ARGS+=(--require-backend-outcome-events)
  fi
  if [ "$H2_ALLOW_TRUNCATED_BACKEND_OUTCOME_EVENTS" = "1" ]; then
    H2_RELEASE_ARGS+=(--allow-truncated-backend-outcome-events)
  fi
  "$PYTHON" -m benchmarks.h2_release_check "${H2_RELEASE_ARGS[@]}"
fi

if [ -n "$BASELINE_RUNS_ROOT" ]; then
  "$PYTHON" -m benchmarks.h1_compare \
    --baseline-runs-root "$BASELINE_RUNS_ROOT" \
    --candidate-runs-root "$RUNS_ROOT"
fi

echo "Nightly regression completed: $RUNS_ROOT"
