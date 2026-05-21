#!/usr/bin/env bash
# CI-friendly structural checks for the strict L1 contract smoke path.
#
# This intentionally does not start backend, agents, or an LLM. It verifies the
# fail-fast safety surface and focused unit tests that protect the real smoke
# runner from silently falling back to demo-login.
set -euo pipefail

cd "$(dirname "$0")/.."

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

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

bash -n \
  benchmarks/run_l1_contract_smoke.sh \
  benchmarks/run_beta0_real_model_pilot.sh \
  benchmarks/run_beta1_l1_packet_check.sh \
  benchmarks/run_beta1_repo_review_packet_check.sh \
  benchmarks/run_beta2_operator_apply_packet_check.sh \
  benchmarks/run_beta2_patch_proposal_packet_check.sh \
  benchmarks/run_l1_contract_smoke_scheduled.sh \
  benchmarks/run_l1_repair_audit_packet_check.sh \
  benchmarks/run_nightly_regression.sh

set +e
env \
  -u L1_PILOT_001_WAKE_CALLBACK_SECRET \
  -u CIVITASOS_WAKE_CALLBACK_SECRET \
  -u L1_PILOT_001_SERVICE_TOKEN_SECRET \
  -u CIVITASOS_SERVICE_TOKEN_SECRET \
  bash benchmarks/run_l1_contract_smoke.sh >"$TMP_DIR/missing_secret.out" 2>&1
missing_secret_status=$?
set -e
if [ "$missing_secret_status" -eq 0 ]; then
  echo "strict L1 smoke must fail when signed-wake/service-token secrets are absent" >&2
  cat "$TMP_DIR/missing_secret.out" >&2
  exit 1
fi
grep -q "requires signed wake" "$TMP_DIR/missing_secret.out"

set +e
env \
  -u CIVITASOS_WAKE_CALLBACK_SECRET \
  -u CIVITASOS_SERVICE_TOKEN_SECRET \
  L1_PILOT_001_WAKE_CALLBACK_SECRET=ci-wake-secret \
  L1_PILOT_001_SERVICE_TOKEN_SECRET=ci-service-secret \
  L1_PILOT_001_SERVICE_SCOPES=pool:read \
  bash benchmarks/run_l1_contract_smoke.sh >"$TMP_DIR/missing_scope.out" 2>&1
missing_scope_status=$?
set -e
if [ "$missing_scope_status" -eq 0 ]; then
  echo "strict L1 smoke must fail when required service-token scopes are absent" >&2
  cat "$TMP_DIR/missing_scope.out" >&2
  exit 1
fi
grep -q "missing required scope: agents:read" "$TMP_DIR/missing_scope.out"

"$PYTHON" -m pytest -q \
  benchmarks/tests/test_beta1_repo_review_proposal.py \
  benchmarks/tests/test_beta2_operator_apply_receipt.py \
  benchmarks/tests/test_beta2_patch_proposal.py \
  benchmarks/tests/test_beta2_patch_review_outcome.py \
  benchmarks/tests/test_l1_nightly_wrapper.py \
  benchmarks/tests/test_l1_export_contract_audit_refs.py \
  benchmarks/tests/test_l1_export_operator_repair_probe_byproducts.py \
  benchmarks/tests/test_l1_pilot_contract_runner.py \
  benchmarks/tests/test_l1_pilot_contract_tasks.py

LEDGER_ROOT="${CIVITASOS_EVIDENCE_LEDGER_ROOT:-../civitasos-evidence-ledger}"
RUN_L1_REPAIR_AUDIT_PACKET_CHECK="${RUN_L1_REPAIR_AUDIT_PACKET_CHECK:-auto}"
RUN_BETA1_L1_PACKET_CHECK="${RUN_BETA1_L1_PACKET_CHECK:-auto}"
RUN_BETA2_OPERATOR_APPLY_PACKET_CHECK="${RUN_BETA2_OPERATOR_APPLY_PACKET_CHECK:-auto}"
RUN_BETA2_PATCH_PROPOSAL_PACKET_CHECK="${RUN_BETA2_PATCH_PROPOSAL_PACKET_CHECK:-auto}"
if [ "$RUN_L1_REPAIR_AUDIT_PACKET_CHECK" != "0" ]; then
  if [ -d "$LEDGER_ROOT" ]; then
    CIVITASOS_EVIDENCE_LEDGER_ROOT="$LEDGER_ROOT" \
    L1_REPAIR_AUDIT_PACKET_CHECK_ROOT="$TMP_DIR/l1_repair_audit_packet_check" \
    PYTHON="$PYTHON" \
      benchmarks/run_l1_repair_audit_packet_check.sh
  elif [ "$RUN_L1_REPAIR_AUDIT_PACKET_CHECK" = "1" ]; then
    echo "RUN_L1_REPAIR_AUDIT_PACKET_CHECK=1 but ledger repo not found: $LEDGER_ROOT" >&2
    exit 1
  else
    echo "Skipping L1 repair audit packet check; ledger repo not found: $LEDGER_ROOT"
  fi
fi

BETA1_REPO_REVIEW_PACKET_CHECK_ROOT="$TMP_DIR/beta1_repo_review_packet_check" \
PYTHON="$PYTHON" \
  benchmarks/run_beta1_repo_review_packet_check.sh

if [ "$RUN_BETA1_L1_PACKET_CHECK" != "0" ]; then
  if [ -d "$LEDGER_ROOT" ]; then
    CIVITASOS_EVIDENCE_LEDGER_ROOT="$LEDGER_ROOT" \
    BETA1_L1_PACKET_CHECK_ROOT="$TMP_DIR/beta1_l1_packet_check" \
    PYTHON="$PYTHON" \
      benchmarks/run_beta1_l1_packet_check.sh
  elif [ "$RUN_BETA1_L1_PACKET_CHECK" = "1" ]; then
    echo "RUN_BETA1_L1_PACKET_CHECK=1 but ledger repo not found: $LEDGER_ROOT" >&2
    exit 1
  else
    echo "Skipping Beta-1 L1 packet check; ledger repo not found: $LEDGER_ROOT"
  fi
fi

if [ "$RUN_BETA2_OPERATOR_APPLY_PACKET_CHECK" != "0" ]; then
  if [ -d "$LEDGER_ROOT" ]; then
    CIVITASOS_EVIDENCE_LEDGER_ROOT="$LEDGER_ROOT" \
    BETA2_OPERATOR_APPLY_PACKET_CHECK_ROOT="$TMP_DIR/beta2_operator_apply_packet_check" \
    PYTHON="$PYTHON" \
      benchmarks/run_beta2_operator_apply_packet_check.sh
  elif [ "$RUN_BETA2_OPERATOR_APPLY_PACKET_CHECK" = "1" ]; then
    echo "RUN_BETA2_OPERATOR_APPLY_PACKET_CHECK=1 but ledger repo not found: $LEDGER_ROOT" >&2
    exit 1
  else
    echo "Skipping Beta-2 operator apply packet check; ledger repo not found: $LEDGER_ROOT"
  fi
fi

if [ "$RUN_BETA2_PATCH_PROPOSAL_PACKET_CHECK" != "0" ]; then
  if [ -d "$LEDGER_ROOT" ]; then
    CIVITASOS_EVIDENCE_LEDGER_ROOT="$LEDGER_ROOT" \
    BETA2_PATCH_PROPOSAL_PACKET_CHECK_ROOT="$TMP_DIR/beta2_patch_proposal_packet_check" \
    PYTHON="$PYTHON" \
      benchmarks/run_beta2_patch_proposal_packet_check.sh
  elif [ "$RUN_BETA2_PATCH_PROPOSAL_PACKET_CHECK" = "1" ]; then
    echo "RUN_BETA2_PATCH_PROPOSAL_PACKET_CHECK=1 but ledger repo not found: $LEDGER_ROOT" >&2
    exit 1
  else
    echo "Skipping Beta-2 patch proposal packet check; ledger repo not found: $LEDGER_ROOT"
  fi
fi

echo "L1 contract smoke CI check passed"
