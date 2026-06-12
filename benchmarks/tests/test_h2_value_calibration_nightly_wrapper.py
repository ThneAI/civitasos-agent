from __future__ import annotations

from pathlib import Path


def test_nightly_wrapper_wires_h2_value_calibration_report() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H2_VALUE_CALIBRATION_REPORT="${RUN_H2_VALUE_CALIBRATION_REPORT:-0}"' in text
    assert 'H2_VALUE_CALIBRATION_REPORT="${H2_VALUE_CALIBRATION_REPORT:-$RUNS_ROOT/h2_value_calibration_report.json}"' in text
    assert "H2_VALUE_MIN_BACKEND_SOURCED_REPEATED_OUTCOME_PATTERN_COUNT" in text
    assert 'if [ "$RUN_H2_VALUE_CALIBRATION_REPORT" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h2_value_calibration_report "${H2_VALUE_ARGS[@]}"' in text
    assert '--min-value-calibration-trace-coverage-ratio "$H2_VALUE_MIN_TRACE_COVERAGE_RATIO"' in text
    assert '--min-repeated-outcome-pattern-count "$H2_VALUE_MIN_REPEATED_OUTCOME_PATTERN_COUNT"' in text
    assert '--min-backend-sourced-repeated-outcome-pattern-count "$H2_VALUE_MIN_BACKEND_SOURCED_REPEATED_OUTCOME_PATTERN_COUNT"' in text
    assert '--require-repeated-outcome-event-kind "$event_kind"' in text


def test_nightly_wrapper_wires_h2_value_calibration_closure() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H2_VALUE_CALIBRATION_CLOSURE="${RUN_H2_VALUE_CALIBRATION_CLOSURE:-0}"' in text
    assert 'H2_VALUE_CALIBRATION_CLOSURE_REPORT="${H2_VALUE_CALIBRATION_CLOSURE_REPORT:-$RUNS_ROOT/h2_value_calibration_closure.json}"' in text
    assert "H2_VALUE_CLOSURE_MIN_BACKEND_SOURCED_REPEATED_OUTCOME_PATTERN_COUNT" in text
    assert 'if [ "$RUN_H2_VALUE_CALIBRATION_CLOSURE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h2_value_calibration_closure "${H2_VALUE_CLOSURE_ARGS[@]}"' in text
    assert '--min-value-calibration-trace-coverage-ratio "$H2_VALUE_CLOSURE_MIN_TRACE_COVERAGE_RATIO"' in text
    assert '--min-repeated-outcome-pattern-count "$H2_VALUE_CLOSURE_MIN_REPEATED_OUTCOME_PATTERN_COUNT"' in text
    assert '--min-backend-sourced-repeated-outcome-pattern-count "$H2_VALUE_CLOSURE_MIN_BACKEND_SOURCED_REPEATED_OUTCOME_PATTERN_COUNT"' in text
    assert '--require-repeated-outcome-event-kind "$event_kind"' in text
    assert '--require-backend-sourced-repeated-outcome-event-kind "$event_kind"' in text
    assert (
        '--delayed-consequence-evidence-report '
        '"$H2_VALUE_CLOSURE_DELAYED_CONSEQUENCE_EVIDENCE_REPORT"'
    ) in text


def test_nightly_wrapper_runs_only_opt_in_vm_csp_smoke() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H2_VM_CSP_SMOKE="${RUN_H2_VM_CSP_SMOKE:-0}"' in text
    assert 'if [ "$RUN_H2_VM_CSP_SMOKE" = "1" ]; then' in text
    assert "-m benchmarks.h2_vm_csp_soak smoke" in text
    assert "-m benchmarks.h2_vm_csp_soak stop" in text
    assert "-m benchmarks.h2_vm_csp_soak cleanup" in text
    assert "-m benchmarks.h2_vm_csp_soak soak" not in text


def test_nightly_wrapper_wires_h2_qualification_and_semantic_checkers() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert (
        'RUN_H2_VM_CSP_QUALIFICATION_CHECK='
        '"${RUN_H2_VM_CSP_QUALIFICATION_CHECK:-0}"'
    ) in text
    assert "-m benchmarks.h2_vm_csp_qualification_check" in text
    assert (
        'RUN_H2_DELAYED_CONSEQUENCE_EVIDENCE_CHECK='
        '"${RUN_H2_DELAYED_CONSEQUENCE_EVIDENCE_CHECK:-0}"'
    ) in text
    assert "-m benchmarks.h2_delayed_consequence_evidence_check" in text
    assert '--owner-id "$H2_MULTI_AGENT_OWNER_ID"' in text


def test_nightly_wrapper_wires_h2_h3_read_only_readiness_chain() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert (
        'H2_DELAYED_CONSEQUENCE_REQUIRE_READY='
        '"${H2_DELAYED_CONSEQUENCE_REQUIRE_READY:-0}"'
    ) in text
    assert 'if [ "$H2_DELAYED_STATUS" -eq 3 ]; then' in text
    assert (
        'RUN_H3_READ_ONLY_GOAL_PROPOSAL_GATE='
        '"${RUN_H3_READ_ONLY_GOAL_PROPOSAL_GATE:-0}"'
    ) in text
    assert "-m benchmarks.h3_read_only_goal_proposal_gate" in text
    assert '--h2-evidence-report "$H3_READ_ONLY_H2_EVIDENCE_REPORT"' in text
    assert (
        'RUN_H3_OPERATOR_REVIEW_RECONCILIATION_GATE='
        '"${RUN_H3_OPERATOR_REVIEW_RECONCILIATION_GATE:-0}"'
    ) in text
    assert "-m benchmarks.h3_operator_review_reconciliation_gate reconcile" in text
    assert "H3_OPERATOR_REVIEW_PACKET is required" in text
    assert (
        'RUN_H3_BOUNDED_PLAN_DRAFT_GATE='
        '"${RUN_H3_BOUNDED_PLAN_DRAFT_GATE:-0}"'
    ) in text
    assert "-m benchmarks.h3_bounded_plan_draft_gate" in text
    assert (
        '--reconciliation-report '
        '"$H3_BOUNDED_PLAN_RECONCILIATION_REPORT"'
    ) in text
    assert (
        'RUN_H3_BOUNDED_PLAN_CHALLENGE_REVIEW_GATE='
        '"${RUN_H3_BOUNDED_PLAN_CHALLENGE_REVIEW_GATE:-0}"'
    ) in text
    assert "-m benchmarks.h3_bounded_plan_challenge_review_gate reconcile" in text
    assert "H3_BOUNDED_PLAN_CHALLENGE_REVIEW_PACKET is required" in text
    assert (
        'RUN_H3_CONTROLLED_PILOT_AUTHORIZATION_REQUEST_GATE='
        '"${RUN_H3_CONTROLLED_PILOT_AUTHORIZATION_REQUEST_GATE:-0}"'
    ) in text
    assert (
        "-m benchmarks.h3_controlled_pilot_authorization_request_gate"
        in text
    )
    assert (
        'RUN_H3_CONTROLLED_PILOT_AUTHORIZATION_DECISION_GATE='
        '"${RUN_H3_CONTROLLED_PILOT_AUTHORIZATION_DECISION_GATE:-0}"'
    ) in text
    assert (
        "-m benchmarks.h3_controlled_pilot_authorization_decision_gate reconcile"
        in text
    )
    assert (
        "H3_CONTROLLED_PILOT_AUTHORIZATION_DECISION_PACKET is required"
        in text
    )
    assert (
        'RUN_H3_CONTROLLED_PILOT_EXECUTION_PREFLIGHT_GATE='
        '"${RUN_H3_CONTROLLED_PILOT_EXECUTION_PREFLIGHT_GATE:-0}"'
    ) in text
    assert (
        "-m benchmarks.h3_controlled_pilot_execution_preflight_gate"
        in text
    )
    assert (
        "H3_CONTROLLED_PILOT_EXECUTION_PREFLIGHT_AUTHORIZATION_RECEIPT_ID is required"
        in text
    )
    assert (
        'RUN_H2_H3_READINESS_SUMMARY='
        '"${RUN_H2_H3_READINESS_SUMMARY:-$RUN_H2_DELAYED_CONSEQUENCE_EVIDENCE_CHECK}"'
    ) in text
    assert "-m benchmarks.h2_h3_readiness_summary" in text


def test_nightly_wrapper_wires_h3_goal_generator_skeleton() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_GENERATOR_SKELETON="${RUN_H3_GOAL_GENERATOR_SKELETON:-0}"' in text
    assert 'H3_GOAL_GENERATOR_SKELETON_REPORT="${H3_GOAL_GENERATOR_SKELETON_REPORT:-$RUNS_ROOT/h3_goal_generator_skeleton.json}"' in text
    assert 'H3_GOAL_GENERATOR_H2_CLOSURE_REPORT="${H3_GOAL_GENERATOR_H2_CLOSURE_REPORT:-$H2_VALUE_CALIBRATION_CLOSURE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_GENERATOR_SKELETON" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_generator_skeleton "${H3_GOAL_GENERATOR_SKELETON_ARGS[@]}"' in text
    assert '--h2-closure-report "$H3_GOAL_GENERATOR_H2_CLOSURE_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_candidate_draft_report() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_CANDIDATE_DRAFT_REPORT="${RUN_H3_GOAL_CANDIDATE_DRAFT_REPORT:-0}"' in text
    assert 'H3_GOAL_CANDIDATE_DRAFT_REPORT="${H3_GOAL_CANDIDATE_DRAFT_REPORT:-$RUNS_ROOT/h3_goal_candidate_draft_report.json}"' in text
    assert 'H3_GOAL_CANDIDATE_SKELETON_REPORT="${H3_GOAL_CANDIDATE_SKELETON_REPORT:-$H3_GOAL_GENERATOR_SKELETON_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_CANDIDATE_DRAFT_REPORT" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_candidate_draft_report "${H3_GOAL_CANDIDATE_DRAFT_ARGS[@]}"' in text
    assert '--h3-skeleton-report "$H3_GOAL_CANDIDATE_SKELETON_REPORT"' in text
    assert '--max-candidate-goals "$H3_GOAL_CANDIDATE_MAX_CANDIDATES"' in text


def test_nightly_wrapper_wires_h3_goal_lifecycle_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_LIFECYCLE_GATE="${RUN_H3_GOAL_LIFECYCLE_GATE:-0}"' in text
    assert 'H3_GOAL_LIFECYCLE_GATE_REPORT="${H3_GOAL_LIFECYCLE_GATE_REPORT:-$RUNS_ROOT/h3_goal_lifecycle_gate.json}"' in text
    assert 'H3_GOAL_LIFECYCLE_DRAFT_REPORT="${H3_GOAL_LIFECYCLE_DRAFT_REPORT:-$H3_GOAL_CANDIDATE_DRAFT_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_LIFECYCLE_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_lifecycle_gate "${H3_GOAL_LIFECYCLE_GATE_ARGS[@]}"' in text
    assert '--draft-report "$H3_GOAL_LIFECYCLE_DRAFT_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_approval_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_APPROVAL_GATE="${RUN_H3_GOAL_APPROVAL_GATE:-0}"' in text
    assert 'H3_GOAL_APPROVAL_GATE_REPORT="${H3_GOAL_APPROVAL_GATE_REPORT:-$RUNS_ROOT/h3_goal_approval_gate.json}"' in text
    assert 'H3_GOAL_APPROVAL_LIFECYCLE_REPORT="${H3_GOAL_APPROVAL_LIFECYCLE_REPORT:-$H3_GOAL_LIFECYCLE_GATE_REPORT}"' in text
    assert 'H3_GOAL_APPROVAL_REVIEW_ARTIFACTS="${H3_GOAL_APPROVAL_REVIEW_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_APPROVAL_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_approval_gate "${H3_GOAL_APPROVAL_GATE_ARGS[@]}"' in text
    assert '--lifecycle-gate "$H3_GOAL_APPROVAL_LIFECYCLE_REPORT"' in text
    assert 'H3_GOAL_APPROVAL_GATE_ARGS+=(--review-artifacts "$H3_GOAL_APPROVAL_REVIEW_ARTIFACTS")' in text


def test_nightly_wrapper_wires_h3_external_review_artifact_fixture() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE="${RUN_H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE:-0}"' in text
    assert 'H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_REPORT="${H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_REPORT:-$RUNS_ROOT/h3_external_review_artifacts_fixture.json}"' in text
    assert 'H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_LIFECYCLE_REPORT="${H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_LIFECYCLE_REPORT:-$H3_GOAL_LIFECYCLE_GATE_REPORT}"' in text
    assert 'H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_MODE="${H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_MODE:-pending}"' in text
    assert 'H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_ACK="${H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_ACK:-0}"' in text
    assert 'if [ "$RUN_H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_external_review_artifacts_fixture "${H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_ARGS[@]}"' in text
    assert '--fixture-mode "$H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_MODE"' in text
    assert 'H3_EXTERNAL_REVIEW_ARTIFACT_FIXTURE_ARGS+=(--ack-synthetic-approval-fixture)' in text


def test_nightly_wrapper_wires_h3_goal_emission_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_GATE="${RUN_H3_GOAL_EMISSION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_GATE_REPORT="${H3_GOAL_EMISSION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_APPROVAL_REPORT="${H3_GOAL_EMISSION_APPROVAL_REPORT:-$H3_GOAL_APPROVAL_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_gate "${H3_GOAL_EMISSION_GATE_ARGS[@]}"' in text
    assert '--approval-gate "$H3_GOAL_EMISSION_APPROVAL_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_emission_activation_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_ACTIVATION_GATE="${RUN_H3_GOAL_EMISSION_ACTIVATION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_GATE_REPORT="${H3_GOAL_EMISSION_ACTIVATION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_activation_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_EMISSION_REPORT="${H3_GOAL_EMISSION_ACTIVATION_EMISSION_REPORT:-$H3_GOAL_EMISSION_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_ACTIVATION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_activation_gate "${H3_GOAL_EMISSION_ACTIVATION_GATE_ARGS[@]}"' in text
    assert '--emission-gate "$H3_GOAL_EMISSION_ACTIVATION_EMISSION_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_emission_activation_artifact_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE="${RUN_H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE_REPORT="${H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_activation_artifact_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_ACTIVATION_REPORT="${H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_ACTIVATION_REPORT:-$H3_GOAL_EMISSION_ACTIVATION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_ARTIFACTS="${H3_GOAL_EMISSION_ACTIVATION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_activation_artifact_gate "${H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE_ARGS[@]}"' in text
    assert '--activation-gate "$H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_ACTIVATION_REPORT"' in text
    assert 'H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE_ARGS+=(--activation-artifacts "$H3_GOAL_EMISSION_ACTIVATION_ARTIFACTS")' in text


def test_nightly_wrapper_wires_h3_goal_emission_runtime_activation_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_activation_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT:-$H3_GOAL_EMISSION_ACTIVATION_ARTIFACT_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_activation_gate "${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE_ARGS[@]}"' in text
    assert '--activation-artifact-gate "$H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_emission_runtime_activation_artifact_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_activation_artifact_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_RUNTIME_REPORT="${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_RUNTIME_REPORT:-$H3_GOAL_EMISSION_RUNTIME_ACTIVATION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_activation_artifact_gate "${H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_ARGS[@]}"' in text
    assert '--runtime-activation-gate "$H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_RUNTIME_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_ARGS+=(--runtime-activation-artifacts "$H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACTS")' in text


def test_nightly_wrapper_wires_h3_goal_emission_runtime_start_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_START_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_START_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_START_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_start_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_START_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_START_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_start_gate "${H3_GOAL_EMISSION_RUNTIME_START_GATE_ARGS[@]}"' in text
    assert '--runtime-activation-artifact-gate "$H3_GOAL_EMISSION_RUNTIME_START_RUNTIME_ACTIVATION_ARTIFACT_GATE_REPORT"' in text


def test_nightly_wrapper_wires_h3_goal_emission_runtime_start_artifact_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_start_artifact_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_START_REPORT="${H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_START_REPORT:-$H3_GOAL_EMISSION_RUNTIME_START_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_START_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_start_artifact_gate "${H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE_ARGS[@]}"' in text
    assert '--runtime-start-gate "$H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_START_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE_ARGS+=(--runtime-start-artifacts "$H3_GOAL_EMISSION_RUNTIME_START_ARTIFACTS")' in text


def test_nightly_wrapper_wires_h3_goal_emission_runtime_execution_gate_and_executor() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_execution_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_START_ARTIFACT_REPORT="${H3_GOAL_EMISSION_RUNTIME_EXECUTION_START_ARTIFACT_REPORT:-$H3_GOAL_EMISSION_RUNTIME_START_ARTIFACT_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_ACK="${H3_GOAL_EMISSION_RUNTIME_EXECUTION_ACK:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_ALLOW_LOCAL_CONTROLLED="${H3_GOAL_EMISSION_RUNTIME_EXECUTION_ALLOW_LOCAL_CONTROLLED:-0}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_execution_gate "${H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_ARGS[@]}"' in text
    assert '--runtime-start-artifact-gate "$H3_GOAL_EMISSION_RUNTIME_EXECUTION_START_ARTIFACT_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_ARGS+=(--ack-runtime-execution)' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_ARGS+=(--allow-local-controlled-execution)' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTOR="${RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTOR:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTOR_REPORT="${H3_GOAL_EMISSION_RUNTIME_EXECUTOR_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_executor.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTOR_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_EXECUTOR_GATE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_EXECUTION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTOR_ACK="${H3_GOAL_EMISSION_RUNTIME_EXECUTOR_ACK:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTOR_RECEIPT_DIR="${H3_GOAL_EMISSION_RUNTIME_EXECUTOR_RECEIPT_DIR:-$RUNS_ROOT/h3_runtime_execution_receipts}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_EXECUTOR" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_executor "${H3_GOAL_EMISSION_RUNTIME_EXECUTOR_ARGS[@]}"' in text
    assert '--runtime-execution-gate "$H3_GOAL_EMISSION_RUNTIME_EXECUTOR_GATE_REPORT"' in text
    assert '--receipt-dir "$H3_GOAL_EMISSION_RUNTIME_EXECUTOR_RECEIPT_DIR"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_EXECUTOR_ARGS+=(--ack-local-runtime-execution)' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_evidence_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_EXECUTOR_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_EXECUTOR_REPORT:-$H3_GOAL_EMISSION_RUNTIME_EXECUTOR_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_evidence_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE_ARGS[@]}"' in text
    assert '--runtime-executor "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_EXECUTOR_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE_ARGS+=(--production-evidence "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_evidence_request.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_GATE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_evidence_request' in text
    assert '--production-evidence-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_GATE_REPORT"' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_evidence_intake.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REQUEST_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REQUEST_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_REQUEST_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_SUBMISSION="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_SUBMISSION:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_evidence_intake "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_ARGS[@]}"' in text
    assert '--production-evidence-request "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REQUEST_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_ARGS+=(--production-evidence-submission "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_SUBMISSION")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_evidence_submission_template.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_INTAKE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_INTAKE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_INTAKE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_evidence_submission_template' in text
    assert '--production-evidence-intake "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_INTAKE_REPORT"' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_evidence_submission_manifest.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_TEMPLATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_TEMPLATE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SUBMISSION="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SUBMISSION:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_evidence_submission_manifest "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_ARGS[@]}"' in text
    assert '--production-evidence-submission-template "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_TEMPLATE_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_ARGS+=(--production-evidence-submission "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SUBMISSION")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_execution_authorization_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_MANIFEST_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_MANIFEST_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_execution_authorization_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_ARGS[@]}"' in text
    assert '--production-evidence-submission-manifest "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_MANIFEST_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_ARGS+=(--production-execution-authorization "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_goal_alignment_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_AUTHORIZATION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_AUTHORIZATION_GATE_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_goal_alignment_gate' in text
    assert '--production-execution-authorization-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_AUTHORIZATION_GATE_REPORT"' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_executor_permission_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GOAL_ALIGNMENT_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GOAL_ALIGNMENT_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_executor_permission_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_ARGS[@]}"' in text
    assert '--production-goal-alignment-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GOAL_ALIGNMENT_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_ARGS+=(--production-executor-permission "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_runtime_execution_handoff_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_PERMISSION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_PERMISSION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_runtime_execution_handoff_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_ARGS[@]}"' in text
    assert '--production-executor-permission-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_PERMISSION_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_ARGS+=(--production-runtime-execution-handoff "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_runtime_execution_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_runtime_execution_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_ARGS[@]}"' in text
    assert '--production-runtime-execution-handoff-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_ARGS+=(--production-runtime-execution "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_runtime_actuation_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_EXECUTION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_EXECUTION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_runtime_actuation_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_ARGS[@]}"' in text
    assert '--production-runtime-execution-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_EXECUTION_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_ARGS+=(--production-runtime-actuation "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_ARTIFACTS")' in text
    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_runtime_receipt_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ACTUATION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ACTUATION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ARTIFACTS="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ARTIFACTS:-}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_runtime_receipt_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE_ARGS[@]}"' in text
    assert '--production-runtime-actuation-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ACTUATION_REPORT"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE_ARGS+=(--production-runtime-receipt "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_ARTIFACTS")' in text


def test_nightly_wrapper_wires_h3_runtime_production_stage_transition_gate() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_GATE="${RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_GATE:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_GATE_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_GATE_REPORT:-$RUNS_ROOT/h3_goal_emission_runtime_production_stage_transition_gate.json}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_MANIFEST_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_MANIFEST_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_BUNDLE_REVIEW="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_BUNDLE_REVIEW:-}"' in text
    assert 'REQUIRE_H3_PRODUCTION_EVIDENCE_BUNDLE_REVIEW="${REQUIRE_H3_PRODUCTION_EVIDENCE_BUNDLE_REVIEW:-0}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_AUTHORIZATION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_AUTHORIZATION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTION_AUTHORIZATION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ALIGNMENT_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ALIGNMENT_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_GOAL_ALIGNMENT_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_PERMISSION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_PERMISSION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_EXECUTOR_PERMISSION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_HANDOFF_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_HANDOFF_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_EXECUTION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_EXECUTION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_EXECUTION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ACTUATION_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ACTUATION_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_ACTUATION_GATE_REPORT}"' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_RECEIPT_REPORT="${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_RECEIPT_REPORT:-$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_RUNTIME_RECEIPT_GATE_REPORT}"' in text
    assert 'if [ "$RUN_H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_GATE" = "1" ]; then' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_stage_transition_gate' in text
    assert '--production-evidence-submission-manifest "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_MANIFEST_REPORT"' in text
    assert '--production-execution-authorization-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_AUTHORIZATION_REPORT"' in text
    assert '--production-goal-alignment-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ALIGNMENT_REPORT"' in text
    assert '--production-executor-permission-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_PERMISSION_REPORT"' in text
    assert '--production-runtime-execution-handoff-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_HANDOFF_REPORT"' in text
    assert '--production-runtime-execution-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_EXECUTION_REPORT"' in text
    assert '--production-runtime-actuation-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ACTUATION_REPORT"' in text
    assert '--production-runtime-receipt-gate "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_RECEIPT_REPORT"' in text
    assert 'H3 production stage transition requires H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_BUNDLE_REVIEW' in text
    assert 'H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ARGS+=(--production-evidence-bundle-review "$H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_BUNDLE_REVIEW")' in text
    assert '"$PYTHON" -m benchmarks.h3_goal_emission_runtime_production_stage_transition_gate "${H3_GOAL_EMISSION_RUNTIME_PRODUCTION_STAGE_TRANSITION_ARGS[@]}"' in text
