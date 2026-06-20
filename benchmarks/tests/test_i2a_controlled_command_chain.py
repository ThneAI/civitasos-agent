from __future__ import annotations

import json
from pathlib import Path

from benchmarks.i2a_controlled_command_chain import (
    write_operator_review,
    write_registration_receipt,
    write_scoped_authorization,
    write_acceptance_receipt,
    write_isolation_preflight,
    run_chain,
)
from benchmarks.tests.i_gate_fixtures import write_i2_request


def test_i2a_chain_passes_without_real_external_commanding(tmp_path: Path) -> None:
    request = write_i2_request(tmp_path, passed=True)

    summary = run_chain(i2_request_path=request, output_root=tmp_path / "i2a")

    assert summary["passed"] is True
    assert summary["readiness"]["i2a_protocol_smoke_complete"] is True
    assert summary["readiness"]["real_external_agent_command_allowed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False

    execution = json.loads((tmp_path / "i2a" / "i2a_command_execution_receipt.json").read_text())
    assert execution["passed"] is True
    assert execution["execution"]["command_consumed"] is True
    assert execution["execution"]["external_side_effect_observed"] is False
    output_ref = execution["execution"]["output_artifact"]
    assert Path(output_ref["path"]).is_file()

    reconciliation = json.loads((tmp_path / "i2a" / "i2a_operator_reconciliation.json").read_text())
    assert reconciliation["readiness"]["i2b_real_external_command_discussion_ready"] is True
    assert reconciliation["readiness"]["real_task_command_allowed"] is False


def test_i2a_operator_review_blocks_failed_i2_request(tmp_path: Path) -> None:
    request = write_i2_request(tmp_path, passed=False)

    report = write_operator_review(
        i2_request_path=request,
        output=tmp_path / "operator_review.json",
        operator_id="operator-cc",
    )

    assert report["passed"] is False
    assert report["checks"]["i2_request_passed"] is False
    assert report["readiness"]["i2_execution_allowed"] is False


def test_i2a_operator_review_blocks_request_boundary_drift(tmp_path: Path) -> None:
    request = write_i2_request(tmp_path, passed=True)
    payload = json.loads(request.read_text(encoding="utf-8"))
    payload["readiness"]["i2_execution_allowed"] = True
    payload["boundary"]["external_agent_command_allowed"] = True
    request.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    report = write_operator_review(
        i2_request_path=request,
        output=tmp_path / "operator_review.json",
        operator_id="operator-cc",
    )

    assert report["passed"] is False
    assert report["checks"]["i2_request_passed"] is True
    assert report["checks"]["request_does_not_already_allow_execution"] is False
    assert report["readiness"]["i2_execution_allowed"] is False
    assert report["boundary"]["external_agent_command_allowed"] is False


def test_i2a_scoped_authorization_blocks_expiry_over_limit(tmp_path: Path) -> None:
    request = write_i2_request(tmp_path, passed=True)
    review_path = tmp_path / "operator_review.json"
    registration_path = tmp_path / "registration.json"
    authorization_path = tmp_path / "authorization.json"
    write_operator_review(
        i2_request_path=request,
        output=review_path,
        operator_id="operator-cc",
    )
    write_registration_receipt(
        operator_review_path=review_path,
        output=registration_path,
        executor_alias="i2a-controlled-external-agent",
    )

    report = write_scoped_authorization(
        operator_review_path=review_path,
        registration_path=registration_path,
        output=authorization_path,
        objective="Return a read-only boundary attestation.",
        expiry_minutes=61,
    )

    assert report["passed"] is False
    assert report["checks"]["expiry_within_limit"] is False
    assert report["readiness"]["single_use_command_ready_for_preflight"] is False
    assert report["readiness"]["command_execution_allowed_before_preflight"] is False
    assert report["boundary"]["source_tree_write_allowed"] is False
    assert report["boundary"]["git_write_allowed"] is False
    assert report["boundary"]["production_transition_allowed"] is False


def test_i2a_preflight_blocks_replayed_acceptance_command_id(tmp_path: Path) -> None:
    request = write_i2_request(tmp_path, passed=True)
    review_path = tmp_path / "operator_review.json"
    registration_path = tmp_path / "registration.json"
    authorization_path = tmp_path / "authorization.json"
    acceptance_path = tmp_path / "acceptance.json"
    write_operator_review(
        i2_request_path=request,
        output=review_path,
        operator_id="operator-cc",
    )
    write_registration_receipt(
        operator_review_path=review_path,
        output=registration_path,
        executor_alias="i2a-controlled-external-agent",
    )
    write_scoped_authorization(
        operator_review_path=review_path,
        registration_path=registration_path,
        output=authorization_path,
        objective="Return a read-only boundary attestation.",
        expiry_minutes=30,
    )
    write_acceptance_receipt(
        registration_path=registration_path,
        authorization_path=authorization_path,
        output=acceptance_path,
    )
    acceptance = json.loads(acceptance_path.read_text(encoding="utf-8"))
    acceptance["acceptance"]["accepted_command_id"] = "i2a-command:replayed-command"
    acceptance_path.write_text(json.dumps(acceptance, indent=2, sort_keys=True), encoding="utf-8")

    report = write_isolation_preflight(
        authorization_path=authorization_path,
        acceptance_path=acceptance_path,
        output=tmp_path / "preflight.json",
        workspace=tmp_path / "workspace",
    )

    assert report["passed"] is False
    assert report["checks"]["command_id_matches_acceptance"] is False
    assert report["readiness"]["command_execution_allowed_in_isolation"] is False
    assert report["boundary"]["isolated_command_execution_allowed"] is False
    assert report["boundary"]["source_tree_write_allowed"] is False
    assert report["boundary"]["git_write_allowed"] is False
