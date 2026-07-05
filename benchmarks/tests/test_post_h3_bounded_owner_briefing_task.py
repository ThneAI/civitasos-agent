from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_bounded_owner_briefing_task import EXECUTION_GATE_NAME, run_chain as run_owner_briefing
from benchmarks.post_h3_bounded_owner_briefing_repeated_validation import (
    run_repeated_validation as run_owner_briefing_repeated_validation,
)
from benchmarks.post_h3_higher_permission_authorization_review_gate import run_gate as run_higher_permission_review
from benchmarks.post_h3_higher_permission_authorization_reconciliation_gate import (
    run_gate as run_higher_permission_reconciliation,
)
from benchmarks.post_h3_operator_feedback_index_update_repeated_validation import run_repeated_validation as run_feedback_repeated
from benchmarks.tests.test_post_h3_minimal_path_stability_and_feedback_update import _write_repeated_validation_fixture
from benchmarks.tests.test_post_h3_minimal_production_task_intake_authorization import _write_readiness_index_fixture


def test_bounded_owner_briefing_runs_artifact_only_chain(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing",
        operator_statement="Authorize one bounded owner briefing for test evidence.",
        ack_bounded_task=True,
    )

    assert summary["passed"] is True
    assert summary["task_class"] == "bounded_owner_briefing"
    assert summary["readiness"]["bounded_owner_briefing_complete"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["owner_briefing_written"] is True
    assert summary["readiness"]["closeout_receipt_written"] is True
    assert summary["readiness"]["strategy_review_complete"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["boundary"]["bounded_task_execution_performed"] is True
    assert summary["boundary"]["backend_task_pool_mutation_performed"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False

    request = json.loads(
        (tmp_path / "owner_briefing" / "authorization" / "post_h3_minimal_task_authorization_request.json").read_text(
            encoding="utf-8"
        )
    )
    receipt = json.loads(
        (tmp_path / "owner_briefing" / "authorization" / "post_h3_minimal_task_authorization_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    briefing = json.loads((tmp_path / "owner_briefing" / "post_h3_bounded_owner_briefing.json").read_text(encoding="utf-8"))
    assert request["required_next_gate"] == EXECUTION_GATE_NAME
    assert receipt["consumption_required_by"] == EXECUTION_GATE_NAME
    assert briefing["owner_recommendation"]["decision"] == "keep_bounded_artifact_only_path_and_prepare_next_reversible_task"
    assert "public_ingress" in briefing["owner_recommendation"]["blocked_expansions"]


def test_bounded_owner_briefing_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing",
        ack_bounded_task=False,
    )

    assert summary["passed"] is False
    assert "explicit_bounded_owner_briefing_ack" in summary["failure_reasons"]
    assert summary["readiness"]["bounded_owner_briefing_complete"] is False


def test_bounded_owner_briefing_repeated_validation_requires_fresh_closeout(
    tmp_path: Path, monkeypatch: Any
) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing_repeated_validation(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing_repeated",
        rounds=3,
        start_index=10,
        ack_repeated_validation=True,
    )

    assert summary["passed"] is True
    assert summary["round_count"] == 3
    assert summary["unique_task_id_count"] == 3
    assert summary["unique_authorization_id_count"] == 3
    assert summary["unique_operator_statement_count"] == 3
    assert summary["readiness"]["fresh_authorization_per_round_verified"] is True
    assert summary["readiness"]["authorization_consumed_per_round_verified"] is True
    assert summary["readiness"]["owner_briefing_per_round_verified"] is True
    assert summary["readiness"]["closeout_per_round_verified"] is True
    assert summary["readiness"]["strategy_review_per_round_verified"] is True
    assert summary["readiness"]["higher_permission_authorization_review_input_ready"] is True
    assert summary["boundary"]["production_task_execution_allowed"] is False
    assert all(round_report["readiness"]["closeout_receipt_written"] is True for round_report in summary["rounds"])


def test_bounded_owner_briefing_repeated_validation_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)

    summary = run_owner_briefing_repeated_validation(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=tmp_path / "owner_briefing_repeated",
        rounds=3,
        ack_repeated_validation=False,
    )

    assert summary["passed"] is False
    assert "explicit_bounded_owner_briefing_repeated_validation_ack" in summary["failure_reasons"]


def test_higher_permission_review_request_consumes_stable_owner_briefing_repeated_validation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    briefing_repeated = _write_owner_briefing_repeated_fixture(
        tmp_path,
        readiness_index=readiness_index,
        feedback_repeated=feedback_repeated,
    )

    summary = run_higher_permission_review(
        bounded_owner_briefing_repeated_validation_summary_path=briefing_repeated,
        output_root=tmp_path / "higher_permission_review",
        operator_statement="Enter higher permission review for test evidence only.",
        ack_review_request=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["higher_permission_authorization_review_ready"] is True
    assert summary["readiness"]["authorization_granted"] is False
    assert summary["readiness"]["future_execution_requires_separate_single_use_authorization"] is True
    assert summary["boundary"]["higher_permission_authorization_review_ready"] is True
    assert summary["boundary"]["public_ingress_authorized"] is False
    assert summary["boundary"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["deploy_authorized"] is False
    assert summary["boundary"]["source_write_authorized"] is False
    assert summary["boundary"]["production_data_access_authorized"] is False
    assert summary["boundary"]["production_task_execution_allowed"] is False


def test_higher_permission_review_request_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    briefing_repeated = _write_owner_briefing_repeated_fixture(
        tmp_path,
        readiness_index=readiness_index,
        feedback_repeated=feedback_repeated,
    )

    summary = run_higher_permission_review(
        bounded_owner_briefing_repeated_validation_summary_path=briefing_repeated,
        output_root=tmp_path / "higher_permission_review",
        ack_review_request=False,
    )

    assert summary["passed"] is False
    assert "explicit_higher_permission_review_request_ack" in summary["failure_reasons"]
    assert summary["readiness"]["higher_permission_authorization_review_ready"] is False


def test_higher_permission_reconciliation_records_five_roles_without_authorization(
    tmp_path: Path, monkeypatch: Any
) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    briefing_repeated = _write_owner_briefing_repeated_fixture(
        tmp_path,
        readiness_index=readiness_index,
        feedback_repeated=feedback_repeated,
    )
    review = _write_higher_permission_review_fixture(tmp_path, briefing_repeated)

    summary = run_higher_permission_reconciliation(
        higher_permission_review_summary_path=review,
        output_root=tmp_path / "higher_permission_reconciliation",
        operator_statement="Reconcile higher permission review for test evidence only.",
        ack_reconciliation=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["higher_permission_authorization_reconciliation_complete"] is True
    assert summary["readiness"]["single_use_authorization_request_ready"] is True
    assert summary["readiness"]["limited_external_usage_authorization_request_ready"] is True
    assert summary["readiness"]["status_only_public_ingress_authorization_request_ready"] is True
    assert summary["readiness"]["bounded_runtime_heartbeat_authorization_request_ready"] is True
    assert summary["readiness"]["authorization_granted"] is False
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["boundary"]["higher_permission_authorization_reconciliation_complete"] is True
    assert summary["boundary"]["single_use_authorization_request_ready"] is True
    assert summary["boundary"]["authorization_granted"] is False
    assert summary["boundary"]["public_ingress_authorized"] is False
    assert summary["boundary"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["deploy_authorized"] is False
    assert summary["boundary"]["source_write_authorized"] is False
    assert summary["boundary"]["production_data_access_authorized"] is False


def test_higher_permission_reconciliation_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    feedback_repeated = _write_feedback_repeated_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    briefing_repeated = _write_owner_briefing_repeated_fixture(
        tmp_path,
        readiness_index=readiness_index,
        feedback_repeated=feedback_repeated,
    )
    review = _write_higher_permission_review_fixture(tmp_path, briefing_repeated)

    summary = run_higher_permission_reconciliation(
        higher_permission_review_summary_path=review,
        output_root=tmp_path / "higher_permission_reconciliation",
        ack_reconciliation=False,
    )

    assert summary["passed"] is False
    assert "explicit_higher_permission_reconciliation_ack" in summary["failure_reasons"]
    assert summary["readiness"]["higher_permission_authorization_reconciliation_complete"] is False


def _write_feedback_repeated_fixture(tmp_path: Path, monkeypatch: Any, readiness_index: Path) -> Path:
    minimal_repeated = _write_repeated_validation_fixture(tmp_path, monkeypatch, readiness_index=readiness_index)
    root = tmp_path / "feedback_repeated"
    run_feedback_repeated(
        readiness_index_path=readiness_index,
        repeated_validation_summary_path=minimal_repeated,
        output_root=root,
        rounds=3,
        start_index=20,
        ack_repeated_validation=True,
    )
    return root / "post_h3_operator_feedback_index_update_repeated_validation_summary.json"


def _write_owner_briefing_repeated_fixture(tmp_path: Path, readiness_index: Path, feedback_repeated: Path) -> Path:
    root = tmp_path / "owner_briefing_repeated_fixture"
    run_owner_briefing_repeated_validation(
        readiness_index_path=readiness_index,
        feedback_repeated_validation_summary_path=feedback_repeated,
        output_root=root,
        rounds=3,
        start_index=30,
        ack_repeated_validation=True,
    )
    return root / "post_h3_bounded_owner_briefing_repeated_validation_summary.json"


def _write_higher_permission_review_fixture(tmp_path: Path, briefing_repeated: Path) -> Path:
    root = tmp_path / "higher_permission_review_fixture"
    run_higher_permission_review(
        bounded_owner_briefing_repeated_validation_summary_path=briefing_repeated,
        output_root=root,
        operator_statement="Enter higher permission review for fixture evidence only.",
        ack_review_request=True,
    )
    return root / "post_h3_higher_permission_authorization_review_summary.json"
