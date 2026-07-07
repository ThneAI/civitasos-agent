from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_limited_external_usage_feedback_authorization_request_gate import (
    AUTHORIZATION_DOMAIN,
    run_gate as run_limited_feedback_authorization_request,
)
from benchmarks.post_h3_limited_feedback_higher_permission_review_reconciliation_gate import run_gate
from benchmarks.post_h3_limited_feedback_higher_permission_review_request_gate import run_gate as run_review_request
from benchmarks.tests.test_post_h3_limited_feedback_higher_permission_review_request_gate import (
    _write_higher_permission_strategy_fixture,
)


def test_limited_feedback_higher_permission_reconciliation_records_five_roles_without_authorization(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = _write_review_request_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        higher_permission_review_request_summary_path=request,
        output_root=tmp_path / "higher_permission_reconciliation",
        operator_statement="Approve higher permission review only; keep execution separately gated.",
        ack_reconciliation=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["higher_permission_review_reconciliation_complete"] is True
    assert summary["readiness"]["single_use_authorization_request_ready"] is True
    assert summary["readiness"]["limited_feedback_authorization_request_ready"] is True
    assert summary["readiness"]["status_only_public_ingress_authorization_request_ready"] is True
    assert summary["readiness"]["bounded_runtime_heartbeat_authorization_request_ready"] is True
    assert summary["readiness"]["authorization_granted"] is False
    assert summary["readiness"]["execution_authorization_ready"] is False
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert summary["readiness"]["public_ingress_authorized"] is False
    assert summary["readiness"]["runtime_expansion_authorized"] is False
    assert summary["boundary"]["single_use_authorization_request_ready"] is True
    assert summary["boundary"]["authorization_granted"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False
    assert summary["boundary"]["source_tree_write_performed"] is False
    assert summary["boundary"]["git_write_performed"] is False



def test_limited_feedback_authorization_request_consumes_limited_feedback_reconciliation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = _write_review_request_fixture(tmp_path, monkeypatch)
    reconciliation_root = tmp_path / "higher_permission_reconciliation"
    run_gate(
        higher_permission_review_request_summary_path=request,
        output_root=reconciliation_root,
        operator_statement="Approve higher permission review only; keep execution separately gated.",
        ack_reconciliation=True,
    )

    summary = run_limited_feedback_authorization_request(
        higher_permission_reconciliation_summary_path=reconciliation_root
        / "post_h3_limited_feedback_higher_permission_review_reconciliation_summary.json",
        output_root=tmp_path / "limited_feedback_authorization_request",
        operator_statement="Request one feedback-only authorization after limited-feedback reconciliation.",
        ack_authorization_request=True,
    )

    assert summary["passed"] is True
    assert summary["authorization_domain"] == AUTHORIZATION_DOMAIN
    assert summary["readiness"]["limited_external_usage_feedback_authorization_request_ready"] is True
    assert summary["readiness"]["single_use_authorization_request_ready"] is True
    assert summary["readiness"]["authorization_decision_required"] is True
    assert summary["readiness"]["authorization_granted"] is False
    assert summary["readiness"]["feedback_collection_execution_ready"] is False
    assert summary["readiness"]["external_user_feedback_collection_allowed"] is False
    assert summary["boundary"]["authorization_request_written"] is True
    assert summary["boundary"]["authorization_granted"] is False
    assert summary["boundary"]["feedback_collection_performed"] is False
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_limited_feedback_higher_permission_reconciliation_requires_ack(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = _write_review_request_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        higher_permission_review_request_summary_path=request,
        output_root=tmp_path / "higher_permission_reconciliation",
        ack_reconciliation=False,
    )

    assert summary["passed"] is False
    assert "explicit_limited_feedback_higher_permission_reconciliation_ack" in summary["failure_reasons"]
    assert summary["readiness"]["single_use_authorization_request_ready"] is False


def test_limited_feedback_higher_permission_reconciliation_blocks_bad_security_decision(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = _write_review_request_fixture(tmp_path, monkeypatch)

    summary = run_gate(
        higher_permission_review_request_summary_path=request,
        output_root=tmp_path / "higher_permission_reconciliation",
        security_decision="allow_unbounded_public_ingress",
        ack_reconciliation=True,
    )

    assert summary["passed"] is False
    assert "security_decision_passed" in summary["failure_reasons"]
    assert summary["readiness"]["single_use_authorization_request_ready"] is False


def test_limited_feedback_higher_permission_reconciliation_blocks_hash_drift(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = _write_review_request_fixture(tmp_path, monkeypatch)
    request_summary = json.loads(request.read_text(encoding="utf-8"))
    request_path = Path(request_summary["artifacts"]["review_request"]["path"])
    request_payload = json.loads(request_path.read_text(encoding="utf-8"))
    request_payload["operator_statement"] = "tampered after request summary hash ref"
    request_path.write_text(
        json.dumps(request_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = run_gate(
        higher_permission_review_request_summary_path=request,
        output_root=tmp_path / "higher_permission_reconciliation",
        ack_reconciliation=True,
    )

    assert summary["passed"] is False
    assert "review_request_hash_valid" in summary["failure_reasons"]


def _write_review_request_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    strategy = _write_higher_permission_strategy_fixture(tmp_path, monkeypatch)
    root = tmp_path / "higher_permission_review_request"
    run_review_request(
        limited_feedback_closeout_strategy_summary_path=strategy,
        output_root=root,
        operator_statement="Request higher permission review only; no execution.",
        ack_review_request=True,
    )
    return root / "post_h3_limited_feedback_higher_permission_review_request_summary.json"
