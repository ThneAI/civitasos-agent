from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_minimal_production_task_authorization_gate import run_gate as run_authorization
from benchmarks.post_h3_minimal_production_task_chain import run_gate as run_minimal_chain
from benchmarks.post_h3_minimal_production_task_execution_gate import run_gate as run_execution
from benchmarks.post_h3_minimal_production_task_intake_gate import DEFAULT_TASK_REQUEST, run_gate as run_intake
from benchmarks.post_h3_observer_mode_readiness_gate import run_gate as run_post_h3ac
from benchmarks.post_h3_readiness_index import build_index
from benchmarks.tests.test_post_h3_observer_mode_readiness_gate import _write_post_h3ab_fixture


def test_post_h3_minimal_task_intake_accepts_readiness_index(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)

    summary = run_intake(
        readiness_index_path=readiness_index,
        output_root=tmp_path / "intake",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["minimal_production_task_intake_ready"] is True
    assert summary["readiness"]["authorization_gate_input_ready"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3_minimal_task_intake_rejects_unsafe_scope(tmp_path: Path, monkeypatch: Any) -> None:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    request = json.loads(json.dumps(DEFAULT_TASK_REQUEST))
    request["scope"]["service_token_scopes"].append("admin:*")
    request_path = tmp_path / "unsafe_task_request.json"
    request_path.write_text(json.dumps(request, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_intake(
        readiness_index_path=readiness_index,
        output_root=tmp_path / "intake",
        task_request_path=request_path,
    )

    assert summary["passed"] is False
    assert "service_scopes_allowlisted" in summary["failure_reasons"]
    assert "service_scopes_safe" in summary["failure_reasons"]
    assert summary["readiness"]["production_task_execution_allowed"] is False


def test_post_h3_minimal_task_authorization_accepts_intake_once(tmp_path: Path, monkeypatch: Any) -> None:
    intake = _write_intake_fixture(tmp_path, monkeypatch)

    summary = run_authorization(
        intake_summary_path=intake,
        output_root=tmp_path / "authorization",
        ack_single_use_authorization=True,
    )

    assert summary["passed"] is True
    assert summary["authorization"]["single_use"] is True
    assert summary["authorization"]["consumed"] is False
    assert summary["readiness"]["minimal_production_task_authorized"] is True
    assert summary["readiness"]["execution_gate_input_ready"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is True
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["boundary"]["single_use_execution_authorized"] is True
    assert summary["boundary"]["runtime_execution_performed"] is False


def test_post_h3_minimal_task_authorization_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    intake = _write_intake_fixture(tmp_path, monkeypatch)

    summary = run_authorization(
        intake_summary_path=intake,
        output_root=tmp_path / "authorization",
        ack_single_use_authorization=False,
    )

    assert summary["passed"] is False
    assert "explicit_single_use_authorization_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_task_execution_allowed"] is False


def test_post_h3_minimal_task_authorization_blocks_intake_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    intake = _write_intake_fixture(tmp_path, monkeypatch)
    intake_packet = tmp_path / "intake" / "post_h3_minimal_task_intake_packet.json"
    payload = json.loads(intake_packet.read_text(encoding="utf-8"))
    payload["task_request"]["risk_class"] = "medium"
    intake_packet.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_authorization(
        intake_summary_path=intake,
        output_root=tmp_path / "authorization",
        ack_single_use_authorization=True,
    )

    assert summary["passed"] is False
    assert "intake_packet_hash_valid" in summary["failure_reasons"]
    assert summary["readiness"]["production_task_execution_allowed"] is False


def test_post_h3_minimal_task_execution_consumes_authorization_and_closes(tmp_path: Path, monkeypatch: Any) -> None:
    authorization = _write_authorization_fixture(tmp_path, monkeypatch)

    summary = run_execution(
        authorization_summary_path=authorization,
        output_root=tmp_path / "execution",
        ack_minimal_task_execution=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["minimal_production_task_execution_complete"] is True
    assert summary["readiness"]["status_evidence_index_written"] is True
    assert summary["readiness"]["execution_receipt_written"] is True
    assert summary["readiness"]["monitoring_receipt_written"] is True
    assert summary["readiness"]["rollback_abort_receipt_written"] is True
    assert summary["readiness"]["closeout_receipt_written"] is True
    assert summary["readiness"]["production_task_execution_allowed"] is False
    assert summary["readiness"]["runtime_execution_performed"] is False
    assert summary["readiness"]["production_runtime_receipt_write_allowed"] is False
    assert summary["boundary"]["production_task_execution_performed"] is True
    assert summary["boundary"]["backend_task_pool_mutation_performed"] is False


def test_post_h3_minimal_task_execution_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    authorization = _write_authorization_fixture(tmp_path, monkeypatch)

    summary = run_execution(
        authorization_summary_path=authorization,
        output_root=tmp_path / "execution",
        ack_minimal_task_execution=False,
    )

    assert summary["passed"] is False
    assert "explicit_execution_ack" in summary["failure_reasons"]
    assert summary["readiness"]["authorization_consumed"] is False
    assert summary["boundary"]["production_task_execution_performed"] is False


def test_post_h3_minimal_task_execution_blocks_reuse(tmp_path: Path, monkeypatch: Any) -> None:
    authorization = _write_authorization_fixture(tmp_path, monkeypatch)

    first = run_execution(
        authorization_summary_path=authorization,
        output_root=tmp_path / "execution_first",
        ack_minimal_task_execution=True,
    )
    second = run_execution(
        authorization_summary_path=authorization,
        output_root=tmp_path / "execution_second",
        ack_minimal_task_execution=True,
    )

    assert first["passed"] is True
    assert second["passed"] is False
    assert "lease_not_already_present" in second["failure_reasons"]
    assert second["readiness"]["authorization_consumed"] is False


def test_post_h3_minimal_task_execution_blocks_authorization_hash_drift(tmp_path: Path, monkeypatch: Any) -> None:
    authorization = _write_authorization_fixture(tmp_path, monkeypatch)
    receipt = tmp_path / "authorization" / "post_h3_minimal_task_authorization_receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["consumed"] = True
    receipt.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_execution(
        authorization_summary_path=authorization,
        output_root=tmp_path / "execution",
        ack_minimal_task_execution=True,
    )

    assert summary["passed"] is False
    assert "authorization_receipt_hash_valid" in summary["failure_reasons"]
    assert summary["readiness"]["authorization_consumed"] is False


def _write_readiness_index_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)
    post_h3ac_root = tmp_path / "post_h3ac"
    run_post_h3ac(
        post_h3ab_summary_path=post_h3ab,
        output_root=post_h3ac_root,
        ack_observer_readiness=True,
    )
    post_h3ac = post_h3ac_root / "post_h3ac_observer_mode_readiness_summary.json"
    minimal_root = tmp_path / "minimal_chain"
    run_minimal_chain(post_h3ac_summary_path=post_h3ac, output_root=minimal_root)
    readiness_index = tmp_path / "post_h3_readiness_index.json"
    build_index(
        post_h3ac_summary_path=post_h3ac,
        minimal_chain_summary_path=minimal_root / "post_h3_minimal_production_task_chain_summary.json",
        output=readiness_index,
    )
    return readiness_index


def _write_intake_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    readiness_index = _write_readiness_index_fixture(tmp_path, monkeypatch)
    root = tmp_path / "intake"
    run_intake(readiness_index_path=readiness_index, output_root=root)
    return root / "post_h3_minimal_task_intake_summary.json"


def _write_authorization_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    intake = _write_intake_fixture(tmp_path, monkeypatch)
    root = tmp_path / "authorization"
    run_authorization(
        intake_summary_path=intake,
        output_root=root,
        ack_single_use_authorization=True,
    )
    return root / "post_h3_minimal_task_authorization_summary.json"
