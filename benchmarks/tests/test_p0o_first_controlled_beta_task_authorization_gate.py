from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0n_controlled_beta_entry_gate import run_gate as run_p0n
from benchmarks.p0o_first_controlled_beta_task_authorization_gate import run_gate
from benchmarks.tests.test_p0n_controlled_beta_entry_gate import _write_p0m_summary


def test_p0o_first_task_authorization_passes(tmp_path: Path) -> None:
    p0n_summary = _write_p0n_summary(tmp_path)

    summary = run_gate(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        operator_id="operator-test",
        ack_first_task_authorization=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0o_first_controlled_beta_task_authorized"] is True
    assert summary["readiness"]["p0p_first_controlled_beta_task_execution_ready"] is True
    assert summary["authorization"]["single_use"] is True
    assert summary["authorization"]["consumed"] is False
    assert summary["boundary"]["task_pool_post_performed"] is False
    assert summary["boundary"]["production_transition_allowed"] is False


def test_p0o_requires_operator_ack(tmp_path: Path) -> None:
    p0n_summary = _write_p0n_summary(tmp_path)

    summary = run_gate(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        operator_id="operator-test",
        ack_first_task_authorization=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_transition_allowed"] is False


def test_p0o_blocks_p0n_artifact_hash_drift(tmp_path: Path) -> None:
    p0n_summary = _write_p0n_summary(tmp_path)
    payload = json.loads(p0n_summary.read_text(encoding="utf-8"))
    task_path = Path(payload["artifacts"]["first_task_proposal"]["path"])
    task_payload = json.loads(task_path.read_text(encoding="utf-8"))
    task_payload["passed"] = False
    task_path.write_text(json.dumps(task_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        operator_id="operator-test",
        ack_first_task_authorization=True,
    )

    assert summary["passed"] is False
    assert "p0n_first_task_proposal_hash_valid" in summary["failure_reasons"]


def test_p0o_blocks_p0n_public_ingress_boundary_drift(tmp_path: Path) -> None:
    p0n_summary = _write_p0n_summary(tmp_path)
    payload = json.loads(p0n_summary.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    p0n_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0n_summary_path=p0n_summary,
        output_root=tmp_path / "p0o",
        operator_id="operator-test",
        ack_first_task_authorization=True,
    )

    assert summary["passed"] is False
    assert "p0n_boundary_closed" in summary["failure_reasons"]


def _write_p0n_summary(tmp_path: Path) -> Path:
    p0m_summary = _write_p0m_summary(tmp_path)
    run_p0n(
        p0m_summary_path=p0m_summary,
        output_root=tmp_path / "p0n",
        operator_id="operator-test",
        ack_controlled_beta_entry=True,
    )
    return tmp_path / "p0n" / "p0n_controlled_beta_entry_chain_summary.json"
