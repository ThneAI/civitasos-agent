from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0m_controlled_beta_readiness_review_gate import run_gate as run_p0m
from benchmarks.p0n_controlled_beta_entry_gate import run_gate
from benchmarks.tests.test_p0m_controlled_beta_readiness_review_gate import _write_p0l_summary


def test_p0n_controlled_beta_entry_passes(tmp_path: Path) -> None:
    p0m_summary = _write_p0m_summary(tmp_path)

    summary = run_gate(
        p0m_summary_path=p0m_summary,
        output_root=tmp_path / "p0n",
        operator_id="operator-test",
        ack_controlled_beta_entry=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["controlled_beta_entry_package_ready"] is True
    assert summary["readiness"]["p0o_first_controlled_beta_task_authorization_ready"] is True
    assert summary["entry"]["service_token_scope_count"] >= 4
    assert summary["boundary"]["service_token_scope_written"] is True
    assert summary["boundary"]["operator_runbook_written"] is True
    assert summary["boundary"]["owner_handoff_written"] is True
    assert summary["boundary"]["stop_conditions_written"] is True
    assert summary["boundary"]["first_task_proposal_written"] is True
    assert summary["boundary"]["production_transition_allowed"] is False


def test_p0n_requires_operator_ack(tmp_path: Path) -> None:
    p0m_summary = _write_p0m_summary(tmp_path)

    summary = run_gate(
        p0m_summary_path=p0m_summary,
        output_root=tmp_path / "p0n",
        operator_id="operator-test",
        ack_controlled_beta_entry=False,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["readiness"]["production_transition_allowed"] is False


def test_p0n_blocks_p0m_artifact_hash_drift(tmp_path: Path) -> None:
    p0m_summary = _write_p0m_summary(tmp_path)
    payload = json.loads(p0m_summary.read_text(encoding="utf-8"))
    scope_path = Path(payload["artifacts"]["beta_scope"]["path"])
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["passed"] = False
    scope_path.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0m_summary_path=p0m_summary,
        output_root=tmp_path / "p0n",
        operator_id="operator-test",
        ack_controlled_beta_entry=True,
    )

    assert summary["passed"] is False
    assert "p0m_beta_scope_hash_valid" in summary["failure_reasons"]


def test_p0n_blocks_scope_that_allows_production(tmp_path: Path) -> None:
    p0m_summary = _write_p0m_summary(tmp_path)
    payload = json.loads(p0m_summary.read_text(encoding="utf-8"))
    scope_path = Path(payload["artifacts"]["beta_scope"]["path"])
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["controlled_beta_scope"]["forbidden_actions"].remove("production_transition")
    scope_path.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    payload["artifacts"]["beta_scope"]["sha256"] = _sha(scope_path)
    p0m_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0m_summary_path=p0m_summary,
        output_root=tmp_path / "p0n",
        operator_id="operator-test",
        ack_controlled_beta_entry=True,
    )

    assert summary["passed"] is False
    assert "scope_forbidden_actions_complete" in summary["failure_reasons"]


def _write_p0m_summary(tmp_path: Path) -> Path:
    p0l_summary = _write_p0l_summary(tmp_path)
    run_p0m(
        p0l_summary_path=p0l_summary,
        output_root=tmp_path / "p0m",
        operator_id="operator-test",
        ack_controlled_beta_readiness=True,
    )
    return tmp_path / "p0m" / "p0m_controlled_beta_readiness_chain_summary.json"


def _sha(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
