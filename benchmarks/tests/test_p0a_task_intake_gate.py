from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0a_task_intake_gate import DEFAULT_TASK_INTAKE, run_gate


def test_p0a_default_task_intake_passes(tmp_path: Path) -> None:
    i2h = _write_i2h_summary(tmp_path)

    summary = run_gate(i2h_summary_path=i2h, output_root=tmp_path / "p0a")

    assert summary["passed"] is True
    assert summary["selected_task"]["task_id"] == "p0-task:pilot-status-evidence-index-preview"
    assert summary["selected_task"]["owner_id"] == "product_owner"
    assert summary["selected_task"]["audit_owner_id"] == "audit_owner"
    assert summary["selected_task"]["rollback_owner_id"] == "rollback_owner"
    assert summary["selected_task"]["vm_target_ids"] == ["vm1", "vm2", "vm3"]
    assert "production_allowed" not in summary["selected_task"]["service_token_scopes"]
    assert summary["readiness"]["p0b_agent_proposal_gate_ready"] is True
    assert summary["readiness"]["p0c_execution_allowed"] is False
    assert summary["boundary"]["vm_contact_allowed"] is False
    assert summary["boundary"]["deploy_allowed"] is False


def test_p0a_blocks_missing_rollback_owner(tmp_path: Path) -> None:
    i2h = _write_i2h_summary(tmp_path)
    intake = _write_task_intake(tmp_path, {"rollback_owner": {"id": "", "role": "rollback_owner"}})

    summary = run_gate(i2h_summary_path=i2h, output_root=tmp_path / "p0a", task_intake_path=intake)

    assert summary["passed"] is False
    assert "rollback_owner_present" in summary["failure_reasons"]
    assert summary["boundary"]["allowed_scope_recording_allowed"] is False


def test_p0a_blocks_production_scope(tmp_path: Path) -> None:
    i2h = _write_i2h_summary(tmp_path)
    replacement = dict(DEFAULT_TASK_INTAKE["service_token"])
    replacement["scopes"] = [*replacement["scopes"], "production:write"]
    intake = _write_task_intake(tmp_path, {"service_token": replacement})

    summary = run_gate(i2h_summary_path=i2h, output_root=tmp_path / "p0a", task_intake_path=intake)

    assert summary["passed"] is False
    assert "service_scopes_allowlisted" in summary["failure_reasons"]
    assert "service_scopes_no_forbidden_tokens" in summary["failure_reasons"]


def test_p0a_blocks_incomplete_vm_topology(tmp_path: Path) -> None:
    i2h = _write_i2h_summary(tmp_path)
    intake = _write_task_intake(tmp_path, {"vm_targets": DEFAULT_TASK_INTAKE["vm_targets"][:2]})

    summary = run_gate(i2h_summary_path=i2h, output_root=tmp_path / "p0a", task_intake_path=intake)

    assert summary["passed"] is False
    assert "vm_targets_complete" in summary["failure_reasons"]


def test_p0a_blocks_failed_i2h(tmp_path: Path) -> None:
    i2h = _write_i2h_summary(tmp_path, passed=False)

    summary = run_gate(i2h_summary_path=i2h, output_root=tmp_path / "p0a")

    assert summary["passed"] is False
    assert "i2h_summary_passed" in summary["failure_reasons"]
    assert summary["readiness"]["p0b_agent_proposal_gate_ready"] is False


def _write_i2h_summary(tmp_path: Path, *, passed: bool = True) -> Path:
    path = tmp_path / "i2h_summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2h-post-merge-smoke-chain:v1",
                "passed": passed,
                "readiness": {
                    "p0_controlled_pilot_discussion_ready": passed,
                    "deploy_allowed": False,
                    "production_transition_allowed": False,
                },
                "boundary": {
                    "deploy_allowed": False,
                    "runtime_state_mutation_allowed": False,
                    "production_transition_allowed": False,
                    "production_receipt_write_allowed": False,
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_task_intake(tmp_path: Path, updates: dict) -> Path:
    value = json.loads(json.dumps(DEFAULT_TASK_INTAKE, sort_keys=True))
    value.update(updates)
    path = tmp_path / "task_intake.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
