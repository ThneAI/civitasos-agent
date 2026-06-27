from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0e_rollback_abort_drill_gate import run_gate as run_p0e
from benchmarks.p0f_vm_preview_preflight_gate import run_gate
from benchmarks.tests.test_p0e_rollback_abort_drill_gate import _write_p0d_summary


def test_p0f_vm_preview_preflight_passes_with_p0e_summary(tmp_path: Path) -> None:
    p0e_summary = _write_p0e_summary(tmp_path)

    summary = run_gate(
        p0e_summary_path=p0e_summary,
        output_root=tmp_path / "p0f",
        vm_target_id="vm1",
        monitoring_owner_id="observability_owner",
        operator_id="operator-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0g_single_vm_private_preview_ready"] is True
    assert summary["boundary"]["vm_target_validated"] is True
    assert summary["boundary"]["service_token_scope_validated"] is True
    assert summary["boundary"]["no_public_ingress_validated"] is True
    assert summary["boundary"]["vm_contact_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False
    scope = json.loads((tmp_path / "p0f" / "p0f_service_token_scope_review.json").read_text(encoding="utf-8"))
    assert scope["service_token_scope_review"]["token_issued"] is False


def test_p0f_blocks_unknown_vm_target(tmp_path: Path) -> None:
    p0e_summary = _write_p0e_summary(tmp_path)

    summary = run_gate(p0e_summary_path=p0e_summary, output_root=tmp_path / "p0f", vm_target_id="vm9")

    assert summary["passed"] is False
    assert "vm_target_authorized_by_selected_task" in summary["failure_reasons"]
    assert "vm_target_descriptor_present" in summary["failure_reasons"]


def test_p0f_blocks_forbidden_service_scope(tmp_path: Path) -> None:
    p0e_summary = _write_p0e_summary(tmp_path)

    summary = run_gate(
        p0e_summary_path=p0e_summary,
        output_root=tmp_path / "p0f",
        service_token_scopes=["pool:read", "production:write"],
    )

    assert summary["passed"] is False
    assert "scopes_match_upstream_allowed_set" in summary["failure_reasons"]
    assert "required_preview_scopes_present" in summary["failure_reasons"]
    assert "no_forbidden_scope_fragment" in summary["failure_reasons"]


def test_p0f_blocks_missing_monitoring_owner(tmp_path: Path) -> None:
    p0e_summary = _write_p0e_summary(tmp_path)

    summary = run_gate(p0e_summary_path=p0e_summary, output_root=tmp_path / "p0f", monitoring_owner_id="")

    assert summary["passed"] is False
    assert "monitoring_owner_id_present" in summary["failure_reasons"]


def test_p0f_blocks_p0e_public_ingress_boundary_drift(tmp_path: Path) -> None:
    p0e_summary = _write_p0e_summary(tmp_path)
    payload = json.loads(p0e_summary.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    p0e_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0e_summary_path=p0e_summary, output_root=tmp_path / "p0f")

    assert summary["passed"] is False
    assert "p0e_boundary_closed" in summary["failure_reasons"]
    assert "no_public_ingress_closed" in summary["failure_reasons"]


def _write_p0e_summary(tmp_path: Path) -> Path:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=True)
    run_p0e(p0d_summary_path=p0d_summary, output_root=tmp_path / "p0e", operator_id="operator-test")
    return tmp_path / "p0e" / "p0e_rollback_abort_drill_chain_summary.json"
