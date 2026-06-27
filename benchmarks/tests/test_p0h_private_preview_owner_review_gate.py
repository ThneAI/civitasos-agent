from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0g_single_vm_private_preview_gate import run_gate as run_p0g
from benchmarks.p0h_private_preview_owner_review_gate import run_gate
from benchmarks.tests.test_p0g_single_vm_private_preview_gate import _py, _write_p0f_summary


def test_p0h_private_preview_owner_review_passes(tmp_path: Path) -> None:
    p0g_summary = _write_p0g_summary(tmp_path)

    summary = run_gate(
        p0g_summary_path=p0g_summary,
        output_root=tmp_path / "p0h",
        operator_id="operator-test",
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0h_private_preview_owner_review_complete"] is True
    assert summary["readiness"]["p0i_vm_service_private_preview_ready"] is True
    assert summary["boundary"]["owner_acceptance_written"] is True
    assert summary["boundary"]["audit_boundary_review_written"] is True
    assert summary["boundary"]["rollback_owner_review_written"] is True
    assert summary["boundary"]["owner_reconciliation_written"] is True
    assert summary["boundary"]["production_transition_allowed"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False


def test_p0h_blocks_owner_rejection(tmp_path: Path) -> None:
    p0g_summary = _write_p0g_summary(tmp_path)

    summary = run_gate(
        p0g_summary_path=p0g_summary,
        output_root=tmp_path / "p0h",
        owner_decision="request_revision",
    )

    assert summary["passed"] is False
    assert "owner_decision_approves_private_preview" in summary["failure_reasons"]
    assert summary["readiness"]["p0i_vm_service_private_preview_ready"] is False


def test_p0h_blocks_p0g_summary_boundary_drift(tmp_path: Path) -> None:
    p0g_summary = _write_p0g_summary(tmp_path)
    payload = json.loads(p0g_summary.read_text(encoding="utf-8"))
    payload["boundary"]["external_public_ingress_opened"] = True
    p0g_summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0g_summary_path=p0g_summary, output_root=tmp_path / "p0h")

    assert summary["passed"] is False
    assert "summary_boundary_closed" in summary["failure_reasons"]


def test_p0h_blocks_p0g_artifact_hash_drift(tmp_path: Path) -> None:
    p0g_summary = _write_p0g_summary(tmp_path)
    payload = json.loads(p0g_summary.read_text(encoding="utf-8"))
    preview_path = Path(payload["artifacts"]["preview_receipt"]["path"])
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    preview["vm_target_id"] = "tampered"
    preview_path.write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(p0g_summary_path=p0g_summary, output_root=tmp_path / "p0h")

    assert summary["passed"] is False
    assert "p0g_preview_receipt_hash_valid" in summary["failure_reasons"]


def _write_p0g_summary(tmp_path: Path) -> Path:
    p0f_summary = _write_p0f_summary(tmp_path)
    run_p0g(
        p0f_summary_path=p0f_summary,
        output_root=tmp_path / "p0g",
        preview_command=_py("from pathlib import Path; Path('preview.marker').write_text('ok', encoding='utf-8')"),
        health_command=_py("from pathlib import Path; raise SystemExit(0 if Path('preview.marker').read_text(encoding='utf-8') == 'ok' else 9)"),
        rollback_command=_py("from pathlib import Path; Path('preview.marker').unlink(missing_ok=True)"),
        rollback_health_command=_py("from pathlib import Path; raise SystemExit(0 if not Path('preview.marker').exists() else 9)"),
        operator_id="operator-test",
        ack_single_vm_private_preview=True,
        working_directory=tmp_path,
    )
    return tmp_path / "p0g" / "p0g_single_vm_private_preview_chain_summary.json"
