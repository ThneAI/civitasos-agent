from __future__ import annotations

import json
import sys
from pathlib import Path

from benchmarks.p0e_rollback_abort_drill_gate import run_gate as run_p0e
from benchmarks.p0f_vm_preview_preflight_gate import run_gate as run_p0f
from benchmarks.p0g_single_vm_private_preview_gate import run_gate
from benchmarks.tests.test_p0e_rollback_abort_drill_gate import _write_p0d_summary


def test_p0g_single_vm_private_preview_passes_with_fixture_commands(tmp_path: Path) -> None:
    p0f_summary = _write_p0f_summary(tmp_path)

    summary = run_gate(
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

    assert summary["passed"] is True
    assert summary["readiness"]["p0h_private_preview_owner_review_ready"] is True
    assert summary["boundary"]["vm_contact_performed"] is True
    assert summary["boundary"]["private_preview_deploy_performed"] is True
    assert summary["boundary"]["rollback_performed"] is True
    assert summary["boundary"]["external_public_ingress_opened"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False
    assert not (tmp_path / "preview.marker").exists()


def test_p0g_requires_explicit_operator_ack(tmp_path: Path) -> None:
    p0f_summary = _write_p0f_summary(tmp_path)

    summary = run_gate(
        p0f_summary_path=p0f_summary,
        output_root=tmp_path / "p0g",
        preview_command=_py("print('preview')"),
        health_command=_py("print('health')"),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        ack_single_vm_private_preview=False,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["boundary"]["vm_contact_performed"] is False


def test_p0g_health_failure_blocks_chain_but_runs_rollback(tmp_path: Path) -> None:
    p0f_summary = _write_p0f_summary(tmp_path)

    summary = run_gate(
        p0f_summary_path=p0f_summary,
        output_root=tmp_path / "p0g",
        preview_command=_py("from pathlib import Path; Path('preview.marker').write_text('ok', encoding='utf-8')"),
        health_command=_py("raise SystemExit(7)"),
        rollback_command=_py("from pathlib import Path; Path('preview.marker').unlink(missing_ok=True)"),
        rollback_health_command=_py("from pathlib import Path; raise SystemExit(0 if not Path('preview.marker').exists() else 9)"),
        ack_single_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "health_command_success" in summary["failure_reasons"]
    assert summary["boundary"]["rollback_performed"] is True
    assert not (tmp_path / "preview.marker").exists()


def test_p0g_preview_failure_skips_rollback_as_noop(tmp_path: Path) -> None:
    p0f_summary = _write_p0f_summary(tmp_path)

    summary = run_gate(
        p0f_summary_path=p0f_summary,
        output_root=tmp_path / "p0g",
        preview_command=_py("raise SystemExit(9)"),
        health_command=_py("print('health')"),
        rollback_command=_py("raise SystemExit(8)"),
        rollback_health_command=_py("raise SystemExit(7)"),
        ack_single_vm_private_preview=True,
        working_directory=tmp_path,
    )
    rollback_receipt = json.loads((tmp_path / "p0g" / "p0g_single_vm_private_preview_rollback_receipt.json").read_text(encoding="utf-8"))

    assert summary["passed"] is False
    assert "preview_command_failed" in summary["failure_reasons"]
    assert "health_command_success" not in summary["failure_reasons"]
    assert rollback_receipt["passed"] is True
    assert rollback_receipt["rollback_needed"] is False
    assert rollback_receipt["checks"]["rollback_not_required_no_deploy"] is True
    assert summary["boundary"]["rollback_performed"] is False


def test_p0g_blocks_p0f_artifact_hash_drift(tmp_path: Path) -> None:
    p0f_summary = _write_p0f_summary(tmp_path)
    summary_payload = json.loads(p0f_summary.read_text(encoding="utf-8"))
    vm_target_path = Path(summary_payload["artifacts"]["vm_target_preflight"]["path"])
    vm_target = json.loads(vm_target_path.read_text(encoding="utf-8"))
    vm_target["vm_target_id"] = "tampered"
    vm_target_path.write_text(json.dumps(vm_target, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0f_summary_path=p0f_summary,
        output_root=tmp_path / "p0g",
        preview_command=_py("print('preview')"),
        health_command=_py("print('health')"),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        ack_single_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "p0f_vm_target_preflight_hash_valid" in summary["failure_reasons"]


def _write_p0f_summary(tmp_path: Path) -> Path:
    p0d_summary = _write_p0d_summary(tmp_path, with_callback=True)
    run_p0e(p0d_summary_path=p0d_summary, output_root=tmp_path / "p0e", operator_id="operator-test")
    p0e_summary = tmp_path / "p0e" / "p0e_rollback_abort_drill_chain_summary.json"
    run_p0f(
        p0e_summary_path=p0e_summary,
        output_root=tmp_path / "p0f",
        vm_target_id="vm1",
        monitoring_owner_id="observability_owner",
        operator_id="operator-test",
    )
    return tmp_path / "p0f" / "p0f_vm_preview_preflight_chain_summary.json"


def _py(code: str) -> str:
    return f"{sys.executable} -c {json.dumps(code)}"
