from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0h_private_preview_owner_review_gate import run_gate as run_p0h
from benchmarks.p0i_vm_service_private_preview_gate import run_gate
from benchmarks.tests.test_p0g_single_vm_private_preview_gate import _py
from benchmarks.tests.test_p0h_private_preview_owner_review_gate import _write_p0g_summary


def test_p0i_vm_service_private_preview_passes(tmp_path: Path) -> None:
    p0h_summary = _write_p0h_summary(tmp_path)

    summary = run_gate(
        p0h_summary_path=p0h_summary,
        output_root=tmp_path / "p0i",
        deploy_command=_py("from pathlib import Path; Path('backend.ok').write_text('ok'); Path('frontend.ok').write_text('ok')"),
        backend_health_command=_py("from pathlib import Path; raise SystemExit(0 if Path('backend.ok').read_text() == 'ok' else 9)"),
        frontend_health_command=_py("from pathlib import Path; raise SystemExit(0 if Path('frontend.ok').read_text() == 'ok' else 9)"),
        rollback_command=_py("from pathlib import Path; Path('backend.ok').unlink(missing_ok=True); Path('frontend.ok').unlink(missing_ok=True)"),
        rollback_health_command=_py("from pathlib import Path; raise SystemExit(0 if not Path('backend.ok').exists() and not Path('frontend.ok').exists() else 9)"),
        operator_id="operator-test",
        ack_vm_service_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0j_multi_vm_private_preview_ready"] is True
    assert summary["boundary"]["vm_contact_performed"] is True
    assert summary["boundary"]["private_preview_deploy_performed"] is True
    assert summary["boundary"]["backend_health_check_performed"] is True
    assert summary["boundary"]["frontend_health_check_performed"] is True
    assert summary["boundary"]["rollback_performed"] is True
    assert summary["boundary"]["production_receipt_write_allowed"] is False
    assert not (tmp_path / "backend.ok").exists()
    assert not (tmp_path / "frontend.ok").exists()


def test_p0i_requires_explicit_operator_ack(tmp_path: Path) -> None:
    p0h_summary = _write_p0h_summary(tmp_path)

    summary = run_gate(
        p0h_summary_path=p0h_summary,
        output_root=tmp_path / "p0i",
        deploy_command=_py("print('deploy')"),
        backend_health_command=_py("print('backend')"),
        frontend_health_command=_py("print('frontend')"),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        ack_vm_service_private_preview=False,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "explicit_operator_ack" in summary["failure_reasons"]
    assert summary["boundary"]["vm_contact_performed"] is False


def test_p0i_frontend_health_failure_blocks_but_rolls_back(tmp_path: Path) -> None:
    p0h_summary = _write_p0h_summary(tmp_path)

    summary = run_gate(
        p0h_summary_path=p0h_summary,
        output_root=tmp_path / "p0i",
        deploy_command=_py("from pathlib import Path; Path('backend.ok').write_text('ok'); Path('frontend.ok').write_text('bad')"),
        backend_health_command=_py("from pathlib import Path; raise SystemExit(0 if Path('backend.ok').read_text() == 'ok' else 9)"),
        frontend_health_command=_py("raise SystemExit(7)"),
        rollback_command=_py("from pathlib import Path; Path('backend.ok').unlink(missing_ok=True); Path('frontend.ok').unlink(missing_ok=True)"),
        rollback_health_command=_py("from pathlib import Path; raise SystemExit(0 if not Path('backend.ok').exists() and not Path('frontend.ok').exists() else 9)"),
        ack_vm_service_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "frontend_health_command_failed" in summary["failure_reasons"]
    assert summary["boundary"]["rollback_performed"] is True
    assert not (tmp_path / "backend.ok").exists()
    assert not (tmp_path / "frontend.ok").exists()


def test_p0i_blocks_p0h_artifact_hash_drift(tmp_path: Path) -> None:
    p0h_summary = _write_p0h_summary(tmp_path)
    payload = json.loads(p0h_summary.read_text(encoding="utf-8"))
    owner_path = Path(payload["artifacts"]["owner_acceptance"]["path"])
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    owner["vm_target_id"] = "tampered"
    owner_path.write_text(json.dumps(owner, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0h_summary_path=p0h_summary,
        output_root=tmp_path / "p0i",
        deploy_command=_py("print('deploy')"),
        backend_health_command=_py("print('backend')"),
        frontend_health_command=_py("print('frontend')"),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        ack_vm_service_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "p0h_owner_acceptance_hash_valid" in summary["failure_reasons"]


def _write_p0h_summary(tmp_path: Path) -> Path:
    p0g_summary = _write_p0g_summary(tmp_path)
    run_p0h(p0g_summary_path=p0g_summary, output_root=tmp_path / "p0h", operator_id="operator-test")
    return tmp_path / "p0h" / "p0h_private_preview_owner_review_chain_summary.json"
