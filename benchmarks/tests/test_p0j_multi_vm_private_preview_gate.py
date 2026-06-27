from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0i_vm_service_private_preview_gate import run_gate as run_p0i
from benchmarks.p0j_multi_vm_private_preview_gate import run_gate
from benchmarks.tests.test_p0g_single_vm_private_preview_gate import _py
from benchmarks.tests.test_p0i_vm_service_private_preview_gate import _write_p0h_summary


def test_p0j_multi_vm_private_preview_passes(tmp_path: Path) -> None:
    p0i_summary = _write_p0i_summary(tmp_path)
    expected = ["vm1", "vm2", "vm3"]

    summary = run_gate(
        p0i_summary_path=p0i_summary,
        output_root=tmp_path / "p0j",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code(expected)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=expected,
        operator_id="operator-test",
        ack_multi_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0k_private_preview_soak_ready"] is True
    assert summary["boundary"]["vm_contact_performed"] is True
    assert summary["boundary"]["multi_vm_private_preview_deploy_performed"] is True
    assert summary["boundary"]["multi_vm_smoke_performed"] is True
    assert summary["boundary"]["rollback_performed"] is True
    assert summary["boundary"]["production_receipt_write_allowed"] is False


def test_p0j_requires_at_least_two_expected_nodes(tmp_path: Path) -> None:
    p0i_summary = _write_p0i_summary(tmp_path)

    summary = run_gate(
        p0i_summary_path=p0i_summary,
        output_root=tmp_path / "p0j",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code(["vm1"])),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1"],
        ack_multi_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "expected_nodes_present" in summary["failure_reasons"]
    assert summary["boundary"]["vm_contact_performed"] is False


def test_p0j_blocks_smoke_node_mismatch_and_rolls_back(tmp_path: Path) -> None:
    p0i_summary = _write_p0i_summary(tmp_path)

    summary = run_gate(
        p0i_summary_path=p0i_summary,
        output_root=tmp_path / "p0j",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code(["vm1", "vm2"])),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        ack_multi_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "smoke_nodes_match_expected" in summary["failure_reasons"]
    assert summary["boundary"]["rollback_performed"] is True


def test_p0j_blocks_p0i_artifact_hash_drift(tmp_path: Path) -> None:
    p0i_summary = _write_p0i_summary(tmp_path)
    payload = json.loads(p0i_summary.read_text(encoding="utf-8"))
    preview_path = Path(payload["artifacts"]["service_preview_receipt"]["path"])
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    preview["vm_target_id"] = "tampered"
    preview_path.write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0i_summary_path=p0i_summary,
        output_root=tmp_path / "p0j",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code(["vm1", "vm2", "vm3"])),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        ack_multi_vm_private_preview=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "p0i_service_preview_receipt_hash_valid" in summary["failure_reasons"]


def _write_p0i_summary(tmp_path: Path) -> Path:
    p0h_summary = _write_p0h_summary(tmp_path)
    run_p0i(
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
    return tmp_path / "p0i" / "p0i_vm_service_private_preview_chain_summary.json"


def _smoke_code(nodes: list[str]) -> str:
    payload = {
        "schema_version": "beta5-real-backend-frontend-multivm-smoke:v1",
        "passed": True,
        "cycles": 1,
        "nodes": nodes,
        "total_checks": len(nodes),
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }
    return "import json; print(json.dumps(" + repr(payload) + "))"
