from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0j_multi_vm_private_preview_gate import run_gate as run_p0j
from benchmarks.p0k_private_preview_soak_gate import run_gate
from benchmarks.tests.test_p0g_single_vm_private_preview_gate import _py
from benchmarks.tests.test_p0j_multi_vm_private_preview_gate import _smoke_code, _write_p0i_summary


def test_p0k_private_preview_soak_passes(tmp_path: Path) -> None:
    p0j_summary = _write_p0j_summary(tmp_path)
    expected = ["vm1", "vm2", "vm3"]

    summary = run_gate(
        p0j_summary_path=p0j_summary,
        output_root=tmp_path / "p0k",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code_with_latency(expected, 12.5)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=expected,
        cycles=2,
        interval_seconds=0,
        max_latency_ms=100,
        operator_id="operator-test",
        ack_private_preview_soak=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["p0l_external_preview_evidence_ready"] is True
    assert summary["soak"]["completed_cycles"] == 2
    assert summary["boundary"]["multi_cycle_smoke_performed"] is True
    assert summary["boundary"]["rollback_performed"] is True
    assert summary["boundary"]["production_receipt_write_allowed"] is False


def test_p0k_requires_at_least_two_cycles(tmp_path: Path) -> None:
    p0j_summary = _write_p0j_summary(tmp_path)

    summary = run_gate(
        p0j_summary_path=p0j_summary,
        output_root=tmp_path / "p0k",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code_with_latency(["vm1", "vm2", "vm3"], 12.5)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        cycles=1,
        ack_private_preview_soak=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "cycles_at_least_two" in summary["failure_reasons"]
    assert summary["boundary"]["vm_contact_performed"] is False


def test_p0k_blocks_smoke_node_mismatch_and_rolls_back(tmp_path: Path) -> None:
    p0j_summary = _write_p0j_summary(tmp_path)

    summary = run_gate(
        p0j_summary_path=p0j_summary,
        output_root=tmp_path / "p0k",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code_with_latency(["vm1", "vm2"], 12.5)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        cycles=2,
        ack_private_preview_soak=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "smoke_cycle_1_failed" in summary["failure_reasons"]
    assert summary["boundary"]["rollback_performed"] is True


def test_p0k_blocks_p0j_artifact_hash_drift(tmp_path: Path) -> None:
    p0j_summary = _write_p0j_summary(tmp_path)
    payload = json.loads(p0j_summary.read_text(encoding="utf-8"))
    preview_path = Path(payload["artifacts"]["multi_vm_preview_receipt"]["path"])
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    preview["observed_nodes"] = ["tampered"]
    preview_path.write_text(json.dumps(preview, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = run_gate(
        p0j_summary_path=p0j_summary,
        output_root=tmp_path / "p0k",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code_with_latency(["vm1", "vm2", "vm3"], 12.5)),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        cycles=2,
        ack_private_preview_soak=True,
        working_directory=tmp_path,
    )

    assert summary["passed"] is False
    assert "p0j_multi_vm_preview_receipt_hash_valid" in summary["failure_reasons"]


def _write_p0j_summary(tmp_path: Path) -> Path:
    p0i_summary = _write_p0i_summary(tmp_path)
    run_p0j(
        p0i_summary_path=p0i_summary,
        output_root=tmp_path / "p0j",
        deploy_command=_py("print('deploy')"),
        smoke_command=_py(_smoke_code(["vm1", "vm2", "vm3"])),
        rollback_command=_py("print('rollback')"),
        rollback_health_command=_py("print('rollback-health')"),
        expected_nodes=["vm1", "vm2", "vm3"],
        operator_id="operator-test",
        ack_multi_vm_private_preview=True,
        working_directory=tmp_path,
    )
    return tmp_path / "p0j" / "p0j_multi_vm_private_preview_chain_summary.json"


def _smoke_code_with_latency(nodes: list[str], latency_ms: float) -> str:
    observations = [{"cycle": 1, "node_id": node, "elapsed_ms": latency_ms} for node in nodes]
    payload = {
        "schema_version": "beta5-real-backend-frontend-multivm-smoke:v1",
        "passed": True,
        "cycles": 1,
        "nodes": nodes,
        "total_checks": len(nodes),
        "latency_ms_min": latency_ms,
        "latency_ms_median": latency_ms,
        "latency_ms_max": latency_ms,
        "backend_port": 18291,
        "frontend_port": 18292,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "observations": observations,
    }
    return "import json; print(json.dumps(" + repr(payload) + "))"
