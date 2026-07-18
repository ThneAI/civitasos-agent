from __future__ import annotations

from pathlib import Path

from scripts.p5b4_multivm_checkpoint_gate import (
    DEFAULT_BACKEND_PORT,
    DEFAULT_REMOTE_ROOT,
    PHASES,
)
from scripts.p5b4_multivm_phases import BuiltInPhaseHandlers


class _NoRemote:
    def copy(self, node, source, destination):  # noqa: ANN001
        raise AssertionError("remote copy was not expected")

    def run(self, node, script, *, timeout):  # noqa: ANN001
        raise AssertionError("remote run was not expected")


def _plan(tmp_path: Path) -> dict:
    materials = tmp_path / "materials" / "manifest.json"
    return {
        "candidate": {
            "materials_manifest_path": str(materials),
            "agent_repo": str(tmp_path / "agent"),
            "runtime_repo": str(tmp_path / "runtime"),
            "backend_binary_path": str(tmp_path / "api_only"),
        },
        "nodes": [
            {"node_id": "vm1", "ssh_host": "vm1", "node_ip": "192.168.56.4"},
            {"node_id": "vm2", "ssh_host": "vm2", "node_ip": "192.168.56.5"},
            {"node_id": "vm3", "ssh_host": "vm3", "node_ip": "192.168.56.6"},
        ],
        "authoritative_node": "vm1",
        "partitioned_follower": "vm3",
        "remote_root": DEFAULT_REMOTE_ROOT,
        "backend_port": DEFAULT_BACKEND_PORT,
        "partition_comment": "civitasos-p5b4-partition",
    }


def test_all_non_cleanup_phases_have_concrete_handlers(tmp_path: Path) -> None:
    phases = BuiltInPhaseHandlers(
        plan=_plan(tmp_path), transport=_NoRemote(), state_root=tmp_path / "state"
    )

    assert set(phases.handlers()) == {
        phase_id for phase_id, _disruptive, _evidence in PHASES if phase_id != "cleanup_and_verify"
    }


def test_partition_apply_and_heal_scripts_are_exact(tmp_path: Path) -> None:
    phases = BuiltInPhaseHandlers(
        plan=_plan(tmp_path), transport=_NoRemote(), state_root=tmp_path / "state"
    )
    apply = phases._partition_rule_script("192.168.56.4", apply=True)
    heal = phases._partition_rule_script("192.168.56.4", apply=False)

    for script in (apply, heal):
        assert "--dport 19454" in script
        assert "--comment civitasos-p5b4-partition" in script
        assert "-s 192.168.56.4" in script
        assert "-d 192.168.56.4" in script
        assert "iptables-save" not in script
    assert "iptables -I INPUT" in apply
    assert "iptables -D INPUT" in heal
