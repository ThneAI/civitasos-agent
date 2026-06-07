from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_vm_csp_remote import (
    DEFAULT_TOPOLOGY,
    load_topology,
    quote_command,
    shell_path,
)


def test_default_topology_uses_three_vm_roles() -> None:
    assert DEFAULT_TOPOLOGY.backend_url == "http://192.168.56.4:8099"
    assert DEFAULT_TOPOLOGY.csp_url == "http://192.168.56.5:8200"
    assert {
        DEFAULT_TOPOLOGY.core.ssh_alias,
        DEFAULT_TOPOLOGY.csp.ssh_alias,
        DEFAULT_TOPOLOGY.agent.ssh_alias,
    } == {"vm1", "vm2", "vm3"}


def test_load_topology_override(tmp_path: Path) -> None:
    path = tmp_path / "topology.json"
    path.write_text(
        json.dumps(
            {
                "core": {"ssh_alias": "core-vm", "address": "10.0.0.10"},
                "csp": {"ssh_alias": "csp-vm", "address": "10.0.0.11"},
                "agent": {"ssh_alias": "agent-vm", "address": "10.0.0.12"},
                "backend_port": 18099,
                "csp_port": 18200,
                "remote_root": "/srv/civitasos-h2/",
            }
        ),
        encoding="utf-8",
    )

    topology = load_topology(path)

    assert topology.backend_url == "http://10.0.0.10:18099"
    assert topology.csp_url == "http://10.0.0.11:18200"
    assert topology.remote_root == "srv/civitasos-h2"


def test_remote_path_and_command_quoting() -> None:
    assert shell_path("/home/cal", "civitasos-h2", "runs", "run 1") == (
        "/home/cal/civitasos-h2/runs/run 1"
    )
    assert quote_command(["python", "--run-root", "/tmp/run 1"]) == (
        "python --run-root '/tmp/run 1'"
    )
