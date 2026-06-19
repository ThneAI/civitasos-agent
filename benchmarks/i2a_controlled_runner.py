"""Controlled runner for I.2-A read-only protocol smoke."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import write_json_object

RESPONSE_SCHEMA = "i2a-controlled-external-agent-response:v1"


def execute_controlled_read_only_command(*, command: dict[str, Any], workspace: Path) -> dict[str, Any]:
    """Write the deterministic I.2-A read-only response under the isolated workspace."""
    response_path = workspace / "external_agent_response.json"
    response = {
        "schema_version": RESPONSE_SCHEMA,
        "command_id": command.get("command_id"),
        "executor_alias": command.get("executor_alias"),
        "verdict": "accepted_scope_executed_read_only",
        "summary": "Controlled adapter inspected the command envelope and wrote this read-only attestation under the isolation workspace.",
        "boundary_attestation": {
            "network_used": False,
            "source_tree_modified": False,
            "git_used": False,
            "runtime_state_mutated": False,
            "production_touched": False,
        },
    }
    write_json_object(response_path, response)
    return {"response": response, "response_path": response_path}
