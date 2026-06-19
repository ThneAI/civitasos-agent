from __future__ import annotations

import json
import os
from pathlib import Path

from benchmarks.i2b_real_external_readonly_command_gate import RESPONSE_SCHEMA


def write_i2_request(tmp_path: Path, *, passed: bool) -> Path:
    path = tmp_path / "i2_request.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2-external-command-gate-request:v1",
                "passed": passed,
                "request": {
                    "request_id": "i2-request:test",
                    "required_future_evidence": [
                        "external_agent_registration_receipt",
                        "scoped_command_authorization_request",
                        "external_agent_acceptance_receipt",
                        "isolation_policy_preflight",
                        "command_execution_receipt",
                        "rollback_or_abort_receipt",
                        "operator_reconciliation",
                    ],
                },
                "readiness": {
                    "i2_gate_requested": True,
                    "operator_authorization_required": True,
                    "i2_execution_allowed": False,
                },
                "boundary": {"external_agent_command_allowed": False},
            }
        ),
        encoding="utf-8",
    )
    return path


def write_i2a_summary(tmp_path: Path, *, passed: bool = True) -> Path:
    path = tmp_path / "i2a_summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i2a-controlled-command-chain:v1",
                "passed": passed,
                "readiness": {
                    "operator_discussion_required_for_i2b": True,
                    "real_task_command_allowed": False,
                },
                "boundary": {"real_task_command_allowed": False},
            }
        ),
        encoding="utf-8",
    )
    return path


def write_external_env(
    path: Path,
    *,
    provider: str = "openai_compatible",
    base_url: str = "https://api.example.test",
    model: str = "example-model",
    api_key: str = "secret-test-key",
    allow_local: bool = False,
) -> Path:
    lines = [
        f"BETA6_EXTERNAL_AGENT_PROVIDER={provider}",
        f"BETA6_EXTERNAL_AGENT_API_BASE_URL={base_url}",
        f"BETA6_EXTERNAL_AGENT_MODEL={model}",
        f"BETA6_EXTERNAL_AGENT_API_KEY={api_key}",
    ]
    if allow_local:
        lines.append("BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP=true")
    path.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def i2b_response(*, recommendation: str = "operator_review_before_next_gate") -> str:
    return json.dumps(
        {
            "schema_version": RESPONSE_SCHEMA,
            "command_id": "__COMMAND_ID__",
            "accepted": True,
            "verdict": "accepted_scope_executed_read_only",
            "summary": "Read-only provider contrast completed.",
            "observations": ["Boundary remained closed.", "Operator review is required for the next gate."],
            "recommendation": recommendation,
            "boundary_attestation": {
                "network_used_only_for_provider_api": True,
                "source_tree_modified": False,
                "git_used": False,
                "runtime_state_mutated": False,
                "production_touched": False,
            },
        }
    )
