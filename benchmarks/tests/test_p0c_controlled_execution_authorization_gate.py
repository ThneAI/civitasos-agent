from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0a_task_intake_gate import run_gate as run_p0a
from benchmarks.p0b_agent_proposal_gate import AGENT_RESPONSE_SCHEMA, run_gate as run_p0b
from benchmarks.p0c_controlled_execution_authorization_gate import run_gate


def test_p0c_authorizes_one_time_controlled_execution(tmp_path: Path) -> None:
    p0b = _run_p0b(tmp_path)
    env_file = _write_service_env(tmp_path)

    summary = run_gate(p0b_summary_path=p0b, output_root=tmp_path / "p0c", service_token_env_file=env_file)

    assert summary["passed"] is True
    assert summary["readiness"]["p0c_one_time_controlled_execution_authorized"] is True
    assert summary["readiness"]["p0c_execution_performed"] is False
    assert summary["boundary"]["one_time_controlled_task_pool_execution_authorized"] is True
    assert summary["boundary"]["task_pool_post_performed"] is False
    assert summary["boundary"]["deploy_performed"] is False
    authorization = json.loads((tmp_path / "p0c" / "p0c_one_time_controlled_execution_authorization.json").read_text(encoding="utf-8"))
    assert authorization["authorization"]["decision"] == "authorize_one_time_p0c_controlled_execution"
    assert authorization["authorization"]["max_tasks"] == 1
    preflight = json.loads((tmp_path / "p0c" / "p0c_service_token_preflight.json").read_text(encoding="utf-8"))
    assert preflight["service_token_preflight"]["secret_present"] is True
    assert preflight["service_token_preflight"]["secret_recorded"] is False


def test_p0c_blocks_failed_p0b(tmp_path: Path) -> None:
    p0b = _run_p0b(tmp_path)
    payload = json.loads(p0b.read_text(encoding="utf-8"))
    payload["passed"] = False
    p0b.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_gate(p0b_summary_path=p0b, output_root=tmp_path / "p0c", service_token_env_file=_write_service_env(tmp_path))

    assert summary["passed"] is False
    assert "p0b_context_valid" in summary["failure_reasons"]
    assert summary["boundary"]["one_time_controlled_task_pool_execution_authorized"] is False


def test_p0c_blocks_missing_service_token_secret(tmp_path: Path) -> None:
    p0b = _run_p0b(tmp_path)
    env_file = tmp_path / "empty.env"
    env_file.write_text("CIVITASOS_SERVICE_TOKEN_SCOPES=pool:read\n", encoding="utf-8")

    summary = run_gate(p0b_summary_path=p0b, output_root=tmp_path / "p0c", service_token_env_file=env_file)

    assert summary["passed"] is False
    assert "service_token_secret_present" in summary["failure_reasons"]


def test_p0c_blocks_forbidden_service_scope(tmp_path: Path) -> None:
    p0b = _run_p0b(tmp_path)
    env_file = _write_service_env(tmp_path)

    summary = run_gate(
        p0b_summary_path=p0b,
        output_root=tmp_path / "p0c",
        service_token_env_file=env_file,
        service_token_scopes=["agents:read", "production:write"],
    )

    assert summary["passed"] is False
    assert "scopes_match_allowed_scope" in summary["failure_reasons"]
    assert "no_forbidden_scope" in summary["failure_reasons"]


def test_p0c_blocks_p0b_artifact_hash_drift(tmp_path: Path) -> None:
    p0b = _run_p0b(tmp_path)
    payload = json.loads(p0b.read_text(encoding="utf-8"))
    reconciliation_path = Path(payload["artifacts"]["operator_reconciliation"]["path"])
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    reconciliation["passed"] = False
    reconciliation_path.write_text(json.dumps(reconciliation, indent=2, sort_keys=True), encoding="utf-8")

    summary = run_gate(p0b_summary_path=p0b, output_root=tmp_path / "p0c", service_token_env_file=_write_service_env(tmp_path))

    assert summary["passed"] is False
    assert "p0b_context_valid" in summary["failure_reasons"]


def _run_p0b(tmp_path: Path) -> Path:
    i2h = tmp_path / "i2h.json"
    i2h.write_text(
        json.dumps(
            {
                "schema_version": "i2h-post-merge-smoke-chain:v1",
                "passed": True,
                "readiness": {"p0_controlled_pilot_discussion_ready": True, "p0c_execution_allowed": False, "production_transition_allowed": False},
                "boundary": {"deploy_allowed": False, "runtime_state_mutation_allowed": False, "production_transition_allowed": False, "production_receipt_write_allowed": False},
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    run_p0a(i2h_summary_path=i2h, output_root=tmp_path / "p0a")
    ext_env = _write_provider_env(tmp_path / "external.env")
    local_env = _write_provider_env(tmp_path / "local.env")
    run_p0b(
        p0a_summary_path=tmp_path / "p0a" / "p0a_task_intake_chain_summary.json",
        output_root=tmp_path / "p0b",
        proposal_providers=[f"external-agent={ext_env}"],
        review_providers=[f"local-gpu-verifier={local_env}"],
        response_overrides={"external-agent": _response("proposal"), "local-gpu-verifier": _response("review")},
    )
    return tmp_path / "p0b" / "p0b_agent_proposal_chain_summary.json"


def _write_provider_env(path: Path) -> Path:
    path.write_text(
        "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://api.example.test\nBETA6_EXTERNAL_AGENT_MODEL=example-model\nBETA6_EXTERNAL_AGENT_API_KEY=test-key\n",
        encoding="utf-8",
    )
    return path


def _write_service_env(tmp_path: Path) -> Path:
    path = tmp_path / "service.env"
    path.write_text("CIVITASOS_SERVICE_TOKEN_SECRET=test-secret\n", encoding="utf-8")
    return path


def _response(role: str) -> str:
    return json.dumps(
        {
            "schema_version": AGENT_RESPONSE_SCHEMA,
            "role": role,
            "task_id": "p0-task:pilot-status-evidence-index-preview",
            "verdict": "approved",
            "summary": "The P0 proposal remains bounded to evidence index preview only.",
            "proposal": {
                "steps": ["read P0-A scope", "prepare preview artifact", "record receipts"],
                "required_receipts": ["proposal_receipt", "future_execution_receipt", "future_rollback_receipt"],
                "rollback_plan": "Abort and delete the pilot preview workspace before owner acceptance.",
            },
            "risk_controls": ["no production transition", "no deploy", "no secret access"],
            "recommendation": "ready_for_p0c_authorization_request",
            "boundary_attestation": {
                "uses_only_p0a_allowed_scope": True,
                "requests_vm_contact_now": False,
                "requests_task_pool_post_now": False,
                "requests_source_write_now": False,
                "requests_git_write_now": False,
                "requests_deploy_now": False,
                "requests_runtime_mutation_now": False,
                "requests_production_transition_now": False,
                "requests_production_receipt_now": False,
            },
        }
    )
