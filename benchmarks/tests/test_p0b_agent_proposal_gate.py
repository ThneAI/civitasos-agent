from __future__ import annotations

import json
from pathlib import Path

from benchmarks.p0a_task_intake_gate import run_gate as run_p0a
from benchmarks.p0b_agent_proposal_gate import AGENT_RESPONSE_SCHEMA, run_gate


def test_p0b_agent_proposal_gate_passes_with_external_and_local(tmp_path: Path) -> None:
    p0a = _run_p0a(tmp_path)
    ext_env = _write_env(tmp_path / "external.env", base_url="https://api.example.test", model="external-model")
    local_env = _write_env(tmp_path / "local.env", base_url="http://127.0.0.1:11434/v1", model="local-model")

    summary = run_gate(
        p0a_summary_path=p0a,
        output_root=tmp_path / "p0b",
        proposal_providers=[f"external-agent={ext_env}"],
        review_providers=[f"local-gpu-verifier={local_env}"],
        response_overrides={
            "external-agent": _response("proposal"),
            "local-gpu-verifier": _response("review"),
        },
    )

    assert summary["passed"] is True
    assert summary["metrics"]["proposal_count"] == 1
    assert summary["metrics"]["review_count"] == 1
    assert summary["readiness"]["p0c_authorization_request_ready"] is True
    assert summary["readiness"]["p0c_execution_allowed"] is False
    assert summary["boundary"]["deploy_allowed"] is False
    assert summary["boundary"]["production_receipt_write_allowed"] is False


def test_p0b_blocks_single_provider(tmp_path: Path) -> None:
    p0a = _run_p0a(tmp_path)
    ext_env = _write_env(tmp_path / "external.env")

    summary = run_gate(
        p0a_summary_path=p0a,
        output_root=tmp_path / "p0b",
        proposal_providers=[f"external-agent={ext_env}"],
        review_providers=[],
        response_overrides={"external-agent": _response("proposal")},
    )

    assert summary["passed"] is False
    assert "local_review_provider_present" in summary["failure_reasons"]


def test_p0b_blocks_forbidden_authority_request(tmp_path: Path) -> None:
    p0a = _run_p0a(tmp_path)
    ext_env = _write_env(tmp_path / "external.env")
    local_env = _write_env(tmp_path / "local.env")
    bad = json.loads(_response("proposal"))
    bad["summary"] = "We should deploy now with production write access."

    summary = run_gate(
        p0a_summary_path=p0a,
        output_root=tmp_path / "p0b",
        proposal_providers=[f"external-agent={ext_env}"],
        review_providers=[f"local-gpu-verifier={local_env}"],
        response_overrides={
            "external-agent": json.dumps(bad),
            "local-gpu-verifier": _response("review"),
        },
    )

    assert summary["passed"] is False
    assert "external-agent:forbidden_authority_not_requested" in summary["failure_reasons"]


def test_p0b_blocks_failed_p0a(tmp_path: Path) -> None:
    p0a = _run_p0a(tmp_path)
    payload = json.loads(p0a.read_text(encoding="utf-8"))
    payload["passed"] = False
    p0a.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    ext_env = _write_env(tmp_path / "external.env")
    local_env = _write_env(tmp_path / "local.env")

    summary = run_gate(
        p0a_summary_path=p0a,
        output_root=tmp_path / "p0b",
        proposal_providers=[f"external-agent={ext_env}"],
        review_providers=[f"local-gpu-verifier={local_env}"],
        response_overrides={
            "external-agent": _response("proposal"),
            "local-gpu-verifier": _response("review"),
        },
    )

    assert summary["passed"] is False
    assert "p0a_summary_passed" in summary["failure_reasons"]


def _run_p0a(tmp_path: Path) -> Path:
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
    return tmp_path / "p0a" / "p0a_task_intake_chain_summary.json"


def _write_env(path: Path, *, base_url: str = "https://api.example.test", model: str = "example-model") -> Path:
    path.write_text(
        f"BETA6_EXTERNAL_AGENT_API_BASE_URL={base_url}\nBETA6_EXTERNAL_AGENT_MODEL={model}\nBETA6_EXTERNAL_AGENT_API_KEY=test-key\n",
        encoding="utf-8",
    )
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
