from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


module = _load("private_beta_proposer_reviewer_execution", SCRIPTS / "private_beta_proposer_reviewer_execution.py")


def test_private_beta_proposer_reviewer_execution_consumes_once(monkeypatch, tmp_path: Path) -> None:
    authorization = _write_authorization_chain(tmp_path)
    _patch_execution_dependencies(monkeypatch, tmp_path)

    summary = module.run_execution(
        authorization_path=authorization,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "run1",
        backend_url="http://localhost.example.test:8099",
        scenario_id="fake-scenario",
        runner_specs=[
            "deepseek-api-agent=command:echo ok",
            "claude-cli-agent=command:echo ok",
            "hermes-cli-agent=command:echo ok",
            "local-gpu-agent=command:echo ok",
        ],
        service_token_secret="test-secret",
        service_id="test-private-beta-exec",
        authorization_consumption_path=None,
        operator_id="operator-cc",
        operator_statement="Consume once for controlled proposer/reviewer execution.",
        ack_consume_authorization=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["proposer_reviewer_outputs_ready_for_closeout"] is True
    assert summary["task_receipt_count"] == 4
    assert summary["boundary"]["authorization_consumed"] is True
    assert summary["boundary"]["agent_execution_performed"] is True
    assert summary["boundary"]["apply_allowed"] is False

    second = module.run_execution(
        authorization_path=authorization,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "run2",
        backend_url="http://localhost.example.test:8099",
        scenario_id="fake-scenario",
        runner_specs=["deepseek-api-agent=command:echo ok", "claude-cli-agent=command:echo ok", "hermes-cli-agent=command:echo ok", "local-gpu-agent=command:echo ok"],
        service_token_secret="test-secret",
        service_id="test-private-beta-exec",
        authorization_consumption_path=None,
        operator_id="operator-cc",
        operator_statement="Attempt duplicate consumption.",
        ack_consume_authorization=True,
    )
    assert second["passed"] is False
    assert any("already consumed" in item for item in second["failure_reasons"])
    assert second["readiness"]["authorization_consumed"] is False


def test_private_beta_proposer_reviewer_execution_requires_ack(tmp_path: Path) -> None:
    authorization = _write_authorization_chain(tmp_path)
    summary = module.run_execution(
        authorization_path=authorization,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "blocked",
        backend_url="http://localhost.example.test:8099",
        scenario_id="fake-scenario",
        runner_specs=[],
        service_token_secret="test-secret",
        service_id="test-private-beta-exec",
        authorization_consumption_path=None,
        operator_id="operator-cc",
        operator_statement="Missing explicit ack.",
        ack_consume_authorization=False,
    )
    assert summary["passed"] is False
    assert any("acknowledgement" in item for item in summary["failure_reasons"])


def _patch_execution_dependencies(monkeypatch, tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs

        def healthz(self) -> None:
            return None

    class FakeGenerator:
        pass

    def fake_parse_runner_specs(values: list[str]) -> dict[str, Any]:
        return {value.split("=", 1)[0]: FakeGenerator() for value in values}

    def fake_write_packet(*, scenario: Any, frontend_root: Path, output_root: Path) -> dict[str, Any]:
        prompts = output_root / "agent_prompts"
        prompts.mkdir(parents=True, exist_ok=True)
        refs: dict[str, Any] = {}
        participants = []
        for participant_id in ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"]:
            prompt = prompts / f"{participant_id}.prompt.txt"
            prompt.write_text(f"Prompt for {participant_id}\n", encoding="utf-8")
            refs[participant_id] = module.artifact_ref(prompt)
            participants.append({"participant_id": participant_id, "role": "tester", "direct_mutation_allowed": False})
        packet = {
            "schema_version": "beta-fe2-frontend-patch-proposal-packet:v1",
            "passed": True,
            "decision": "beta_fe2_patch_proposal_packet_ready",
            "patch_slice_id": "fake-slice",
            "participants": participants,
            "agent_prompt_refs": refs,
            "collaboration_boundary": {},
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        }
        (output_root / "frontend_four_agent_packet_summary.json").write_text(json.dumps(packet), encoding="utf-8")
        return packet

    def fake_post_claim_generate_deliver(**kwargs: Any) -> dict[str, Any]:
        participant_id = kwargs["participant"]["participant_id"]
        return {
            "schema_version": module.TASK_RECEIPT_SCHEMA,
            "participant_id": participant_id,
            "task_id": f"task-{participant_id}",
            "worker": kwargs["worker"],
            "final_task": {"status": "Delivered"},
            "claim_observed": True,
            "generation_observed_after_claim": True,
            "delivery_observed": True,
            "boundary": {"apply_allowed": False},
        }

    monkeypatch.setattr(module.four_agent, "SCENARIOS", {"fake-scenario": object()})
    monkeypatch.setattr(module.four_agent, "write_packet", fake_write_packet)
    monkeypatch.setattr(module.fe26, "HttpJsonClient", FakeClient)
    monkeypatch.setattr(module.fe26, "_parse_runner_specs", fake_parse_runner_specs)
    monkeypatch.setattr(module.fe26, "_post_claim_generate_deliver", fake_post_claim_generate_deliver)
    monkeypatch.setattr(module.fe26, "_auth_report", lambda client: {"auth_method": "service_token", "token_recorded": False})


def _write_authorization_chain(tmp_path: Path) -> Path:
    mediation = tmp_path / "source_mediation.json"
    receipts = []
    for participant_id in ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"]:
        receipt = tmp_path / f"{participant_id}.receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema_version": module.TASK_RECEIPT_SCHEMA,
                    "participant_id": participant_id,
                    "worker": {"did": f"did:civ:test:{participant_id}", "alias": participant_id},
                }
            ),
            encoding="utf-8",
        )
        receipts.append(module.artifact_ref(receipt))
    mediation.write_text(
        json.dumps(
            {
                "schema_version": module.FE26_SCHEMA,
                "passed": True,
                "requester": {"did": "did:civ:test:requester", "alias": "requester"},
                "task_receipts": receipts,
            }
        ),
        encoding="utf-8",
    )
    package = tmp_path / "package.json"
    package.write_text(
        json.dumps(
            {
                "schema_version": module.PACKAGE_SCHEMA,
                "passed": True,
                "readiness": {"controlled_proposer_reviewer_extension_ready": True},
                "source_artifacts": {"mediation_summary": module.artifact_ref(mediation)},
            }
        ),
        encoding="utf-8",
    )
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        json.dumps(
            {
                "schema_version": module.AUTHORIZATION_SCHEMA,
                "passed": True,
                "decision": "controlled_proposer_reviewer_authorized_once",
                "authorization_id": "private-beta-proposer-reviewer-auth:test",
                "single_use": True,
                "consumed": False,
                "source_private_beta_package": module.artifact_ref(package),
                "authorized_scope": {
                    "allowed_modes": ["patch_proposal", "release_review"],
                    "forbidden_actions": ["apply", "commit", "push", "merge", "deploy", "public_ingress", "production_runtime_execution", "production_receipt_write"],
                    "max_proposals": 1,
                    "max_reviews": 3,
                    "proposer_agents": ["deepseek-api-agent"],
                    "reviewer_agents": ["claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"],
                    "service_token_scopes": ["agents:read", "pool:post", "pool:read", "pool:claim", "pool:write"],
                },
                "boundary": {
                    "patch_proposal_allowed": True,
                    "release_review_allowed": True,
                    "apply_allowed": False,
                    "commit_allowed": False,
                    "push_allowed": False,
                    "merge_allowed": False,
                    "deploy_allowed": False,
                    "external_public_ingress_opened": False,
                    "production_runtime_execution_allowed": False,
                    "production_receipt_write_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    return authorization
