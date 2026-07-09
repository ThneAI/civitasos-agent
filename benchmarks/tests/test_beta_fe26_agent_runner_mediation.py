from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_fe26_agent_runner_mediation", SCRIPTS / "beta_fe26_agent_runner_mediation.py")


def test_beta_fe26_extracts_reasoning_content_when_content_empty() -> None:
    payload = {"choices": [{"message": {"content": "", "reasoning_content": "Patch proposal verdict: proceed"}}]}

    assert module._extract_openai_content(payload) == "Patch proposal verdict: proceed"


def test_beta_fe26_posts_claims_generates_after_claim_and_delivers(tmp_path: Path) -> None:
    packet_path = _write_fe2_packet(tmp_path / "fe2_packet.json", tmp_path)
    client = FakeClient()
    generators = {
        participant_id: FakeGenerator()
        for participant_id in ("deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent")
    }

    summary = module.run_mediation(
        client=client,
        fe2_packet_summary_path=packet_path,
        output_root=tmp_path / "run",
        generators=generators,
        backend_url="http://backend",
        confirm_deliveries=True,
    )

    assert summary["passed"] is True
    assert summary["mediation_level"] == "civitasos_agent_runner_claim_generate_deliver"
    assert summary["agent_runner_mediation_observed"] is True
    assert summary["task_receipt_count"] == 3
    assert summary["claim_observed_count"] == 3
    assert summary["generation_after_claim_observed_count"] == 3
    assert summary["delivery_observed_count"] == 3
    assert summary["boundary"]["frontend_code_modified"] is False
    assert client.calls.count("healthz") == 1
    assert client.call_kinds["/api/v1/a2a/quickstart"] == 4
    assert client.call_kinds["/api/v1/a2a/pool/post"] == 3
    assert client.call_kinds["/api/v1/a2a/pool/claim"] == 3
    assert client.call_kinds["/api/v1/a2a/task/execute"] == 3
    assert client.call_kinds["/api/v1/a2a/pool/confirm"] == 3
    first_output = client.tasks["task-1"]["output"]
    assert "response_excerpt" not in first_output
    assert first_output["response_text_stored_in_generation_response_ref"] is True
    assert first_output["response_sha256"]
    assert "H.3 blocked" in first_output["contract_boundary_statement"]
    for generator in generators.values():
        assert generator.seen_claimed_task_statuses == ["Claimed"]
        assert generator.seen_claimed_by
    task_receipt = json.loads(
        (tmp_path / "run" / "deepseek-api-agent.task_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert task_receipt["artifact_envelope"]["artifact_kind"] == "task"
    assert task_receipt["artifact_envelope"]["plane"] == "runtime"
    assert task_receipt["artifact_envelope"]["subject_id"].startswith("pool-task:")


def test_beta_fe26_allowlist_records_excluded_participants(tmp_path: Path) -> None:
    packet_path = _write_fe2_packet(
        tmp_path / "fe2_packet.json",
        tmp_path,
        participant_ids=("deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"),
    )
    generators = {
        participant_id: FakeGenerator()
        for participant_id in ("deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent")
    }

    summary = module.run_mediation(
        client=FakeClient(),
        fe2_packet_summary_path=packet_path,
        output_root=tmp_path / "run",
        generators=generators,
        participant_allowlist=["deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent"],
    )

    assert summary["passed"] is True
    assert summary["task_receipt_count"] == 3
    assert summary["excluded_participant_ids"] == ["claude-cli-agent"]
    assert summary["participant_allowlist"] == ["deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent"]


def test_beta_fe26_accepts_custom_expected_patch_slice(tmp_path: Path) -> None:
    packet_path = _write_fe2_packet(tmp_path / "fe2_packet.json", tmp_path)
    payload = json.loads(packet_path.read_text(encoding="utf-8"))
    payload["patch_slice_id"] = "task_pool_presentation_extraction"
    packet_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = module.run_mediation(
        client=FakeClient(),
        fe2_packet_summary_path=packet_path,
        output_root=tmp_path / "run",
        generators={
            "deepseek-api-agent": FakeGenerator(),
            "hermes-cli-agent": FakeGenerator(),
            "local-gpu-agent": FakeGenerator(),
        },
        expected_patch_slice_id="task_pool_presentation_extraction",
    )

    assert summary["passed"] is True
    assert summary["expected_patch_slice_id"] == "task_pool_presentation_extraction"


def test_beta_fe26_blocks_missing_runner_generator(tmp_path: Path) -> None:
    packet_path = _write_fe2_packet(tmp_path / "fe2_packet.json", tmp_path)

    try:
        module.run_mediation(
            client=FakeClient(),
            fe2_packet_summary_path=packet_path,
            output_root=tmp_path / "run",
            generators={"deepseek-api-agent": FakeGenerator()},
        )
    except ValueError as exc:
        assert "missing runner generator" in str(exc)
        assert "hermes-cli-agent" in str(exc)
        assert "local-gpu-agent" in str(exc)
    else:
        raise AssertionError("expected FE-2.6 mediation to block missing runner generators")


def test_beta_fe26_blocks_non_ready_fe2_packet(tmp_path: Path) -> None:
    packet_path = _write_fe2_packet(tmp_path / "fe2_packet.json", tmp_path)
    payload = json.loads(packet_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    packet_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        module.run_mediation(
            client=FakeClient(),
            fe2_packet_summary_path=packet_path,
            output_root=tmp_path / "run",
            generators={
                "deepseek-api-agent": FakeGenerator(),
                "hermes-cli-agent": FakeGenerator(),
                "local-gpu-agent": FakeGenerator(),
            },
        )
    except ValueError as exc:
        assert "FE-2 packet must be passed" in str(exc)
    else:
        raise AssertionError("expected FE-2.6 mediation to block non-ready FE-2 packet")


def test_beta_fe26_command_runner_supports_prompt_placeholder(monkeypatch) -> None:
    captured = {}

    class Result:
        returncode = 0
        stdout = "placeholder response"
        stderr = ""

    def fake_run(argv, input, text, capture_output, check, timeout, env):
        captured["argv"] = argv
        captured["input"] = input
        return Result()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    generator = module.CommandGenerator(command="claude -p {prompt}")
    result = generator.generate(
        participant_id="claude-cli-agent",
        prompt="claimed task prompt",
        task_id="task-1",
        claimed_task={"status": "Claimed", "claimed_by": "did:worker"},
        worker={"did": "did:worker"},
    )

    assert result.content == "placeholder response"
    assert captured["argv"] == ["claude", "-p", "claimed task prompt"]
    assert captured["input"] is None


def test_beta_fe26_model_normalization_preserves_colon_model_names() -> None:
    assert module._normalize_model("openai:deepseek-chat") == "deepseek-chat"
    assert module._normalize_model("gemma4:26b") == "gemma4:26b"


def test_beta_fe26_parses_ollama_native_runner_spec() -> None:
    generators = module._parse_runner_specs(["local-gpu-agent=ollama-native:qwen3.6:latest"])

    generator = generators["local-gpu-agent"]
    assert isinstance(generator, module.OllamaNativeGenerator)
    assert generator.reviewer.model == "qwen3.6:latest"


def test_beta_fe26_ollama_native_generator_records_structured_review() -> None:
    class FakeReviewer:
        model = "qwen3.6:latest"

        def review_patch_proposal(self, prompt):
            assert "claimed task prompt" in prompt
            return module.OllamaReviewResult(
                payload={
                    "verdict": "proceed",
                    "allowed_files_only": True,
                    "reviewed_files": ["src/App.tsx"],
                    "findings": [],
                    "tests": ["npm test"],
                    "summary": "bounded",
                },
                raw_text='{"verdict":"proceed"}',
                report={"runner_kind": "ollama_native_reviewer", "attempt_count": 1},
            )

    generator = module.OllamaNativeGenerator(model="unused", reviewer=FakeReviewer())
    result = generator.generate(
        participant_id="local-gpu-agent",
        prompt="claimed task prompt",
        task_id="task-1",
        claimed_task={"status": "Claimed", "claimed_by": "did:worker"},
        worker={"did": "did:worker"},
    )

    assert result.runner_kind == "ollama_native_reviewer"
    assert result.content.startswith("Patch proposal verdict: proceed")
    assert result.raw_report["review_payload"]["allowed_files_only"] is True
    assert result.raw_report["generated_after_claim"] is True


def test_beta_fe26_run_alias_suffix_uses_full_run_path(tmp_path: Path) -> None:
    first = module._run_alias_suffix(tmp_path / "run-a" / "mediation")
    second = module._run_alias_suffix(tmp_path / "run-b" / "mediation")

    assert first != second
    assert len(first) == 16
    assert len(second) == 16


class FakeGenerator:
    def __init__(self) -> None:
        self.seen_claimed_task_statuses: list[str] = []
        self.seen_claimed_by: list[str] = []

    def generate(
        self,
        *,
        participant_id: str,
        prompt: str,
        task_id: str,
        claimed_task: dict[str, Any],
        worker: dict[str, Any],
    ):
        self.seen_claimed_task_statuses.append(str(claimed_task.get("status")))
        self.seen_claimed_by.append(str(claimed_task.get("claimed_by")))
        assert task_id in prompt
        assert str(worker.get("did")) in prompt
        assert claimed_task.get("status") == "Claimed"
        assert claimed_task.get("claimed_by") == worker.get("did")
        return module.GenerationResult(
            participant_id=participant_id,
            runner_kind="fake_test_runner",
            content=f"{participant_id} generated after claimed task {task_id}",
            raw_report={
                "schema_version": module.GENERATION_SCHEMA,
                "participant_id": participant_id,
                "runner_kind": "fake_test_runner",
                "task_id": task_id,
                "claimed_task_status": claimed_task.get("status"),
                "claimed_by": claimed_task.get("claimed_by"),
                "generated_after_claim": True,
            },
        )


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.call_kinds: dict[str, int] = {}
        self.did_count = 0
        self.task_count = 0
        self.tasks: dict[str, dict[str, Any]] = {}

    def healthz(self) -> None:
        self.calls.append("healthz")

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        kind = path if not path.startswith("/api/v1/a2a/pool/confirm/") else "/api/v1/a2a/pool/confirm"
        self.call_kinds[kind] = self.call_kinds.get(kind, 0) + 1
        if path == "/api/v1/a2a/quickstart":
            self.did_count += 1
            alias = payload.get("alias") or f"agent-{self.did_count}"
            did = f"did:civ:test:{alias}"
            return {"agent": {"did": did, "alias": alias, "name": payload.get("name")}}
        if path == "/api/v1/a2a/pool/post":
            self.task_count += 1
            task_id = f"task-{self.task_count}"
            self.tasks[task_id] = {
                "id": task_id,
                "requester": payload["requester"],
                "required_capability": payload["required_capability"],
                "status": "Open",
                "claimed_by": None,
                "posted_at": "2026-06-03T00:00:00Z",
                "claimed_at": None,
                "delivered_at": None,
                "challenge_deadline_at": None,
                "challenge_window_secs": None,
                "output": None,
            }
            return {"task_id": task_id, "status": "open"}
        if path == "/api/v1/a2a/pool/claim":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Claimed"
            task["claimed_by"] = payload["agent_id"]
            task["claimed_at"] = "2026-06-03T00:00:01Z"
            return {"claimed": True, "task": task}
        if path == "/api/v1/a2a/task/execute":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Delivered"
            task["output"] = payload["output"]
            task["delivered_at"] = "2026-06-03T00:00:02Z"
            task["challenge_deadline_at"] = "2026-06-03T00:01:02Z"
            task["challenge_window_secs"] = 60
            return {"task_id": payload["task_id"], "status": "delivered"}
        if path.startswith("/api/v1/a2a/pool/confirm/"):
            task_id = path.rsplit("/", 1)[-1]
            self.tasks[task_id]["status"] = "Completed"
            return {"task_id": task_id, "status": "completed"}
        raise AssertionError(f"unexpected POST {path}")

    def get(self, path: str) -> dict[str, Any]:
        if path.startswith("/api/v1/a2a/pool/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            return {"task": self.tasks[task_id]}
        raise AssertionError(f"unexpected GET {path}")


def _write_fe2_packet(
    path: Path,
    root: Path,
    participant_ids: tuple[str, ...] = ("deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent"),
) -> Path:
    role_by_participant = {
        "deepseek-api-agent": "implementation_proposer",
        "claude-cli-agent": "architecture_reviewer",
        "hermes-cli-agent": "ux_product_reviewer",
        "local-gpu-agent": "smoke_verifier",
    }
    participants = []
    prompt_refs = {}
    for participant_id in participant_ids:
        role = role_by_participant[participant_id]
        prompt = root / f"{participant_id}.prompt.txt"
        prompt.write_text(f"Prompt for {participant_id}\n", encoding="utf-8")
        prompt_refs[participant_id] = {"path": str(prompt), "sha256": _sha256(prompt)}
        participants.append({
            "participant_id": participant_id,
            "role": role,
            "focus": "test focus",
            "direct_mutation_allowed": False,
        })
    payload = {
        "schema_version": "beta-fe2-frontend-patch-proposal-packet:v1",
        "passed": True,
        "decision": "beta_fe2_patch_proposal_packet_ready",
        "patch_slice_id": "task_read_adapter_extraction",
        "participants": participants,
        "agent_prompt_refs": prompt_refs,
        "collaboration_boundary": {
            "direct_mutation_allowed": False,
            "apply_allowed": False,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    return _write_json(path, payload)


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
