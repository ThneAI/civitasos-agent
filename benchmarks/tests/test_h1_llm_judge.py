from __future__ import annotations

import importlib
import json

import pytest

import benchmarks.h1.llm_judge as llm_judge
from benchmarks.h1.llm_judge import (
    DisabledJudge,
    JudgeBackendUnavailable,
    JudgeRequest,
    JudgeResponseInvalid,
    OllamaNativeJudge,
    OpenAICompatibleJudge,
    build_judge_from_env,
)


def test_disabled_judge_returns_skipped_result() -> None:
    judge = DisabledJudge()
    out = judge.evaluate(
        JudgeRequest(
            task_id="A01_adversarial_01",
            criterion_body="judge this",
            briefing="b",
            final_output="o",
            action_trace=["pool_claim", "task_execute"],
        )
    )
    assert out.skipped is True
    assert out.passed is None
    assert out.score is None


def test_build_judge_from_env_defaults_to_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CIVITASOS_H1_JUDGE_ENABLED", raising=False)
    judge = build_judge_from_env()

    out = judge.evaluate(
        JudgeRequest(
            task_id="A01_happy_01",
            criterion_body="judge this",
            briefing="b",
            final_output="o",
            action_trace=[],
        )
    )
    assert out.skipped is True


def test_build_judge_from_env_fails_closed_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_ENABLED", "1")
    monkeypatch.delenv("CIVITASOS_H1_JUDGE_BACKEND", raising=False)

    with pytest.raises(JudgeBackendUnavailable):
        build_judge_from_env()


def test_build_judge_from_env_rejects_same_agent_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_ENABLED", "1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BACKEND", "openai-compatible")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BASE_URL", "http://judge.local/v1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_MODEL", "qwen3:latest")
    monkeypatch.setenv("AGENT_LLM", "ollama:qwen3:latest")

    with pytest.raises(JudgeBackendUnavailable):
        build_judge_from_env()


def test_build_judge_from_env_builds_openai_compatible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_ENABLED", "1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BACKEND", "openai-compatible")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BASE_URL", "http://judge.local/v1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_MODEL", "judge-qwen2.5")
    monkeypatch.setenv("AGENT_LLM", "ollama:qwen3:latest")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_THINK", "0")

    judge = build_judge_from_env()

    assert isinstance(judge, OpenAICompatibleJudge)
    assert judge.model == "judge-qwen2.5"
    assert judge.think is False
    assert judge.max_retries == 2


def test_build_judge_from_env_builds_ollama_native(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_ENABLED", "1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BACKEND", "ollama-native")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CIVITASOS_H1_JUDGE_MODEL", "gemma4:26b")
    monkeypatch.setenv("AGENT_LLM", "ollama:qwen3:latest")
    monkeypatch.delenv("CIVITASOS_H1_JUDGE_THINK", raising=False)

    judge = build_judge_from_env()

    assert isinstance(judge, OllamaNativeJudge)
    assert judge.base_url == "http://localhost:11434"
    assert judge.think is False


def test_openai_compatible_judge_parses_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            content = json.dumps(
                {"passed": True, "score": 0.87, "rationale": "criterion satisfied"}
            )
            return json.dumps({"choices": [{"message": {"content": content}}]}).encode()

    def fake_urlopen(request: object, timeout: float) -> Response:
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["payload"] = json.loads(request.data.decode("utf-8"))
        return Response()

    monkeypatch.setattr(llm_judge, "urlopen", fake_urlopen)
    judge = OpenAICompatibleJudge(
        base_url="http://judge.local/v1",
        model="judge-model-v2",
        timeout_s=7,
    )
    result = judge.evaluate(
        JudgeRequest(
            task_id="V04_h1_verifier_before_delivery_01",
            criterion_body="Verifier before delivery",
            briefing="Transfer request",
            final_output="address_diff passed before transfer",
            action_trace=["address_diff", "task_execute"],
            sample_id="sample-1",
            telos="verified transfer",
        )
    )

    assert seen["url"] == "http://judge.local/v1/chat/completions"
    assert seen["timeout"] == 7
    assert seen["payload"]["model"] == "judge-model-v2"
    assert "think" not in seen["payload"]
    assert result.passed is True
    assert result.score == 0.87
    assert result.model == "judge-model-v2"
    assert result.prompt_version == "h1-judge-v1"
    assert result.prompt_hash.startswith("sha256:")


def test_openai_compatible_judge_rejects_invalid_judge_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"choices": [{"message": {"content": "{\"passed\": \"yes\"}"}}]}
            ).encode()

    monkeypatch.setattr(llm_judge, "urlopen", lambda *_args, **_kwargs: Response())
    judge = OpenAICompatibleJudge(base_url="http://judge.local/v1", model="judge-model-v2")

    with pytest.raises(JudgeResponseInvalid):
        judge.evaluate(
            JudgeRequest(
                task_id="bad-json",
                criterion_body="criterion",
                briefing="briefing",
                final_output="output",
                action_trace=[],
            )
        )


def test_openai_compatible_judge_retries_empty_content(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    class Response:
        def __init__(self, content: str) -> None:
            self.content = content

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"choices": [{"message": {"content": self.content}}]}).encode()

    def fake_urlopen(*_args: object, **_kwargs: object) -> Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return Response("")
        return Response(json.dumps({"passed": True, "score": 1.0, "rationale": "ok"}))

    monkeypatch.setattr(llm_judge, "urlopen", fake_urlopen)
    judge = OpenAICompatibleJudge(
        base_url="http://judge.local/v1",
        model="judge-model-v2",
        max_retries=1,
    )

    result = judge.evaluate(
        JudgeRequest(
            task_id="transient-empty",
            criterion_body="criterion",
            briefing="briefing",
            final_output="output",
            action_trace=[],
        )
    )

    assert calls == 2
    assert result.passed is True
    assert result.score == 1.0


def test_ollama_native_judge_parses_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "message": {
                        "content": json.dumps(
                            {"passed": True, "score": 0.91, "rationale": "native ok"}
                        )
                    }
                }
            ).encode()

    def fake_urlopen(request: object, timeout: float) -> Response:
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["payload"] = json.loads(request.data.decode("utf-8"))
        return Response()

    monkeypatch.setattr(llm_judge, "urlopen", fake_urlopen)
    judge = OllamaNativeJudge(
        base_url="http://localhost:11434/v1",
        model="gemma4:26b",
        timeout_s=9,
        max_tokens=700,
        think=False,
    )
    result = judge.evaluate(
        JudgeRequest(
            task_id="A01_adversarial_01",
            criterion_body="criterion",
            briefing="briefing",
            final_output="output",
            action_trace=["get_reputation", "task_execute"],
        )
    )

    assert seen["url"] == "http://localhost:11434/api/chat"
    assert seen["timeout"] == 9
    assert seen["payload"]["think"] is False
    assert seen["payload"]["options"]["num_predict"] == 700
    assert result.passed is True
    assert result.score == 0.91
    assert result.model == "gemma4:26b"


def test_telos_alignment_derives_verifier_plan_and_served_layer() -> None:
    telos = importlib.import_module("benchmarks.h1.telos")
    alignment = telos.build_telos_alignment(
        {
            "active_tasks": [
                {
                    "task_id": "task-1",
                    "telos": "deliver correct code with edge-case tests",
                    "verifier_tools": ["test_runner"],
                }
            ]
        },
        {},
        {"relation": {"edge": {"verification_level": "strict"}}},
    )
    assert alignment["active_layer"] == "short"
    assert alignment["verification_plan"]["required"] is True
    assert alignment["verification_plan"]["level"] == "strict"
    assert "test_runner" in alignment["verification_plan"]["tools"]
    assert telos.served_intent_layer_for_action("test_runner", {}, alignment) == "short"
    assert telos.served_intent_layer_for_action("task_execute", {}, alignment) == "immediate"
