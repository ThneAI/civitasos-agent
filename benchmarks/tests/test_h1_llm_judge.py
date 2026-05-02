from __future__ import annotations

import importlib
import os

from benchmarks.h1.llm_judge import (
    DisabledJudge,
    JudgeBackendUnavailable,
    JudgeRequest,
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


def test_build_judge_from_env_defaults_to_disabled() -> None:
    original = os.environ.pop("CIVITASOS_H1_JUDGE_ENABLED", None)
    try:
        judge = build_judge_from_env()
    finally:
        if original is not None:
            os.environ["CIVITASOS_H1_JUDGE_ENABLED"] = original

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


def test_build_judge_from_env_fails_closed_when_enabled() -> None:
    original = os.environ.get("CIVITASOS_H1_JUDGE_ENABLED")
    os.environ["CIVITASOS_H1_JUDGE_ENABLED"] = "1"

    try:
        build_judge_from_env()
    except JudgeBackendUnavailable:
        pass
    else:
        raise AssertionError("expected JudgeBackendUnavailable")
    finally:
        if original is None:
            os.environ.pop("CIVITASOS_H1_JUDGE_ENABLED", None)
        else:
            os.environ["CIVITASOS_H1_JUDGE_ENABLED"] = original


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
