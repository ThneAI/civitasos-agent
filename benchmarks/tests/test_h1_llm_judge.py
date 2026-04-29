from __future__ import annotations

from benchmarks.h1.llm_judge import DisabledJudge, JudgeRequest


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
