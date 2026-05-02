"""H.1 LLM-judge minimal scaffold.

This module intentionally does not wire into F.1 execution yet. It defines
the contract and an explicit disabled implementation so future H.1 rollout
can land incrementally without changing F.1 behavior.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class JudgeRequest:
    task_id: str
    criterion_body: str
    briefing: str
    final_output: str
    action_trace: list[str]


@dataclass(frozen=True)
class JudgeResult:
    passed: bool | None
    score: float | None
    rationale: str
    skipped: bool = False


class LLMJudge(Protocol):
    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        ...


class JudgeBackendUnavailable(RuntimeError):
    """Raised when H.1 judge is explicitly required but no backend exists."""


class DisabledJudge:
    """Fallback until H.1 evaluator is enabled and calibrated."""

    def __init__(self, reason: str = "H.1 judge disabled") -> None:
        self._reason = reason

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        return JudgeResult(
            passed=None,
            score=None,
            rationale=f"{self._reason}: {req.task_id}",
            skipped=True,
        )


def build_judge_from_env() -> LLMJudge:
    """Build judge backend from env flags.

    Current phase only supports DisabledJudge. Real backends (OpenAI/Ollama)
    should be added in H.1 implementation with prompt/version pinning.
    """
    enabled = os.getenv("CIVITASOS_H1_JUDGE_ENABLED", "").strip().lower()
    if enabled in {"1", "true", "yes", "on"}:
        raise JudgeBackendUnavailable(
            "CIVITASOS_H1_JUDGE_ENABLED is set, but no calibrated H.1 judge "
            "backend is implemented yet"
        )
    return DisabledJudge()
