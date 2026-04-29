"""CollectorAdapter — installed via CognitiveLoop.on_reflect(...).

Hook signature is fn(ctx) only (per civitasos_runtime/loop.py:267-271). The
EnergyState snapshot is read from the bound `loop._energy.state` reference;
this internal access is acknowledged in observability/metrics/README.md as
acceptable until G.x exposes a public energy snapshot API.
"""
from __future__ import annotations

import logging
from typing import Any

from .schema import (
    F0_DEFAULT_MODE,
    F0_DEFAULT_WAIT_REFERENCES_TELOS,
    bool_to_csv,
    escape_reasoning,
)
from .writer import RawWriter

logger = logging.getLogger(__name__)


class CollectorAdapter:
    """Per-agent reflect-phase observer that materialises one CSV row per tick.

    Lifecycle:
        adapter = CollectorAdapter(run_id=..., agent_id=..., loop=loop, writer=w)
        loop.on_reflect(adapter)
        adapter.bind_task("R01_happy_01")
        # ... ticks happen, each appends one row to writer ...
        adapter.unbind_task()
    """

    def __init__(
        self,
        *,
        run_id: str,
        agent_id: str,
        loop: Any,
        writer: RawWriter,
    ) -> None:
        self.run_id = run_id
        self.agent_id = agent_id
        self._loop = loop
        self._writer = writer
        self._task_id: str | None = None
        self._tick_seq: int = 0

    # --- task lifecycle -------------------------------------------------

    def bind_task(self, task_id: str) -> None:
        self._task_id = task_id
        self._tick_seq = 0

    def unbind_task(self) -> None:
        self._task_id = None
        self._tick_seq = 0

    @property
    def task_id(self) -> str | None:
        return self._task_id

    @property
    def tick_seq(self) -> int:
        return self._tick_seq

    # --- hook entrypoint ------------------------------------------------

    def __call__(self, ctx: Any) -> None:
        """Invoked by CognitiveLoop after the reflect phase. Never raises."""
        if self._task_id is None:
            return
        self._tick_seq += 1
        try:
            row = self._build_row(ctx)
            self._writer.write(row)
        except Exception:  #守则 5：采集失败不影响 agent
            logger.exception("CollectorAdapter row build/write failed")

    # --- row construction ----------------------------------------------

    def _build_row(self, ctx: Any) -> dict[str, object]:
        decision = getattr(ctx, "decision", None)
        verdict = getattr(ctx, "conscience_verdict", None)
        evaluation = getattr(ctx, "evaluation", None)
        energy = self._snapshot_energy()

        action = getattr(decision, "action", None) if decision else None
        is_wait = action == "wait"
        lessons_count = self._snapshot_lessons_count()
        identity = self._snapshot_identity(ctx)

        return {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "task_id": self._task_id,
            "tick_seq": self._tick_seq,
            "tick_id": getattr(ctx, "tick_id", ""),
            "timestamp": getattr(ctx, "timestamp", ""),
            "phase_reached": _phase_value(getattr(ctx, "phase", None)),
            "decision_action": action or "",
            "decision_source": _enum_value(getattr(decision, "source", None)),
            "decision_reasoning": escape_reasoning(
                getattr(decision, "reasoning", None) if decision else None
            ),
            "served_intent_layer": "",  # H.1+
            "conscience_allowed": bool_to_csv(
                getattr(verdict, "allowed", None) if verdict else None
            ),
            "conscience_reason": (getattr(verdict, "reason", "") if verdict else ""),
            "eval_success": bool_to_csv(
                getattr(evaluation, "success", None) if evaluation else None
            ),
            "eval_cost": _num(getattr(evaluation, "cost", None) if evaluation else None),
            "eval_duration_ms": _num(
                getattr(evaluation, "duration_ms", None) if evaluation else None
            ),
            "aspect_gap": _num(energy.get("aspect_gap"), default=0.0),
            "peer_trust_avg": _num(energy.get("peer_trust_avg"), default=0.0),
            "balance": _num(energy.get("balance"), default=0.0),
            "identity_state": str(identity.get("state", "")),
            "identity_remaining_epochs": _num(identity.get("remaining_epochs")),
            "identity_prompt_injected": bool_to_csv(identity.get("prompt_injected")),
            "mode": F0_DEFAULT_MODE,
            "is_wait": bool_to_csv(is_wait),
            "lessons_count": lessons_count,
            "wait_references_telos": bool_to_csv(F0_DEFAULT_WAIT_REFERENCES_TELOS),
        }

    def _snapshot_energy(self) -> dict[str, float]:
        energy_obj = getattr(self._loop, "_energy", None)
        state = getattr(energy_obj, "state", None) if energy_obj else None
        if state is None:
            return {}
        return {
            "aspect_gap": getattr(state, "aspect_gap", 0.0),
            "peer_trust_avg": getattr(state, "peer_trust_avg", 0.0),
            "balance": getattr(state, "balance", 0.0),
        }

    def _snapshot_lessons_count(self) -> int:
        mem = getattr(self._loop, "_memory", None)
        lessons = None
        if mem is not None and hasattr(mem, "recall"):
            try:
                lessons = mem.recall("lessons_learned")
            except Exception:
                logger.debug("CollectorAdapter: memory.recall(lessons_learned) failed")
        if lessons is None:
            agent = getattr(self._loop, "_agent", None)
            if agent is not None and hasattr(agent, "recall"):
                try:
                    lessons = agent.recall("lessons_learned")
                except Exception:
                    logger.debug("CollectorAdapter: agent.recall(lessons_learned) failed")
        if isinstance(lessons, list):
            return len(lessons)
        return 0

    @staticmethod
    def _snapshot_identity(ctx: Any) -> dict[str, object]:
        briefing = getattr(ctx, "briefing", None)
        if not isinstance(briefing, dict):
            return {}
        identity = briefing.get("identity")
        if not isinstance(identity, dict):
            identity = {}
        return {
            "state": identity.get("state", ""),
            "remaining_epochs": identity.get("remaining_epochs"),
            "prompt_injected": briefing.get("_identity_prompt_injected"),
        }


def _phase_value(phase: Any) -> str:
    if phase is None:
        return ""
    return getattr(phase, "value", str(phase))


def _enum_value(enum_obj: Any) -> str:
    if enum_obj is None:
        return ""
    return getattr(enum_obj, "value", str(enum_obj))


def _num(value: Any, default: float | None = None) -> str:
    if value is None:
        return "" if default is None else str(default)
    return str(value)
