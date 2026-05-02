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
        subjective_time = self._snapshot_subjective_time(ctx)
        relation_time = self._snapshot_relation_time(ctx)
        h0 = self._snapshot_h0(ctx)
        served_intent_layer = _text(
            getattr(decision, "served_intent_layer", "") if decision else ""
        )
        wait_references_telos = (
            is_wait
            and served_intent_layer in {"short", "mid", "long", "telos"}
        )

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
            "served_intent_layer": served_intent_layer,
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
            "identity_state": _text(identity.get("state")),
            "identity_remaining_epochs": _num(identity.get("remaining_epochs")),
            "identity_prompt_injected": bool_to_csv(identity.get("prompt_injected")),
            "mode": self._snapshot_mode(),
            "is_wait": bool_to_csv(is_wait),
            "lessons_count": lessons_count,
            "wait_references_telos": bool_to_csv(
                wait_references_telos or F0_DEFAULT_WAIT_REFERENCES_TELOS
            ),
            "subjective_lifecycle_stage": _text(subjective_time.get("lifecycle_stage")),
            "subjective_recommended_mode": _text(subjective_time.get("recommended_mode")),
            "llm_mode_request": _text(subjective_time.get("llm_mode_request")),
            "llm_mode_selected": bool_to_csv(subjective_time.get("llm_mode_selected")),
            "relation_context_id": _text(relation_time.get("relation_context_id")),
            "relation_memory_refs": _text(relation_time.get("relation_memory_refs")),
            "time_window_id": _text(relation_time.get("time_window_id")),
            "challenge_deadline_bucket": _text(relation_time.get("challenge_deadline_bucket")),
            "relation_context_source": _text(relation_time.get("relation_context_source")),
            "relation_id_source": _text(relation_time.get("relation_id_source")),
            "relation_pair_present": bool_to_csv(relation_time.get("relation_pair_present")),
            "relation_pair_failure_source": _text(
                relation_time.get("relation_pair_failure_source")
            ),
            "relation_pair_failure_events_present": bool_to_csv(
                relation_time.get("relation_pair_failure_events_present")
            ),
            "relation_pair_failure_ref_present": bool_to_csv(
                relation_time.get("relation_pair_failure_ref_present")
            ),
            "h0_expectation_trace_present": bool_to_csv(h0["expectation_trace_present"]),
            "h0_survival_surprise_present": bool_to_csv(h0["survival_surprise_present"]),
            "h0_economic_surprise_present": bool_to_csv(h0["economic_surprise_present"]),
            "h0_reputation_surprise_present": bool_to_csv(h0["reputation_surprise_present"]),
            "h0_task_surprise_present": bool_to_csv(h0["task_surprise_present"]),
            "h0_governance_surprise_present": bool_to_csv(h0["governance_surprise_present"]),
            "h0_relation_surprise_present": bool_to_csv(h0["relation_surprise_present"]),
            "h0_drive_constitution_verdict_present": bool_to_csv(
                h0["drive_constitution_verdict_present"]
            ),
            "h0_iem_update_log_present": bool_to_csv(h0["iem_update_log_present"]),
            "h0_relation_action_bias_present": bool_to_csv(
                h0["relation_action_bias_present"]
            ),
            "h0_normative_local_update_blocked": bool_to_csv(
                h0["normative_local_update_blocked"]
            ),
            "h0_relation_training_sample_present": bool_to_csv(
                h0["relation_training_sample_present"]
            ),
            "h0_relation_negative_fast_learning_present": bool_to_csv(
                h0["relation_negative_fast_learning_present"]
            ),
            "h0_relation_repair_sample_present": bool_to_csv(
                h0["relation_repair_sample_present"]
            ),
            "h0_relation_repair_slow_recovery_present": bool_to_csv(
                h0["relation_repair_slow_recovery_present"]
            ),
            "h0_relation_history_preserved_present": bool_to_csv(
                h0["relation_history_preserved_present"]
            ),
            "h0_identity_action_bias_present": bool_to_csv(
                h0["identity_action_bias_present"]
            ),
            "h0_constitutional_surprise_present": bool_to_csv(
                h0["constitutional_surprise_present"]
            ),
            "h0_normative_governance_trigger_present": bool_to_csv(
                h0["normative_governance_trigger_present"]
            ),
            "h0_governed_revision_present": bool_to_csv(
                h0["governed_revision_present"]
            ),
            "h0_predicted_update_present": bool_to_csv(h0["predicted_update_present"]),
            "h0_desired_slow_drift_present": bool_to_csv(
                h0["desired_slow_drift_present"]
            ),
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

    def _snapshot_mode(self) -> str:
        mode = getattr(self._loop, "mode", None)
        if mode is None:
            mode = getattr(self._loop, "_mode", None)
        return _enum_value(mode) or "active"

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

    @staticmethod
    def _snapshot_subjective_time(ctx: Any) -> dict[str, object]:
        briefing = getattr(ctx, "briefing", None)
        if not isinstance(briefing, dict):
            return {}
        subjective = briefing.get("subjective_time")
        if not isinstance(subjective, dict):
            return {}
        return {
            "lifecycle_stage": subjective.get("lifecycle_stage", ""),
            "recommended_mode": subjective.get("recommended_mode", ""),
            "llm_mode_request": subjective.get("llm_mode_request", ""),
            "llm_mode_selected": subjective.get("llm_mode_selected"),
        }

    @staticmethod
    def _snapshot_relation_time(ctx: Any) -> dict[str, object]:
        briefing = getattr(ctx, "briefing", None)
        if not isinstance(briefing, dict):
            return {}
        relation = briefing.get("relation_context")
        if not isinstance(relation, dict):
            relation = briefing.get("g3_relation_context")
        if not isinstance(relation, dict):
            relation = {}
        window = briefing.get("time_window")
        if not isinstance(window, dict):
            window = briefing.get("g3_time_window")
        if not isinstance(window, dict):
            window = {}

        refs = relation.get("memory_refs")
        if refs is None:
            refs = relation.get("relation_memory_refs")
        if isinstance(refs, list):
            refs = ";".join(str(ref) for ref in refs if ref is not None)

        relation_id = (
            relation.get("relation_id")
            or relation.get("id")
            or relation.get("relation_context_id")
        )
        relation_pair = relation.get("relation_pair") or window.get("relation_pair")
        recent_failures = relation.get("recent_failures")

        return {
            "relation_context_id": (
                relation.get("id")
                or relation.get("relation_context_id")
                or relation.get("relation_id")
            ),
            "relation_memory_refs": refs,
            "time_window_id": window.get("id") or window.get("time_window_id"),
            "challenge_deadline_bucket": (
                window.get("challenge_deadline_bucket")
                or relation.get("challenge_deadline_bucket")
            ),
            "relation_context_source": relation.get("source") or window.get("source"),
            "relation_id_source": (
                relation.get("relation_id_source") or window.get("relation_id_source")
            ),
            "relation_pair_present": _relation_pair_present(relation_pair),
            "relation_pair_failure_source": relation.get("relation_pair_failure_source"),
            "relation_pair_failure_events_present": (
                isinstance(recent_failures, list) and bool(recent_failures)
            ),
            "relation_pair_failure_ref_present": _relation_pair_failure_ref_present(
                refs,
                str(relation_id or ""),
            ),
        }

    @staticmethod
    def _snapshot_h0(ctx: Any) -> dict[str, bool]:
        expectations = _mapping(getattr(ctx, "expectations", None))
        surprise = _mapping(getattr(ctx, "surprise", None))
        drive = _mapping(getattr(ctx, "drive", None))
        action_bias = _mapping(getattr(ctx, "action_bias", None))
        briefing = _mapping(getattr(ctx, "briefing", None))
        relation_training = _mapping(briefing.get("h0_relation_training_invariants"))
        updates = getattr(ctx, "expectation_updates", None)
        if updates is None:
            updates = []

        return {
            "expectation_trace_present": bool(expectations or surprise or drive),
            "survival_surprise_present": _domain_present(surprise, "survival"),
            "economic_surprise_present": _domain_present(surprise, "economic"),
            "reputation_surprise_present": _domain_present(surprise, "reputation"),
            "task_surprise_present": _domain_present(surprise, "task"),
            "governance_surprise_present": _domain_present(surprise, "governance"),
            "relation_surprise_present": _domain_present(surprise, "relation"),
            "drive_constitution_verdict_present": _has_nested_text(
                drive, "constitution_verdict"
            ),
            "iem_update_log_present": bool(updates),
            "relation_action_bias_present": _domain_present(action_bias, "relation"),
            "normative_local_update_blocked": _normative_update_blocked(updates),
            "relation_training_sample_present": bool(
                relation_training.get("training_sample_present")
            ),
            "relation_negative_fast_learning_present": bool(
                relation_training.get("negative_fast_learning_present")
            ),
            "relation_repair_sample_present": bool(
                relation_training.get("repair_sample_present")
            ),
            "relation_repair_slow_recovery_present": bool(
                relation_training.get("repair_slow_recovery_present")
            ),
            "relation_history_preserved_present": bool(
                relation_training.get("history_preserved_present")
            ),
            "identity_action_bias_present": _identity_action_bias_present(action_bias),
            "constitutional_surprise_present": _domain_present(surprise, "constitutional"),
            "normative_governance_trigger_present": _governance_trigger_present(
                updates,
                action_bias,
                drive,
            ),
            "governed_revision_present": _governed_revision_present(updates),
            "predicted_update_present": _update_rule_or_target_present(
                updates,
                rules={"precision_weighted_delta"},
                targets={"identity_expectation_vector", "identity_precision_vector"},
            ),
            "desired_slow_drift_present": _update_rule_or_target_present(
                updates,
                rules={"slow_trait_drift"},
                targets={"identity_desire_vector"},
            ),
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


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _domain_present(payload: dict[str, Any], domain: str) -> bool:
    if not payload:
        return False
    direct = payload.get(domain)
    if direct not in (None, "", {}, []):
        return True
    prefixed = payload.get(f"{domain}_surprise") or payload.get(f"{domain}_bias")
    return prefixed not in (None, "", {}, [])


def _relation_pair_present(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    requester = str(value.get("requester") or "").strip()
    worker = str(value.get("worker") or value.get("peer_agent_id") or "").strip()
    agents = value.get("agents")
    return bool((requester and worker) or (isinstance(agents, list) and len(agents) >= 2))


def _relation_pair_failure_ref_present(refs: Any, relation_id: str) -> bool:
    text = str(refs or "").strip()
    if "failure:" not in text:
        return False
    if not relation_id:
        return True
    prefix = f"failure:{relation_id}:"
    return any(ref.strip().startswith(prefix) for ref in text.split(";"))


def _has_nested_text(payload: dict[str, Any], key: str) -> bool:
    if not payload:
        return False
    direct = payload.get(key)
    if direct not in (None, ""):
        return True
    for value in payload.values():
        if isinstance(value, dict) and _has_nested_text(value, key):
            return True
    return False


def _identity_action_bias_present(action_bias: dict[str, Any]) -> bool:
    return any(
        _domain_present(action_bias, domain)
        for domain in (
            "survival",
            "economic",
            "reputation",
            "task",
            "governance",
            "normative",
            "constitutional",
        )
    )


def _governance_trigger_present(
    updates: Any,
    action_bias: dict[str, Any],
    drive: dict[str, Any],
) -> bool:
    if _contains_nested_value(action_bias.get("normative"), "governance_trigger"):
        return True
    if _contains_nested_value(drive.get("constitutional"), "governance_trigger"):
        return True
    return _update_rule_or_target_present(
        updates,
        rules={"governance_trigger"},
        targets={"normative_state"},
    )


def _governed_revision_present(updates: Any) -> bool:
    if not isinstance(updates, list):
        return False
    for update in updates:
        if _update_rule(update) != "governed_revision":
            continue
        blocked = bool(getattr(update, "local_update_blocked", False))
        if isinstance(update, dict):
            blocked = bool(update.get("local_update_blocked", blocked))
        if not blocked:
            return True
    return False


def _contains_nested_value(value: Any, expected: str) -> bool:
    if str(value or "") == expected:
        return True
    if isinstance(value, dict):
        return any(_contains_nested_value(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(_contains_nested_value(child, expected) for child in value)
    return False


def _update_rule_or_target_present(
    updates: Any,
    *,
    rules: set[str],
    targets: set[str],
) -> bool:
    if not isinstance(updates, list):
        return False
    for update in updates:
        rule = _update_rule(update)
        target = _update_target(update)
        if rule in rules or target in targets:
            return True
    return False


def _normative_update_blocked(updates: Any) -> bool:
    if not isinstance(updates, list):
        return False
    for update in updates:
        target = _update_target(update)
        blocked = bool(getattr(update, "local_update_blocked", False))
        if isinstance(update, dict):
            blocked = bool(update.get("local_update_blocked", blocked))
        if "normative" in target and blocked:
            return True
    return False


def _update_target(update: Any) -> str:
    target = getattr(update, "target", "")
    if not target and isinstance(update, dict):
        target = update.get("target", "")
    return str(target or "").lower()


def _update_rule(update: Any) -> str:
    rule = getattr(update, "rule", None)
    if rule is None and isinstance(update, dict):
        rule = update.get("rule")
    value = getattr(rule, "value", rule)
    return str(value or "").lower()


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
