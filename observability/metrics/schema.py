"""Raw Tick CSV schema constants — single source of truth for column order.

Mirrors observability/metrics/schema.yaml. test_schema.py verifies parity.
"""
from __future__ import annotations

# Column order is the on-disk CSV column order. DO NOT reorder without bumping
# schema_version and updating schema.yaml + computers + tests in lockstep.
RAW_COLUMNS: tuple[str, ...] = (
    "run_id",
    "agent_id",
    "task_id",
    "tick_seq",
    "tick_id",
    "timestamp",
    "phase_reached",
    "decision_action",
    "decision_source",
    "decision_reasoning",
    "served_intent_layer",
    "conscience_allowed",
    "conscience_reason",
    "eval_success",
    "eval_cost",
    "eval_duration_ms",
    "aspect_gap",
    "peer_trust_avg",
    "balance",
    "identity_state",
    "identity_remaining_epochs",
    "identity_prompt_injected",
    "mode",
    "is_wait",
    "lessons_count",
    "wait_references_telos",
    "subjective_lifecycle_stage",
    "subjective_recommended_mode",
    "llm_mode_request",
    "llm_mode_selected",
    "relation_context_id",
    "relation_memory_refs",
    "time_window_id",
    "challenge_deadline_bucket",
    "relation_context_source",
    "relation_id_source",
    "relation_pair_present",
    "relation_pair_failure_source",
    "relation_pair_failure_events_present",
    "relation_pair_failure_ref_present",
    "h0_expectation_trace_present",
    "h0_survival_surprise_present",
    "h0_economic_surprise_present",
    "h0_reputation_surprise_present",
    "h0_task_surprise_present",
    "h0_governance_surprise_present",
    "h0_relation_surprise_present",
    "h0_drive_constitution_verdict_present",
    "h0_iem_update_log_present",
    "h0_relation_action_bias_present",
    "h0_normative_local_update_blocked",
    "h0_relation_training_sample_present",
    "h0_relation_negative_fast_learning_present",
    "h0_relation_repair_sample_present",
    "h0_relation_repair_slow_recovery_present",
    "h0_relation_history_preserved_present",
    "h0_identity_action_bias_present",
    "h0_constitutional_surprise_present",
    "h0_normative_governance_trigger_present",
    "h0_governed_revision_present",
    "h0_predicted_update_present",
    "h0_desired_slow_drift_present",
)

REQUIRED_COLUMNS: frozenset[str] = frozenset({
    "run_id",
    "agent_id",
    "task_id",
    "tick_seq",
    "tick_id",
    "timestamp",
    "phase_reached",
    "aspect_gap",
    "peer_trust_avg",
    "balance",
    "is_wait",
})

SCHEMA_VERSION = "1.13"

# Truncation for decision_reasoning (post-newline-escape).
REASONING_MAX_LEN = 500

# F.0 default values for fields the runtime does not yet expose.
F0_DEFAULT_MODE = "active"
F0_DEFAULT_WAIT_REFERENCES_TELOS = False  # written as "false" in CSV


def escape_reasoning(text: str | None) -> str:
    """Escape newlines then truncate to REASONING_MAX_LEN chars.

    Order matters: escape first so truncation does not split a `\\n` token.
    """
    if text is None:
        return ""
    escaped = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(escaped) > REASONING_MAX_LEN:
        escaped = escaped[: REASONING_MAX_LEN - 1] + "…"
    return escaped


def bool_to_csv(value: bool | None) -> str:
    """Render a Python bool as the CSV literal `true`/`false`/empty."""
    if value is None:
        return ""
    return "true" if value else "false"
