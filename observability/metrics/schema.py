"""Raw Tick CSV schema constants — single source of truth for column order.

Mirrors observability/metrics/schema.yaml v1.1. test_schema.py verifies parity.
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
    "mode",
    "is_wait",
    "wait_references_telos",
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

SCHEMA_VERSION = "1.1"

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
