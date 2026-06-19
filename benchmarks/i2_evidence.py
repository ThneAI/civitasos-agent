"""Backward-compatible import surface for I.2 evidence helpers."""

from benchmarks.i_gate_evidence import (
    artifact_ref,
    object_value,
    read_json_object,
    write_boundaries_closed,
    write_json_object,
)

__all__ = [
    "artifact_ref",
    "object_value",
    "read_json_object",
    "write_boundaries_closed",
    "write_json_object",
]
