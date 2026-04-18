"""M4: lessons_impact_rate — F.0 vacated.

Returns (None, "pending H.2") to signal the aggregator to write null + notes.
"""
from __future__ import annotations

from collections.abc import Iterable

from ._loader import TaskRun

NOTES = "pending H.2 (lessons store not implemented in civitasos_runtime)"


def compute(tasks: Iterable[TaskRun]) -> tuple[None, str]:
    # Touch tasks to keep the signature uniform with other computers (and to
    # avoid the unused-arg lint).
    _ = list(tasks)
    return None, NOTES
