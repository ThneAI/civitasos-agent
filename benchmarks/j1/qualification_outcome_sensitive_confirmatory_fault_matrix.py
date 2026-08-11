"""Fault matrix for prospective confirmatory J1-D offline recovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .qualification_fault_matrix_v4 import (
    run_fault_matrix as run_base_fault_matrix,
    validate_fault_matrix as validate_base_fault_matrix,
)
from .qualification_outcome_sensitive_confirmatory_orchestrator import (
    ConfirmatoryOfflineAdapter,
    ConfirmatoryOverrunAdapter,
)


REPORT_SCHEMA = "j1-qualification-outcome-sensitive-confirmatory-fault-matrix-report:v1"


def run_fault_matrix(*, contract: dict[str, Any], root: Path) -> dict[str, Any]:
    return run_base_fault_matrix(
        contract=contract,
        root=root,
        adapter_factory=ConfirmatoryOfflineAdapter,
        overrun_adapter_factory=ConfirmatoryOverrunAdapter,
        report_schema=REPORT_SCHEMA,
    )


def validate_fault_matrix(value: Any) -> list[str]:
    return validate_base_fault_matrix(value, expected_schema=REPORT_SCHEMA)
