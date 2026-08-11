"""Offline recovery adapter for prospective confirmatory J1-D execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_orchestrator import (
    OutcomeSensitiveOfflineAdapter,
    OutcomeSensitiveOverrunAdapter,
    run_offline_orchestrator as run_outcome_offline_orchestrator,
)


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-offline-orchestrator-report:v1"
)


class ConfirmatoryOfflineAdapter(OutcomeSensitiveOfflineAdapter):
    """Use the frozen structured decision boundary without external effects."""


class ConfirmatoryOverrunAdapter(OutcomeSensitiveOverrunAdapter):
    """Exercise deterministic reservation failure under confirmatory binding."""


def run_offline_orchestrator(
    *,
    contract: dict[str, Any],
    run_id: str,
    root: Path,
    adapter: ConfirmatoryOfflineAdapter | None = None,
    checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
    task_limit: int | None = None,
) -> dict[str, Any]:
    report = run_outcome_offline_orchestrator(
        contract=contract,
        run_id=run_id,
        root=root,
        adapter=adapter or ConfirmatoryOfflineAdapter(),
        checkpoint=checkpoint,
        task_limit=task_limit,
    )
    method = contract.get("confirmatory_method_binding", {})
    report["schema_version"] = REPORT_SCHEMA
    report["confirmatory_method_binding"] = {
        "method_sha256": method.get("method_sha256"),
        "promotion_gate_sha256": method.get("promotion_gate_sha256"),
        "consent_gate_sha256": method.get("consent_gate_sha256"),
        "prior_run_reanalysis_performed": False,
        "advice_adherence_inferred": False,
        "effectiveness_scored": False,
    }
    report["report_sha256"] = canonical_sha256(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    return report
