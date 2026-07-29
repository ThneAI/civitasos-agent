"""Offline orchestration adapter for outcome-sensitive J1-D decisions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .controlled_comparison import canonical_sha256
from .qualification_orchestrator_v4 import (
    OfflineAdapter,
    run_offline_orchestrator as run_base_offline_orchestrator,
)


REPORT_SCHEMA = "j1-qualification-outcome-sensitive-offline-orchestrator-report:v1"


class OutcomeSensitiveOfflineAdapter(OfflineAdapter):
    """Exercise strict decisions and observations without external effects."""

    def prepare_request(self, task: dict[str, Any]) -> dict[str, Any]:
        fixture = task["task"]
        return {
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "task_id": fixture["task_id"],
            "task_ordinal": fixture["task_ordinal"],
            "phase": fixture["phase"],
            "prompt_sha256": fixture["prompt_sha256"],
            "advice_mode": task["advice"]["mode"],
            "response_contract": {
                "format": "strict_json",
                "required_fields": [
                    "selected_action_id",
                    "predicted_pattern_ids",
                ],
                "unknown_fields_allowed": False,
                "allowed_action_ids": fixture["allowed_action_ids"],
                "allowed_pattern_ids": fixture["allowed_pattern_ids"],
            },
            "fixture_ground_truth_available": False,
            "offline_synthetic": True,
        }

    def provider_call(
        self, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]:
        self.provider_calls += 1
        decision = {
            "selected_action_id": task["task"]["allowed_action_ids"][0],
            "predicted_pattern_ids": [task["task"]["allowed_pattern_ids"][0]],
        }
        return {
            "content": json.dumps(decision, separators=(",", ":"), sort_keys=True),
            "request_sha256": canonical_sha256(request),
            "usage": {
                "input_cache_hit": 0,
                "input_cache_miss": 32,
                "output": 16,
                "cost_microunits": 28,
            },
            "offline_synthetic": True,
        }

    def finalize_decision(
        self, task: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        value = json.loads(response["content"])
        if not isinstance(value, dict) or set(value) != {
            "selected_action_id",
            "predicted_pattern_ids",
        }:
            raise ValueError("structured decision shape invalid")
        action = value["selected_action_id"]
        patterns = value["predicted_pattern_ids"]
        if action not in task["task"]["allowed_action_ids"]:
            raise ValueError("structured decision action invalid")
        if (
            not isinstance(patterns, list)
            or len(patterns) != len(set(patterns))
            or not all(
                isinstance(item, str)
                and item in task["task"]["allowed_pattern_ids"]
                for item in patterns
            )
        ):
            raise ValueError("structured decision patterns invalid")
        return {
            "schema_version": "j1-qualification-structured-decision:v1",
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "task_id": task["task"]["task_id"],
            "task_ordinal": task["task"]["task_ordinal"],
            "phase": task["task"]["phase"],
            "selected_action_id": action,
            "predicted_pattern_ids": sorted(patterns),
            "provider_response_sha256": canonical_sha256(response),
            "offline_synthetic": True,
        }

    def verify_event_trace(
        self,
        task: dict[str, Any],
        decision: dict[str, Any],
        signature: dict[str, Any],
    ) -> dict[str, Any]:
        fixture = task["task"]
        return {
            "schema_version": "j1-qualification-direct-behavior-observation:v1",
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "task_id": fixture["task_id"],
            "task_ordinal": fixture["task_ordinal"],
            "phase": fixture["phase"],
            "prompt_sha256": fixture["prompt_sha256"],
            "ground_truth_commitment_sha256": fixture[
                "ground_truth_commitment_sha256"
            ],
            "selected_action_id": decision["selected_action_id"],
            "predicted_pattern_ids": decision["predicted_pattern_ids"],
            "participant_signature_sha256": canonical_sha256(signature),
            "deterministic_verifier": fixture["deterministic_verifier"],
            "ground_truth_revealed": False,
            "effectiveness_scored": False,
            "verified": True,
            "offline_synthetic": True,
        }

    def event_receipts(self, task: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": (
                "j1-qualification-direct-observation-receipt-projection:v1"
            ),
            "task_execution_id": task["task_execution_id"],
            "fixture_commitment_sha256": task["task"][
                "ground_truth_commitment_sha256"
            ],
            "raw_ground_truth_persisted": False,
            "offline_synthetic": True,
        }


class OutcomeSensitiveOverrunAdapter(OutcomeSensitiveOfflineAdapter):
    """Return deterministic usage above both per-call reservations."""

    def provider_call(
        self, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]:
        response = super().provider_call(task, request)
        response["usage"] = {
            "input_cache_hit": 0,
            "input_cache_miss": 2501,
            "output": 0,
            "cost_microunits": 1524,
        }
        return response


def run_offline_orchestrator(
    *,
    contract: dict[str, Any],
    run_id: str,
    root: Path,
    adapter: OutcomeSensitiveOfflineAdapter | None = None,
    checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
    task_limit: int | None = None,
) -> dict[str, Any]:
    """Execute or resume the 480-task contract through offline-only adapters."""
    report = run_base_offline_orchestrator(
        contract=contract,
        run_id=run_id,
        root=root,
        adapter=adapter or OutcomeSensitiveOfflineAdapter(),
        checkpoint=checkpoint,
        task_limit=task_limit,
    )
    report["schema_version"] = REPORT_SCHEMA
    report["execution_boundary"] = {
        **report["execution_boundary"],
        "strict_structured_decision_simulated": True,
        "direct_behavior_observation_simulated": True,
        "fixture_ground_truth_revealed": False,
        "effectiveness_scored": False,
    }
    report["report_sha256"] = canonical_sha256(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    return report
