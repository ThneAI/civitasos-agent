"""H.3 production runtime stage transition closure gate.

This artifact-only layer summarizes the production evidence, authorization,
permission, handoff, execution, actuation, and receipt review chain. It turns
the five-round transition plan into a stable readiness report. It does not
collect evidence, authorize execution, start runtime, write receipts, call
LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_submission_manifest import (
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_execution_authorization_gate import (
    SCHEMA_VERSION as PRODUCTION_EXECUTION_AUTHORIZATION_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_executor_permission_gate import (
    SCHEMA_VERSION as PRODUCTION_EXECUTOR_PERMISSION_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_goal_alignment_gate import (
    NORTH_STAR_MISSION,
    NORTH_STAR_VALUES,
    NORTH_STAR_VISION,
    SCHEMA_VERSION as PRODUCTION_GOAL_ALIGNMENT_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_runtime_actuation_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_ACTUATION_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_runtime_execution_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_runtime_execution_handoff_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_SCHEMA_VERSION,
)
from benchmarks.h3_goal_emission_runtime_production_runtime_receipt_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_RECEIPT_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-stage-transition-gate:v1"

EXPECTED_NODES: dict[str, dict[str, Any]] = {
    "production_evidence_submission_manifest": {
        "schema": PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SCHEMA_VERSION,
        "complete_field": "production_evidence_submission_manifest_complete",
        "ready_decision": "production_evidence_submission_manifest_reviewed_no_runtime_execution",
        "round": 2,
    },
    "production_execution_authorization": {
        "schema": PRODUCTION_EXECUTION_AUTHORIZATION_GATE_SCHEMA_VERSION,
        "complete_field": "production_execution_authorization_complete",
        "ready_decision": "production_execution_authorization_reviewed_no_runtime_execution",
        "round": 3,
    },
    "production_goal_alignment": {
        "schema": PRODUCTION_GOAL_ALIGNMENT_GATE_SCHEMA_VERSION,
        "complete_field": "production_goal_alignment_preserved",
        "ready_decision": "production_goal_alignment_preserved_requires_executor_permission_layer",
        "round": 4,
    },
    "production_executor_permission": {
        "schema": PRODUCTION_EXECUTOR_PERMISSION_GATE_SCHEMA_VERSION,
        "complete_field": "production_executor_permission_complete",
        "ready_decision": "production_executor_permission_reviewed_no_runtime_execution",
        "round": 4,
    },
    "production_runtime_execution_handoff": {
        "schema": PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_SCHEMA_VERSION,
        "complete_field": "production_runtime_execution_handoff_complete",
        "ready_decision": "production_runtime_execution_handoff_reviewed_no_runtime_execution",
        "round": 4,
    },
    "production_runtime_execution": {
        "schema": PRODUCTION_RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
        "complete_field": "production_runtime_execution_artifact_complete",
        "ready_decision": "production_runtime_execution_reviewed_no_runtime_start",
        "round": 5,
    },
    "production_runtime_actuation": {
        "schema": PRODUCTION_RUNTIME_ACTUATION_GATE_SCHEMA_VERSION,
        "complete_field": "production_runtime_actuation_artifact_complete",
        "ready_decision": "production_runtime_actuation_reviewed_no_runtime_start",
        "round": 5,
    },
    "production_runtime_receipt": {
        "schema": PRODUCTION_RUNTIME_RECEIPT_GATE_SCHEMA_VERSION,
        "complete_field": "production_runtime_receipt_artifact_complete",
        "ready_decision": "production_runtime_receipt_reviewed_no_receipt_write",
        "round": 5,
    },
}

ROUND_PLAN = [
    {
        "round": 1,
        "name": "stage_transition_closure_gate",
        "exit_condition": "closure gate generated a machine-readable not-ready/ready summary without creating production evidence",
        "requires_external_evidence": False,
    },
    {
        "round": 2,
        "name": "real_production_evidence_submission",
        "exit_condition": "production evidence submission manifest is complete and contains real non-local production evidence records",
        "requires_external_evidence": True,
    },
    {
        "round": 3,
        "name": "independent_execution_authorization",
        "exit_condition": "independent authorization artifact is complete and bound to the production evidence manifest hash",
        "requires_external_evidence": True,
    },
    {
        "round": 4,
        "name": "permission_and_runtime_handoff",
        "exit_condition": "VMV alignment is preserved and executor permission plus runtime handoff are independently reviewed",
        "requires_external_evidence": True,
    },
    {
        "round": 5,
        "name": "production_runtime_execution_actuation_receipt_review",
        "exit_condition": "production runtime execution, actuation, and receipt artifacts are reviewed without this gate starting runtime or writing receipts",
        "requires_external_evidence": True,
    },
]


def build_h3_goal_emission_runtime_production_stage_transition_gate(
    *,
    production_evidence_submission_manifest_path: Path,
    production_execution_authorization_gate_path: Path,
    production_goal_alignment_gate_path: Path,
    production_executor_permission_gate_path: Path,
    production_runtime_execution_handoff_gate_path: Path,
    production_runtime_execution_gate_path: Path,
    production_runtime_actuation_gate_path: Path,
    production_runtime_receipt_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    node_paths = {
        "production_evidence_submission_manifest": production_evidence_submission_manifest_path,
        "production_execution_authorization": production_execution_authorization_gate_path,
        "production_goal_alignment": production_goal_alignment_gate_path,
        "production_executor_permission": production_executor_permission_gate_path,
        "production_runtime_execution_handoff": production_runtime_execution_handoff_gate_path,
        "production_runtime_execution": production_runtime_execution_gate_path,
        "production_runtime_actuation": production_runtime_actuation_gate_path,
        "production_runtime_receipt": production_runtime_receipt_gate_path,
    }
    resolved_paths = {name: _resolve_path(path, agent_root) for name, path in node_paths.items()}
    checks: dict[str, bool] = {}
    failures: list[str] = []
    nodes: dict[str, dict[str, Any]] = {}

    for node_name, node_path in resolved_paths.items():
        report = _read_json(node_path, failures)
        expected = EXPECTED_NODES[node_name]
        if report is None:
            _fail(checks, failures, f"{node_name}_present", f"missing H3 production transition node {node_name}: {node_path}")
            nodes[node_name] = _missing_node(node_name, node_path, expected)
            continue
        checks[f"{node_name}_present"] = True
        _require_equal(f"{node_name}_schema_version", report.get("schema_version"), expected["schema"], checks=checks, failures=failures)
        _require_bool(f"{node_name}_passed", bool(report.get("passed")), checks=checks, failures=failures)
        readiness = _object(report.get("readiness"))
        decision = str(readiness.get("decision") or "")
        complete = bool(readiness.get(str(expected["complete_field"]))) and decision == expected["ready_decision"]
        node_gaps = _collect_gaps(report)
        nodes[node_name] = {
            "node": node_name,
            "path": str(node_path),
            "schema_version": report.get("schema_version"),
            "passed": bool(report.get("passed")),
            "decision": decision,
            "required_decision": expected["ready_decision"],
            "complete_field": expected["complete_field"],
            "complete": complete,
            "round": expected["round"],
            "gap_count": len(node_gaps),
            "gaps": node_gaps,
            "runtime_flags_safe": _runtime_flags_safe(report),
            "non_claims_preserved": _non_claims_preserved(report),
        }
        _require_bool(f"{node_name}_runtime_flags_safe", nodes[node_name]["runtime_flags_safe"], checks=checks, failures=failures)
        _require_bool(f"{node_name}_non_claims_preserved", nodes[node_name]["non_claims_preserved"], checks=checks, failures=failures)

    completed_rounds = _completed_rounds(nodes)
    next_blocking_round = _next_blocking_round(nodes)
    open_requirements = _open_requirements(nodes)
    all_stage_nodes_complete = bool(nodes) and all(node.get("complete") for node in nodes.values())
    metrics = {
        "stage_transition_node_count": len(nodes),
        "stage_transition_complete_node_count": sum(1 for node in nodes.values() if node.get("complete")),
        "stage_transition_open_requirement_count": len(open_requirements),
        "stage_transition_completed_round_count": len(completed_rounds),
        "stage_transition_next_blocking_round": next_blocking_round,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_actuation_ready_count": 0,
        "production_runtime_receipt_write_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    for flag_name in (
        "production_runtime_execution_ready_count",
        "production_runtime_actuation_ready_count",
        "production_runtime_receipt_write_ready_count",
        "agent_loop_start_ready_count",
        "llm_call_ready_count",
        "external_system_mutation_ready_count",
        "iem_mutation_ready_count",
        "normative_mutation_ready_count",
    ):
        _require_bool(f"{flag_name}_blocked", metrics[flag_name] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _transition_decision(passed, all_stage_nodes_complete)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "readiness": {
            "production_stage_transition_evaluated": passed,
            "next_stage_ready": passed and all_stage_nodes_complete,
            "production_runtime_execution_ready": False,
            "production_runtime_actuation_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "next_blocking_round": next_blocking_round,
            "completed_rounds": completed_rounds,
            "allowed_scope": _allowed_scope(passed, all_stage_nodes_complete, next_blocking_round),
        },
        "runtime_production_stage_transition_boundary": {
            "artifact_only": True,
            "stage_transition_review_allowed": passed,
            "production_evidence_generation_allowed": False,
            "production_execution_authorization_generation_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_actuation_allowed": False,
            "production_runtime_receipt_write_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_stage_transition_policy": {
            "north_star_vision": NORTH_STAR_VISION,
            "north_star_mission": NORTH_STAR_MISSION,
            "north_star_values": NORTH_STAR_VALUES,
            "round_plan": ROUND_PLAN,
            "stage_node_order": list(EXPECTED_NODES),
            "blocked_after_transition_review": [
                "stage_transition_reviewed -> production_evidence_generated_by_this_gate",
                "stage_transition_reviewed -> production_runtime_started_by_this_gate",
                "stage_transition_reviewed -> production_runtime_receipt_written_by_this_gate",
                "stage_transition_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_stage_transition_surface": {
            "mode": "production_stage_transition_review_only_no_runtime",
            "stage_nodes": nodes,
            "open_requirements": open_requirements,
            "round_status": _round_status(nodes),
        },
        "metrics": metrics,
        "evidence": {
            "source_paths": {name: str(path) for name, path in resolved_paths.items()},
        },
        "non_claims": [
            "does_not_create_or_validate_new_production_evidence",
            "does_not_create_independent_authorization_artifacts",
            "does_not_grant_executor_permission_or_runtime_handoff",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_stage_transition_review_as_runtime_execution_permission",
        ],
    }


def _missing_node(node_name: str, node_path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    return {
        "node": node_name,
        "path": str(node_path),
        "schema_version": None,
        "passed": False,
        "decision": "missing_stage_transition_node",
        "required_decision": expected["ready_decision"],
        "complete_field": expected["complete_field"],
        "complete": False,
        "round": expected["round"],
        "gap_count": 1,
        "gaps": [
            {
                "state": "stage_transition_node_missing",
                "gap_reason": f"missing required stage transition input: {node_name}",
            }
        ],
        "runtime_flags_safe": False,
        "non_claims_preserved": False,
    }


def _completed_rounds(nodes: dict[str, dict[str, Any]]) -> list[int]:
    completed = [1]
    for round_number in (2, 3, 4, 5):
        round_nodes = [node for node in nodes.values() if node.get("round") == round_number]
        if round_nodes and all(node.get("complete") for node in round_nodes):
            completed.append(round_number)
    return completed


def _next_blocking_round(nodes: dict[str, dict[str, Any]]) -> int:
    for round_number in (2, 3, 4, 5):
        round_nodes = [node for node in nodes.values() if node.get("round") == round_number]
        if round_nodes and not all(node.get("complete") for node in round_nodes):
            return round_number
    return 0


def _open_requirements(nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    requirements: list[dict[str, Any]] = []
    for node_name, node in nodes.items():
        if node.get("complete"):
            continue
        requirements.append(
            {
                "node": node_name,
                "round": node.get("round"),
                "current_decision": node.get("decision"),
                "required_decision": node.get("required_decision"),
                "complete_field": node.get("complete_field"),
                "gap_count": node.get("gap_count"),
                "gaps": node.get("gaps", []),
            }
        )
    return sorted(requirements, key=lambda item: (int(item.get("round") or 0), str(item.get("node") or "")))


def _round_status(nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    status = []
    for plan in ROUND_PLAN:
        round_number = int(plan["round"])
        if round_number == 1:
            complete = True
            open_nodes: list[str] = []
        else:
            round_nodes = [node for node in nodes.values() if node.get("round") == round_number]
            complete = bool(round_nodes) and all(node.get("complete") for node in round_nodes)
            open_nodes = [str(node.get("node")) for node in round_nodes if not node.get("complete")]
        status.append({**plan, "complete": complete, "open_nodes": open_nodes})
    return status


def _transition_decision(passed: bool, all_stage_nodes_complete: bool) -> str:
    if not passed:
        return "blocked_before_production_stage_transition_review"
    if all_stage_nodes_complete:
        return "ready_for_production_runtime_stage_review_no_runtime_start"
    return "not_ready_for_next_stage"


def _allowed_scope(passed: bool, all_stage_nodes_complete: bool, next_blocking_round: int) -> str:
    if not passed:
        return "stage transition input validation failed; no production runtime readiness claim is allowed"
    if all_stage_nodes_complete:
        return "all required production transition artifacts have been reviewed; this gate still does not start runtime or write receipts"
    return f"round {next_blocking_round} is still blocked; this gate only reports missing transition requirements"


def _runtime_flags_safe(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {
                "production_runtime_execution_allowed",
                "production_runtime_actuation_allowed",
                "production_runtime_receipt_allowed",
                "production_runtime_receipt_write_allowed",
                "agent_loop_start_allowed",
                "llm_planning_allowed",
                "external_system_mutation_allowed",
                "iem_value_mutation_allowed",
                "normative_local_mutation_allowed",
            } and child is True:
                return False
            if not _runtime_flags_safe(child):
                return False
    elif isinstance(value, list):
        return all(_runtime_flags_safe(item) for item in value)
    return True


def _non_claims_preserved(report: dict[str, Any]) -> bool:
    non_claims = set(_record_text_list(report.get("non_claims")))
    return {
        "does_not_start_runtime_or_agent_loop",
        "does_not_mutate_iem_or_normative_state",
    }.issubset(non_claims)


def _collect_gaps(value: Any) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if isinstance(value, dict):
        state = str(value.get("state") or "")
        gap_reason = value.get("gap_reason")
        if "gap" in state or gap_reason:
            gaps.append({key: value.get(key) for key in sorted(value) if key in {"state", "gap_reason", "goal_id", "missing_production_evidence_kinds", "missing_receipt_goal_ids", "missing_actuation_goal_ids", "missing_execution_goal_ids"}})
        for child in value.values():
            gaps.extend(_collect_gaps(child))
    elif isinstance(value, list):
        for item in value:
            gaps.extend(_collect_gaps(item))
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for gap in gaps:
        encoded = json.dumps(gap, sort_keys=True)
        if encoded not in seen:
            seen.add(encoded)
            deduped.append(gap)
    return deduped


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON {path}: {exc}")
    return None


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _record_text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _fail(checks: dict[str, bool], failures: list[str], key: str, reason: str) -> None:
    checks[key] = False
    failures.append(reason)


def _require_bool(key: str, condition: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[key] = bool(condition)
    if not condition:
        failures.append(f"{key} failed")


def _require_equal(key: str, actual: Any, expected: Any, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[key] = actual == expected
    if actual != expected:
        failures.append(f"{key} expected {expected!r}, got {actual!r}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build H3 production runtime stage transition closure gate")
    parser.add_argument("--production-evidence-submission-manifest", type=Path, required=True)
    parser.add_argument("--production-execution-authorization-gate", type=Path, required=True)
    parser.add_argument("--production-goal-alignment-gate", type=Path, required=True)
    parser.add_argument("--production-executor-permission-gate", type=Path, required=True)
    parser.add_argument("--production-runtime-execution-handoff-gate", type=Path, required=True)
    parser.add_argument("--production-runtime-execution-gate", type=Path, required=True)
    parser.add_argument("--production-runtime-actuation-gate", type=Path, required=True)
    parser.add_argument("--production-runtime-receipt-gate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _build_arg_parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    report = build_h3_goal_emission_runtime_production_stage_transition_gate(
        production_evidence_submission_manifest_path=args.production_evidence_submission_manifest,
        production_execution_authorization_gate_path=args.production_execution_authorization_gate,
        production_goal_alignment_gate_path=args.production_goal_alignment_gate,
        production_executor_permission_gate_path=args.production_executor_permission_gate,
        production_runtime_execution_handoff_gate_path=args.production_runtime_execution_handoff_gate,
        production_runtime_execution_gate_path=args.production_runtime_execution_gate,
        production_runtime_actuation_gate_path=args.production_runtime_actuation_gate,
        production_runtime_receipt_gate_path=args.production_runtime_receipt_gate,
        agent_root=agent_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())