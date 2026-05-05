"""H.3 runtime production goal-alignment drift guard.

This artifact-only layer reads the production execution authorization gate and
checks that the chain still matches the CivitasOS north star: human sovereignty,
rules before capability, verifiable truth, non-disappearing accountability, and
safety over efficiency. It does not grant executor permission, start runtime,
write receipts, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_execution_authorization_gate import (
    SCHEMA_VERSION as PRODUCTION_EXECUTION_AUTHORIZATION_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-goal-alignment-gate:v1"
NORTH_STAR_VISION = "Build a verifiable, accountable, evolvable human-sovereign AI social operating system."
NORTH_STAR_MISSION = "Institutionalize AI execution/governance with long-term safety, value alignment, and continuous rule evolution."
NORTH_STAR_VALUES = [
    "human_sovereignty",
    "rules_before_capability",
    "verifiable_truth",
    "non_disappearing_accountability",
    "safety_over_efficiency",
    "long_termism",
    "incremental_evolution",
    "open_collaboration_with_security_boundaries",
]


def build_h3_goal_emission_runtime_production_goal_alignment_gate(
    *,
    production_execution_authorization_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    production_execution_authorization_gate_path = _resolve_path(production_execution_authorization_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    authorization_gate_report = _read_json(production_execution_authorization_gate_path, failures)

    authorization_readiness: dict[str, Any] = {}
    authorization_boundary: dict[str, Any] = {}
    authorization_surface: dict[str, Any] = {}
    authorization_gaps: list[dict[str, Any]] = []
    authorization_summary: dict[str, Any] = {}
    if authorization_gate_report is None:
        _fail(
            checks,
            failures,
            "production_execution_authorization_gate_present",
            f"missing H3 runtime production execution authorization gate: {production_execution_authorization_gate_path}",
        )
    else:
        checks["production_execution_authorization_gate_present"] = True
        _require_equal(
            "production_execution_authorization_gate_schema_version",
            authorization_gate_report.get("schema_version"),
            PRODUCTION_EXECUTION_AUTHORIZATION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_execution_authorization_gate_passed", bool(authorization_gate_report.get("passed")), checks=checks, failures=failures)
        authorization_readiness = _object(authorization_gate_report.get("readiness"))
        _require_authorization_readiness(authorization_readiness, checks=checks, failures=failures)
        authorization_boundary = _object(authorization_gate_report.get("runtime_production_execution_authorization_boundary"))
        _require_authorization_boundary(authorization_boundary, checks=checks, failures=failures)
        authorization_surface = _object(authorization_gate_report.get("runtime_production_execution_authorization_surface"))
        _require_equal(
            "production_execution_authorization_surface_mode",
            authorization_surface.get("mode"),
            "production_execution_authorization_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        authorization_gaps = _record_list(authorization_surface.get("production_execution_authorization_gaps"))
        authorization_summary = _object(authorization_surface.get("production_execution_authorization_summary"))
        _require_authorization_surface(authorization_summary, authorization_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(authorization_gate_report.get("non_claims")), checks=checks, failures=failures)

    metrics = {
        "north_star_value_count": len(NORTH_STAR_VALUES),
        "north_star_value_present_count": sum(1 for value in NORTH_STAR_VALUES if value),
        "production_execution_authorization_gap_count": len(authorization_gaps),
        "production_execution_authorization_reviewed_count": int(bool(authorization_summary)),
        "production_executor_permission_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("north_star_values_complete", metrics["north_star_value_present_count"] == metrics["north_star_value_count"], checks=checks, failures=failures)
    _require_bool("rules_before_capability_preserved", metrics["production_executor_permission_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("accountability_gap_or_summary_preserved", bool(authorization_gaps or authorization_summary), checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    upstream_decision = str(authorization_readiness.get("decision") or "")
    decision = _alignment_decision(passed, upstream_decision, authorization_summary, authorization_gaps)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_execution_authorization_gate_path": str(production_execution_authorization_gate_path),
        "checks": checks,
        "readiness": {
            "production_goal_alignment_evaluated": passed,
            "production_goal_alignment_preserved": passed,
            "production_executor_permission_ready": False,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "upstream_authorization_decision": upstream_decision,
            "allowed_scope": _allowed_scope(passed, upstream_decision, authorization_summary, authorization_gaps),
        },
        "runtime_production_goal_alignment_boundary": {
            "artifact_only": True,
            "goal_alignment_review_allowed": passed,
            "production_executor_permission_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_goal_alignment_policy": {
            "north_star_vision": NORTH_STAR_VISION,
            "north_star_mission": NORTH_STAR_MISSION,
            "north_star_values": NORTH_STAR_VALUES,
            "required_upstream_schema": PRODUCTION_EXECUTION_AUTHORIZATION_GATE_SCHEMA_VERSION,
            "blocked_drift_vectors": [
                "authorization_review -> executor_permission",
                "readiness_artifact -> runtime_execution",
                "local_controlled_receipt -> production_readiness",
                "missing_evidence_gap -> implicit_approval",
                "goal_alignment_review -> iem_or_normative_mutation",
            ],
        },
        "runtime_production_goal_alignment_surface": {
            "mode": "production_goal_alignment_review_only_no_runtime",
            "goal_alignment_state": "aligned_but_runtime_blocked" if passed else "blocked_before_goal_alignment",
            "source_production_execution_authorization_summary": authorization_summary,
            "source_production_execution_authorization_gaps": authorization_gaps,
            "north_star_review": {
                "vision": NORTH_STAR_VISION,
                "mission": NORTH_STAR_MISSION,
                "values": NORTH_STAR_VALUES,
            },
        },
        "metrics": metrics,
        "evidence": {
            "production_execution_authorization_readiness": authorization_readiness,
            "production_execution_authorization_boundary": authorization_boundary,
        },
        "non_claims": [
            "does_not_grant_production_executor_permission",
            "does_not_treat_goal_alignment_as_runtime_execution_permission",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
        ],
    }


def _require_authorization_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_execution_authorization",
        "production_execution_authorization_not_required_no_manifest_targets",
        "production_execution_authorization_blocked_pending_submission_manifest",
        "production_execution_authorization_blocked_manifest_gaps",
        "production_execution_authorization_blocked_pending_authorization_artifact",
        "production_execution_authorization_gap_detected",
        "production_execution_authorization_reviewed_no_runtime_execution",
    }
    _require_bool("production_execution_authorization_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_execution_authorization_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_execution_authorization_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_authorization_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_execution_authorization_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_execution_authorization_runtime_permission_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_execution_authorization_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_authorization_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_execution_authorization_surface_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
    if summary:
        _require_equal(
            "production_execution_authorization_summary_state",
            summary.get("state"),
            "production_execution_authorization_reviewed_no_runtime_execution",
            checks=checks,
            failures=failures,
        )
        _require_bool("production_execution_authorization_summary_execution_blocked", summary.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
        _require_bool("production_execution_authorization_summary_receipt_blocked", summary.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)
    if gaps:
        _require_bool("production_execution_authorization_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_execution_authorization") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_treat_authorization_review_as_runtime_execution_permission",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_execution_authorization_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _alignment_decision(passed: bool, upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> str:
    if not passed:
        return "blocked_before_runtime_production_goal_alignment"
    if upstream_decision == "production_execution_authorization_reviewed_no_runtime_execution" and summary and not gaps:
        return "production_goal_alignment_preserved_requires_executor_permission_layer"
    if upstream_decision == "production_execution_authorization_not_required_no_manifest_targets":
        return "production_goal_alignment_preserved_no_manifest_targets"
    return "production_goal_alignment_preserved_upstream_blocked"


def _allowed_scope(passed: bool, upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> str:
    if not passed:
        return "do not proceed until goal-alignment and upstream authorization boundaries are valid"
    if upstream_decision == "production_execution_authorization_reviewed_no_runtime_execution" and summary and not gaps:
        return "alignment preserved, but production executor permission must be a separate future gate"
    if upstream_decision == "production_execution_authorization_not_required_no_manifest_targets":
        return "alignment preserved with no production execution target"
    return "alignment preserved while upstream production execution authorization remains blocked"


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None
    return payload


def _record_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _record_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _require_equal(name: str, actual: object, expected: object, *, checks: dict[str, bool], failures: list[str]) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _resolve_path(path: Path | None, agent_root: Path) -> Path:
    assert path is not None
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-execution-authorization-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_goal_alignment_gate(
        production_execution_authorization_gate_path=Path(args.production_execution_authorization_gate),
        agent_root=agent_root,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())