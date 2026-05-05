"""H.3 production runtime actuation gate.

This artifact-only layer reads the production runtime execution gate and an
optional production runtime actuation artifact. It ensures runtime actuation
cannot be reviewed until production runtime execution has been independently
reviewed. It does not start runtime, write production receipts, call LLMs, or
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import NON_PRODUCTION_SOURCE_TOKENS
from benchmarks.h3_goal_emission_runtime_production_runtime_execution_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-actuation-gate:v1"
PRODUCTION_RUNTIME_ACTUATION_SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-actuation:v1"
ACCEPTED_PRODUCTION_RUNTIME_ACTUATION_STATUSES = frozenset({"approved", "actuation_ready", "green", "ready"})
PRODUCTION_RUNTIME_ACTUATION_REQUIRED_FIELDS = [
    "actuation_id",
    "goal_id",
    "runtime_executor",
    "runtime_executor_role",
    "source",
    "status",
    "attestation_ref",
    "runtime_execution_ref",
    "runtime_execution_sha256",
    "deployment_environment_ref",
    "operator_console_ref",
    "process_supervisor_ref",
    "start_command_ref",
    "kill_switch_ref",
    "rollback_checkpoint_ref",
    "audit_sink_ref",
    "receipt_sink_ref",
]


def build_h3_goal_emission_runtime_production_runtime_actuation_gate(
    *,
    production_runtime_execution_gate_path: Path,
    agent_root: Path,
    production_runtime_actuation_path: Path | None = None,
) -> dict[str, Any]:
    production_runtime_execution_gate_path = _resolve_path(production_runtime_execution_gate_path, agent_root)
    production_runtime_actuation_path = (
        _resolve_path(production_runtime_actuation_path, agent_root)
        if production_runtime_actuation_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution_gate_report = _read_json(production_runtime_execution_gate_path, failures)

    execution_readiness: dict[str, Any] = {}
    execution_boundary: dict[str, Any] = {}
    execution_gaps: list[dict[str, Any]] = []
    execution_summary: dict[str, Any] = {}
    if execution_gate_report is None:
        _fail(
            checks,
            failures,
            "production_runtime_execution_gate_present",
            f"missing H3 production runtime execution gate: {production_runtime_execution_gate_path}",
        )
    else:
        checks["production_runtime_execution_gate_present"] = True
        _require_equal(
            "production_runtime_execution_gate_schema_version",
            execution_gate_report.get("schema_version"),
            PRODUCTION_RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_execution_gate_passed", bool(execution_gate_report.get("passed")), checks=checks, failures=failures)
        execution_readiness = _object(execution_gate_report.get("readiness"))
        _require_execution_readiness(execution_readiness, checks=checks, failures=failures)
        execution_boundary = _object(execution_gate_report.get("runtime_production_execution_boundary"))
        _require_execution_boundary(execution_boundary, checks=checks, failures=failures)
        execution_surface = _object(execution_gate_report.get("runtime_production_execution_surface"))
        _require_equal(
            "production_runtime_execution_surface_mode",
            execution_surface.get("mode"),
            "production_runtime_execution_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        execution_gaps = _record_list(execution_surface.get("production_runtime_execution_gaps"))
        execution_summary = _object(execution_surface.get("production_runtime_execution_summary"))
        _require_execution_surface(execution_summary, execution_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(execution_gate_report.get("non_claims")), checks=checks, failures=failures)

    upstream_decision = str(execution_readiness.get("decision") or "")
    execution_reviewed = _execution_reviewed(upstream_decision, execution_summary, execution_gaps)
    execution_targets_present = bool(execution_summary or execution_gaps)
    actuation_records: list[dict[str, Any]] = []
    actuation_payload: dict[str, Any] | None = None
    actuation_sha256 = ""
    if production_runtime_actuation_path:
        actuation_payload, actuation_sha256 = _read_json_with_sha256(production_runtime_actuation_path, failures)
        checks["production_runtime_actuation_artifact_present"] = actuation_payload is not None
        if actuation_payload is not None:
            _require_bool("production_runtime_actuation_requires_execution_review", execution_reviewed, checks=checks, failures=failures)
            _require_equal(
                "production_runtime_actuation_schema_version",
                actuation_payload.get("schema_version"),
                PRODUCTION_RUNTIME_ACTUATION_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            actuation_records = _record_list(actuation_payload.get("production_runtime_actuation_records") or actuation_payload.get("actuation_records") or actuation_payload.get("records"))
            _require_bool("production_runtime_actuation_records_present", bool(actuation_records), checks=checks, failures=failures)
            _require_actuation_record_shape(actuation_records, execution_summary, checks=checks, failures=failures)
    else:
        checks["production_runtime_actuation_optional_absent"] = True

    actuation_summary: dict[str, Any] = {}
    actuation_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        actuation_summary, actuation_gaps = _build_actuation_summary(
            actuation_path=production_runtime_actuation_path,
            actuation_sha256=actuation_sha256,
            execution_reviewed=execution_reviewed,
            execution_summary=execution_summary,
            execution_gaps=execution_gaps,
            actuation_records=actuation_records,
        )

    metrics = {
        "production_runtime_execution_gap_count": len(execution_gaps),
        "production_runtime_execution_reviewed_count": int(bool(execution_summary)),
        "production_runtime_actuation_record_count": len(actuation_records),
        "production_runtime_actuation_gap_count": len(actuation_gaps),
        "production_runtime_actuation_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_actuation_not_started_by_gate", metrics["production_runtime_actuation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _actuation_decision(
        passed=passed,
        execution_targets_present=execution_targets_present,
        execution_reviewed=execution_reviewed,
        actuation_path_present=bool(production_runtime_actuation_path),
        actuation_summary=actuation_summary,
        actuation_gaps=actuation_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_runtime_execution_gate_path": str(production_runtime_execution_gate_path),
        "production_runtime_actuation_path": str(production_runtime_actuation_path) if production_runtime_actuation_path else None,
        "checks": checks,
        "readiness": {
            "production_runtime_actuation_evaluated": passed,
            "production_runtime_actuation_artifact_present": passed and bool(actuation_summary),
            "production_runtime_actuation_artifact_complete": passed and bool(actuation_summary) and not actuation_gaps,
            "production_runtime_actuation_ready": False,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "upstream_runtime_execution_decision": upstream_decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                execution_targets_present=execution_targets_present,
                execution_reviewed=execution_reviewed,
                actuation_path_present=bool(production_runtime_actuation_path),
                actuation_summary=actuation_summary,
                actuation_gaps=actuation_gaps,
            ),
        },
        "runtime_production_actuation_boundary": {
            "artifact_only": True,
            "production_runtime_actuation_review_allowed": passed,
            "production_runtime_actuation_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_actuation_policy": {
            "runtime_execution_gate_schema": PRODUCTION_RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
            "runtime_actuation_schema": PRODUCTION_RUNTIME_ACTUATION_SCHEMA_VERSION,
            "required_runtime_actuation_fields": PRODUCTION_RUNTIME_ACTUATION_REQUIRED_FIELDS,
            "accepted_runtime_actuation_statuses": sorted(ACCEPTED_PRODUCTION_RUNTIME_ACTUATION_STATUSES),
            "forbidden_runtime_actuation_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_runtime_execution_decision": "production_runtime_execution_reviewed_no_runtime_start",
            "blocked_after_runtime_actuation_review": [
                "runtime_actuation_reviewed -> runtime_started_by_this_gate",
                "runtime_actuation_reviewed -> production_runtime_execution_receipt_written",
                "runtime_actuation_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_actuation_surface": {
            "mode": "production_runtime_actuation_review_only_no_runtime",
            "production_runtime_actuation_summary": actuation_summary,
            "production_runtime_actuation_gap_count": len(actuation_gaps),
            "production_runtime_actuation_gaps": actuation_gaps,
            "source_runtime_execution_decision": upstream_decision,
            "source_production_runtime_execution_summary": execution_summary,
            "source_production_runtime_execution_gaps": execution_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_runtime_execution_readiness": execution_readiness,
            "production_runtime_execution_boundary": execution_boundary,
        },
        "non_claims": [
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_actuation_review_as_runtime_start",
        ],
    }


def _require_execution_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_runtime_execution",
        "production_runtime_execution_not_required_no_handoff_targets",
        "production_runtime_execution_blocked_upstream_handoff",
        "production_runtime_execution_blocked_pending_execution_artifact",
        "production_runtime_execution_gap_detected",
        "production_runtime_execution_reviewed_no_runtime_start",
    }
    _require_bool("production_runtime_execution_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_execution_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_runtime_execution_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_execution_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
    if summary:
        _require_equal(
            "production_runtime_execution_summary_state",
            summary.get("state"),
            "production_runtime_execution_reviewed_no_runtime_start",
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_execution_summary_execution_blocked", summary.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
        _require_bool("production_runtime_execution_summary_receipt_blocked", summary.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)
    if gaps:
        _require_bool("production_runtime_execution_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_runtime_execution") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_treat_runtime_execution_review_as_runtime_start",
        "does_not_start_runtime_or_agent_loop",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_runtime_execution_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _require_actuation_record_shape(records: list[dict[str, Any]], execution_summary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_actuation_common_fields_present", all(_actuation_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_RUNTIME_ACTUATION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_runtime_actuation") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_record_runtime_flags_blocked", all(record.get("production_runtime_actuation_allowed") is not True and record.get("production_runtime_execution_allowed") is not True and record.get("production_runtime_receipt_allowed") is not True and record.get("agent_loop_start_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_records_match_execution_goals", all(_record_matches_execution_goal(record, execution_summary) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_records_match_execution_sha256", all(str(record.get("runtime_execution_sha256") or "") == str(execution_summary.get("execution_sha256") or "") for record in records), checks=checks, failures=failures)


def _build_actuation_summary(
    *,
    actuation_path: Path | None,
    actuation_sha256: str,
    execution_reviewed: bool,
    execution_summary: dict[str, Any],
    execution_gaps: list[dict[str, Any]],
    actuation_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not execution_reviewed:
        return {}, _execution_blocking_gaps(execution_gaps)
    if actuation_path is None:
        return {}, _actuation_missing_gaps(execution_summary, actuation_records, "production runtime actuation artifact is absent")
    missing_gaps = _actuation_missing_gaps(execution_summary, actuation_records, "submitted runtime actuation artifact is missing execution goal actuation")
    actuation_goal_ids = sorted({str(record.get("goal_id") or "") for record in actuation_records if record.get("goal_id")})
    summary = {
        "state": "production_runtime_actuation_reviewed_no_runtime_start",
        "actuation_path": str(actuation_path),
        "actuation_sha256": actuation_sha256,
        "actuation_schema_version": PRODUCTION_RUNTIME_ACTUATION_SCHEMA_VERSION,
        "actuation_record_count": len(actuation_records),
        "actuation_goal_ids": actuation_goal_ids,
        "actuation_refs": [str(record.get("actuation_id") or "") for record in actuation_records],
        "source_runtime_execution_sha256": str(execution_summary.get("execution_sha256") or ""),
        "production_runtime_actuation_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return summary, missing_gaps


def _actuation_decision(
    *,
    passed: bool,
    execution_targets_present: bool,
    execution_reviewed: bool,
    actuation_path_present: bool,
    actuation_summary: dict[str, Any],
    actuation_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_runtime_actuation"
    if not execution_targets_present:
        return "production_runtime_actuation_not_required_no_execution_targets"
    if not execution_reviewed:
        return "production_runtime_actuation_blocked_upstream_execution"
    if not actuation_path_present:
        return "production_runtime_actuation_blocked_pending_actuation_artifact"
    if actuation_summary and actuation_gaps:
        return "production_runtime_actuation_gap_detected"
    return "production_runtime_actuation_reviewed_no_runtime_start"


def _allowed_scope(
    *,
    passed: bool,
    execution_targets_present: bool,
    execution_reviewed: bool,
    actuation_path_present: bool,
    actuation_summary: dict[str, Any],
    actuation_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production runtime actuation until execution and actuation schemas are valid"
    if not execution_targets_present:
        return "no production runtime actuation target is available"
    if not execution_reviewed:
        return "runtime execution is not reviewed; runtime actuation remains blocked"
    if not actuation_path_present:
        return "runtime execution is reviewed, but runtime actuation artifact is absent; runtime start remains blocked"
    if actuation_summary and actuation_gaps:
        return "runtime actuation artifact has missing execution goal actuations; runtime start remains blocked"
    return "runtime actuation reviewed only; this gate still does not start runtime"


def _execution_reviewed(upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return upstream_decision == "production_runtime_execution_reviewed_no_runtime_start" and bool(summary) and not gaps


def _execution_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_runtime_actuation_blocked_by_execution_gap",
            "gap_reason": "production runtime execution has not been reviewed",
            "source_execution_gap_reason": gap.get("gap_reason"),
        }
        for gap in gaps
    ]


def _actuation_missing_gaps(summary: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    execution_goal_ids = [str(goal_id) for goal_id in summary.get("execution_goal_ids") or [] if goal_id]
    actuation_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in execution_goal_ids if goal_id not in actuation_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_runtime_actuation_gap",
            "gap_reason": reason,
            "missing_actuation_goal_ids": missing_goal_ids,
            "source_runtime_execution_sha256": summary.get("execution_sha256"),
        }
    ]


def _actuation_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_RUNTIME_ACTUATION_REQUIRED_FIELDS)


def _record_matches_execution_goal(record: dict[str, Any], summary: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in summary.get("execution_goal_ids") or []}


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


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


def _read_json_with_sha256(path: Path, failures: list[str]) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None, ""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None, digest
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None, digest
    return payload, digest


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
    parser.add_argument("--production-runtime-execution-gate", required=True)
    parser.add_argument("--production-runtime-actuation", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_runtime_actuation_gate(
        production_runtime_execution_gate_path=Path(args.production_runtime_execution_gate),
        agent_root=agent_root,
        production_runtime_actuation_path=Path(args.production_runtime_actuation) if args.production_runtime_actuation else None,
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