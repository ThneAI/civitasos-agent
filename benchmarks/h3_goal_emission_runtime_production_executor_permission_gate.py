"""H.3 runtime production executor permission gate.

This artifact-only layer reads the production goal-alignment gate and an
optional production executor permission artifact. It verifies that executor
permission cannot be reviewed until production evidence, authorization, and
goal alignment have all reached the explicit permission handoff state. It does
not grant runtime execution, write receipts, call LLMs, or mutate IEM/value
state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import NON_PRODUCTION_SOURCE_TOKENS
from benchmarks.h3_goal_emission_runtime_production_goal_alignment_gate import (
    NORTH_STAR_VALUES,
    SCHEMA_VERSION as PRODUCTION_GOAL_ALIGNMENT_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-executor-permission-gate:v1"
PRODUCTION_EXECUTOR_PERMISSION_SCHEMA_VERSION = "h3-goal-emission-runtime-production-executor-permission:v1"
ACCEPTED_PRODUCTION_EXECUTOR_PERMISSION_STATUSES = frozenset({"approved", "permitted", "green", "ready"})
PRODUCTION_EXECUTOR_PERMISSION_REQUIRED_FIELDS = [
    "permission_id",
    "goal_id",
    "executor",
    "executor_role",
    "source",
    "status",
    "attestation_ref",
    "authorization_ref",
    "authorization_sha256",
    "goal_alignment_ref",
    "goal_alignment_sha256",
    "change_ticket_ref",
    "dual_operator_ack_ref",
    "kill_switch_ref",
    "rollback_checkpoint_ref",
    "monitoring_green_ref",
    "audit_sink_ref",
    "execution_window_ref",
]


def build_h3_goal_emission_runtime_production_executor_permission_gate(
    *,
    production_goal_alignment_gate_path: Path,
    agent_root: Path,
    production_executor_permission_path: Path | None = None,
) -> dict[str, Any]:
    production_goal_alignment_gate_path = _resolve_path(production_goal_alignment_gate_path, agent_root)
    production_executor_permission_path = (
        _resolve_path(production_executor_permission_path, agent_root)
        if production_executor_permission_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    goal_alignment_report, goal_alignment_sha256 = _read_json_with_sha256(production_goal_alignment_gate_path, failures)

    goal_alignment_readiness: dict[str, Any] = {}
    goal_alignment_boundary: dict[str, Any] = {}
    goal_alignment_surface: dict[str, Any] = {}
    goal_alignment_gaps: list[dict[str, Any]] = []
    authorization_summary: dict[str, Any] = {}
    if goal_alignment_report is None:
        _fail(
            checks,
            failures,
            "production_goal_alignment_gate_present",
            f"missing H3 runtime production goal alignment gate: {production_goal_alignment_gate_path}",
        )
    else:
        checks["production_goal_alignment_gate_present"] = True
        _require_equal(
            "production_goal_alignment_gate_schema_version",
            goal_alignment_report.get("schema_version"),
            PRODUCTION_GOAL_ALIGNMENT_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_goal_alignment_gate_passed", bool(goal_alignment_report.get("passed")), checks=checks, failures=failures)
        goal_alignment_readiness = _object(goal_alignment_report.get("readiness"))
        _require_goal_alignment_readiness(goal_alignment_readiness, checks=checks, failures=failures)
        goal_alignment_boundary = _object(goal_alignment_report.get("runtime_production_goal_alignment_boundary"))
        _require_goal_alignment_boundary(goal_alignment_boundary, checks=checks, failures=failures)
        goal_alignment_policy = _object(goal_alignment_report.get("runtime_production_goal_alignment_policy"))
        _require_goal_alignment_policy(goal_alignment_policy, checks=checks, failures=failures)
        goal_alignment_surface = _object(goal_alignment_report.get("runtime_production_goal_alignment_surface"))
        _require_equal(
            "production_goal_alignment_surface_mode",
            goal_alignment_surface.get("mode"),
            "production_goal_alignment_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        goal_alignment_gaps = _record_list(goal_alignment_surface.get("source_production_execution_authorization_gaps"))
        authorization_summary = _object(goal_alignment_surface.get("source_production_execution_authorization_summary"))
        _require_goal_alignment_surface(authorization_summary, goal_alignment_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(goal_alignment_report.get("non_claims")), checks=checks, failures=failures)

    upstream_decision = str(goal_alignment_readiness.get("decision") or "")
    alignment_requires_permission = _alignment_requires_permission(upstream_decision, authorization_summary, goal_alignment_gaps)
    alignment_targets_present = bool(authorization_summary or goal_alignment_gaps)
    permission_records: list[dict[str, Any]] = []
    permission_payload: dict[str, Any] | None = None
    permission_sha256 = ""
    if production_executor_permission_path:
        permission_payload, permission_sha256 = _read_json_with_sha256(production_executor_permission_path, failures)
        checks["production_executor_permission_artifact_present"] = permission_payload is not None
        if permission_payload is not None:
            _require_bool("production_executor_permission_requires_goal_alignment_handoff", alignment_requires_permission, checks=checks, failures=failures)
            _require_equal(
                "production_executor_permission_schema_version",
                permission_payload.get("schema_version"),
                PRODUCTION_EXECUTOR_PERMISSION_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            permission_records = _record_list(permission_payload.get("production_executor_permission_records") or permission_payload.get("permission_records") or permission_payload.get("records"))
            _require_bool("production_executor_permission_records_present", bool(permission_records), checks=checks, failures=failures)
            _require_permission_record_shape(
                permission_records,
                authorization_summary,
                goal_alignment_sha256,
                checks=checks,
                failures=failures,
            )
    else:
        checks["production_executor_permission_optional_absent"] = True

    permission_summary: dict[str, Any] = {}
    permission_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        permission_summary, permission_gaps = _build_permission_summary(
            permission_path=production_executor_permission_path,
            permission_sha256=permission_sha256,
            goal_alignment_path=production_goal_alignment_gate_path,
            goal_alignment_sha256=goal_alignment_sha256,
            alignment_requires_permission=alignment_requires_permission,
            authorization_summary=authorization_summary,
            goal_alignment_gaps=goal_alignment_gaps,
            permission_records=permission_records,
        )

    metrics = {
        "production_goal_alignment_gap_count": len(goal_alignment_gaps),
        "production_goal_alignment_reviewed_authorization_count": int(bool(authorization_summary)),
        "production_executor_permission_record_count": len(permission_records),
        "production_executor_permission_gap_count": len(permission_gaps),
        "production_executor_permission_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_executor_permission_not_granted_by_gate", metrics["production_executor_permission_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _permission_decision(
        passed=passed,
        alignment_targets_present=alignment_targets_present,
        alignment_requires_permission=alignment_requires_permission,
        permission_path_present=bool(production_executor_permission_path),
        permission_summary=permission_summary,
        permission_gaps=permission_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_goal_alignment_gate_path": str(production_goal_alignment_gate_path),
        "production_executor_permission_path": str(production_executor_permission_path) if production_executor_permission_path else None,
        "checks": checks,
        "readiness": {
            "production_executor_permission_evaluated": passed,
            "production_executor_permission_present": passed and bool(permission_summary),
            "production_executor_permission_complete": passed and bool(permission_summary) and not permission_gaps,
            "production_executor_permission_ready": False,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "upstream_goal_alignment_decision": upstream_decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                alignment_targets_present=alignment_targets_present,
                alignment_requires_permission=alignment_requires_permission,
                permission_path_present=bool(production_executor_permission_path),
                permission_summary=permission_summary,
                permission_gaps=permission_gaps,
            ),
        },
        "runtime_production_executor_permission_boundary": {
            "artifact_only": True,
            "production_executor_permission_review_allowed": passed,
            "production_executor_permission_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_executor_permission_policy": {
            "goal_alignment_schema": PRODUCTION_GOAL_ALIGNMENT_GATE_SCHEMA_VERSION,
            "executor_permission_schema": PRODUCTION_EXECUTOR_PERMISSION_SCHEMA_VERSION,
            "required_executor_permission_fields": PRODUCTION_EXECUTOR_PERMISSION_REQUIRED_FIELDS,
            "accepted_executor_permission_statuses": sorted(ACCEPTED_PRODUCTION_EXECUTOR_PERMISSION_STATUSES),
            "forbidden_executor_permission_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_goal_alignment_decision": "production_goal_alignment_preserved_requires_executor_permission_layer",
            "blocked_after_executor_permission_review": [
                "executor_permission_reviewed -> runtime_started_by_this_gate",
                "executor_permission_reviewed -> production_runtime_execution_receipt_written",
                "executor_permission_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_executor_permission_surface": {
            "mode": "production_executor_permission_review_only_no_runtime",
            "production_executor_permission_summary": permission_summary,
            "production_executor_permission_gap_count": len(permission_gaps),
            "production_executor_permission_gaps": permission_gaps,
            "source_goal_alignment_decision": upstream_decision,
            "source_production_execution_authorization_summary": authorization_summary,
            "source_production_execution_authorization_gaps": goal_alignment_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_goal_alignment_readiness": goal_alignment_readiness,
            "production_goal_alignment_boundary": goal_alignment_boundary,
        },
        "non_claims": [
            "does_not_grant_production_executor_permission",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_executor_permission_review_as_runtime_execution_permission",
        ],
    }


def _require_goal_alignment_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_goal_alignment",
        "production_goal_alignment_preserved_requires_executor_permission_layer",
        "production_goal_alignment_preserved_no_manifest_targets",
        "production_goal_alignment_preserved_upstream_blocked",
    }
    _require_bool("production_goal_alignment_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_goal_alignment_executor_permission_blocked", readiness.get("production_executor_permission_ready") is False, checks=checks, failures=failures)
    _require_bool("production_goal_alignment_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_goal_alignment_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_goal_alignment_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_goal_alignment_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_executor_permission_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_goal_alignment_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_goal_alignment_policy(policy: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    values = set(_record_text_list(policy.get("north_star_values")))
    _require_bool("production_goal_alignment_north_star_values_preserved", set(NORTH_STAR_VALUES).issubset(values), checks=checks, failures=failures)
    blocked_vectors = set(_record_text_list(policy.get("blocked_drift_vectors")))
    _require_bool("production_goal_alignment_executor_permission_drift_blocked", "authorization_review -> executor_permission" in blocked_vectors, checks=checks, failures=failures)


def _require_goal_alignment_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_goal_alignment_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
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
        _require_bool("production_goal_alignment_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_execution_authorization") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_grant_production_executor_permission",
        "does_not_treat_goal_alignment_as_runtime_execution_permission",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_goal_alignment_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _require_permission_record_shape(records: list[dict[str, Any]], authorization_summary: dict[str, Any], goal_alignment_sha256: str, *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_executor_permission_common_fields_present", all(_permission_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_EXECUTOR_PERMISSION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_executor_permission") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_record_runtime_flags_blocked", all(record.get("production_executor_permission_allowed") is not True and record.get("production_runtime_execution_allowed") is not True and record.get("production_runtime_receipt_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_records_match_authorized_goals", all(_record_matches_authorized_goal(record, authorization_summary) for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_records_match_authorization_sha256", all(str(record.get("authorization_sha256") or "") == str(authorization_summary.get("authorization_sha256") or "") for record in records), checks=checks, failures=failures)
    _require_bool("production_executor_permission_records_match_goal_alignment_sha256", all(str(record.get("goal_alignment_sha256") or "") == goal_alignment_sha256 for record in records), checks=checks, failures=failures)


def _build_permission_summary(
    *,
    permission_path: Path | None,
    permission_sha256: str,
    goal_alignment_path: Path,
    goal_alignment_sha256: str,
    alignment_requires_permission: bool,
    authorization_summary: dict[str, Any],
    goal_alignment_gaps: list[dict[str, Any]],
    permission_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not alignment_requires_permission:
        return {}, _goal_alignment_blocking_gaps(goal_alignment_gaps)
    if permission_path is None:
        return {}, _permission_missing_gaps(authorization_summary, permission_records, "production executor permission artifact is absent")
    missing_gaps = _permission_missing_gaps(authorization_summary, permission_records, "submitted executor permission artifact is missing authorized goal permission")
    permitted_goal_ids = sorted({str(record.get("goal_id") or "") for record in permission_records if record.get("goal_id")})
    summary = {
        "state": "production_executor_permission_reviewed_no_runtime_execution",
        "permission_path": str(permission_path),
        "permission_sha256": permission_sha256,
        "permission_schema_version": PRODUCTION_EXECUTOR_PERMISSION_SCHEMA_VERSION,
        "permission_record_count": len(permission_records),
        "permitted_goal_ids": permitted_goal_ids,
        "permission_refs": [str(record.get("permission_id") or "") for record in permission_records],
        "source_goal_alignment_path": str(goal_alignment_path),
        "source_goal_alignment_sha256": goal_alignment_sha256,
        "source_authorization_sha256": str(authorization_summary.get("authorization_sha256") or ""),
        "production_executor_permission_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return summary, missing_gaps


def _permission_decision(
    *,
    passed: bool,
    alignment_targets_present: bool,
    alignment_requires_permission: bool,
    permission_path_present: bool,
    permission_summary: dict[str, Any],
    permission_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_executor_permission"
    if not alignment_targets_present:
        return "production_executor_permission_not_required_no_alignment_targets"
    if not alignment_requires_permission:
        return "production_executor_permission_blocked_upstream_goal_alignment"
    if not permission_path_present:
        return "production_executor_permission_blocked_pending_permission_artifact"
    if permission_summary and permission_gaps:
        return "production_executor_permission_gap_detected"
    return "production_executor_permission_reviewed_no_runtime_execution"


def _allowed_scope(
    *,
    passed: bool,
    alignment_targets_present: bool,
    alignment_requires_permission: bool,
    permission_path_present: bool,
    permission_summary: dict[str, Any],
    permission_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production executor permission until goal-alignment and permission schemas are valid"
    if not alignment_targets_present:
        return "no production executor permission target is available"
    if not alignment_requires_permission:
        return "goal alignment has not reached executor permission handoff; runtime execution remains blocked"
    if not permission_path_present:
        return "goal alignment handoff is present, but executor permission artifact is absent; runtime execution remains blocked"
    if permission_summary and permission_gaps:
        return "executor permission artifact has missing authorized goal permissions; runtime execution remains blocked"
    return "executor permission reviewed only; runtime execution remains blocked"


def _alignment_requires_permission(upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return upstream_decision == "production_goal_alignment_preserved_requires_executor_permission_layer" and bool(summary) and not gaps


def _goal_alignment_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_executor_permission_blocked_by_goal_alignment_gap",
            "gap_reason": "production goal alignment has not reached executor permission handoff",
            "source_authorization_gap_reason": gap.get("gap_reason"),
        }
        for gap in gaps
    ]


def _permission_missing_gaps(summary: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    authorized_goal_ids = [str(goal_id) for goal_id in summary.get("authorized_goal_ids") or [] if goal_id]
    permitted_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in authorized_goal_ids if goal_id not in permitted_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_executor_permission_gap",
            "gap_reason": reason,
            "missing_permission_goal_ids": missing_goal_ids,
            "source_authorization_sha256": summary.get("authorization_sha256"),
        }
    ]


def _permission_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_EXECUTOR_PERMISSION_REQUIRED_FIELDS)


def _record_matches_authorized_goal(record: dict[str, Any], summary: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in summary.get("authorized_goal_ids") or []}


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


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
    parser.add_argument("--production-goal-alignment-gate", required=True)
    parser.add_argument("--production-executor-permission", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_executor_permission_gate(
        production_goal_alignment_gate_path=Path(args.production_goal_alignment_gate),
        agent_root=agent_root,
        production_executor_permission_path=Path(args.production_executor_permission) if args.production_executor_permission else None,
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