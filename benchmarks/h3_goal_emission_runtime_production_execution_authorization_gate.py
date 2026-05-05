"""H.3 runtime production execution authorization gate.

This artifact-only layer reads a production evidence submission manifest and an
optional production execution authorization artifact. It checks that production
evidence submission is complete before authorization can be reviewed, and that
authorization records are independent, production-sourced, and tied to the
manifest hash. It does not grant runtime execution, write receipts, call LLMs,
or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import NON_PRODUCTION_SOURCE_TOKENS
from benchmarks.h3_goal_emission_runtime_production_evidence_submission_manifest import (
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-execution-authorization-gate:v1"
PRODUCTION_EXECUTION_AUTHORIZATION_SCHEMA_VERSION = "h3-goal-emission-runtime-production-execution-authorization:v1"
ACCEPTED_PRODUCTION_EXECUTION_AUTHORIZATION_STATUSES = frozenset({"approved", "authorized", "green", "ready"})
PRODUCTION_EXECUTION_AUTHORIZATION_REQUIRED_FIELDS = [
    "authorization_id",
    "goal_id",
    "authorizer",
    "authorizer_role",
    "source",
    "status",
    "attestation_ref",
    "manifest_ref",
    "manifest_sha256",
    "change_ticket_ref",
    "dual_operator_ack_ref",
    "kill_switch_ref",
    "rollback_checkpoint_ref",
    "monitoring_green_ref",
    "audit_sink_ref",
]


def build_h3_goal_emission_runtime_production_execution_authorization_gate(
    *,
    production_evidence_submission_manifest_path: Path,
    agent_root: Path,
    production_execution_authorization_path: Path | None = None,
) -> dict[str, Any]:
    production_evidence_submission_manifest_path = _resolve_path(production_evidence_submission_manifest_path, agent_root)
    production_execution_authorization_path = (
        _resolve_path(production_execution_authorization_path, agent_root)
        if production_execution_authorization_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    submission_manifest_report = _read_json(production_evidence_submission_manifest_path, failures)

    submission_manifest_readiness: dict[str, Any] = {}
    submission_manifest_boundary: dict[str, Any] = {}
    source_submission_manifest: dict[str, Any] = {}
    source_submission_manifest_gaps: list[dict[str, Any]] = []
    if submission_manifest_report is None:
        _fail(
            checks,
            failures,
            "production_evidence_submission_manifest_present",
            f"missing H3 runtime production evidence submission manifest: {production_evidence_submission_manifest_path}",
        )
    else:
        checks["production_evidence_submission_manifest_present"] = True
        _require_equal(
            "production_evidence_submission_manifest_schema_version",
            submission_manifest_report.get("schema_version"),
            PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_evidence_submission_manifest_passed", bool(submission_manifest_report.get("passed")), checks=checks, failures=failures)
        submission_manifest_readiness = _object(submission_manifest_report.get("readiness"))
        _require_submission_manifest_readiness(submission_manifest_readiness, checks=checks, failures=failures)
        submission_manifest_boundary = _object(submission_manifest_report.get("runtime_production_evidence_submission_manifest_boundary"))
        _require_submission_manifest_boundary(submission_manifest_boundary, checks=checks, failures=failures)
        surface = _object(submission_manifest_report.get("runtime_production_evidence_submission_manifest_surface"))
        _require_equal(
            "production_evidence_submission_manifest_surface_mode",
            surface.get("mode"),
            "production_evidence_submission_manifest_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        source_submission_manifest = _object(surface.get("production_evidence_submission_manifest"))
        source_submission_manifest_gaps = _record_list(surface.get("production_evidence_submission_manifest_gaps"))
        _require_submission_manifest_surface(source_submission_manifest, source_submission_manifest_gaps, checks=checks, failures=failures)

    submission_manifest_complete = _submission_manifest_complete(source_submission_manifest, source_submission_manifest_gaps)
    submission_manifest_targets_present = bool(source_submission_manifest or source_submission_manifest_gaps)
    authorization_records: list[dict[str, Any]] = []
    authorization_payload: dict[str, Any] | None = None
    authorization_sha256 = ""
    if production_execution_authorization_path:
        authorization_payload, authorization_sha256 = _read_json_with_sha256(production_execution_authorization_path, failures)
        checks["production_execution_authorization_artifact_present"] = authorization_payload is not None
        if authorization_payload is not None:
            _require_bool("production_execution_authorization_requires_complete_manifest", submission_manifest_complete, checks=checks, failures=failures)
            _require_equal(
                "production_execution_authorization_schema_version",
                authorization_payload.get("schema_version"),
                PRODUCTION_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            authorization_records = _record_list(authorization_payload.get("production_execution_authorization_records") or authorization_payload.get("authorization_records") or authorization_payload.get("records"))
            _require_bool("production_execution_authorization_records_present", bool(authorization_records), checks=checks, failures=failures)
            _require_authorization_record_shape(authorization_records, source_submission_manifest, checks=checks, failures=failures)
    else:
        checks["production_execution_authorization_optional_absent"] = True

    authorization_summary: dict[str, Any] = {}
    authorization_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        authorization_summary, authorization_gaps = _build_authorization_summary(
            authorization_path=production_execution_authorization_path,
            authorization_sha256=authorization_sha256,
            source_submission_manifest=source_submission_manifest,
            source_submission_manifest_gaps=source_submission_manifest_gaps,
            authorization_records=authorization_records,
        )

    metrics = {
        "production_evidence_submission_manifest_present_count": 1 if source_submission_manifest else 0,
        "production_evidence_submission_manifest_gap_count": len(source_submission_manifest_gaps),
        "submitted_production_evidence_record_count": int(source_submission_manifest.get("submitted_record_count") or 0),
        "production_execution_authorization_record_count": len(authorization_records),
        "production_execution_authorization_gap_count": len(authorization_gaps),
        "authorized_goal_count": len(authorization_summary.get("authorized_goal_ids") or []),
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _authorization_decision(
        passed=passed,
        submission_manifest_targets_present=submission_manifest_targets_present,
        submission_manifest_complete=submission_manifest_complete,
        source_submission_manifest=source_submission_manifest,
        authorization_path_present=bool(production_execution_authorization_path),
        authorization_summary=authorization_summary,
        authorization_gaps=authorization_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_evidence_submission_manifest_path": str(production_evidence_submission_manifest_path),
        "production_execution_authorization_path": str(production_execution_authorization_path) if production_execution_authorization_path else None,
        "checks": checks,
        "readiness": {
            "production_execution_authorization_evaluated": passed,
            "production_execution_authorization_present": passed and bool(authorization_summary),
            "production_execution_authorization_complete": passed and bool(authorization_summary) and not authorization_gaps and submission_manifest_complete,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                submission_manifest_targets_present=submission_manifest_targets_present,
                submission_manifest_complete=submission_manifest_complete,
                source_submission_manifest=source_submission_manifest,
                authorization_path_present=bool(production_execution_authorization_path),
                authorization_summary=authorization_summary,
                authorization_gaps=authorization_gaps,
            ),
        },
        "runtime_production_execution_authorization_boundary": {
            "artifact_only": True,
            "production_execution_authorization_review_allowed": passed,
            "production_execution_authorization_runtime_permission_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_execution_authorization_policy": {
            "submission_manifest_schema": PRODUCTION_EVIDENCE_SUBMISSION_MANIFEST_SCHEMA_VERSION,
            "authorization_schema": PRODUCTION_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
            "required_authorization_fields": PRODUCTION_EXECUTION_AUTHORIZATION_REQUIRED_FIELDS,
            "accepted_authorization_statuses": sorted(ACCEPTED_PRODUCTION_EXECUTION_AUTHORIZATION_STATUSES),
            "forbidden_authorization_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "blocked_after_authorization_review": [
                "production_execution_authorization_reviewed -> runtime_started_by_this_gate",
                "production_execution_authorization_reviewed -> production_runtime_execution_receipt_written",
                "production_execution_authorization_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_execution_authorization_surface": {
            "mode": "production_execution_authorization_review_only_no_runtime",
            "production_execution_authorization_summary": authorization_summary,
            "production_execution_authorization_gap_count": len(authorization_gaps),
            "production_execution_authorization_gaps": authorization_gaps,
            "source_production_evidence_submission_manifest": source_submission_manifest,
            "source_production_evidence_submission_manifest_gaps": source_submission_manifest_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_evidence_submission_manifest_readiness": submission_manifest_readiness,
            "production_evidence_submission_manifest_boundary": submission_manifest_boundary,
        },
        "non_claims": [
            "does_not_validate_evidence_truth_or_attestation_authenticity",
            "does_not_ingest_or_forward_production_evidence_to_runtime",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_authorization_review_as_runtime_execution_permission",
        ],
    }


def _require_submission_manifest_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "production_evidence_submission_manifest_not_required_no_template_targets",
        "production_evidence_submission_manifest_blocked_pending_submission",
        "production_evidence_submission_manifest_gap_detected",
        "production_evidence_submission_manifest_reviewed_no_runtime_execution",
    }
    _require_bool("production_evidence_submission_manifest_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_evidence_submission_manifest_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_submission_manifest_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_submission_manifest_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_submission_manifest_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_evidence_truth_validation_allowed",
        "valid_production_evidence_record_generation_allowed",
        "production_evidence_ingestion_allowed",
        "production_evidence_forwarding_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_evidence_submission_manifest_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_submission_manifest_surface(manifest: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_submission_manifest_gaps_state_valid", all(gap.get("state") == "production_evidence_submission_manifest_gap" for gap in gaps), checks=checks, failures=failures)
    if not manifest:
        checks["production_evidence_submission_manifest_optional_absent_or_pending"] = True
        return
    required_fields = [
        "state",
        "submission_path",
        "submission_sha256",
        "submission_schema_version",
        "submitted_record_count",
        "submitted_goal_ids",
        "submitted_evidence_kinds",
    ]
    _require_bool("production_evidence_submission_manifest_required_fields_present", all(bool(manifest.get(field)) for field in required_fields), checks=checks, failures=failures)
    _require_equal(
        "production_evidence_submission_manifest_state_reviewed_no_runtime",
        manifest.get("state"),
        "production_evidence_submission_manifest_reviewed_no_runtime_execution",
        checks=checks,
        failures=failures,
    )
    _require_bool("production_evidence_submission_manifest_sha256_shape", _sha256_shape(manifest.get("submission_sha256")), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_manifest_runtime_blocked", manifest.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_submission_manifest_receipt_blocked", manifest.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_authorization_record_shape(records: list[dict[str, Any]], manifest: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_execution_authorization_common_fields_present", all(_authorization_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_EXECUTION_AUTHORIZATION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_execution_authorization") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_record_runtime_flags_blocked", all(record.get("production_runtime_execution_allowed") is not True and record.get("production_runtime_receipt_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_records_match_manifest_goals", all(_record_matches_manifest_goal(record, manifest) for record in records), checks=checks, failures=failures)
    _require_bool("production_execution_authorization_records_match_manifest_sha256", all(str(record.get("manifest_sha256") or "") == str(manifest.get("submission_sha256") or "") for record in records), checks=checks, failures=failures)


def _build_authorization_summary(
    *,
    authorization_path: Path | None,
    authorization_sha256: str,
    source_submission_manifest: dict[str, Any],
    source_submission_manifest_gaps: list[dict[str, Any]],
    authorization_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not _submission_manifest_complete(source_submission_manifest, source_submission_manifest_gaps):
        return {}, _submission_manifest_blocking_gaps(source_submission_manifest_gaps)
    if authorization_path is None:
        return {}, _authorization_missing_gaps(source_submission_manifest, authorization_records, "production execution authorization artifact is absent")
    missing_gaps = _authorization_missing_gaps(source_submission_manifest, authorization_records, "submitted authorization artifact is missing manifest goal authorization")
    authorized_goal_ids = sorted({str(record.get("goal_id") or "") for record in authorization_records if record.get("goal_id")})
    summary = {
        "state": "production_execution_authorization_reviewed_no_runtime_execution",
        "authorization_path": str(authorization_path),
        "authorization_sha256": authorization_sha256,
        "authorization_schema_version": PRODUCTION_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        "authorization_record_count": len(authorization_records),
        "authorized_goal_ids": authorized_goal_ids,
        "authorization_refs": [str(record.get("authorization_id") or "") for record in authorization_records],
        "source_manifest_sha256": str(source_submission_manifest.get("submission_sha256") or ""),
        "source_manifest_submission_path": str(source_submission_manifest.get("submission_path") or ""),
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return summary, missing_gaps


def _authorization_decision(
    *,
    passed: bool,
    submission_manifest_targets_present: bool,
    submission_manifest_complete: bool,
    source_submission_manifest: dict[str, Any],
    authorization_path_present: bool,
    authorization_summary: dict[str, Any],
    authorization_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_execution_authorization"
    if not submission_manifest_targets_present:
        return "production_execution_authorization_not_required_no_manifest_targets"
    if not submission_manifest_complete:
        if source_submission_manifest:
            return "production_execution_authorization_blocked_manifest_gaps"
        return "production_execution_authorization_blocked_pending_submission_manifest"
    if not authorization_path_present:
        return "production_execution_authorization_blocked_pending_authorization_artifact"
    if authorization_summary and authorization_gaps:
        return "production_execution_authorization_gap_detected"
    return "production_execution_authorization_reviewed_no_runtime_execution"


def _allowed_scope(
    *,
    passed: bool,
    submission_manifest_targets_present: bool,
    submission_manifest_complete: bool,
    source_submission_manifest: dict[str, Any],
    authorization_path_present: bool,
    authorization_summary: dict[str, Any],
    authorization_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production execution authorization until manifest and authorization schemas are valid"
    if not submission_manifest_targets_present:
        return "no production execution authorization target is available"
    if not submission_manifest_complete:
        if source_submission_manifest:
            return "submission manifest still has missing production evidence; runtime execution remains blocked"
        return "submission manifest is pending real production evidence; runtime execution remains blocked"
    if not authorization_path_present:
        return "submission manifest is complete, but independent execution authorization is absent; runtime execution remains blocked"
    if authorization_summary and authorization_gaps:
        return "execution authorization artifact has missing manifest goal authorizations; runtime execution remains blocked"
    return "execution authorization reviewed only; runtime execution remains blocked"


def _submission_manifest_complete(manifest: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return bool(manifest) and not gaps and manifest.get("state") == "production_evidence_submission_manifest_reviewed_no_runtime_execution" and bool(manifest.get("submission_sha256"))


def _submission_manifest_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_execution_authorization_blocked_by_submission_manifest_gap",
            "gap_reason": "production evidence submission manifest is incomplete",
            "missing_production_evidence_kinds": gap.get("missing_production_evidence_kinds") or [],
        }
        for gap in gaps
    ]


def _authorization_missing_gaps(manifest: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    manifest_goal_ids = [str(goal_id) for goal_id in manifest.get("submitted_goal_ids") or [] if goal_id]
    authorized_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in manifest_goal_ids if goal_id not in authorized_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_execution_authorization_gap",
            "gap_reason": reason,
            "missing_authorization_goal_ids": missing_goal_ids,
            "source_manifest_sha256": manifest.get("submission_sha256"),
        }
    ]


def _authorization_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_EXECUTION_AUTHORIZATION_REQUIRED_FIELDS)


def _record_matches_manifest_goal(record: dict[str, Any], manifest: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in manifest.get("submitted_goal_ids") or []}


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


def _sha256_shape(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


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
    parser.add_argument("--production-evidence-submission-manifest", required=True)
    parser.add_argument("--production-execution-authorization", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_execution_authorization_gate(
        production_evidence_submission_manifest_path=Path(args.production_evidence_submission_manifest),
        agent_root=agent_root,
        production_execution_authorization_path=Path(args.production_execution_authorization) if args.production_execution_authorization else None,
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