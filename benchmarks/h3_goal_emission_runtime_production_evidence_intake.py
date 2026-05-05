"""H.3 runtime production evidence intake review gate.

This artifact-only layer reads production evidence request packets plus an
optional submitted evidence bundle. It checks whether the submission satisfies
the open requests, but it does not ingest evidence into runtime, start runtime,
write receipts, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    ACCEPTED_PRODUCTION_STATUSES,
    NON_PRODUCTION_SOURCE_TOKENS,
    PRODUCTION_EVIDENCE_COMMON_FIELDS,
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    PRODUCTION_EVIDENCE_SCHEMA_VERSION,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
)
from benchmarks.h3_goal_emission_runtime_production_evidence_request import (
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_REQUEST_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence-intake:v1"


def build_h3_goal_emission_runtime_production_evidence_intake(
    *,
    production_evidence_request_path: Path,
    agent_root: Path,
    production_evidence_submission_path: Path | None = None,
) -> dict[str, Any]:
    production_evidence_request_path = _resolve_path(production_evidence_request_path, agent_root)
    production_evidence_submission_path = (
        _resolve_path(production_evidence_submission_path, agent_root)
        if production_evidence_submission_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    request_bundle = _read_json(production_evidence_request_path, failures)

    request_readiness: dict[str, Any] = {}
    request_boundary: dict[str, Any] = {}
    request_packets: list[dict[str, Any]] = []
    closed_reviews: list[dict[str, Any]] = []
    if request_bundle is None:
        _fail(
            checks,
            failures,
            "production_evidence_request_present",
            f"missing H3 runtime production evidence request bundle: {production_evidence_request_path}",
        )
    else:
        checks["production_evidence_request_present"] = True
        _require_equal(
            "production_evidence_request_schema_version",
            request_bundle.get("schema_version"),
            PRODUCTION_EVIDENCE_REQUEST_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_evidence_request_passed", bool(request_bundle.get("passed")), checks=checks, failures=failures)
        request_readiness = _object(request_bundle.get("readiness"))
        _require_request_readiness(request_readiness, checks=checks, failures=failures)
        request_boundary = _object(request_bundle.get("runtime_production_evidence_request_boundary"))
        _require_request_boundary(request_boundary, checks=checks, failures=failures)
        surface = _object(request_bundle.get("runtime_production_evidence_request_surface"))
        _require_equal(
            "production_evidence_request_surface_mode",
            surface.get("mode"),
            "production_evidence_request_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        request_packets = _record_list(surface.get("production_evidence_request_packets"))
        closed_reviews = _record_list(surface.get("closed_production_evidence_reviews"))
        _require_request_packet_shape(request_packets, checks=checks, failures=failures)
        _require_closed_review_shape(closed_reviews, checks=checks, failures=failures)

    submission_records, submission_payload = _load_submission(production_evidence_submission_path, failures)
    if production_evidence_submission_path:
        checks["production_evidence_submission_present"] = submission_payload is not None
        if submission_payload is not None:
            _require_equal(
                "production_evidence_submission_schema_version",
                submission_payload.get("schema_version"),
                PRODUCTION_EVIDENCE_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool("production_evidence_submission_records_present", bool(submission_records), checks=checks, failures=failures)
            _require_submission_record_shape(submission_records, request_packets, checks=checks, failures=failures)
    else:
        checks["production_evidence_submission_optional_absent"] = True

    reviewed_packets: list[dict[str, Any]] = []
    intake_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        reviewed_packets, intake_gaps = _evaluate_submission(request_packets, submission_records)

    metrics = {
        "production_evidence_request_packet_count": len(request_packets),
        "closed_production_evidence_review_count": len(closed_reviews),
        "submitted_production_evidence_record_count": len(submission_records),
        "reviewed_production_evidence_intake_packet_count": len(reviewed_packets),
        "production_evidence_intake_gap_count": len(intake_gaps),
        "missing_production_evidence_item_count": sum(len(gap["missing_production_evidence_kinds"]) for gap in intake_gaps),
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _intake_decision(passed, request_packets, closed_reviews, submission_records, reviewed_packets, intake_gaps)
    submission_complete = passed and bool(reviewed_packets) and not intake_gaps
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_evidence_request_path": str(production_evidence_request_path),
        "production_evidence_submission_path": str(production_evidence_submission_path) if production_evidence_submission_path else None,
        "checks": checks,
        "readiness": {
            "production_evidence_intake_evaluated": passed,
            "production_evidence_submission_present": bool(submission_records),
            "production_evidence_submission_complete": submission_complete,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, request_packets, closed_reviews, submission_records, reviewed_packets, intake_gaps),
        },
        "runtime_production_evidence_intake_boundary": {
            "artifact_only": True,
            "production_evidence_submission_review_allowed": passed and bool(submission_records),
            "production_evidence_ingestion_allowed": False,
            "production_evidence_forwarding_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_evidence_intake_policy": {
            "request_schema": PRODUCTION_EVIDENCE_REQUEST_SCHEMA_VERSION,
            "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
            "common_required_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
            "kind_ref_fields": PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
            "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
            "forbidden_evidence_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "blocked_after_intake_review": [
                "production_evidence_intake_reviewed -> production_runtime_execution_allowed",
                "production_evidence_intake_reviewed -> production_runtime_receipt_written",
                "production_evidence_intake_reviewed -> external_system_mutation",
            ],
        },
        "runtime_production_evidence_intake_surface": {
            "mode": "production_evidence_intake_review_only_no_runtime",
            "reviewed_production_evidence_intake_packet_count": len(reviewed_packets),
            "reviewed_production_evidence_intake_packets": reviewed_packets,
            "production_evidence_intake_gap_count": len(intake_gaps),
            "production_evidence_intake_gaps": intake_gaps,
            "source_production_evidence_request_packets": request_packets,
            "source_closed_production_evidence_reviews": closed_reviews,
        },
        "metrics": metrics,
        "evidence": {
            "production_evidence_request_readiness": request_readiness,
            "production_evidence_request_boundary": request_boundary,
        },
        "non_claims": [
            "does_not_ingest_or_forward_production_evidence_to_runtime",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_complete_intake_review_as_runtime_execution_permission",
        ],
    }


def _require_request_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "production_evidence_request_open_local_controlled_not_production",
        "production_evidence_request_open",
        "production_evidence_request_closed_no_runtime_execution",
        "production_evidence_request_blocked_no_runtime_targets",
    }
    _require_bool("production_evidence_request_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_evidence_request_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_request_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_request_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_request_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_evidence_ingestion_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_evidence_request_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_request_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["production_evidence_request_packets_optional_or_present"] = True
        return
    _require_bool("production_evidence_request_packet_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_request_packet_state_valid", all(packet.get("state") == "production_evidence_request_open" for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_request_packet_submission_schema_valid", all(packet.get("submission_schema") == PRODUCTION_EVIDENCE_SCHEMA_VERSION for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_request_items_present", all(bool(_request_items(packet)) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_request_items_known", all(_request_items_known(packet) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_request_items_fields_valid", all(_request_item_fields_valid(packet) for packet in packets), checks=checks, failures=failures)


def _require_closed_review_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["closed_production_evidence_reviews_optional_or_present"] = True
        return
    _require_bool("closed_production_evidence_review_state_valid", all(packet.get("state") == "production_evidence_reviewed_no_runtime_execution" for packet in packets), checks=checks, failures=failures)
    _require_bool("closed_production_evidence_review_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)
    _require_bool("closed_production_evidence_review_runtime_blocked", all(_review_runtime_blocked(packet) for packet in packets), checks=checks, failures=failures)


def _require_submission_record_shape(
    records: list[dict[str, Any]],
    request_packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("production_evidence_submission_common_fields_present", all(_common_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_kind_known", all(record.get("evidence_kind") in REQUIRED_PRODUCTION_EVIDENCE_KINDS for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_kind_refs_present", all(_kind_ref_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_records_requested", all(_record_requested(record, request_packets) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_fields_match_request", all(_record_matches_request_fields(record, request_packets) for record in records), checks=checks, failures=failures)


def _evaluate_submission(
    request_packets: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not request_packets:
        return [], []
    records_by_goal_kind = {(str(record.get("goal_id") or ""), str(record.get("evidence_kind") or "")): record for record in records}
    reviewed: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for packet in request_packets:
        goal_id = str(packet.get("goal_id") or "")
        requested_kinds = [item["evidence_kind"] for item in _request_items(packet)]
        missing = [kind for kind in requested_kinds if (goal_id, kind) not in records_by_goal_kind]
        if missing:
            gaps.append(
                {
                    "goal_id": goal_id,
                    "state": "production_evidence_intake_gap",
                    "gap_reason": "missing requested production evidence submission records",
                    "missing_production_evidence_kinds": missing,
                    "request_packet_id": packet.get("request_packet_id"),
                }
            )
            continue
        reviewed.append(
            {
                "production_evidence_intake_packet_id": f"h3-runtime-production-evidence-intake:{goal_id}",
                "goal_id": goal_id,
                "state": "production_evidence_intake_reviewed_no_runtime_execution",
                "request_packet_id": packet.get("request_packet_id"),
                "production_evidence_refs": {kind: records_by_goal_kind[(goal_id, kind)]["artifact_id"] for kind in requested_kinds},
                "gate_status": {
                    "production_evidence_submission_complete": True,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                },
            }
        )
    return reviewed, gaps


def _intake_decision(
    passed: bool,
    request_packets: list[dict[str, Any]],
    closed_reviews: list[dict[str, Any]],
    records: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    intake_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_evidence_intake"
    if closed_reviews and not request_packets:
        return "production_evidence_intake_not_required_already_reviewed_no_runtime"
    if not request_packets:
        return "production_evidence_intake_not_required_no_runtime_targets"
    if not records:
        return "production_evidence_intake_blocked_pending_submission"
    if reviewed_packets and not intake_gaps:
        return "production_evidence_intake_reviewed_no_runtime_execution"
    return "production_evidence_intake_gap_detected"


def _allowed_scope(
    passed: bool,
    request_packets: list[dict[str, Any]],
    closed_reviews: list[dict[str, Any]],
    records: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    intake_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production evidence submissions until request and submission schemas are valid"
    if closed_reviews and not request_packets:
        return "upstream production evidence is already reviewed; runtime execution remains blocked"
    if not request_packets:
        return "no production evidence intake target is available"
    if not records:
        return "production evidence submission is still pending; runtime execution remains blocked"
    if reviewed_packets and not intake_gaps:
        return "production evidence submission reviewed only; runtime execution remains blocked"
    return "production evidence submission remains incomplete; runtime execution remains blocked"


def _request_items(packet: dict[str, Any]) -> list[dict[str, Any]]:
    return _record_list(packet.get("requested_evidence_items"))


def _request_items_known(packet: dict[str, Any]) -> bool:
    return all(item.get("evidence_kind") in REQUIRED_PRODUCTION_EVIDENCE_KINDS for item in _request_items(packet))


def _request_item_fields_valid(packet: dict[str, Any]) -> bool:
    for item in _request_items(packet):
        kind = str(item.get("evidence_kind") or "")
        if item.get("state") != "production_evidence_item_required":
            return False
        if item.get("required_common_fields") != PRODUCTION_EVIDENCE_COMMON_FIELDS:
            return False
        if item.get("required_kind_ref_field") != PRODUCTION_EVIDENCE_KIND_REF_FIELDS.get(kind):
            return False
    return True


def _review_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return (
        gate_status.get("production_runtime_execution_ready") is False
        and gate_status.get("production_runtime_receipt_ready") is False
    )


def _common_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_EVIDENCE_COMMON_FIELDS)


def _kind_ref_present(record: dict[str, Any]) -> bool:
    ref_field = PRODUCTION_EVIDENCE_KIND_REF_FIELDS.get(str(record.get("evidence_kind") or ""))
    return bool(ref_field and record.get(ref_field))


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


def _record_requested(record: dict[str, Any], request_packets: list[dict[str, Any]]) -> bool:
    goal_id = str(record.get("goal_id") or "")
    kind = str(record.get("evidence_kind") or "")
    return any(str(packet.get("goal_id") or "") == goal_id and kind in _packet_requested_kinds(packet) for packet in request_packets)


def _record_matches_request_fields(record: dict[str, Any], request_packets: list[dict[str, Any]]) -> bool:
    goal_id = str(record.get("goal_id") or "")
    kind = str(record.get("evidence_kind") or "")
    for packet in request_packets:
        if str(packet.get("goal_id") or "") != goal_id:
            continue
        for item in _request_items(packet):
            if item.get("evidence_kind") == kind:
                common_fields = [str(field) for field in item.get("required_common_fields", [])]
                ref_field = str(item.get("required_kind_ref_field") or "")
                statuses = {str(status) for status in item.get("accepted_statuses", [])}
                return (
                    all(bool(record.get(field)) for field in common_fields)
                    and bool(ref_field and record.get(ref_field))
                    and str(record.get("status") or "") in statuses
                    and not _non_production_source(record)
                )
    return False


def _packet_requested_kinds(packet: dict[str, Any]) -> set[str]:
    return {str(item.get("evidence_kind") or "") for item in _request_items(packet)}


def _load_submission(path: Path | None, failures: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if path is None:
        return [], None
    payload = _read_json(path, failures)
    if payload is None:
        return [], None
    return _record_list(payload.get("production_evidence_records") or payload.get("records")), payload


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
    parser.add_argument("--production-evidence-request", required=True)
    parser.add_argument("--production-evidence-submission", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_evidence_intake(
        production_evidence_request_path=Path(args.production_evidence_request),
        agent_root=agent_root,
        production_evidence_submission_path=Path(args.production_evidence_submission) if args.production_evidence_submission else None,
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