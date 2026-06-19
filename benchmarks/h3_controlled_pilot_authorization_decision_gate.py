"""Record one-time H.3 controlled-pilot authorization decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_evidence import (
    artifact_ref,
    object_value,
    objects_value,
    read_json_object,
    resolve_under_root,
    sha256_file,
    write_json_object,
)
from benchmarks.h3_controlled_pilot_receipts import (
    AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
)
from benchmarks.h3_controlled_pilot_authorization_request_gate import (
    BOUNDARY as REQUEST_BOUNDARY,
)
from benchmarks.h3_controlled_pilot_authorization_request_gate import (
    SCHEMA_VERSION as REQUEST_SCHEMA_VERSION,
)


PACKET_SCHEMA_VERSION = "h3-controlled-pilot-authorization-decision-packet:v1"
RECONCILIATION_SCHEMA_VERSION = (
    "h3-controlled-pilot-authorization-decision-reconciliation:v1"
)
ALLOWED_DECISIONS = {"authorize_once", "reject", "request_revision"}
BOUNDARY = {
    "artifact_only": True,
    "authorization_decision_recording_allowed": True,
    "authorization_receipt_generation_allowed": True,
    "authorization_mutation_allowed": False,
    "controlled_pilot_execution_allowed": False,
    "goal_emission_allowed": False,
    "executable_plan_allowed": False,
    "runtime_execution_allowed": False,
    "llm_planning_allowed": False,
    "agent_dispatch_allowed": False,
    "external_side_effect_allowed": False,
    "iem_mutation_allowed": False,
    "relation_mutation_allowed": False,
    "normative_local_mutation_allowed": False,
    "production_transition_allowed": False,
}
CONTROL_FIELDS = (
    "preflight_ref",
    "kill_switch_ref",
    "rollback_checkpoint_ref",
    "post_run_receipt_sink_ref",
)


def create_authorization_decision_packet(
    *,
    authorization_request_report_path: Path,
    output_path: Path,
    agent_root: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    source_path = resolve_under_root(authorization_request_report_path, agent_root)
    output = resolve_under_root(output_path, agent_root)
    if output.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite authorization packet: {output}")

    failures: list[str] = []
    source = read_json_object(source_path, failures, "authorization request report")
    requests = _validate_request_report(source, failures=failures)
    if failures:
        raise ValueError(f"cannot create authorization packet: {failures}")

    profile = str(source.get("validation_profile") or "qualification")
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "state": "authorization_decisions_pending",
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": profile == "qualification",
        "source_authorization_request_report": artifact_ref(source_path),
        "request_count": len(requests),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "decisions": [_pending_decision(request) for request in requests],
        "boundary": dict(BOUNDARY),
        "non_claims": _non_claims(profile=profile),
    }
    write_json_object(output, packet)
    return packet


def record_authorization_decision(
    *,
    decision_packet_path: Path,
    agent_root: Path,
    request_id: str,
    decision: str,
    operator_id: str,
    reason: str,
    monitoring_owner_id: str | None = None,
    audit_owner_id: str | None = None,
    valid_for_seconds: int | None = None,
    preflight_ref: str | None = None,
    kill_switch_ref: str | None = None,
    rollback_checkpoint_ref: str | None = None,
    post_run_receipt_sink_ref: str | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    packet_path = resolve_under_root(decision_packet_path, agent_root)
    failures: list[str] = []
    packet = read_json_object(packet_path, failures, "authorization decision packet")
    if packet is None or failures:
        raise ValueError(f"cannot record authorization decision: {failures}")
    if packet.get("schema_version") != PACKET_SCHEMA_VERSION:
        raise ValueError("authorization decision packet schema mismatch")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"unsupported authorization decision: {decision}")
    if not operator_id.strip():
        raise ValueError("operator id is required")
    if len(reason.strip()) < 8:
        raise ValueError("authorization reason must contain at least 8 characters")

    matches = [
        item
        for item in objects_value(packet.get("decisions"))
        if item.get("request_id") == request_id
    ]
    if len(matches) != 1:
        raise ValueError("authorization decision slot not found or duplicated")
    item = matches[0]
    if item.get("decision") != "pending":
        raise FileExistsError("authorization decision is already completed")

    now = _as_utc(current_time or datetime.now(timezone.utc))
    controls = {field: None for field in CONTROL_FIELDS}
    valid_from = None
    valid_until = None
    if decision == "authorize_once":
        max_seconds = _integer(
            object_value(item.get("requested_scope")).get("max_duration_seconds")
        )
        duration = _integer(valid_for_seconds)
        if duration < 1 or duration > max_seconds:
            raise ValueError(
                f"authorization duration must be between 1 and {max_seconds} seconds"
            )
        owners = {
            "monitoring_owner_id": str(monitoring_owner_id or "").strip(),
            "audit_owner_id": str(audit_owner_id or "").strip(),
        }
        if not all(owners.values()):
            raise ValueError("monitoring owner and audit owner are required")
        controls = {
            "preflight_ref": str(preflight_ref or "").strip(),
            "kill_switch_ref": str(kill_switch_ref or "").strip(),
            "rollback_checkpoint_ref": str(rollback_checkpoint_ref or "").strip(),
            "post_run_receipt_sink_ref": str(
                post_run_receipt_sink_ref or ""
            ).strip(),
        }
        if not all(controls.values()):
            raise ValueError("all controlled-pilot control refs are required")
        valid_from = now.isoformat()
        valid_until = (now + timedelta(seconds=duration)).isoformat()
    else:
        owners = {
            "monitoring_owner_id": None,
            "audit_owner_id": None,
        }
        if any(
            value not in (None, "")
            for value in (
                monitoring_owner_id,
                audit_owner_id,
                valid_for_seconds,
                preflight_ref,
                kill_switch_ref,
                rollback_checkpoint_ref,
                post_run_receipt_sink_ref,
            )
        ):
            raise ValueError("authorization controls are only valid for authorize_once")

    item.update(
        {
            "decision": decision,
            "operator_id": operator_id.strip(),
            "reason": reason.strip(),
            "decided_at": now.isoformat(),
            "monitoring_owner_id": owners["monitoring_owner_id"],
            "audit_owner_id": owners["audit_owner_id"],
            "valid_from": valid_from,
            "valid_until": valid_until,
            "controls": controls,
        }
    )
    _write_json_atomic(packet_path, packet)
    return {
        "schema_version": "h3-controlled-pilot-authorization-decision-record:v1",
        "recorded": True,
        "packet_path": str(packet_path),
        "request_id": request_id,
        "decision": decision,
        "operator_id": operator_id.strip(),
        "decided_at": now.isoformat(),
        "packet_sha256": sha256_file(packet_path),
        "controlled_pilot_execution_allowed": False,
    }


def reconcile_authorization_decisions(
    *,
    authorization_request_report_path: Path,
    decision_packet_path: Path,
    output_path: Path,
    agent_root: Path,
    current_time: datetime | None = None,
    max_future_skew_seconds: float = 300.0,
) -> dict[str, Any]:
    source_path = resolve_under_root(authorization_request_report_path, agent_root)
    packet_path = resolve_under_root(decision_packet_path, agent_root)
    output = resolve_under_root(output_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    source = read_json_object(source_path, failures, "authorization request report")
    packet = read_json_object(packet_path, failures, "authorization decision packet")
    requests = _validate_request_report(source, failures=failures, checks=checks)
    decisions = _validate_decision_packet(
        packet,
        source_path=source_path,
        requests=requests,
        failures=failures,
        checks=checks,
        current_time=_as_utc(current_time or datetime.now(timezone.utc)),
        max_future_skew_seconds=max_future_skew_seconds,
    )
    profile = str(object_value(source).get("validation_profile") or "qualification")
    pending_ids = sorted(
        str(item.get("request_id") or "")
        for item in decisions
        if item.get("decision") == "pending"
    )
    _require(checks, failures, "authorization_decisions_complete", not pending_ids)

    passed = not failures and all(checks.values())
    authorized = (
        [_build_receipt(item, packet_path) for item in decisions if item["decision"] == "authorize_once"]
        if passed
        else []
    )
    rejected = sorted(
        str(item.get("request_id") or "")
        for item in decisions
        if item.get("decision") == "reject"
    )
    revisions = sorted(
        str(item.get("request_id") or "")
        for item in decisions
        if item.get("decision") == "request_revision"
    )
    ready = passed and bool(authorized)
    report = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": profile == "qualification",
        "source_authorization_request_report": (
            artifact_ref(source_path) if source_path.is_file() else None
        ),
        "source_decision_packet": (
            artifact_ref(packet_path) if packet_path.is_file() else None
        ),
        "decision_summary": {
            "request_count": len(requests),
            "decision_count": len(decisions),
            "authorized_once_count": len(authorized),
            "rejected_count": len(rejected),
            "revision_requested_count": len(revisions),
            "pending_count": len(pending_ids),
        },
        "authorization_receipts": authorized,
        "blocked_request_ids": sorted(rejected + revisions + pending_ids),
        "readiness": {
            "authorization_decision_complete": passed,
            "one_time_authorization_receipts_ready": ready,
            "controlled_pilot_execution_preflight_input_ready": ready,
            "controlled_pilot_execution_ready": False,
            "decision": (
                "h3_one_time_authorization_receipts_ready_for_execution_preflight"
                if ready
                else "h3_authorization_decisions_complete_without_authorized_requests"
                if passed
                else "blocked_h3_controlled_pilot_authorization_decision_gate"
            ),
            "next_action": (
                "run a separate A7 execution preflight; do not dispatch agents yet"
                if ready
                else "repair or complete authorization decisions"
            ),
        },
        "boundary": dict(BOUNDARY),
        "non_claims": _non_claims(profile=profile),
    }
    write_json_object(output, report)
    return report


def authorization_decision_status(
    *,
    decision_packet_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    packet_path = resolve_under_root(decision_packet_path, agent_root)
    failures: list[str] = []
    packet = read_json_object(packet_path, failures, "authorization decision packet") or {}
    decisions = objects_value(packet.get("decisions"))
    pending = [
        str(item.get("request_id") or "")
        for item in decisions
        if item.get("decision") == "pending"
    ]
    return {
        "schema_version": "h3-controlled-pilot-authorization-decision-status:v1",
        "packet_path": str(packet_path),
        "packet_present": packet_path.is_file(),
        "packet_schema_valid": packet.get("schema_version") == PACKET_SCHEMA_VERSION,
        "validation_profile": packet.get("validation_profile"),
        "request_count": len(decisions),
        "completed_count": len(decisions) - len(pending),
        "pending_count": len(pending),
        "pending_request_ids": pending,
        "failures": failures,
    }


def _validate_request_report(
    value: dict[str, Any] | None,
    *,
    failures: list[str],
    checks: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    checks = checks if checks is not None else {}
    if value is None:
        _require(checks, failures, "authorization_request_report_present", False)
        return []
    checks["authorization_request_report_present"] = True
    _require_equal(
        checks,
        failures,
        "authorization_request_report_schema",
        value.get("schema_version"),
        REQUEST_SCHEMA_VERSION,
    )
    _require(checks, failures, "authorization_request_report_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "authorization_request_report_boundary",
        value.get("boundary"),
        REQUEST_BOUNDARY,
    )
    profile = str(value.get("validation_profile") or "qualification")
    _require(
        checks,
        failures,
        "authorization_request_profile_supported",
        profile in {"development", "qualification"},
    )
    _require_equal(
        checks,
        failures,
        "authorization_request_development_flag",
        value.get("development_only"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "authorization_request_qualification_flag",
        value.get("valid_for_qualification"),
        profile == "qualification",
    )
    readiness = object_value(value.get("readiness"))
    _require(
        checks,
        failures,
        "authorization_requests_ready_for_review",
        readiness.get("authorization_requests_ready_for_review") is True
        and readiness.get("authorization_granted") is False
        and readiness.get("controlled_pilot_execution_ready") is False,
    )
    surface = object_value(value.get("authorization_request_surface"))
    requests = objects_value(surface.get("requests"))
    request_ids = [str(item.get("request_id") or "") for item in requests]
    _require(checks, failures, "authorization_requests_present", bool(requests))
    _require_equal(
        checks,
        failures,
        "authorization_request_count_consistent",
        surface.get("request_count"),
        len(requests),
    )
    _require(
        checks,
        failures,
        "authorization_request_ids_unique",
        all(request_ids) and len(request_ids) == len(set(request_ids)),
    )
    _require(
        checks,
        failures,
        "authorization_request_contracts_valid",
        all(_valid_request(item, profile) for item in requests),
    )
    return requests


def _valid_request(item: dict[str, Any], profile: str) -> bool:
    controls = object_value(item.get("requested_controls"))
    scope = object_value(item.get("requested_scope"))
    state = (
        "development_authorization_request_review_required"
        if profile == "development"
        else "controlled_pilot_authorization_request_review_required"
    )
    return (
        item.get("state") == state
        and item.get("validation_profile") == profile
        and item.get("development_only") is (profile == "development")
        and item.get("valid_for_qualification") is (profile == "qualification")
        and scope.get("production_use_allowed") is False
        and scope.get("automatic_rollout_allowed") is False
        and _integer(scope.get("max_tasks")) >= 1
        and _integer(scope.get("max_agents")) >= 1
        and _integer(scope.get("max_duration_seconds")) >= 1
        and all(controls.get(name) is True for name in (
            "one_time_authorization_required",
            "authorization_expiry_required",
            "named_operator_required",
            "named_monitoring_owner_required",
            "named_audit_owner_required",
            "kill_switch_required",
            "rollback_checkpoint_required",
            "preflight_required",
            "post_run_receipt_required",
        ))
        and controls.get("automatic_approval_allowed") is False
        and object_value(item.get("authorization_state")).get("authorization_granted")
        is False
        and object_value(item.get("authorization_state")).get("execution_allowed")
        is False
    )


def _validate_decision_packet(
    value: dict[str, Any] | None,
    *,
    source_path: Path,
    requests: list[dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
    current_time: datetime,
    max_future_skew_seconds: float,
) -> list[dict[str, Any]]:
    if value is None:
        _require(checks, failures, "authorization_decision_packet_present", False)
        return []
    checks["authorization_decision_packet_present"] = True
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_schema",
        value.get("schema_version"),
        PACKET_SCHEMA_VERSION,
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_state",
        value.get("state"),
        "authorization_decisions_pending",
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_source_binding",
        value.get("source_authorization_request_report"),
        artifact_ref(source_path) if source_path.is_file() else None,
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_boundary",
        value.get("boundary"),
        BOUNDARY,
    )
    profile = str(value.get("validation_profile") or "qualification")
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_non_claims",
        value.get("non_claims"),
        _non_claims(profile=profile),
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_allowed_decisions",
        value.get("allowed_decisions"),
        sorted(ALLOWED_DECISIONS),
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_development_flag",
        value.get("development_only"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "authorization_decision_qualification_flag",
        value.get("valid_for_qualification"),
        profile == "qualification",
    )

    decisions = objects_value(value.get("decisions"))
    request_by_id = {str(item["request_id"]): item for item in requests}
    decision_ids = [str(item.get("request_id") or "") for item in decisions]
    _require_equal(
        checks,
        failures,
        "authorization_decision_request_count",
        value.get("request_count"),
        len(requests),
    )
    _require(
        checks,
        failures,
        "authorization_decision_partition_complete",
        len(decision_ids) == len(set(decision_ids))
        and set(decision_ids) == set(request_by_id),
    )
    _require(
        checks,
        failures,
        "authorization_decision_records_valid",
        all(
            _valid_decision(
                item,
                request=request_by_id.get(str(item.get("request_id") or "")),
                current_time=current_time,
                max_future_skew_seconds=max_future_skew_seconds,
            )
            for item in decisions
        ),
    )
    return decisions


def _valid_decision(
    item: dict[str, Any],
    *,
    request: dict[str, Any] | None,
    current_time: datetime,
    max_future_skew_seconds: float,
) -> bool:
    if request is None:
        return False
    if item.get("request_sha256") != _canonical_sha256(request):
        return False
    if item.get("requested_scope") != request.get("requested_scope"):
        return False
    decision = str(item.get("decision") or "")
    if decision == "pending":
        return _pending_fields_empty(item)
    if decision not in ALLOWED_DECISIONS:
        return False
    decided_at = _timestamp(item.get("decided_at"))
    if (
        not str(item.get("operator_id") or "").strip()
        or len(str(item.get("reason") or "").strip()) < 8
        or decided_at is None
        or decided_at > current_time + timedelta(seconds=max_future_skew_seconds)
    ):
        return False
    if decision != "authorize_once":
        return _non_authorization_fields_empty(item)

    valid_from = _timestamp(item.get("valid_from"))
    valid_until = _timestamp(item.get("valid_until"))
    max_duration = _integer(
        object_value(request.get("requested_scope")).get("max_duration_seconds")
    )
    controls = object_value(item.get("controls"))
    return (
        bool(str(item.get("monitoring_owner_id") or "").strip())
        and bool(str(item.get("audit_owner_id") or "").strip())
        and valid_from == decided_at
        and valid_until is not None
        and 0 < (valid_until - valid_from).total_seconds() <= max_duration
        and all(bool(str(controls.get(field) or "").strip()) for field in CONTROL_FIELDS)
    )


def _pending_decision(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": request["request_id"],
        "request_sha256": _canonical_sha256(request),
        "requested_scope": request["requested_scope"],
        "decision": "pending",
        "operator_id": "",
        "reason": "",
        "decided_at": "",
        "monitoring_owner_id": None,
        "audit_owner_id": None,
        "valid_from": None,
        "valid_until": None,
        "controls": {field: None for field in CONTROL_FIELDS},
    }


def _build_receipt(item: dict[str, Any], packet_path: Path) -> dict[str, Any]:
    seed = {
        "request_id": item["request_id"],
        "request_sha256": item["request_sha256"],
        "decision_packet_sha256": sha256_file(packet_path),
        "decided_at": item["decided_at"],
    }
    return {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
        "authorization_receipt_id": (
            f"h3-one-time-authorization:{_canonical_sha256(seed)[:20]}"
        ),
        "state": "one_time_authorization_granted_pending_execution_preflight",
        "request_id": item["request_id"],
        "request_sha256": item["request_sha256"],
        "decision_packet_sha256": sha256_file(packet_path),
        "authorized_scope": item["requested_scope"],
        "operator_id": item["operator_id"],
        "monitoring_owner_id": item["monitoring_owner_id"],
        "audit_owner_id": item["audit_owner_id"],
        "valid_from": item["valid_from"],
        "valid_until": item["valid_until"],
        "controls": item["controls"],
        "single_use": True,
        "consumed": False,
        "controlled_pilot_execution_allowed": False,
    }


def _pending_fields_empty(item: dict[str, Any]) -> bool:
    return (
        item.get("operator_id") == ""
        and item.get("reason") == ""
        and item.get("decided_at") == ""
        and _non_authorization_fields_empty(item)
    )


def _non_authorization_fields_empty(item: dict[str, Any]) -> bool:
    controls = object_value(item.get("controls"))
    return (
        item.get("monitoring_owner_id") is None
        and item.get("audit_owner_id") is None
        and item.get("valid_from") is None
        and item.get("valid_until") is None
        and all(controls.get(field) is None for field in CONTROL_FIELDS)
    )


def _non_claims(*, profile: str) -> list[str]:
    claims = [
        "authorization_receipt_is_not_an_execution_receipt",
        "authorization_receipt_requires_a_separate_execution_preflight",
        "authorization_decision_does_not_dispatch_agents_or_start_runtime",
        "authorization_decision_does_not_create_external_side_effects",
        "authorization_decision_does_not_mutate_iem_relation_or_normative_state",
        "authorization_decision_does_not_authorize_production_transition",
    ]
    claims.append(
        "development_authorization_is_not_qualification_evidence"
        if profile == "development"
        else "qualification_authorization_requires_qualification_execution_preflight"
    )
    return claims


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return value.astimezone(timezone.utc)

def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    condition: bool,
) -> None:
    checks[name] = bool(condition)
    if not condition:
        failures.append(name)


def _require_equal(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    actual: Any,
    expected: Any,
) -> None:
    condition = actual == expected
    checks[name] = condition
    if not condition:
        failures.append(f"{name}: expected {expected!r}, got {actual!r}")

def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    write_json_object(temporary, value)
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a pending decision packet")
    init.add_argument("--authorization-request-report", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--overwrite", action="store_true")

    status = commands.add_parser("status", help="show pending decisions")
    status.add_argument("--decision-packet", type=Path, required=True)

    record = commands.add_parser("record", help="record one operator decision")
    record.add_argument("--decision-packet", type=Path, required=True)
    record.add_argument("--request-id", required=True)
    record.add_argument("--decision", choices=sorted(ALLOWED_DECISIONS), required=True)
    record.add_argument("--operator-id", required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--monitoring-owner-id")
    record.add_argument("--audit-owner-id")
    record.add_argument("--valid-for-seconds", type=int)
    record.add_argument("--preflight-ref")
    record.add_argument("--kill-switch-ref")
    record.add_argument("--rollback-checkpoint-ref")
    record.add_argument("--post-run-receipt-sink-ref")

    reconcile = commands.add_parser("reconcile", help="validate completed decisions")
    reconcile.add_argument("--authorization-request-report", type=Path, required=True)
    reconcile.add_argument("--decision-packet", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    reconcile.add_argument("--max-future-skew-seconds", type=float, default=300.0)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    if args.command == "init":
        report = create_authorization_decision_packet(
            authorization_request_report_path=args.authorization_request_report,
            output_path=args.output,
            agent_root=agent_root,
            overwrite=args.overwrite,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if args.command == "status":
        report = authorization_decision_status(
            decision_packet_path=args.decision_packet,
            agent_root=agent_root,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if args.command == "record":
        report = record_authorization_decision(
            decision_packet_path=args.decision_packet,
            agent_root=agent_root,
            request_id=args.request_id,
            decision=args.decision,
            operator_id=args.operator_id,
            reason=args.reason,
            monitoring_owner_id=args.monitoring_owner_id,
            audit_owner_id=args.audit_owner_id,
            valid_for_seconds=args.valid_for_seconds,
            preflight_ref=args.preflight_ref,
            kill_switch_ref=args.kill_switch_ref,
            rollback_checkpoint_ref=args.rollback_checkpoint_ref,
            post_run_receipt_sink_ref=args.post_run_receipt_sink_ref,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return

    report = reconcile_authorization_decisions(
        authorization_request_report_path=args.authorization_request_report,
        decision_packet_path=args.decision_packet,
        output_path=args.output,
        agent_root=agent_root,
        max_future_skew_seconds=args.max_future_skew_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
