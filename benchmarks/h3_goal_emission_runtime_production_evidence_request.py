"""H.3 runtime production evidence request bundle.

This artifact-only layer reads the production evidence gap gate output and turns
open gaps into concrete evidence request packets. It does not collect evidence,
start runtime, write receipts, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import (
    ACCEPTED_PRODUCTION_STATUSES,
    NON_PRODUCTION_SOURCE_TOKENS,
    PRODUCTION_EVIDENCE_COMMON_FIELDS,
    PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
    PRODUCTION_EVIDENCE_SCHEMA_VERSION,
    REQUIRED_PRODUCTION_EVIDENCE_KINDS,
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence-request:v1"


def build_h3_goal_emission_runtime_production_evidence_request(
    *,
    production_evidence_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    production_evidence_gate_path = _resolve_path(production_evidence_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    evidence_gate = _read_json(production_evidence_gate_path, failures)

    readiness: dict[str, Any] = {}
    boundary: dict[str, Any] = {}
    evidence_gaps: list[dict[str, Any]] = []
    reviewed_packets: list[dict[str, Any]] = []
    if evidence_gate is None:
        _fail(
            checks,
            failures,
            "production_evidence_gate_present",
            f"missing H3 runtime production evidence gate: {production_evidence_gate_path}",
        )
    else:
        checks["production_evidence_gate_present"] = True
        _require_equal(
            "production_evidence_gate_schema_version",
            evidence_gate.get("schema_version"),
            PRODUCTION_EVIDENCE_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_evidence_gate_passed", bool(evidence_gate.get("passed")), checks=checks, failures=failures)
        readiness = _object(evidence_gate.get("readiness"))
        _require_gate_readiness(readiness, checks=checks, failures=failures)
        boundary = _object(evidence_gate.get("runtime_production_evidence_boundary"))
        _require_gate_boundary(boundary, checks=checks, failures=failures)
        surface = _object(evidence_gate.get("runtime_production_evidence_surface"))
        _require_equal(
            "production_evidence_surface_mode",
            surface.get("mode"),
            "production_evidence_gap_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        evidence_gaps = _record_list(surface.get("production_evidence_gaps"))
        reviewed_packets = _record_list(surface.get("reviewed_production_evidence_packets"))
        _require_gap_shape(evidence_gaps, checks=checks, failures=failures)
        _require_reviewed_packet_shape(reviewed_packets, checks=checks, failures=failures)

    request_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        request_packets = [_request_packet(gap) for gap in evidence_gaps]

    requested_item_count = sum(len(packet["requested_evidence_items"]) for packet in request_packets)
    metrics = {
        "production_evidence_gap_count": len(evidence_gaps),
        "production_evidence_request_packet_count": len(request_packets),
        "requested_production_evidence_item_count": requested_item_count,
        "closed_production_evidence_review_count": len(reviewed_packets),
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
    decision = _request_decision(passed, request_packets, reviewed_packets, readiness)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_evidence_gate_path": str(production_evidence_gate_path),
        "checks": checks,
        "readiness": {
            "production_evidence_request_evaluated": passed,
            "production_evidence_requests_open": passed and bool(request_packets),
            "production_evidence_review_complete_without_runtime": passed and bool(reviewed_packets) and not request_packets,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, request_packets, reviewed_packets),
        },
        "runtime_production_evidence_request_boundary": {
            "artifact_only": True,
            "production_evidence_request_allowed": passed and bool(request_packets),
            "production_evidence_ingestion_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_evidence_request_policy": {
            "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
            "review_gate_schema": PRODUCTION_EVIDENCE_GATE_SCHEMA_VERSION,
            "common_required_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
            "kind_ref_fields": PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
            "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
            "forbidden_evidence_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "blocked_after_request": [
                "production_evidence_requested -> production_evidence_ingested_by_this_gate",
                "production_evidence_requested -> production_runtime_execution_allowed",
                "production_evidence_requested -> production_runtime_receipt_written",
            ],
        },
        "runtime_production_evidence_request_surface": {
            "mode": "production_evidence_request_only_no_runtime",
            "production_evidence_request_packet_count": len(request_packets),
            "production_evidence_request_packets": request_packets,
            "closed_production_evidence_review_count": len(reviewed_packets),
            "closed_production_evidence_reviews": reviewed_packets,
            "source_production_evidence_gaps": evidence_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_evidence_gate_readiness": readiness,
            "production_evidence_gate_boundary": boundary,
        },
        "non_claims": [
            "does_not_collect_or_validate_new_production_evidence",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_evidence_requests_as_runtime_execution_permission",
        ],
    }


def _require_gate_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "production_evidence_blocked_local_controlled_only",
        "production_evidence_gap_detected",
        "production_evidence_reviewed_no_runtime_execution",
        "production_evidence_blocked_missing_artifacts",
        "production_evidence_blocked_no_runtime_execution_targets",
    }
    _require_bool("production_evidence_gate_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_evidence_gate_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_gate_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_gate_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_evidence_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_gap_shape(gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not gaps:
        checks["production_evidence_gaps_optional_or_present"] = True
        return
    _require_bool("production_evidence_gap_goal_present", all(bool(gap.get("goal_id")) for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_gap_state_valid", all(gap.get("state") == "production_evidence_gap" for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_gap_missing_kinds_present", all(bool(_string_list(gap.get("missing_production_evidence_kinds"))) for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_gap_missing_kinds_known", all(_missing_kinds_known(gap) for gap in gaps), checks=checks, failures=failures)


def _require_reviewed_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["reviewed_production_evidence_packets_optional_or_present"] = True
        return
    _require_bool("reviewed_production_evidence_packet_state_valid", all(packet.get("state") == "production_evidence_reviewed_no_runtime_execution" for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_production_evidence_packet_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_production_evidence_packet_runtime_blocked", all(_reviewed_packet_runtime_blocked(packet) for packet in packets), checks=checks, failures=failures)


def _request_packet(gap: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(gap.get("goal_id") or "unknown")
    missing_kinds = _string_list(gap.get("missing_production_evidence_kinds"))
    return {
        "request_packet_id": f"h3-runtime-production-evidence-request:{_safe_slug(goal_id)}",
        "goal_id": goal_id,
        "state": "production_evidence_request_open",
        "gap_reason": str(gap.get("gap_reason") or "missing required production evidence records"),
        "requires_production_origin_runtime_execution_target": _requires_production_target(gap),
        "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
        "requested_evidence_item_count": len(missing_kinds),
        "requested_evidence_items": [_request_item(kind) for kind in missing_kinds],
        "collection_policy": {
            "requires_real_production_source": True,
            "forbidden_source_tokens": list(NON_PRODUCTION_SOURCE_TOKENS),
            "local_controlled_receipts_count_as_production": False,
            "synthetic_or_fixture_records_count_as_production": False,
        },
        "gate_status": {
            "production_evidence_request_open": True,
            "production_evidence_complete": False,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "production_evidence_request_open -> production_runtime_execution_allowed",
                "reason": "request packets only describe missing evidence; they do not authorize runtime execution",
            },
            {
                "transition": "production_evidence_request_open -> production_runtime_receipt_written",
                "reason": "production receipts require a later production executor authorization layer",
            },
        ],
    }


def _request_item(kind: str) -> dict[str, Any]:
    return {
        "evidence_kind": kind,
        "state": "production_evidence_item_required",
        "required_common_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
        "required_kind_ref_field": PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind],
        "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
        "forbidden_source_tokens": list(NON_PRODUCTION_SOURCE_TOKENS),
    }


def _request_decision(
    passed: bool,
    request_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    gate_readiness: dict[str, Any],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_evidence_request"
    if request_packets and gate_readiness.get("decision") == "production_evidence_blocked_local_controlled_only":
        return "production_evidence_request_open_local_controlled_not_production"
    if request_packets:
        return "production_evidence_request_open"
    if reviewed_packets:
        return "production_evidence_request_closed_no_runtime_execution"
    return "production_evidence_request_blocked_no_runtime_targets"


def _allowed_scope(passed: bool, request_packets: list[dict[str, Any]], reviewed_packets: list[dict[str, Any]]) -> str:
    if not passed:
        return "do not request production evidence until the production evidence gap gate is valid"
    if request_packets:
        return "production evidence request packets only; collection and runtime execution remain outside this gate"
    if reviewed_packets:
        return "production evidence already reviewed by upstream gate; runtime execution remains blocked"
    return "no production evidence request target is available"


def _requires_production_target(gap: dict[str, Any]) -> bool:
    return str(gap.get("gap_reason") or "") == "local controlled execution receipt is not production evidence"


def _missing_kinds_known(gap: dict[str, Any]) -> bool:
    return all(kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS for kind in _string_list(gap.get("missing_production_evidence_kinds")))


def _reviewed_packet_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return (
        gate_status.get("production_runtime_execution_ready") is False
        and gate_status.get("production_runtime_receipt_ready") is False
    )


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


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item or "").strip() for item in value if str(item or "").strip()]


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


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-") or "unknown"


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-evidence-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_evidence_request(
        production_evidence_gate_path=Path(args.production_evidence_gate),
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