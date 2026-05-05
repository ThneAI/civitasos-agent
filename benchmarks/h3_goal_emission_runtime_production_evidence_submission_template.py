"""H.3 runtime production evidence submission template gate.

This artifact-only layer reads production evidence intake gaps and emits blank
submission templates for real reviewers/operators to fill. It does not create
valid production evidence records, ingest evidence, start runtime, write
receipts, call LLMs, or mutate IEM/value state.
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
)
from benchmarks.h3_goal_emission_runtime_production_evidence_intake import (
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_INTAKE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence-submission-template:v1"


def build_h3_goal_emission_runtime_production_evidence_submission_template(
    *,
    production_evidence_intake_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    production_evidence_intake_path = _resolve_path(production_evidence_intake_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    intake_report = _read_json(production_evidence_intake_path, failures)

    intake_readiness: dict[str, Any] = {}
    intake_boundary: dict[str, Any] = {}
    intake_gaps: list[dict[str, Any]] = []
    reviewed_packets: list[dict[str, Any]] = []
    if intake_report is None:
        _fail(
            checks,
            failures,
            "production_evidence_intake_present",
            f"missing H3 runtime production evidence intake report: {production_evidence_intake_path}",
        )
    else:
        checks["production_evidence_intake_present"] = True
        _require_equal(
            "production_evidence_intake_schema_version",
            intake_report.get("schema_version"),
            PRODUCTION_EVIDENCE_INTAKE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_evidence_intake_passed", bool(intake_report.get("passed")), checks=checks, failures=failures)
        intake_readiness = _object(intake_report.get("readiness"))
        _require_intake_readiness(intake_readiness, checks=checks, failures=failures)
        intake_boundary = _object(intake_report.get("runtime_production_evidence_intake_boundary"))
        _require_intake_boundary(intake_boundary, checks=checks, failures=failures)
        surface = _object(intake_report.get("runtime_production_evidence_intake_surface"))
        _require_equal(
            "production_evidence_intake_surface_mode",
            surface.get("mode"),
            "production_evidence_intake_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        intake_gaps = _record_list(surface.get("production_evidence_intake_gaps"))
        reviewed_packets = _record_list(surface.get("reviewed_production_evidence_intake_packets"))
        _require_intake_gap_shape(intake_gaps, checks=checks, failures=failures)
        _require_reviewed_packet_shape(reviewed_packets, checks=checks, failures=failures)

    template_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        template_packets = [_template_packet(gap) for gap in intake_gaps]

    template_item_count = sum(len(packet["submission_template_items"]) for packet in template_packets)
    metrics = {
        "production_evidence_intake_gap_count": len(intake_gaps),
        "reviewed_production_evidence_intake_packet_count": len(reviewed_packets),
        "production_evidence_submission_template_packet_count": len(template_packets),
        "production_evidence_submission_template_item_count": template_item_count,
        "valid_production_evidence_record_count": 0,
        "production_evidence_ingestion_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("valid_production_evidence_records_absent", metrics["valid_production_evidence_record_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_evidence_ingestion_blocked", metrics["production_evidence_ingestion_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _template_decision(passed, template_packets, reviewed_packets)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_evidence_intake_path": str(production_evidence_intake_path),
        "checks": checks,
        "readiness": {
            "production_evidence_submission_template_evaluated": passed,
            "production_evidence_submission_templates_open": passed and bool(template_packets),
            "production_evidence_submission_template_not_required": passed and not template_packets,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, template_packets, reviewed_packets),
        },
        "runtime_production_evidence_submission_template_boundary": {
            "artifact_only": True,
            "production_evidence_submission_template_allowed": passed and bool(template_packets),
            "valid_production_evidence_record_generation_allowed": False,
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
        "runtime_production_evidence_submission_template_policy": {
            "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
            "intake_schema": PRODUCTION_EVIDENCE_INTAKE_SCHEMA_VERSION,
            "common_required_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
            "kind_ref_fields": PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
            "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
            "forbidden_evidence_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "blocked_after_template": [
                "production_evidence_template_generated -> production_evidence_ingested_by_this_gate",
                "production_evidence_template_generated -> production_runtime_execution_allowed",
                "production_evidence_template_generated -> production_runtime_receipt_written",
            ],
        },
        "runtime_production_evidence_submission_template_surface": {
            "mode": "production_evidence_submission_template_only_no_runtime",
            "production_evidence_submission_template_packet_count": len(template_packets),
            "production_evidence_submission_template_packets": template_packets,
            "source_production_evidence_intake_gaps": intake_gaps,
            "source_reviewed_production_evidence_intake_packets": reviewed_packets,
        },
        "metrics": metrics,
        "evidence": {
            "production_evidence_intake_readiness": intake_readiness,
            "production_evidence_intake_boundary": intake_boundary,
        },
        "non_claims": [
            "does_not_create_valid_production_evidence_records",
            "does_not_ingest_or_forward_production_evidence_to_runtime",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_submission_templates_as_runtime_execution_permission",
        ],
    }


def _require_intake_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "production_evidence_intake_blocked_pending_submission",
        "production_evidence_intake_gap_detected",
        "production_evidence_intake_reviewed_no_runtime_execution",
        "production_evidence_intake_not_required_already_reviewed_no_runtime",
        "production_evidence_intake_not_required_no_runtime_targets",
    }
    _require_bool("production_evidence_intake_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_evidence_intake_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_intake_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_intake_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_intake_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
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
        _require_bool(f"production_evidence_intake_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_intake_gap_shape(gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not gaps:
        checks["production_evidence_intake_gaps_optional_or_present"] = True
        return
    _require_bool("production_evidence_intake_gap_goal_present", all(bool(gap.get("goal_id")) for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_intake_gap_state_valid", all(gap.get("state") == "production_evidence_intake_gap" for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_intake_gap_missing_kinds_present", all(bool(_string_list(gap.get("missing_production_evidence_kinds"))) for gap in gaps), checks=checks, failures=failures)
    _require_bool("production_evidence_intake_gap_missing_kinds_known", all(_missing_kinds_known(gap) for gap in gaps), checks=checks, failures=failures)


def _require_reviewed_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["reviewed_production_evidence_intake_packets_optional_or_present"] = True
        return
    _require_bool("reviewed_production_evidence_intake_packet_state_valid", all(packet.get("state") == "production_evidence_intake_reviewed_no_runtime_execution" for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_production_evidence_intake_packet_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_production_evidence_intake_packet_runtime_blocked", all(_reviewed_packet_runtime_blocked(packet) for packet in packets), checks=checks, failures=failures)


def _template_packet(gap: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(gap.get("goal_id") or "unknown")
    missing_kinds = _string_list(gap.get("missing_production_evidence_kinds"))
    return {
        "submission_template_packet_id": f"h3-runtime-production-evidence-submission-template:{_safe_slug(goal_id)}",
        "goal_id": goal_id,
        "state": "production_evidence_submission_template_open",
        "request_packet_id": gap.get("request_packet_id"),
        "gap_reason": str(gap.get("gap_reason") or "missing requested production evidence submission records"),
        "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
        "submission_template_item_count": len(missing_kinds),
        "submission_template_items": [_template_item(goal_id, kind) for kind in missing_kinds],
        "template_policy": {
            "template_records_are_valid_production_evidence": False,
            "requires_real_production_source_before_submission": True,
            "requires_reviewer_completion_before_submission": True,
            "forbidden_source_tokens": list(NON_PRODUCTION_SOURCE_TOKENS),
        },
        "gate_status": {
            "production_evidence_submission_template_open": True,
            "valid_production_evidence_record_count": 0,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
        },
    }


def _template_item(goal_id: str, kind: str) -> dict[str, Any]:
    ref_field = PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind]
    placeholder_record: dict[str, Any] = {
        "artifact_id": "<required:production-artifact-id>",
        "goal_id": goal_id,
        "evidence_kind": kind,
        "reviewer": "<required:human-or-governance-reviewer>",
        "reviewer_role": "<required:reviewer-role>",
        "source": "template_local_placeholder_not_production",
        "status": "<required:accepted-production-status>",
        "attestation_ref": "<required:production-attestation-ref>",
        ref_field: f"<required:{ref_field}>",
        "template_only": True,
        "valid_production_evidence_record": False,
    }
    return {
        "evidence_kind": kind,
        "state": "production_evidence_submission_template_item",
        "required_common_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
        "required_kind_ref_field": ref_field,
        "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
        "forbidden_source_tokens": list(NON_PRODUCTION_SOURCE_TOKENS),
        "placeholder_record": placeholder_record,
    }


def _template_decision(passed: bool, template_packets: list[dict[str, Any]], reviewed_packets: list[dict[str, Any]]) -> str:
    if not passed:
        return "blocked_before_runtime_production_evidence_submission_template"
    if template_packets:
        return "production_evidence_submission_template_open"
    if reviewed_packets:
        return "production_evidence_submission_template_not_required_reviewed_no_runtime"
    return "production_evidence_submission_template_not_required_no_intake_gaps"


def _allowed_scope(passed: bool, template_packets: list[dict[str, Any]], reviewed_packets: list[dict[str, Any]]) -> str:
    if not passed:
        return "do not generate submission templates until intake schema and boundary are valid"
    if template_packets:
        return "blank submission templates only; reviewers must replace placeholders with real production evidence before a later intake review"
    if reviewed_packets:
        return "intake already reviewed submitted evidence; runtime execution remains blocked"
    return "no production evidence submission template is needed"


def _reviewed_packet_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return gate_status.get("production_runtime_execution_ready") is False and gate_status.get("production_runtime_receipt_ready") is False


def _missing_kinds_known(gap: dict[str, Any]) -> bool:
    return all(kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS for kind in _string_list(gap.get("missing_production_evidence_kinds")))


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-") or "unknown"


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
    parser.add_argument("--production-evidence-intake", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_evidence_submission_template(
        production_evidence_intake_path=Path(args.production_evidence_intake),
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