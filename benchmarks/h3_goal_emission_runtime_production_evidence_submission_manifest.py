"""H.3 runtime production evidence submission manifest gate.

This artifact-only layer reads production evidence submission templates plus an
optional submitted evidence bundle. It creates a manifest summary with hashes,
source checks, and request coverage gaps. It does not validate evidence truth,
ingest evidence into runtime, start runtime, write receipts, call LLMs, or
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import hashlib
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
from benchmarks.h3_goal_emission_runtime_production_evidence_submission_template import (
    SCHEMA_VERSION as PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence-submission-manifest:v1"


def build_h3_goal_emission_runtime_production_evidence_submission_manifest(
    *,
    production_evidence_submission_template_path: Path,
    agent_root: Path,
    production_evidence_submission_path: Path | None = None,
) -> dict[str, Any]:
    production_evidence_submission_template_path = _resolve_path(production_evidence_submission_template_path, agent_root)
    production_evidence_submission_path = (
        _resolve_path(production_evidence_submission_path, agent_root)
        if production_evidence_submission_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    template_report = _read_json(production_evidence_submission_template_path, failures)

    template_readiness: dict[str, Any] = {}
    template_boundary: dict[str, Any] = {}
    template_packets: list[dict[str, Any]] = []
    if template_report is None:
        _fail(
            checks,
            failures,
            "production_evidence_submission_template_present",
            f"missing H3 runtime production evidence submission template: {production_evidence_submission_template_path}",
        )
    else:
        checks["production_evidence_submission_template_present"] = True
        _require_equal(
            "production_evidence_submission_template_schema_version",
            template_report.get("schema_version"),
            PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_evidence_submission_template_passed", bool(template_report.get("passed")), checks=checks, failures=failures)
        template_readiness = _object(template_report.get("readiness"))
        _require_template_readiness(template_readiness, checks=checks, failures=failures)
        template_boundary = _object(template_report.get("runtime_production_evidence_submission_template_boundary"))
        _require_template_boundary(template_boundary, checks=checks, failures=failures)
        surface = _object(template_report.get("runtime_production_evidence_submission_template_surface"))
        _require_equal(
            "production_evidence_submission_template_surface_mode",
            surface.get("mode"),
            "production_evidence_submission_template_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        template_packets = _record_list(surface.get("production_evidence_submission_template_packets"))
        _require_template_packet_shape(template_packets, checks=checks, failures=failures)

    submission_records: list[dict[str, Any]] = []
    submission_payload: dict[str, Any] | None = None
    submission_sha256 = ""
    if production_evidence_submission_path:
        submission_payload, submission_sha256 = _read_json_with_sha256(production_evidence_submission_path, failures)
        checks["production_evidence_submission_present"] = submission_payload is not None
        if submission_payload is not None:
            _require_equal(
                "production_evidence_submission_schema_version",
                submission_payload.get("schema_version"),
                PRODUCTION_EVIDENCE_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            submission_records = _record_list(submission_payload.get("production_evidence_records") or submission_payload.get("records"))
            _require_bool("production_evidence_submission_records_present", bool(submission_records), checks=checks, failures=failures)
            _require_submission_record_shape(submission_records, template_packets, checks=checks, failures=failures)
    else:
        checks["production_evidence_submission_optional_absent"] = True

    manifest: dict[str, Any] = {}
    manifest_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        manifest, manifest_gaps = _build_manifest(
            submission_path=production_evidence_submission_path,
            submission_sha256=submission_sha256,
            template_packets=template_packets,
            submission_records=submission_records,
        )

    metrics = {
        "production_evidence_submission_template_packet_count": len(template_packets),
        "production_evidence_submission_template_item_count": _template_item_count(template_packets),
        "submitted_production_evidence_record_count": len(submission_records),
        "production_evidence_submission_manifest_gap_count": len(manifest_gaps),
        "missing_template_evidence_item_count": sum(len(gap["missing_production_evidence_kinds"]) for gap in manifest_gaps),
        "valid_production_evidence_record_generation_count": 0,
        "production_evidence_ingestion_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("valid_production_evidence_record_generation_blocked", metrics["valid_production_evidence_record_generation_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_evidence_ingestion_blocked", metrics["production_evidence_ingestion_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _manifest_decision(passed, bool(production_evidence_submission_path), manifest, manifest_gaps, template_packets)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_evidence_submission_template_path": str(production_evidence_submission_template_path),
        "production_evidence_submission_path": str(production_evidence_submission_path) if production_evidence_submission_path else None,
        "checks": checks,
        "readiness": {
            "production_evidence_submission_manifest_evaluated": passed,
            "production_evidence_submission_manifest_present": passed and bool(manifest),
            "production_evidence_submission_manifest_complete": passed and bool(manifest) and not manifest_gaps,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, bool(production_evidence_submission_path), manifest, manifest_gaps, template_packets),
        },
        "runtime_production_evidence_submission_manifest_boundary": {
            "artifact_only": True,
            "production_evidence_submission_manifest_allowed": passed and bool(manifest),
            "production_evidence_truth_validation_allowed": False,
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
        "runtime_production_evidence_submission_manifest_policy": {
            "template_schema": PRODUCTION_EVIDENCE_SUBMISSION_TEMPLATE_SCHEMA_VERSION,
            "submission_schema": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
            "common_required_fields": PRODUCTION_EVIDENCE_COMMON_FIELDS,
            "kind_ref_fields": PRODUCTION_EVIDENCE_KIND_REF_FIELDS,
            "accepted_statuses": sorted(ACCEPTED_PRODUCTION_STATUSES),
            "forbidden_evidence_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_manifest_fields": [
                "submission_path",
                "submission_sha256",
                "submission_schema_version",
                "submitted_record_count",
                "submitted_goal_ids",
                "submitted_evidence_kinds",
            ],
            "blocked_after_manifest": [
                "production_evidence_submission_manifest_reviewed -> production_evidence_ingested_by_this_gate",
                "production_evidence_submission_manifest_reviewed -> production_runtime_execution_allowed",
                "production_evidence_submission_manifest_reviewed -> production_runtime_receipt_written",
            ],
        },
        "runtime_production_evidence_submission_manifest_surface": {
            "mode": "production_evidence_submission_manifest_only_no_runtime",
            "production_evidence_submission_manifest": manifest,
            "production_evidence_submission_manifest_gap_count": len(manifest_gaps),
            "production_evidence_submission_manifest_gaps": manifest_gaps,
            "source_production_evidence_submission_template_packets": template_packets,
        },
        "metrics": metrics,
        "evidence": {
            "production_evidence_submission_template_readiness": template_readiness,
            "production_evidence_submission_template_boundary": template_boundary,
        },
        "non_claims": [
            "does_not_validate_evidence_truth_or_attestation_authenticity",
            "does_not_create_valid_production_evidence_records",
            "does_not_ingest_or_forward_production_evidence_to_runtime",
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_submission_manifest_as_runtime_execution_permission",
        ],
    }


def _require_template_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "production_evidence_submission_template_open",
        "production_evidence_submission_template_not_required_reviewed_no_runtime",
        "production_evidence_submission_template_not_required_no_intake_gaps",
    }
    _require_bool("production_evidence_submission_template_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_template_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_submission_template_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
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
        _require_bool(f"production_evidence_submission_template_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_template_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["production_evidence_submission_template_packets_optional_or_present"] = True
        return
    _require_bool("production_evidence_submission_template_packet_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_packet_state_valid", all(packet.get("state") == "production_evidence_submission_template_open" for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_packet_schema_valid", all(packet.get("submission_schema") == PRODUCTION_EVIDENCE_SCHEMA_VERSION for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_items_present", all(bool(_template_items(packet)) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_items_known", all(_template_items_known(packet) for packet in packets), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_items_not_valid_records", all(_template_items_not_valid_records(packet) for packet in packets), checks=checks, failures=failures)


def _require_submission_record_shape(
    records: list[dict[str, Any]],
    template_packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("production_evidence_submission_common_fields_present", all(_common_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_kind_known", all(record.get("evidence_kind") in REQUIRED_PRODUCTION_EVIDENCE_KINDS for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_kind_refs_present", all(_kind_ref_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_evidence_record") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_submission_records_match_templates", all(_record_matches_template(record, template_packets) for record in records), checks=checks, failures=failures)


def _build_manifest(
    *,
    submission_path: Path | None,
    submission_sha256: str,
    template_packets: list[dict[str, Any]],
    submission_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if submission_path is None:
        return {}, _missing_gaps(template_packets, submission_records, "production evidence submission artifact is absent")
    submitted_goal_ids = sorted({str(record.get("goal_id") or "") for record in submission_records if record.get("goal_id")})
    submitted_evidence_kinds = sorted({str(record.get("evidence_kind") or "") for record in submission_records if record.get("evidence_kind")})
    missing_gaps = _missing_gaps(template_packets, submission_records, "submitted evidence bundle is missing template-requested records")
    manifest = {
        "state": "production_evidence_submission_manifest_reviewed_no_runtime_execution",
        "submission_path": str(submission_path),
        "submission_sha256": submission_sha256,
        "submission_schema_version": PRODUCTION_EVIDENCE_SCHEMA_VERSION,
        "submitted_record_count": len(submission_records),
        "submitted_goal_ids": submitted_goal_ids,
        "submitted_evidence_kinds": submitted_evidence_kinds,
        "submitted_record_refs": [str(record.get("artifact_id") or "") for record in submission_records],
        "missing_template_evidence_item_count": sum(len(gap["missing_production_evidence_kinds"]) for gap in missing_gaps),
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return manifest, missing_gaps


def _missing_gaps(template_packets: list[dict[str, Any]], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    submitted = {(str(record.get("goal_id") or ""), str(record.get("evidence_kind") or "")) for record in records}
    gaps: list[dict[str, Any]] = []
    for packet in template_packets:
        goal_id = str(packet.get("goal_id") or "")
        missing = [kind for kind in _template_kinds(packet) if (goal_id, kind) not in submitted]
        if missing:
            gaps.append(
                {
                    "goal_id": goal_id,
                    "state": "production_evidence_submission_manifest_gap",
                    "gap_reason": reason,
                    "missing_production_evidence_kinds": missing,
                    "template_packet_id": packet.get("submission_template_packet_id"),
                }
            )
    return gaps


def _manifest_decision(
    passed: bool,
    submission_path_present: bool,
    manifest: dict[str, Any],
    manifest_gaps: list[dict[str, Any]],
    template_packets: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_evidence_submission_manifest"
    if not template_packets:
        return "production_evidence_submission_manifest_not_required_no_template_targets"
    if not submission_path_present:
        return "production_evidence_submission_manifest_blocked_pending_submission"
    if manifest and manifest_gaps:
        return "production_evidence_submission_manifest_gap_detected"
    return "production_evidence_submission_manifest_reviewed_no_runtime_execution"


def _allowed_scope(
    passed: bool,
    submission_path_present: bool,
    manifest: dict[str, Any],
    manifest_gaps: list[dict[str, Any]],
    template_packets: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not create submission manifests until template and submission schemas are valid"
    if not template_packets:
        return "no production evidence submission manifest target is available"
    if not submission_path_present:
        return "submission manifest is pending real production evidence; runtime execution remains blocked"
    if manifest and manifest_gaps:
        return "submission manifest has missing template-requested evidence; runtime execution remains blocked"
    return "submission manifest reviewed only; runtime execution remains blocked"


def _template_items(packet: dict[str, Any]) -> list[dict[str, Any]]:
    return _record_list(packet.get("submission_template_items") or packet.get("template_items"))


def _template_kinds(packet: dict[str, Any]) -> list[str]:
    return [str(item.get("evidence_kind") or "") for item in _template_items(packet) if item.get("evidence_kind")]


def _template_item_count(packets: list[dict[str, Any]]) -> int:
    return sum(len(_template_items(packet)) for packet in packets)


def _template_items_known(packet: dict[str, Any]) -> bool:
    return all(kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS for kind in _template_kinds(packet))


def _template_items_not_valid_records(packet: dict[str, Any]) -> bool:
    for item in _template_items(packet):
        placeholder = _object(item.get("placeholder_record"))
        if placeholder.get("template_only") is not True:
            return False
        if placeholder.get("valid_production_evidence_record") is not False:
            return False
    return True


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


def _record_matches_template(record: dict[str, Any], template_packets: list[dict[str, Any]]) -> bool:
    goal_id = str(record.get("goal_id") or "")
    kind = str(record.get("evidence_kind") or "")
    return any(str(packet.get("goal_id") or "") == goal_id and kind in _template_kinds(packet) for packet in template_packets)


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
    parser.add_argument("--production-evidence-submission-template", required=True)
    parser.add_argument("--production-evidence-submission", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_evidence_submission_manifest(
        production_evidence_submission_template_path=Path(args.production_evidence_submission_template),
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