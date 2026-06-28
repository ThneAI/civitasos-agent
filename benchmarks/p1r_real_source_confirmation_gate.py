"""Run P1-R real source confirmation gate.

P1-R consumes P0-Q candidate source refs, a P1 charter summary, and four
operator-supplied real source confirmation files. It normalizes those
confirmations into a Round 2 source manifest, calls the evidence-ledger Round 2
assembler, then reruns the H.3 gap mapper against the assembled submission.

This gate does not create real evidence by itself. It only accepts explicitly
supplied production-origin confirmations and fails closed when source refs look
local, test, mock, synthetic, demo, or candidate-only.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import NON_PRODUCTION_SOURCE_TOKENS
from benchmarks.h3_production_evidence_gap_mapper import run_mapper
from benchmarks.i_gate_evidence import (
    artifact_ref,
    check,
    object_value,
    read_json_object,
    sha256_file,
    sha256_json,
    write_json_object,
)
from benchmarks.p0q_p1_source_ref_collection_gate import CHAIN_SCHEMA as P0Q_CHAIN_SCHEMA
from benchmarks.p1_controlled_production_pilot_charter_gate import CHAIN_SCHEMA as P1_CHAIN_SCHEMA

CHAIN_SCHEMA = "p1r-real-source-confirmation-chain:v1"
CONFIRMATION_SCHEMA = "p1r-real-source-confirmation:v1"
CONFIRMATION_PACKET_SCHEMA = "p1r-real-source-confirmation-packet:v1"
SOURCE_MANIFEST_SCHEMA = "h3-round2-real-evidence-source-manifest:v1"
EVIDENCE_PROFILE_STRICT = "strict_real_source"
EVIDENCE_PROFILE_OPERATOR_ATTESTED_PRODUCTION = "operator_attested_production"

ROLE_CONFIRMATION_FILES = ("owner", "audit", "monitoring", "rollback")
FORBIDDEN_SOURCE_TOKENS = tuple(
    sorted(set(NON_PRODUCTION_SOURCE_TOKENS + ("candidate", "simulated", "simulation", "demo", "placeholder")))
)

ROUND2_EVENT_ORDER = (
    "human_review_approved",
    "governance_runtime_execution_approved",
    "challenge_r2r_rollback_attested",
    "activation_artifact_chain_attested",
    "runtime_safety_envelope_reviewed",
    "rollout_window_approved",
    "live_monitoring_green",
    "rollback_drill_attested",
    "operator_oncall_acknowledged",
    "kill_switch_armed",
    "runtime_start_change_ticket_opened",
    "runtime_start_dual_operator_acknowledged",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_checked",
    "runtime_start_rollback_checkpoint_created",
    "runtime_start_audit_sink_ready",
)

EVENT_CATALOG = {
    "human_review_approved": {
        "role": "owner",
        "evidence_kind": "external_human_review_approval",
        "ref_field": "human_review_ref",
        "status": "approved",
        "reviewer_role": "human_governance_reviewer",
    },
    "governance_runtime_execution_approved": {
        "role": "owner",
        "evidence_kind": "governance_runtime_execution_approval",
        "ref_field": "governance_ref",
        "status": "approved",
        "reviewer_role": "governance_runtime_approver",
    },
    "challenge_r2r_rollback_attested": {
        "role": "rollback",
        "evidence_kind": "challenge_r2r_rollback_attestation",
        "ref_field": "r2r_rollback_ref",
        "status": "attested",
        "reviewer_role": "independent_authorizer",
    },
    "activation_artifact_chain_attested": {
        "role": "audit",
        "evidence_kind": "activation_artifact_chain_attestation",
        "ref_field": "activation_chain_ref",
        "status": "attested",
        "reviewer_role": "activation_authority",
    },
    "runtime_safety_envelope_reviewed": {
        "role": "audit",
        "evidence_kind": "runtime_safety_envelope",
        "ref_field": "runtime_safety_ref",
        "status": "approved",
        "reviewer_role": "runtime_safety_reviewer",
    },
    "rollout_window_approved": {
        "role": "owner",
        "evidence_kind": "rollout_window_approval",
        "ref_field": "rollout_window_ref",
        "status": "approved",
        "reviewer_role": "production_operator",
    },
    "live_monitoring_green": {
        "role": "monitoring",
        "evidence_kind": "live_monitoring_attestation",
        "ref_field": "live_monitoring_ref",
        "status": "green",
        "reviewer_role": "observability_owner",
    },
    "rollback_drill_attested": {
        "role": "rollback",
        "evidence_kind": "rollback_drill_attestation",
        "ref_field": "rollback_drill_ref",
        "status": "attested",
        "reviewer_role": "runtime_change_authority",
    },
    "operator_oncall_acknowledged": {
        "role": "owner",
        "evidence_kind": "operator_oncall_ack",
        "ref_field": "operator_oncall_ref",
        "status": "acknowledged",
        "reviewer_role": "production_operator",
    },
    "kill_switch_armed": {
        "role": "rollback",
        "evidence_kind": "kill_switch_attestation",
        "ref_field": "kill_switch_ref",
        "status": "armed",
        "reviewer_role": "production_operator",
    },
    "runtime_start_change_ticket_opened": {
        "role": "rollback",
        "evidence_kind": "runtime_start_change_ticket",
        "ref_field": "change_ticket_ref",
        "status": "approved",
        "reviewer_role": "runtime_change_authority",
    },
    "runtime_start_dual_operator_acknowledged": {
        "role": "owner",
        "evidence_kind": "runtime_start_dual_operator_ack",
        "ref_field": "dual_operator_ack_ref",
        "status": "acknowledged",
        "reviewer_role": "production_operator",
    },
    "runtime_start_final_monitoring_green": {
        "role": "monitoring",
        "evidence_kind": "runtime_start_final_monitoring_green",
        "ref_field": "final_monitoring_ref",
        "status": "green",
        "reviewer_role": "observability_owner",
    },
    "runtime_start_final_kill_switch_checked": {
        "role": "rollback",
        "evidence_kind": "runtime_start_final_kill_switch_check",
        "ref_field": "final_kill_switch_ref",
        "status": "armed",
        "reviewer_role": "production_operator",
    },
    "runtime_start_rollback_checkpoint_created": {
        "role": "rollback",
        "evidence_kind": "runtime_start_rollback_checkpoint",
        "ref_field": "rollback_checkpoint_ref",
        "status": "complete",
        "reviewer_role": "runtime_change_authority",
    },
    "runtime_start_audit_sink_ready": {
        "role": "audit",
        "evidence_kind": "runtime_start_audit_sink_ready",
        "ref_field": "audit_sink_ref",
        "status": "ready",
        "reviewer_role": "audit_owner",
    },
}

NON_CLAIMS = (
    "p1r_does_not_create_real_production_evidence",
    "p1r_only_normalizes_operator_supplied_real_source_confirmations",
    "p1r_round2_submission_is_not_l2_anchor_or_independent_verification",
    "p1r_does_not_authorize_runtime_execution_or_production_transition",
    "p1r_does_not_write_production_runtime_receipts",
)


class P1RValidationError(RuntimeError):
    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__("p1r_validation_failed")
        self.report = report


def run_gate(
    *,
    p0q_summary_path: Path,
    p1_summary_path: Path,
    owner_confirmation_path: Path,
    audit_confirmation_path: Path,
    monitoring_confirmation_path: Path,
    rollback_confirmation_path: Path,
    output_root: Path,
    evidence_ledger_src: Path | None = None,
    operator_attested_controlled_pilot: bool = False,
    operator_attested_production: bool = False,
    operator_attester: str | None = None,
    operator_attestation_statement: str | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "confirmation_packet": output_root / "p1r_real_source_confirmation_packet.json",
        "source_manifest": output_root / "round2_real_evidence_source_manifest.json",
        "source_manifest_validation": output_root / "round2_source_manifest_validation.json",
        "production_evidence_submission": output_root / "production_evidence_submission.json",
        "round2_assembly_report": output_root / "round2_assembly_report.json",
        "gap_map": output_root / "h3_production_evidence_gap_map_after_p1r.json",
        "summary": output_root / "p1r_real_source_confirmation_summary.json",
    }
    confirmation_paths = {
        "owner": owner_confirmation_path,
        "audit": audit_confirmation_path,
        "monitoring": monitoring_confirmation_path,
        "rollback": rollback_confirmation_path,
    }

    try:
        operator_attested = operator_attested_controlled_pilot or operator_attested_production
        evidence_profile = EVIDENCE_PROFILE_OPERATOR_ATTESTED_PRODUCTION if operator_attested else EVIDENCE_PROFILE_STRICT
        operator_attestation = _operator_attestation_context(
            enabled=operator_attested,
            operator_attester=operator_attester,
            statement=operator_attestation_statement,
        )
        context = _validate_context(p0q_summary_path=p0q_summary_path, p1_summary_path=p1_summary_path)
        confirmations = _load_confirmations(confirmation_paths)
        normalized_sources = _normalize_confirmation_sources(
            confirmations,
            operator_attestation=operator_attestation,
        )
        packet = _write_confirmation_packet(
            output=artifacts["confirmation_packet"],
            context=context,
            confirmations=confirmations,
            normalized_sources=normalized_sources,
            confirmation_paths=confirmation_paths,
            evidence_profile=evidence_profile,
            operator_attestation=operator_attestation,
        )
        manifest = _write_source_manifest(
            output=artifacts["source_manifest"],
            goal_id=str(context["p1_summary"].get("pilot_id") or ""),
            normalized_sources=normalized_sources,
            packet_path=artifacts["confirmation_packet"],
        )
        tools = _load_evidence_ledger_tools(evidence_ledger_src)
        source_validation = tools["validate_source_manifest"](
            artifacts["source_manifest"],
            goal_id=str(context["p1_summary"].get("pilot_id") or ""),
        )
        write_json_object(artifacts["source_manifest_validation"], source_validation)
        assembly_report = tools["assemble_submission"](
            artifacts["source_manifest"],
            artifacts["production_evidence_submission"],
            goal_id=str(context["p1_summary"].get("pilot_id") or ""),
            overwrite=True,
        )
        write_json_object(artifacts["round2_assembly_report"], assembly_report)
        gap_map = run_mapper(
            output=artifacts["gap_map"],
            p0q_summary_path=p0q_summary_path,
            p1_summary_path=p1_summary_path,
            production_evidence_path=artifacts["production_evidence_submission"],
        )
    except P1RValidationError as exc:
        summary = _summary(
            passed=False,
            failures=exc.report.get("failure_reasons", []),
            p0q_summary_path=p0q_summary_path,
            p1_summary_path=p1_summary_path,
            confirmation_paths=confirmation_paths,
            artifacts={name: path for name, path in artifacts.items() if name != "summary"},
            readiness_state="blocked_p1r_real_source_confirmation",
            extra={"validation_report": exc.report},
        )
        write_json_object(artifacts["summary"], summary)
        return summary
    except Exception as exc:  # noqa: BLE001
        summary = _summary(
            passed=False,
            failures=[f"p1r_unexpected_error:{type(exc).__name__}:{exc}"],
            p0q_summary_path=p0q_summary_path,
            p1_summary_path=p1_summary_path,
            confirmation_paths=confirmation_paths,
            artifacts={name: path for name, path in artifacts.items() if name != "summary"},
            readiness_state="blocked_p1r_unexpected_error",
        )
        write_json_object(artifacts["summary"], summary)
        return summary

    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "confirmation_packet_passed", packet.get("passed") is True)
    check(checks, failures, "source_manifest_written", manifest.get("passed") is True and artifacts["source_manifest"].is_file())
    check(checks, failures, "source_manifest_validation_passed", source_validation.get("passed") is True)
    check(checks, failures, "round2_assembly_passed", assembly_report.get("passed") is True)
    check(checks, failures, "production_submission_written", artifacts["production_evidence_submission"].is_file())
    check(checks, failures, "gap_map_passed", gap_map.get("passed") is True)
    check(checks, failures, "gap_map_satisfied_16", object_value(gap_map.get("counts")).get("production_satisfied_count") == len(ROUND2_EVENT_ORDER))
    check(checks, failures, "gap_map_missing_0", object_value(gap_map.get("counts")).get("production_missing_count") == 0)
    passed = bool(checks) and all(checks.values()) and not failures
    summary = _summary(
        passed=passed,
        failures=failures,
        p0q_summary_path=p0q_summary_path,
        p1_summary_path=p1_summary_path,
        confirmation_paths=confirmation_paths,
        artifacts={name: path for name, path in artifacts.items() if name != "summary"},
        readiness_state="p1r_round2_real_source_confirmation_ready" if passed else "blocked_p1r_real_source_confirmation",
        extra={
            "checked_at": _now(),
            "checks": checks,
            "round2_required_evidence_count": len(ROUND2_EVENT_ORDER),
            "normalized_source_count": len(normalized_sources),
            "production_satisfied_count": object_value(gap_map.get("counts")).get("production_satisfied_count"),
            "production_missing_count": object_value(gap_map.get("counts")).get("production_missing_count"),
            "round2_source_manifest_validation_passed": source_validation.get("passed") is True,
            "round2_assembly_passed": assembly_report.get("passed") is True,
            "h3_gap_map_passed": gap_map.get("passed") is True,
            "evidence_profile": evidence_profile,
            "operator_attested_production": operator_attested,
            "operator_attestation": operator_attestation,
        },
    )
    write_json_object(artifacts["summary"], summary)
    return summary


def _validate_context(*, p0q_summary_path: Path, p1_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0q = read_json_object(p0q_summary_path)
        p1 = read_json_object(p1_summary_path)
    except Exception as exc:  # noqa: BLE001
        raise P1RValidationError(_report(False, [f"context_unreadable:{exc}"], checks)) from exc

    check(checks, failures, "p0q_summary_passed", p0q.get("schema_version") == P0Q_CHAIN_SCHEMA and p0q.get("passed") is True)
    check(checks, failures, "p1_summary_passed", p1.get("schema_version") == P1_CHAIN_SCHEMA and p1.get("passed") is True)
    check(checks, failures, "p0q_real_confirmation_ready", object_value(p0q.get("readiness")).get("p1_real_source_confirmation_ready") is True)
    check(checks, failures, "p1_collection_ready", object_value(p1.get("readiness")).get("h3_production_evidence_collection_ready") is True)
    check(checks, failures, "p0q_boundary_closed", _boundary_closed(object_value(p0q.get("boundary"))))
    check(checks, failures, "p1_boundary_closed", _boundary_closed(object_value(p1.get("boundary"))))
    check(checks, failures, "p0q_p1_source_hash_matches", _p0q_links_p1(p0q, p1_summary_path))
    _check_artifact_refs(p0q, checks, failures, "p0q")
    _check_artifact_refs(p1, checks, failures, "p1")

    if not (checks and all(checks.values()) and not failures):
        raise P1RValidationError(_report(False, failures, checks))
    return {
        "passed": True,
        "p0q_summary": p0q,
        "p1_summary": p1,
        "source_artifacts": {
            "p0q_summary": artifact_ref(p0q_summary_path),
            "p1_summary": artifact_ref(p1_summary_path),
        },
    }


def _load_confirmations(paths: dict[str, Path]) -> dict[str, dict[str, Any]]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    confirmations: dict[str, dict[str, Any]] = {}
    for role, path in paths.items():
        try:
            payload = read_json_object(path)
        except Exception as exc:  # noqa: BLE001
            check(checks, failures, f"{role}_confirmation_readable", False)
            failures.append(f"{role}_confirmation_unreadable:{exc}")
            continue
        confirmations[role] = payload
        check(checks, failures, f"{role}_schema_valid", payload.get("schema_version") == CONFIRMATION_SCHEMA)
        check(checks, failures, f"{role}_role_matches", payload.get("confirmation_role") == role)
        check(checks, failures, f"{role}_production_origin_confirmed", payload.get("production_origin_confirmed") is True)
        check(checks, failures, f"{role}_candidate_ref_not_promoted", payload.get("candidate_ref_promoted") is False)
        check(checks, failures, f"{role}_confirmed_by_present", bool(str(payload.get("confirmed_by") or "").strip()))
        check(checks, failures, f"{role}_records_present", isinstance(payload.get("records"), list) and bool(payload.get("records")))
    if set(confirmations) != set(ROLE_CONFIRMATION_FILES):
        failures.append("confirmation_roles_incomplete")
    if failures or not all(checks.values()):
        raise P1RValidationError(_report(False, failures, checks))
    return confirmations


def _operator_attestation_context(
    *,
    enabled: bool,
    operator_attester: str | None,
    statement: str | None,
) -> dict[str, Any] | None:
    if not enabled:
        return None
    checks: dict[str, bool] = {}
    failures: list[str] = []
    attester = str(operator_attester or "").strip()
    attestation_statement = str(statement or "").strip()
    check(checks, failures, "operator_attester_present", bool(attester))
    check(checks, failures, "operator_attestation_statement_present", bool(attestation_statement))
    check(
        checks,
        failures,
        "operator_attestation_statement_declares_production",
        "生产" in attestation_statement or "production" in attestation_statement.lower(),
    )
    if failures or not all(checks.values()):
        raise P1RValidationError(_report(False, failures, checks))
    return {
        "schema_version": "p1r-operator-attestation-context:v1",
        "evidence_profile": EVIDENCE_PROFILE_OPERATOR_ATTESTED_PRODUCTION,
        "operator_attester": attester,
        "operator_attestation_statement": attestation_statement,
        "operator_attestation_statement_sha256": sha256_json(attestation_statement),
        "recorded_at": _now(),
        "scope": "h3_production_transition_evidence",
        "raw_pending_markers_may_be_overlaid": True,
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _normalize_confirmation_sources(
    confirmations: dict[str, dict[str, Any]],
    *,
    operator_attestation: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    normalized_by_event: dict[str, dict[str, Any]] = {}
    for role in ROLE_CONFIRMATION_FILES:
        confirmation = confirmations[role]
        defaults = {
            "source": confirmation.get("source"),
            "source_provider": confirmation.get("source_provider"),
            "source_uri": confirmation.get("source_uri"),
            "captured_at": confirmation.get("captured_at"),
            "reviewer": confirmation.get("reviewer") or confirmation.get("confirmed_by"),
        }
        for index, record in enumerate(confirmation.get("records", [])):
            if not isinstance(record, dict):
                check(checks, failures, f"{role}_record_{index}_object", False)
                continue
            source_event_kind = str(record.get("source_event_kind") or "")
            catalog = EVENT_CATALOG.get(source_event_kind)
            if catalog is None:
                check(checks, failures, f"{role}_record_{index}_event_known", False)
                continue
            check(checks, failures, f"{source_event_kind}_assigned_role", catalog["role"] == role)
            check(checks, failures, f"{source_event_kind}_not_duplicate", source_event_kind not in normalized_by_event)
            entry = _normalize_source_entry(record, defaults, source_event_kind, catalog)
            if operator_attestation:
                entry = _apply_operator_attested_pilot_overlay(
                    source_event_kind=source_event_kind,
                    entry=entry,
                    raw_record=record,
                    operator_attestation=operator_attestation,
                )
            _validate_normalized_entry(source_event_kind, entry, checks, failures)
            normalized_by_event[source_event_kind] = entry

    missing = [kind for kind in ROUND2_EVENT_ORDER if kind not in normalized_by_event]
    check(checks, failures, "all_round2_event_kinds_present", not missing)
    if missing:
        failures.append(f"missing_round2_event_kinds:{missing}")
    if failures or not all(checks.values()):
        raise P1RValidationError(_report(False, failures, checks))
    return [normalized_by_event[kind] for kind in ROUND2_EVENT_ORDER]


def _normalize_source_entry(
    record: dict[str, Any],
    defaults: dict[str, Any],
    source_event_kind: str,
    catalog: dict[str, str],
) -> dict[str, Any]:
    ref_field = catalog["ref_field"]
    attestation_ref = str(record.get("attestation_ref") or record.get(ref_field) or "").strip()
    entry = {
        "source_event_kind": source_event_kind,
        "evidence_kind": catalog["evidence_kind"],
        "required_kind_ref_field": ref_field,
        "artifact_id": record.get("artifact_id") or f"p1r-{source_event_kind}-{_safe_ref_suffix(attestation_ref)}",
        "reviewer": record.get("reviewer") or defaults.get("reviewer"),
        "reviewer_role": record.get("reviewer_role") or catalog["reviewer_role"],
        "source": record.get("source") or defaults.get("source") or defaults.get("source_provider"),
        "status": record.get("status") or catalog["status"],
        "attestation_ref": attestation_ref,
        ref_field: record.get(ref_field) or attestation_ref,
        "source_uri": record.get("source_uri") or defaults.get("source_uri"),
        "source_provider": record.get("source_provider") or defaults.get("source_provider"),
        "captured_at": record.get("captured_at") or defaults.get("captured_at"),
        "evidence_summary": record.get("evidence_summary"),
    }
    for optional_field in ("source_artifact_sha256", "risk_level", "rollback_required"):
        if optional_field in record:
            entry[optional_field] = record[optional_field]
    return entry


def _apply_operator_attested_pilot_overlay(
    *,
    source_event_kind: str,
    entry: dict[str, Any],
    raw_record: dict[str, Any],
    operator_attestation: dict[str, Any],
) -> dict[str, Any]:
    overlaid = dict(entry)
    raw_text = json.dumps(raw_record, ensure_ascii=False, sort_keys=True).lower()
    markers = _pending_markers_in_text(raw_text)
    reviewer = str(overlaid.get("reviewer") or "")
    if "unassigned" in reviewer.lower():
        overlaid["reviewer"] = operator_attestation["operator_attester"]
    if markers:
        overlaid["raw_evidence_summary"] = overlaid.get("evidence_summary")
        overlaid["evidence_summary"] = (
            f"Operator-attested controlled production pilot evidence for {source_event_kind}; "
            f"raw generated marker was superseded by operator attestation "
            f"{operator_attestation['operator_attestation_statement_sha256'][:12]}."
        )
    overlaid["operator_attested_production"] = True
    overlaid["operator_attestation_statement_sha256"] = operator_attestation[
        "operator_attestation_statement_sha256"
    ]
    overlaid["operator_attestation_scope"] = operator_attestation["scope"]
    overlaid["raw_record_sha256"] = sha256_json(raw_record)
    overlaid["raw_pending_markers_detected"] = markers
    return overlaid


def _validate_normalized_entry(
    source_event_kind: str,
    entry: dict[str, Any],
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    required_fields = (
        "artifact_id",
        "reviewer",
        "reviewer_role",
        "source",
        "status",
        "attestation_ref",
        "source_uri",
        "source_provider",
        "captured_at",
        "evidence_summary",
        EVENT_CATALOG[source_event_kind]["ref_field"],
    )
    for field in required_fields:
        check(checks, failures, f"{source_event_kind}_{field}_present", bool(str(entry.get(field) or "").strip()))
    source = str(entry.get("source") or "").lower()
    source_provider = str(entry.get("source_provider") or "").lower()
    source_uri = str(entry.get("source_uri") or "").lower()
    evidence_summary = str(entry.get("evidence_summary") or "").lower()
    reviewer = str(entry.get("reviewer") or "").lower()
    attestation_ref = str(entry.get("attestation_ref") or "").lower()
    ref_field = str(entry.get(EVENT_CATALOG[source_event_kind]["ref_field"]) or "").lower()
    check(
        checks,
        failures,
        f"{source_event_kind}_source_not_non_production",
        not _has_forbidden_source_marker(
            source,
            source_provider,
            " ".join([source_uri, evidence_summary, reviewer, attestation_ref, ref_field]),
        ),
    )
    catalog = EVENT_CATALOG[source_event_kind]
    check(checks, failures, f"{source_event_kind}_reviewer_role_expected", entry.get("reviewer_role") == catalog["reviewer_role"])
    check(checks, failures, f"{source_event_kind}_status_expected", entry.get("status") == catalog["status"])


def _has_forbidden_source_marker(source: str, source_provider: str, source_uri: str) -> bool:
    source_text = " ".join([source, source_provider])
    if any(token in source_text for token in FORBIDDEN_SOURCE_TOKENS):
        return True
    pending_markers = (
        "verification-pending",
        "unassigned",
        "generated intake marker",
        "no real production-origin evidence was supplied",
        "not an approval or attestation",
    )
    uri_markers = (
        "local://",
        "mock://",
        "fixture://",
        "synthetic",
        "candidate_ref",
        "candidate-only",
        "placeholder",
        "todo_replace",
        "demo://",
        *pending_markers,
    )
    return any(marker in source_uri for marker in uri_markers)


def _pending_markers_in_text(value: str) -> list[str]:
    markers = (
        "verification-pending",
        "unassigned",
        "generated intake marker",
        "no real production-origin evidence was supplied",
        "not an approval or attestation",
    )
    return [marker for marker in markers if marker in value]


def _write_confirmation_packet(
    *,
    output: Path,
    context: dict[str, Any],
    confirmations: dict[str, dict[str, Any]],
    normalized_sources: list[dict[str, Any]],
    confirmation_paths: dict[str, Path],
    evidence_profile: str,
    operator_attestation: dict[str, Any] | None,
) -> dict[str, Any]:
    packet = {
        "schema_version": CONFIRMATION_PACKET_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "recorded_at": _now(),
        "confirmation_roles": list(ROLE_CONFIRMATION_FILES),
        "confirmation_artifacts": {role: artifact_ref(path) for role, path in confirmation_paths.items()},
        "source_artifacts": context.get("source_artifacts", {}),
        "normalized_source_count": len(normalized_sources),
        "normalized_source_event_kinds": [entry["source_event_kind"] for entry in normalized_sources],
        "confirmed_by": {role: confirmations[role].get("confirmed_by") for role in ROLE_CONFIRMATION_FILES},
        "evidence_profile": evidence_profile,
        "operator_attestation": operator_attestation,
        "operator_attested_production": operator_attestation is not None,
        "raw_pending_marker_event_count": sum(
            1 for entry in normalized_sources if entry.get("raw_pending_markers_detected")
        ),
        "production_origin_confirmed": True,
        "candidate_ref_promoted": False,
        "boundary": _boundary(source_confirmation_collected=True),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, packet)
    return packet


def _write_source_manifest(
    *,
    output: Path,
    goal_id: str,
    normalized_sources: list[dict[str, Any]],
    packet_path: Path,
) -> dict[str, Any]:
    manifest = {
        "schema_version": SOURCE_MANIFEST_SCHEMA,
        "goal_id": goal_id,
        "evidence_sources": normalized_sources,
        "production_runtime_execution_allowed": False,
        "production_runtime_receipt_allowed": False,
        "agent_loop_start_allowed": False,
        "llm_planning_allowed": False,
        "external_system_mutation_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
        "source_artifacts": {"p1r_confirmation_packet": artifact_ref(packet_path)},
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, manifest)
    return {
        "schema_version": "p1r-round2-source-manifest-write-report:v1",
        "passed": True,
        "output": str(output.resolve()),
        "source_entry_count": len(normalized_sources),
        "required_source_entry_count": len(ROUND2_EVENT_ORDER),
        "boundary": _boundary(source_manifest_written=True),
        "non_claims": list(NON_CLAIMS),
    }


def _load_evidence_ledger_tools(evidence_ledger_src: Path | None) -> dict[str, Callable[..., dict[str, Any]]]:
    src_path = evidence_ledger_src or _default_evidence_ledger_src()
    if src_path and src_path.is_dir() and str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    try:
        from civitasos_evidence_ledger.round2_source_manifest import (  # type: ignore[import-not-found]
            assemble_round2_real_evidence_submission,
            validate_round2_real_evidence_source_manifest,
        )
    except Exception as exc:  # noqa: BLE001
        raise P1RValidationError(_report(False, [f"evidence_ledger_round2_tools_unavailable:{exc}"], {})) from exc
    return {
        "validate_source_manifest": validate_round2_real_evidence_source_manifest,
        "assemble_submission": assemble_round2_real_evidence_submission,
    }


def _default_evidence_ledger_src() -> Path:
    return Path(__file__).resolve().parents[2] / "civitasos-evidence-ledger" / "src"


def _check_artifact_refs(summary: dict[str, Any], checks: dict[str, bool], failures: list[str], prefix: str) -> None:
    for name, value in object_value(summary.get("artifacts")).items():
        ref = object_value(value)
        path = Path(str(ref.get("path") or ""))
        expected_hash = str(ref.get("sha256") or "")
        check(checks, failures, f"{prefix}_{name}_path_present", path.is_file())
        if path.is_file():
            check(checks, failures, f"{prefix}_{name}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)


def _p0q_links_p1(p0q: dict[str, Any], p1_summary_path: Path) -> bool:
    ref = object_value(object_value(p0q.get("source_artifacts")).get("p1_summary"))
    return bool(ref.get("sha256")) and p1_summary_path.is_file() and sha256_file(p1_summary_path) == ref.get("sha256")


def _boundary_closed(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "runtime_execution_allowed",
        "vm_contact_performed",
        "external_system_contact_performed",
        "preview_command_executed",
        "deploy_performed",
        "external_public_ingress_opened",
        "production_data_accessed",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "l2_anchor_written",
        "independent_verification_written",
        "secrets_recorded",
        "source_tree_write_performed",
        "git_write_performed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _summary(
    *,
    passed: bool,
    failures: list[str],
    p0q_summary_path: Path,
    p1_summary_path: Path,
    confirmation_paths: dict[str, Path],
    artifacts: dict[str, Path],
    readiness_state: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    production_submission_path = artifacts.get("production_evidence_submission")
    source_manifest_path = artifacts.get("source_manifest")
    gap_map_path = artifacts.get("gap_map")
    return {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": sorted(set(str(item) for item in failures)),
        "source_artifacts": {
            "p0q_summary": artifact_ref(p0q_summary_path) if p0q_summary_path.is_file() else {"path": str(p0q_summary_path)},
            "p1_summary": artifact_ref(p1_summary_path) if p1_summary_path.is_file() else {"path": str(p1_summary_path)},
            "confirmations": {
                role: artifact_ref(path) if path.is_file() else {"path": str(path)}
                for role, path in confirmation_paths.items()
            },
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if path.is_file()},
        "readiness": {
            "state": readiness_state,
            "p1r_real_source_confirmation_complete": passed,
            "round2_source_manifest_ready": bool(source_manifest_path and source_manifest_path.is_file()) and passed,
            "round2_production_evidence_submission_ready": bool(production_submission_path and production_submission_path.is_file()) and passed,
            "h3_gap_map_complete": bool(gap_map_path and gap_map_path.is_file()) and passed,
            "h3_bundle_validation_ready": False,
            "l2_external_anchor_input_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            source_confirmation_collected=passed,
            source_manifest_written=bool(source_manifest_path and source_manifest_path.is_file()),
            production_evidence_submission_written=bool(production_submission_path and production_submission_path.is_file()) and passed,
            h3_gap_mapper_rerun=bool(gap_map_path and gap_map_path.is_file()) and passed,
        ),
        "non_claims": list(NON_CLAIMS),
        **(extra or {}),
    }


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "source_confirmation_collected": False,
        "source_manifest_written": False,
        "production_evidence_submission_written": False,
        "h3_gap_mapper_rerun": False,
        "runtime_execution_allowed": False,
        "vm_contact_performed": False,
        "external_system_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_data_accessed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "l2_anchor_written": False,
        "independent_verification_written": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


def _report(passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": "p1r-validation-report:v1",
        "passed": passed,
        "failure_reasons": sorted(set(str(item) for item in failures)),
        "checks": checks,
        "checked_at": _now(),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _safe_ref_suffix(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip())
    safe = "-".join(part for part in safe.split("-") if part)
    return safe[:48] or "missing-ref"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P1-R real source confirmation gate")
    parser.add_argument("--p0q-summary", required=True, type=Path)
    parser.add_argument("--p1-summary", required=True, type=Path)
    parser.add_argument("--owner-confirmation", required=True, type=Path)
    parser.add_argument("--audit-confirmation", required=True, type=Path)
    parser.add_argument("--monitoring-confirmation", required=True, type=Path)
    parser.add_argument("--rollback-confirmation", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--evidence-ledger-src", type=Path)
    parser.add_argument("--operator-attested-controlled-pilot", action="store_true")
    parser.add_argument("--operator-attested-production", action="store_true")
    parser.add_argument("--operator-attester")
    parser.add_argument("--operator-attestation-statement")
    args = parser.parse_args()
    summary = run_gate(
        p0q_summary_path=args.p0q_summary,
        p1_summary_path=args.p1_summary,
        owner_confirmation_path=args.owner_confirmation,
        audit_confirmation_path=args.audit_confirmation,
        monitoring_confirmation_path=args.monitoring_confirmation,
        rollback_confirmation_path=args.rollback_confirmation,
        output_root=args.output_root,
        evidence_ledger_src=args.evidence_ledger_src,
        operator_attested_controlled_pilot=args.operator_attested_controlled_pilot,
        operator_attested_production=args.operator_attested_production,
        operator_attester=args.operator_attester,
        operator_attestation_statement=args.operator_attestation_statement,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
