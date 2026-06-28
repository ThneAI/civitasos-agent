"""Map P0/P1 artifacts to H.3 production evidence gaps.

The mapper is intentionally conservative. P0/P1 artifacts can become candidate
refs for the 16 Round 2 evidence kinds, but they are not production-origin
evidence by themselves. A kind is marked satisfied only when a supplied
production evidence submission contains a structurally valid production record
without local/test/mock/synthetic markers.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
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
from benchmarks.i_gate_evidence import artifact_ref, object_value, read_json_object, write_json_object
from benchmarks.p0n_controlled_beta_entry_gate import CHAIN_SCHEMA as P0N_CHAIN_SCHEMA
from benchmarks.p0o_first_controlled_beta_task_authorization_gate import CHAIN_SCHEMA as P0O_CHAIN_SCHEMA
from benchmarks.p0p_first_controlled_beta_task_execution_gate import CHAIN_SCHEMA as P0P_CHAIN_SCHEMA
from benchmarks.p1_controlled_production_pilot_charter_gate import CHAIN_SCHEMA as P1_CHAIN_SCHEMA

SCHEMA_VERSION = "h3-production-evidence-gap-map:v1"
NON_CLAIMS = (
    "gap_mapper_does_not_create_production_evidence",
    "p0_p1_candidate_refs_do_not_satisfy_round2_by_themselves",
    "production_evidence_satisfaction_requires_operator_supplied_real_records",
    "gap_mapper_does_not_write_l2_anchor_or_verification",
    "gap_mapper_does_not_authorize_runtime_execution_or_production_transition",
)


def run_mapper(
    *,
    output: Path,
    p0n_summary_path: Path | None = None,
    p0o_summary_path: Path | None = None,
    p0p_summary_path: Path | None = None,
    p1_summary_path: Path | None = None,
    production_evidence_path: Path | None = None,
) -> dict[str, Any]:
    contexts = _load_contexts(
        p0n_summary_path=p0n_summary_path,
        p0o_summary_path=p0o_summary_path,
        p0p_summary_path=p0p_summary_path,
        p1_summary_path=p1_summary_path,
    )
    production_records = _load_production_records(production_evidence_path)
    items = []
    for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS:
        record = production_records.get(kind)
        production_valid = _production_record_valid(kind, record) if record else False
        candidates = _candidate_refs_for_kind(kind, contexts)
        items.append(
            {
                "evidence_kind": kind,
                "required_ref_field": PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind],
                "production_satisfied": production_valid,
                "production_record_artifact_id": record.get("artifact_id") if production_valid and record else None,
                "candidate_ref_count": len(candidates),
                "candidate_refs": candidates,
                "gap_reason": "satisfied_by_real_production_record"
                if production_valid
                else _gap_reason(candidates, record),
            }
        )
    satisfied_count = sum(1 for item in items if item["production_satisfied"])
    summary = {
        "schema_version": SCHEMA_VERSION,
        "passed": True,
        "checked_at": _now(),
        "source_artifacts": _source_artifacts(
            p0n_summary_path=p0n_summary_path,
            p0o_summary_path=p0o_summary_path,
            p0p_summary_path=p0p_summary_path,
            p1_summary_path=p1_summary_path,
            production_evidence_path=production_evidence_path,
        ),
        "counts": {
            "required_evidence_count": len(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
            "production_satisfied_count": satisfied_count,
            "production_missing_count": len(REQUIRED_PRODUCTION_EVIDENCE_KINDS) - satisfied_count,
            "candidate_ref_count": sum(int(item["candidate_ref_count"]) for item in items),
        },
        "readiness": {
            "round2_complete": satisfied_count == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
            "h3_bundle_validation_ready": satisfied_count == len(REQUIRED_PRODUCTION_EVIDENCE_KINDS),
            "production_transition_allowed": False,
        },
        "gap_items": items,
        "boundary": {
            "mapping_only": True,
            "runtime_execution_allowed": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
            "l2_anchor_written": False,
            "independent_verification_written": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, summary)
    return summary


def _load_contexts(
    *,
    p0n_summary_path: Path | None,
    p0o_summary_path: Path | None,
    p0p_summary_path: Path | None,
    p1_summary_path: Path | None,
) -> dict[str, dict[str, Any]]:
    contexts: dict[str, dict[str, Any]] = {}
    for key, path, schema in (
        ("p0n", p0n_summary_path, P0N_CHAIN_SCHEMA),
        ("p0o", p0o_summary_path, P0O_CHAIN_SCHEMA),
        ("p0p", p0p_summary_path, P0P_CHAIN_SCHEMA),
        ("p1", p1_summary_path, P1_CHAIN_SCHEMA),
    ):
        if path is None:
            continue
        payload = read_json_object(path)
        contexts[key] = {
            "path": path,
            "payload": payload,
            "schema_valid": payload.get("schema_version") == schema,
            "passed": payload.get("passed") is True,
        }
    return contexts


def _load_production_records(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    payload = read_json_object(path)
    if payload.get("schema_version") != PRODUCTION_EVIDENCE_SCHEMA_VERSION:
        return {}
    records = payload.get("production_evidence_records")
    if not isinstance(records, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        if isinstance(record, dict):
            result[str(record.get("evidence_kind") or "")] = record
    return result


def _production_record_valid(kind: str, record: dict[str, Any] | None) -> bool:
    if not record:
        return False
    if record.get("evidence_kind") != kind:
        return False
    common_fields_present = all(
        field in record and str(record.get(field) or "").strip()
        for field in PRODUCTION_EVIDENCE_COMMON_FIELDS
    )
    if not common_fields_present:
        return False
    ref_field = PRODUCTION_EVIDENCE_KIND_REF_FIELDS[kind]
    if not str(record.get(ref_field) or "").strip():
        return False
    if record.get("status") not in ACCEPTED_PRODUCTION_STATUSES:
        return False
    source = str(record.get("source") or "").lower()
    if any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS):
        return False
    forbidden_text = json.dumps(record, ensure_ascii=False).lower()
    return not any(token in forbidden_text for token in ("todo_replace", "template_only", "placeholder"))


def _candidate_refs_for_kind(kind: str, contexts: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    p0n = contexts.get("p0n")
    p0o = contexts.get("p0o")
    p0p = contexts.get("p0p")
    p1 = contexts.get("p1")
    if kind in {"activation_artifact_chain_attestation", "challenge_r2r_rollback_attestation"}:
        _append_context_ref(refs, p0n, "p0n_controlled_beta_entry_package")
    if kind in {"governance_runtime_execution_approval", "activation_artifact_chain_attestation"}:
        _append_context_ref(refs, p0o, "p0o_single_use_authorization_package")
    if kind in {
        "external_human_review_approval",
        "governance_runtime_execution_approval",
        "activation_artifact_chain_attestation",
        "runtime_safety_envelope",
        "rollback_drill_attestation",
        "operator_oncall_ack",
    }:
        _append_context_ref(refs, p0p, "p0p_first_controlled_beta_task_execution")
    if kind in {
        "external_human_review_approval",
        "governance_runtime_execution_approval",
        "runtime_safety_envelope",
        "rollout_window_approval",
        "live_monitoring_attestation",
        "rollback_drill_attestation",
        "operator_oncall_ack",
        "kill_switch_attestation",
        "runtime_start_change_ticket",
        "runtime_start_dual_operator_ack",
        "runtime_start_final_monitoring_green",
        "runtime_start_final_kill_switch_check",
        "runtime_start_rollback_checkpoint",
        "runtime_start_audit_sink_ready",
    }:
        _append_context_ref(refs, p1, "p1_charter_candidate_ref")
    return refs


def _append_context_ref(refs: list[dict[str, str]], context: dict[str, Any] | None, label: str) -> None:
    if not context or context.get("passed") is not True or context.get("schema_valid") is not True:
        return
    path = context["path"]
    refs.append(
        {
            "label": label,
            "path": str(path.resolve()),
            "sha256": artifact_ref(path)["sha256"],
            "satisfies_production_origin": "false",
            "reason": "candidate_ref_only_not_real_production_origin_evidence",
        }
    )


def _gap_reason(candidates: list[dict[str, str]], record: dict[str, Any] | None) -> str:
    if record:
        return "production_record_present_but_invalid_or_non_production_source"
    if candidates:
        return "candidate_refs_present_but_missing_real_production_origin_record"
    return "missing_real_production_origin_record_and_candidate_ref"


def _source_artifacts(
    *,
    p0n_summary_path: Path | None,
    p0o_summary_path: Path | None,
    p0p_summary_path: Path | None,
    p1_summary_path: Path | None,
    production_evidence_path: Path | None,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for key, path in (
        ("p0n_summary", p0n_summary_path),
        ("p0o_summary", p0o_summary_path),
        ("p0p_summary", p0p_summary_path),
        ("p1_summary", p1_summary_path),
        ("production_evidence_submission", production_evidence_path),
    ):
        if path is not None and path.is_file():
            result[key] = artifact_ref(path)
    return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Map P0/P1 artifacts to H.3 production evidence gaps")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--p0n-summary", type=Path)
    parser.add_argument("--p0o-summary", type=Path)
    parser.add_argument("--p0p-summary", type=Path)
    parser.add_argument("--p1-summary", type=Path)
    parser.add_argument("--production-evidence-submission", type=Path)
    args = parser.parse_args()
    summary = run_mapper(
        output=args.output,
        p0n_summary_path=args.p0n_summary,
        p0o_summary_path=args.p0o_summary,
        p0p_summary_path=args.p0p_summary,
        p1_summary_path=args.p1_summary,
        production_evidence_path=args.production_evidence_submission,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
