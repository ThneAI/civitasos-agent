"""Run P0-Q / P1 source-ref collection gate.

P0-Q consumes a passed P0-P controlled beta task execution summary and a passed
P1 controlled production pilot charter summary. It packages owner/audit/
monitoring/rollback source refs for later real production-origin confirmation.
It does not claim that those refs are production evidence, and it does not
authorize runtime production transition.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0p_first_controlled_beta_task_execution_gate import CHAIN_SCHEMA as P0P_CHAIN_SCHEMA
from benchmarks.p1_controlled_production_pilot_charter_gate import CHAIN_SCHEMA as P1_CHAIN_SCHEMA

CHAIN_SCHEMA = "p0q-p1-source-ref-collection-chain:v1"
CONTEXT_SCHEMA = "p0q-p1-source-ref-context-validation:v1"
SOURCE_REF_SCHEMA = "p0q-p1-source-ref:v1"
INDEX_SCHEMA = "p0q-p1-source-ref-index:v1"

ROLE_TO_OWNER_FIELD = {
    "owner": "owner_id",
    "audit": "audit_owner_id",
    "monitoring": "monitoring_owner_id",
    "rollback": "rollback_owner_id",
}

H3_KIND_HINTS = {
    "owner": [
        "external_human_review_approval",
        "operator_oncall_ack",
        "governance_runtime_execution_approval",
    ],
    "audit": [
        "runtime_safety_envelope",
        "runtime_start_audit_sink_ready",
        "operator_oncall_ack",
    ],
    "monitoring": [
        "live_monitoring_attestation",
        "runtime_start_final_monitoring_green",
        "activation_artifact_chain_attestation",
    ],
    "rollback": [
        "rollback_drill_attestation",
        "runtime_start_rollback_checkpoint",
        "kill_switch_attestation",
    ],
}

NON_CLAIMS = (
    "p0q_collects_candidate_source_refs_only",
    "p0q_source_refs_do_not_satisfy_h3_production_origin_by_themselves",
    "p0q_requires_later_external_owner_audit_monitoring_rollback_confirmation",
    "p0q_does_not_contact_vms_or_external_systems",
    "p0q_does_not_write_l2_anchor_or_independent_verification",
    "p0q_does_not_authorize_runtime_execution_or_production_transition",
    "p0q_does_not_write_production_receipts",
)


class ContextValidationError(RuntimeError):
    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__("p0q_context_validation_failed")
        self.report = report


def run_gate(
    *,
    p0p_summary_path: Path,
    p1_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "owner_source_ref": output_root / "p0q_owner_source_ref.json",
        "audit_source_ref": output_root / "p0q_audit_source_ref.json",
        "monitoring_source_ref": output_root / "p0q_monitoring_source_ref.json",
        "rollback_source_ref": output_root / "p0q_rollback_source_ref.json",
        "source_ref_index": output_root / "p0q_p1_source_ref_index.json",
        "summary": output_root / "p0q_p1_source_ref_collection_summary.json",
    }
    try:
        context = validate_context(p0p_summary_path=p0p_summary_path, p1_summary_path=p1_summary_path)
    except ContextValidationError as exc:
        summary = _summary(
            passed=False,
            failures=exc.report.get("failure_reasons", []),
            p0p_summary_path=p0p_summary_path,
            p1_summary_path=p1_summary_path,
            artifacts={},
            readiness_state="blocked_p0q_context_validation",
            source_ref_collection_complete=False,
            boundary=_boundary(),
            extra={"context_validation": exc.report},
        )
        write_json_object(artifacts["summary"], summary)
        return summary

    refs = {
        role: _write_source_ref(
            output=artifacts[f"{role}_source_ref"],
            role=role,
            context=context,
            operator_id=operator_id,
        )
        for role in ("owner", "audit", "monitoring", "rollback")
    }
    index = _write_index(
        output=artifacts["source_ref_index"],
        context=context,
        source_ref_paths={role: artifacts[f"{role}_source_ref"] for role in refs},
    )
    reports = [context, index, *refs.values()]
    failures = _failures(reports)
    checks = {
        "context_passed": context.get("passed") is True,
        "all_source_refs_written": all(ref.get("passed") is True for ref in refs.values()),
        "index_written": index.get("passed") is True,
        "no_ref_claims_production_origin": all(ref.get("satisfies_production_origin") is False for ref in refs.values()),
    }
    for name, passed in list(checks.items()):
        if not passed and name not in failures:
            failures.append(name)
    passed = _passed(checks, failures)
    summary = _summary(
        passed=passed,
        failures=failures,
        p0p_summary_path=p0p_summary_path,
        p1_summary_path=p1_summary_path,
        artifacts={name: path for name, path in artifacts.items() if name != "summary"},
        readiness_state="p0q_p1_source_ref_collection_ready" if passed else "blocked_p0q_p1_source_ref_collection",
        source_ref_collection_complete=passed,
        boundary=_boundary(source_ref_collection_written=passed),
        extra={
            "checked_at": _now(),
            "operator_id": operator_id,
            "checks": checks,
            "source_ref_roles": sorted(refs),
            "source_ref_count": len(refs),
            "candidate_source_artifact_count": int(index.get("candidate_source_artifact_count") or 0),
            "h3_kind_hints": H3_KIND_HINTS,
        },
    )
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_context(*, p0p_summary_path: Path, p1_summary_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        p0p = read_json_object(p0p_summary_path)
        p1 = read_json_object(p1_summary_path)
    except Exception as exc:  # noqa: BLE001
        report = _report(CONTEXT_SCHEMA, False, [f"context_unreadable:{exc}"], checks)
        raise ContextValidationError(report) from exc

    check(checks, failures, "p0p_summary_passed", p0p.get("schema_version") == P0P_CHAIN_SCHEMA and p0p.get("passed") is True)
    check(checks, failures, "p1_summary_passed", p1.get("schema_version") == P1_CHAIN_SCHEMA and p1.get("passed") is True)
    check(checks, failures, "p0p_boundary_closed", _p0p_boundary_closed(object_value(p0p.get("boundary"))))
    check(checks, failures, "p1_boundary_closed", _p1_boundary_closed(object_value(p1.get("boundary"))))
    check(checks, failures, "p0p_source_refs_ready", object_value(p0p.get("readiness")).get("p1_h3_source_ref_collection_ready") is True)
    check(checks, failures, "p1_collection_ready", object_value(p1.get("readiness")).get("h3_production_evidence_collection_ready") is True)
    check(checks, failures, "p0p_production_transition_closed", object_value(p0p.get("readiness")).get("production_transition_allowed") is False)
    check(checks, failures, "p1_production_transition_closed", object_value(p1.get("readiness")).get("production_transition_allowed") is False)

    p0p_artifacts = _read_verified_artifacts(p0p, checks, failures, prefix="p0p")
    p1_artifacts = _read_verified_artifacts(p1, checks, failures, prefix="p1")
    p0p_p0o_ref = object_value(object_value(p0p.get("source_artifacts")).get("p0o_summary"))
    p1_p0o_ref = object_value(object_value(p1.get("source_artifacts")).get("p0o_summary"))
    check(checks, failures, "p0p_p1_share_p0o_source", bool(p0p_p0o_ref) and bool(p1_p0o_ref) and p0p_p0o_ref.get("sha256") == p1_p0o_ref.get("sha256"))

    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "p0p_summary": p0p,
        "p1_summary": p1,
        "p0p_artifacts": p0p_artifacts,
        "p1_artifacts": p1_artifacts,
        "source_artifacts": {
            "p0p_summary": artifact_ref(p0p_summary_path),
            "p1_summary": artifact_ref(p1_summary_path),
        },
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    if not passed:
        raise ContextValidationError(report)
    return report


def _write_source_ref(*, output: Path, role: str, context: dict[str, Any], operator_id: str) -> dict[str, Any]:
    owners = object_value(object_value(context.get("p1_summary")).get("owners"))
    owner_field = ROLE_TO_OWNER_FIELD[role]
    source_artifacts = _role_artifacts(role, context)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    check(checks, failures, "role_known", role in ROLE_TO_OWNER_FIELD)
    check(checks, failures, "role_owner_present", bool(str(owners.get(owner_field) or "").strip()))
    check(checks, failures, "source_artifacts_present", bool(source_artifacts))
    check(checks, failures, "source_artifact_hashes_bound", all(_ref_hash_matches(ref) for ref in source_artifacts.values()))
    passed = _passed(checks, failures)
    value = {
        "schema_version": SOURCE_REF_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "operator_id": operator_id,
        "source_ref_role": role,
        "source_owner_field": owner_field,
        "source_owner_id": owners.get(owner_field),
        "source_artifacts": source_artifacts,
        "candidate_only": True,
        "satisfies_production_origin": False,
        "requires_real_external_confirmation": True,
        "required_confirmation": {
            "confirmed_by": owners.get(owner_field),
            "confirmation_must_originate_from": f"real_{role}_system_or_operator_record",
            "forbidden_sources": ["local_fixture", "synthetic", "candidate_ref", "simulated_owner_confirmation"],
        },
        "h3_evidence_kind_hints": H3_KIND_HINTS[role],
        "boundary": _boundary(source_ref_collection_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _write_index(*, output: Path, context: dict[str, Any], source_ref_paths: dict[str, Path]) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    source_ref_artifacts = {role: artifact_ref(path) for role, path in source_ref_paths.items() if path.is_file()}
    check(checks, failures, "all_role_source_refs_present", set(source_ref_artifacts) == set(ROLE_TO_OWNER_FIELD))
    check(checks, failures, "context_passed", context.get("passed") is True)
    passed = _passed(checks, failures)
    value = {
        "schema_version": INDEX_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "source_ref_artifacts": source_ref_artifacts,
        "candidate_source_artifact_count": sum(len(_role_artifacts(role, context)) for role in ROLE_TO_OWNER_FIELD),
        "source_artifacts": context.get("source_artifacts", {}),
        "candidate_only": True,
        "satisfies_production_origin": False,
        "h3_bundle_validation_ready": False,
        "production_transition_allowed": False,
        "boundary": _boundary(source_ref_collection_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, value)
    return value


def _role_artifacts(role: str, context: dict[str, Any]) -> dict[str, dict[str, str]]:
    p0p = object_value(context.get("p0p_artifacts"))
    p1 = object_value(context.get("p1_artifacts"))
    role_labels = {
        "owner": (
            ("p0p_controlled_beta_artifact", p0p.get("controlled_beta_artifact")),
            ("p0p_owner_audit_rollback_review", p0p.get("owner_audit_rollback_review")),
            ("p1_charter", p1.get("charter")),
            ("p1_operator_acceptance", p1.get("operator_acceptance")),
        ),
        "audit": (
            ("p0p_no_production_attestation", p0p.get("no_production_attestation")),
            ("p0p_owner_audit_rollback_review", p0p.get("owner_audit_rollback_review")),
            ("p1_evidence_collection_plan", p1.get("evidence_collection_plan")),
            ("p1_operator_acceptance", p1.get("operator_acceptance")),
        ),
        "monitoring": (
            ("p0p_task_pool_execution_receipt", p0p.get("task_pool_execution_receipt")),
            ("p0p_callback_sink_receipt", p0p.get("callback_sink_receipt")),
            ("p0p_controlled_beta_artifact", p0p.get("controlled_beta_artifact")),
            ("p1_evidence_collection_plan", p1.get("evidence_collection_plan")),
        ),
        "rollback": (
            ("p0p_rollback_or_abort_receipt", p0p.get("rollback_or_abort_receipt")),
            ("p0p_no_production_attestation", p0p.get("no_production_attestation")),
            ("p1_evidence_collection_plan", p1.get("evidence_collection_plan")),
        ),
    }
    return {label: ref for label, ref in role_labels[role] if isinstance(ref, dict) and ref.get("path") and ref.get("sha256")}


def _read_verified_artifacts(summary: dict[str, Any], checks: dict[str, bool], failures: list[str], *, prefix: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    artifacts = object_value(summary.get("artifacts"))
    for name, value in artifacts.items():
        ref = object_value(value)
        path = Path(str(ref.get("path") or ""))
        expected_hash = str(ref.get("sha256") or "")
        check(checks, failures, f"{prefix}_{name}_path_present", path.is_file())
        if not path.is_file():
            continue
        check(checks, failures, f"{prefix}_{name}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
        result[name] = artifact_ref(path)
    return result


def _ref_hash_matches(ref: dict[str, str]) -> bool:
    path = Path(str(ref.get("path") or ""))
    return path.is_file() and sha256_file(path) == ref.get("sha256")


def _p0p_boundary_closed(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "demo_login_used",
        "vm_contact_performed",
        "source_tree_write_performed",
        "git_write_performed",
        "deploy_performed",
        "external_public_ingress_opened",
        "production_data_accessed",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "secrets_recorded",
    )
    required_true_keys = (
        "service_token_used",
        "authorization_consumed",
        "task_pool_post_performed",
        "task_pool_claim_performed",
        "task_pool_execute_performed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys) and all(boundary.get(key) is True for key in required_true_keys)


def _p1_boundary_closed(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "runtime_execution_allowed",
        "vm_contact_performed",
        "preview_command_executed",
        "external_public_ingress_opened",
        "production_data_accessed",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "secrets_recorded",
        "source_tree_write_performed",
        "git_write_performed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _summary(
    *,
    passed: bool,
    failures: list[str],
    p0p_summary_path: Path,
    p1_summary_path: Path,
    artifacts: dict[str, Path],
    readiness_state: str,
    source_ref_collection_complete: bool,
    boundary: dict[str, bool],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": sorted(set(str(item) for item in failures)),
        "source_artifacts": {
            "p0p_summary": artifact_ref(p0p_summary_path) if p0p_summary_path.is_file() else {"path": str(p0p_summary_path)},
            "p1_summary": artifact_ref(p1_summary_path) if p1_summary_path.is_file() else {"path": str(p1_summary_path)},
        },
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if path.is_file()},
        "readiness": {
            "state": readiness_state,
            "p0q_p1_source_ref_collection_complete": source_ref_collection_complete,
            "p1_real_source_confirmation_ready": source_ref_collection_complete,
            "h3_bundle_validation_ready": False,
            "production_transition_allowed": False,
        },
        "boundary": boundary,
        "non_claims": list(NON_CLAIMS),
        **(extra or {}),
    }


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "context_validation_written": False,
        "source_ref_collection_written": False,
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


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "boundary": _boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return failures


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-Q / P1 source-ref collection gate")
    parser.add_argument("--p0p-summary", required=True, type=Path)
    parser.add_argument("--p1-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--operator-id", default="operator-cc")
    args = parser.parse_args()
    summary = run_gate(
        p0p_summary_path=args.p0p_summary,
        p1_summary_path=args.p1_summary,
        output_root=args.output_root,
        operator_id=args.operator_id,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
