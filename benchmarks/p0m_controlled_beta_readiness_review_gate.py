"""Run P0-M controlled beta readiness review gate.

P0-M consumes a passed P0-L external preview evidence summary and reviews the
P0-A..P0-L chain for controlled beta readiness. It is evidence-only: it does
not contact VMs, deploy services, mutate source/Git, open public ingress,
authorize production transition, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0a_task_intake_gate import CHAIN_SCHEMA as P0A_CHAIN_SCHEMA
from benchmarks.p0b_agent_proposal_gate import CHAIN_SCHEMA as P0B_CHAIN_SCHEMA
from benchmarks.p0c_controlled_execution_authorization_gate import CHAIN_SCHEMA as P0C_AUTH_CHAIN_SCHEMA
from benchmarks.p0c_controlled_task_pool_execution import CHAIN_SCHEMA as P0C_EXEC_CHAIN_SCHEMA
from benchmarks.p0d_preview_smoke_gate import CHAIN_SCHEMA as P0D_CHAIN_SCHEMA
from benchmarks.p0e_rollback_abort_drill_gate import CHAIN_SCHEMA as P0E_CHAIN_SCHEMA
from benchmarks.p0f_vm_preview_preflight_gate import CHAIN_SCHEMA as P0F_CHAIN_SCHEMA
from benchmarks.p0g_single_vm_private_preview_gate import CHAIN_SCHEMA as P0G_CHAIN_SCHEMA
from benchmarks.p0h_private_preview_owner_review_gate import CHAIN_SCHEMA as P0H_CHAIN_SCHEMA
from benchmarks.p0i_vm_service_private_preview_gate import CHAIN_SCHEMA as P0I_CHAIN_SCHEMA
from benchmarks.p0j_multi_vm_private_preview_gate import CHAIN_SCHEMA as P0J_CHAIN_SCHEMA
from benchmarks.p0k_private_preview_soak_gate import CHAIN_SCHEMA as P0K_CHAIN_SCHEMA
from benchmarks.p0l_external_preview_evidence_gate import (
    AUDIT_REVIEW_SCHEMA as P0L_AUDIT_REVIEW_SCHEMA,
    CHAIN_SCHEMA as P0L_CHAIN_SCHEMA,
    ENVIRONMENT_PROOF_SCHEMA as P0L_ENVIRONMENT_PROOF_SCHEMA,
    NO_PRODUCTION_BOUNDARY_SCHEMA as P0L_NO_PRODUCTION_BOUNDARY_SCHEMA,
    OWNER_FEEDBACK_SCHEMA as P0L_OWNER_FEEDBACK_SCHEMA,
    ROLLBACK_PROOF_SCHEMA as P0L_ROLLBACK_PROOF_SCHEMA,
)

CHAIN_SCHEMA = "p0m-controlled-beta-readiness-review-chain:v1"
CHAIN_VALIDATION_SCHEMA = "p0m-p0-chain-validation:v1"
READINESS_REVIEW_SCHEMA = "p0m-controlled-beta-readiness-review:v1"
BETA_SCOPE_SCHEMA = "p0m-controlled-beta-scope:v1"
OPERATOR_RECONCILIATION_SCHEMA = "p0m-controlled-beta-operator-reconciliation:v1"
ACCEPTED_OPERATOR_DECISION = "approve_controlled_beta_candidate"

CHAIN_STEPS: tuple[dict[str, str | None], ...] = (
    {"gate": "p0l", "schema": P0L_CHAIN_SCHEMA, "next_key": "p0k_summary"},
    {"gate": "p0k", "schema": P0K_CHAIN_SCHEMA, "next_key": "p0j_summary"},
    {"gate": "p0j", "schema": P0J_CHAIN_SCHEMA, "next_key": "p0i_summary"},
    {"gate": "p0i", "schema": P0I_CHAIN_SCHEMA, "next_key": "p0h_summary"},
    {"gate": "p0h", "schema": P0H_CHAIN_SCHEMA, "next_key": "p0g_summary"},
    {"gate": "p0g", "schema": P0G_CHAIN_SCHEMA, "next_key": "p0f_summary"},
    {"gate": "p0f", "schema": P0F_CHAIN_SCHEMA, "next_key": "p0e_summary"},
    {"gate": "p0e", "schema": P0E_CHAIN_SCHEMA, "next_key": "p0d_summary"},
    {"gate": "p0d", "schema": P0D_CHAIN_SCHEMA, "next_key": "p0c_execution_summary"},
    {"gate": "p0c_execution", "schema": P0C_EXEC_CHAIN_SCHEMA, "next_key": "p0c_summary"},
    {"gate": "p0c_authorization", "schema": P0C_AUTH_CHAIN_SCHEMA, "next_key": "p0b_summary"},
    {"gate": "p0b", "schema": P0B_CHAIN_SCHEMA, "next_key": "p0a_summary"},
    {"gate": "p0a", "schema": P0A_CHAIN_SCHEMA, "next_key": None},
)

P0L_ARTIFACT_SCHEMAS = {
    "owner_feedback": P0L_OWNER_FEEDBACK_SCHEMA,
    "audit_review": P0L_AUDIT_REVIEW_SCHEMA,
    "environment_proof": P0L_ENVIRONMENT_PROOF_SCHEMA,
    "rollback_proof": P0L_ROLLBACK_PROOF_SCHEMA,
    "no_production_boundary": P0L_NO_PRODUCTION_BOUNDARY_SCHEMA,
}

NON_CLAIMS = (
    "p0m_is_controlled_beta_readiness_review_only",
    "p0m_requires_passed_p0a_to_p0l_chain",
    "p0m_does_not_contact_vms_or_run_preview_commands",
    "p0m_does_not_open_public_ingress",
    "p0m_does_not_touch_production_data",
    "p0m_does_not_modify_source_or_git",
    "p0m_does_not_write_production_receipts",
    "p0m_does_not_authorize_production_transition",
)


def run_gate(
    *,
    p0l_summary_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    operator_decision: str = ACCEPTED_OPERATOR_DECISION,
    ack_controlled_beta_readiness: bool = False,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "chain_validation": output_root / "p0m_p0_chain_validation.json",
        "readiness_review": output_root / "p0m_controlled_beta_readiness_review.json",
        "beta_scope": output_root / "p0m_controlled_beta_scope.json",
        "operator_reconciliation": output_root / "p0m_controlled_beta_operator_reconciliation.json",
        "summary": output_root / "p0m_controlled_beta_readiness_chain_summary.json",
    }
    chain = write_chain_validation(p0l_summary_path=p0l_summary_path, output=artifacts["chain_validation"])
    review = write_readiness_review(chain_validation_path=artifacts["chain_validation"], output=artifacts["readiness_review"])
    scope = write_beta_scope(chain_validation_path=artifacts["chain_validation"], readiness_review_path=artifacts["readiness_review"], output=artifacts["beta_scope"])
    reconciliation = write_operator_reconciliation(
        chain_validation_path=artifacts["chain_validation"],
        readiness_review_path=artifacts["readiness_review"],
        beta_scope_path=artifacts["beta_scope"],
        output=artifacts["operator_reconciliation"],
        operator_id=operator_id,
        operator_decision=operator_decision,
        ack_controlled_beta_readiness=ack_controlled_beta_readiness,
    )
    reports = [chain, review, scope, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "operator_id": operator_id,
        "task_id": chain.get("task_id"),
        "vm_target_ids": chain.get("vm_target_ids", []),
        "source_artifacts": {"p0l_summary": artifact_ref(p0l_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "review": {
            "gate_count": chain.get("gate_count"),
            "evidence_count": review.get("evidence_count"),
            "decision": reconciliation.get("decision"),
            "blocking_gaps": review.get("blocking_gaps", []),
            "non_blocking_gaps": review.get("non_blocking_gaps", []),
        },
        "readiness": {
            "state": "p0m_controlled_beta_readiness_passed" if passed else "blocked_p0m_controlled_beta_readiness",
            "controlled_beta_candidate_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            chain_validation_written=chain.get("passed") is True,
            readiness_review_written=review.get("passed") is True,
            beta_scope_written=scope.get("passed") is True,
            operator_reconciliation_written=reconciliation.get("passed") is True,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_chain_validation(*, p0l_summary_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    chain_entries: list[dict[str, Any]] = []
    current_path = p0l_summary_path
    p0l_summary: dict[str, Any] = {}

    for step in CHAIN_STEPS:
        gate = str(step["gate"])
        expected_schema = str(step["schema"])
        summary = _read_summary(current_path, checks, failures, gate)
        if gate == "p0l":
            p0l_summary = summary
        boundary = object_value(summary.get("boundary"))
        readiness = object_value(summary.get("readiness"))
        check(checks, failures, f"{gate}_schema", summary.get("schema_version") == expected_schema)
        check(checks, failures, f"{gate}_passed", summary.get("passed") is True)
        check(checks, failures, f"{gate}_readiness_production_closed", readiness.get("production_transition_allowed") is False)
        check(checks, failures, f"{gate}_boundary_no_production_violation", _no_production_violation(boundary))
        chain_entries.append(
            {
                "gate": gate,
                "schema_version": summary.get("schema_version"),
                "path": str(current_path.resolve()),
                "sha256": sha256_file(current_path) if current_path.is_file() else "",
                "passed": summary.get("passed") is True,
                "readiness_state": readiness.get("state"),
            }
        )
        next_key = step.get("next_key")
        if next_key is None:
            continue
        current_path = _next_summary_path(summary, str(next_key), checks, failures, gate)

    evidence_artifacts = _read_p0l_evidence_artifacts(p0l_summary, checks, failures)
    check(checks, failures, "full_p0_chain_count", len(chain_entries) == len(CHAIN_STEPS))
    check(checks, failures, "p0l_evidence_artifact_count", len(evidence_artifacts) == len(P0L_ARTIFACT_SCHEMAS))
    passed = _passed(checks, failures)
    report = {
        "schema_version": CHAIN_VALIDATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "task_id": p0l_summary.get("task_id"),
        "vm_target_ids": p0l_summary.get("vm_target_ids", []),
        "gate_count": len(chain_entries),
        "chain_entries": chain_entries,
        "p0l_evidence_artifacts": evidence_artifacts,
        "source_artifacts": {"p0l_summary": artifact_ref(p0l_summary_path)},
        "boundary": _boundary(chain_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_readiness_review(*, chain_validation_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    chain = read_json_object(chain_validation_path)
    evidence_artifacts = chain.get("p0l_evidence_artifacts") if isinstance(chain.get("p0l_evidence_artifacts"), list) else []
    evidence_names = {str(item.get("name")) for item in evidence_artifacts if isinstance(item, dict)}
    check(checks, failures, "chain_validation_passed", chain.get("schema_version") == CHAIN_VALIDATION_SCHEMA and chain.get("passed") is True)
    check(checks, failures, "all_required_evidence_present", set(P0L_ARTIFACT_SCHEMAS) <= evidence_names)
    check(checks, failures, "gate_count_complete", int(chain.get("gate_count") or 0) == len(CHAIN_STEPS))
    passed = _passed(checks, failures)
    non_blocking_gaps = [
        "controlled_beta_candidate_is_not_production_readiness",
        "requires_longer_soak_before_public_or_production_boundary",
        "h3_production_transition_still_requires_real_production_origin_evidence",
    ]
    report = {
        "schema_version": READINESS_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "reviewed_at": _now(),
        "decision": "controlled_beta_candidate_ready_for_operator_scope" if passed else "blocked_controlled_beta_readiness_review",
        "evidence_count": len(evidence_artifacts),
        "blocking_gaps": [] if passed else failures,
        "non_blocking_gaps": non_blocking_gaps,
        "source_artifacts": {"chain_validation": artifact_ref(chain_validation_path)},
        "boundary": _boundary(readiness_review_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_beta_scope(*, chain_validation_path: Path, readiness_review_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    chain = read_json_object(chain_validation_path)
    review = read_json_object(readiness_review_path)
    check(checks, failures, "chain_validation_passed", chain.get("passed") is True)
    check(checks, failures, "readiness_review_passed", review.get("schema_version") == READINESS_REVIEW_SCHEMA and review.get("passed") is True)
    passed = _passed(checks, failures)
    scope = {
        "allowed_environment": "private_virtualbox_preview_only",
        "allowed_targets": chain.get("vm_target_ids", []),
        "allowed_actions": [
            "service_token_task_pool_preview",
            "private_backend_frontend_preview",
            "private_preview_soak",
            "owner_audit_rollback_evidence_packaging",
        ],
        "forbidden_actions": [
            "public_ingress",
            "production_data_access",
            "production_transition",
            "production_receipt_write",
            "unscoped_external_deploy",
        ],
    }
    report = {
        "schema_version": BETA_SCOPE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "recorded_at": _now(),
        "controlled_beta_scope": scope,
        "source_artifacts": {
            "chain_validation": artifact_ref(chain_validation_path),
            "readiness_review": artifact_ref(readiness_review_path),
        },
        "boundary": _boundary(beta_scope_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def write_operator_reconciliation(
    *,
    chain_validation_path: Path,
    readiness_review_path: Path,
    beta_scope_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    ack_controlled_beta_readiness: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    chain = read_json_object(chain_validation_path)
    review = read_json_object(readiness_review_path)
    scope = read_json_object(beta_scope_path)
    check(checks, failures, "chain_validation_passed", chain.get("passed") is True)
    check(checks, failures, "readiness_review_passed", review.get("passed") is True)
    check(checks, failures, "beta_scope_passed", scope.get("schema_version") == BETA_SCOPE_SCHEMA and scope.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    check(checks, failures, "explicit_operator_ack", ack_controlled_beta_readiness is True)
    check(checks, failures, "operator_decision_accepted", operator_decision == ACCEPTED_OPERATOR_DECISION)
    passed = _passed(checks, failures)
    report = {
        "schema_version": OPERATOR_RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "decided_at": _now(),
        "operator_id": operator_id,
        "decision": operator_decision if passed else "blocked_controlled_beta_readiness",
        "source_artifacts": {
            "chain_validation": artifact_ref(chain_validation_path),
            "readiness_review": artifact_ref(readiness_review_path),
            "beta_scope": artifact_ref(beta_scope_path),
        },
        "boundary": _boundary(operator_reconciliation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _read_summary(path: Path, checks: dict[str, bool], failures: list[str], gate: str) -> dict[str, Any]:
    check(checks, failures, f"{gate}_path_present", path.is_file())
    if not path.is_file():
        return {}
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{gate}_summary_unreadable:{exc}")
        return {}


def _next_summary_path(summary: dict[str, Any], key: str, checks: dict[str, bool], failures: list[str], gate: str) -> Path:
    ref = object_value(object_value(summary.get("source_artifacts")).get(key))
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{gate}_source_{key}_path_present", path.is_file())
    if path.is_file():
        check(checks, failures, f"{gate}_source_{key}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return path


def _read_p0l_evidence_artifacts(p0l: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> list[dict[str, Any]]:
    artifacts = object_value(p0l.get("artifacts"))
    results: list[dict[str, Any]] = []
    for name, expected_schema in P0L_ARTIFACT_SCHEMAS.items():
        ref = object_value(artifacts.get(name))
        path = Path(str(ref.get("path") or ""))
        expected_hash = str(ref.get("sha256") or "")
        check(checks, failures, f"p0l_{name}_path_present", path.is_file())
        if not path.is_file():
            continue
        hash_valid = bool(expected_hash) and sha256_file(path) == expected_hash
        check(checks, failures, f"p0l_{name}_hash_valid", hash_valid)
        value = read_json_object(path) if hash_valid else {}
        check(checks, failures, f"p0l_{name}_schema", value.get("schema_version") == expected_schema)
        check(checks, failures, f"p0l_{name}_passed", value.get("passed") is True)
        check(checks, failures, f"p0l_{name}_boundary_closed", _no_production_violation(object_value(value.get("boundary"))))
        results.append({"name": name, "schema_version": value.get("schema_version"), "path": str(path.resolve()), "sha256": expected_hash})
    return results


def _no_production_violation(boundary: dict[str, Any]) -> bool:
    forbidden_true_keys = (
        "external_public_ingress_opened",
        "production_transition_allowed",
        "production_receipt_write_allowed",
        "production_data_accessed",
        "secrets_recorded",
        "source_tree_write_performed",
        "git_write_performed",
        "preview_command_executed",
    )
    return all(boundary.get(key) is not True for key in forbidden_true_keys)


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "chain_validation_written": False,
        "readiness_review_written": False,
        "beta_scope_written": False,
        "operator_reconciliation_written": False,
        "vm_contact_performed": False,
        "preview_command_executed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
        "production_data_accessed": False,
        "secrets_recorded": False,
    }
    base.update(overrides)
    return base


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(values))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-M controlled beta readiness review gate")
    parser.add_argument("--p0l-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--operator-decision", default=ACCEPTED_OPERATOR_DECISION)
    parser.add_argument("--ack-controlled-beta-readiness", action="store_true")
    args = parser.parse_args()
    summary = run_gate(
        p0l_summary_path=Path(args.p0l_summary),
        output_root=Path(args.output_root),
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        ack_controlled_beta_readiness=bool(args.ack_controlled_beta_readiness),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
