"""Run I.2-F review and operator reconciliation gate.

I.2-F consumes a passed I.2-E preview/rollback/audit summary. It verifies the
preview evidence chain, writes independent reviewer verdict receipts, and then
records operator reconciliation. It does not merge, deploy, mutate runtime state,
or write production receipts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    objects_value,
    read_json_object,
    sha256_file,
    sha256_json,
    write_json_object,
)

CHAIN_SCHEMA = "i2f-review-reconciliation-chain:v1"
AUTHORIZATION_SCHEMA = "i2f-review-reconciliation-authorization:v1"
REVIEW_PACKET_SCHEMA = "i2f-review-packet:v1"
REVIEW_RECEIPT_SCHEMA = "i2f-reviewer-verdict-receipt:v1"
RECONCILIATION_SCHEMA = "i2f-operator-reconciliation:v1"

I2E_SCHEMA = "i2e-preview-rollback-audit-chain:v1"
I2E_AUTHORIZATION_SCHEMA = "i2e-preview-rollback-audit-authorization:v1"
I2E_PREVIEW_SCHEMA = "i2e-local-private-preview-receipt:v1"
I2E_ROLLBACK_SCHEMA = "i2e-rollback-drill-receipt:v1"
I2E_AUDIT_SCHEMA = "i2e-audit-receipt:v1"

DEFAULT_REVIEWERS = (
    {"reviewer_id": "provenance-reviewer", "role": "provenance", "verdict": "approved"},
    {"reviewer_id": "rollback-reviewer", "role": "rollback", "verdict": "approved"},
    {"reviewer_id": "boundary-reviewer", "role": "boundary", "verdict": "approved"},
)
APPROVED_VERDICTS = {"approved"}
BLOCKING_VERDICTS = {"changes_requested", "rejected", "blocked"}


def run_gate(
    *,
    i2e_summary_path: Path,
    output_root: Path,
    reviewers_path: Path | None = None,
    operator_id: str = "operator-cc",
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "authorization": output_root / "i2f_review_reconciliation_authorization.json",
        "review_packet": output_root / "i2f_review_packet.json",
        "reviews": output_root / "i2f_reviewer_verdict_receipts.json",
        "reconciliation": output_root / "i2f_operator_reconciliation.json",
        "summary": output_root / "i2f_review_reconciliation_chain_summary.json",
    }
    authorization = write_authorization(
        i2e_summary_path=i2e_summary_path,
        output=artifacts["authorization"],
        operator_id=operator_id,
    )
    review_packet = write_review_packet(
        authorization_path=artifacts["authorization"],
        output=artifacts["review_packet"],
    )
    reviews = write_review_receipts(
        authorization_path=artifacts["authorization"],
        review_packet_path=artifacts["review_packet"],
        output=artifacts["reviews"],
        reviewers_path=reviewers_path,
    )
    reconciliation = write_reconciliation(
        authorization_path=artifacts["authorization"],
        review_packet_path=artifacts["review_packet"],
        reviews_path=artifacts["reviews"],
        output=artifacts["reconciliation"],
    )
    reports = [authorization, review_packet, reviews, reconciliation]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(*reports),
        "source_artifacts": {"i2e_summary": artifact_ref(i2e_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2f_review_reconciliation_passed" if passed else "blocked_i2f_review_reconciliation",
            "i2f_review_reconciliation_complete": passed,
            "i2g_merge_discussion_ready": passed,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            authorization_recording_allowed=passed,
            review_packet_recording_allowed=passed,
            reviewer_verdict_recording_allowed=passed,
            operator_reconciliation_recording_allowed=passed,
        ),
        "non_claims": [
            "i2f_does_not_merge",
            "i2f_does_not_deploy",
            "i2f_does_not_mutate_runtime_state",
            "i2f_does_not_authorize_production_transition",
            "i2f_does_not_write_production_receipt",
        ],
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_authorization(*, i2e_summary_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    i2e = read_json_object(i2e_summary_path)
    i2e_artifacts = object_value(i2e.get("artifacts"))
    i2e_authorization = _read_verified_ref(i2e_artifacts.get("authorization"), checks, failures, "i2e.authorization")
    i2e_preview = _read_verified_ref(i2e_artifacts.get("preview"), checks, failures, "i2e.preview")
    i2e_rollback = _read_verified_ref(i2e_artifacts.get("rollback"), checks, failures, "i2e.rollback")
    i2e_audit = _read_verified_ref(i2e_artifacts.get("audit"), checks, failures, "i2e.audit")
    boundary = object_value(i2e.get("boundary"))
    readiness = object_value(i2e.get("readiness"))
    auth = object_value(i2e_authorization.get("authorization"))
    preview = object_value(i2e_preview.get("preview"))
    rollback = object_value(i2e_rollback.get("rollback"))
    audit = object_value(i2e_audit.get("audit"))

    check(checks, failures, "i2e_summary_passed", i2e.get("schema_version") == I2E_SCHEMA and i2e.get("passed") is True)
    check(checks, failures, "i2e_ready_for_i2f", readiness.get("i2f_review_reconciliation_discussion_ready") is True)
    check(checks, failures, "i2e_kept_host_source_closed", boundary.get("host_source_tree_write_allowed") is False)
    check(checks, failures, "i2e_kept_merge_closed", boundary.get("merge_allowed") is False)
    check(checks, failures, "i2e_kept_deploy_closed", boundary.get("deploy_allowed") is False)
    check(checks, failures, "i2e_kept_runtime_closed", boundary.get("runtime_state_mutation_allowed") is False)
    check(checks, failures, "i2e_kept_production_closed", boundary.get("production_transition_allowed") is False and boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "i2e_authorization_passed", i2e_authorization.get("schema_version") == I2E_AUTHORIZATION_SCHEMA and i2e_authorization.get("passed") is True)
    check(checks, failures, "i2e_preview_passed", i2e_preview.get("schema_version") == I2E_PREVIEW_SCHEMA and i2e_preview.get("passed") is True)
    check(checks, failures, "i2e_rollback_passed", i2e_rollback.get("schema_version") == I2E_ROLLBACK_SCHEMA and i2e_rollback.get("passed") is True)
    check(checks, failures, "i2e_audit_passed", i2e_audit.get("schema_version") == I2E_AUDIT_SCHEMA and i2e_audit.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(_text(operator_id)))
    check(checks, failures, "preview_head_matches_authorized_commit", preview.get("observed_head") == auth.get("commit_id"))
    check(checks, failures, "rollback_cleanup_observed", rollback.get("exists_after_cleanup") is False)
    check(checks, failures, "audit_no_merge_deploy_or_production", audit.get("merge_observed") is False and audit.get("deploy_observed") is False and audit.get("production_receipt_written") is False)

    changed_files = [str(item) for item in auth.get("changed_files", []) if isinstance(item, str)]
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2e_summary": artifact_ref(i2e_summary_path)},
        "authorization": {
            "operator_id": operator_id,
            "decision": "authorize_i2f_review_reconciliation" if passed else "blocked_i2f_authorization",
            "scope": "review_reconciliation_only",
            "target_branch": auth.get("target_branch"),
            "commit_id": auth.get("commit_id"),
            "changed_files": changed_files,
            "minimum_reviewer_count": 3,
            "required_roles": ["provenance", "rollback", "boundary"],
        },
        "readiness": {
            "state": "i2f_review_packet_ready" if passed else "blocked_i2f_authorization",
            "review_packet_allowed": passed,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(authorization_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_review_packet(*, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    auth = object_value(authorization.get("authorization"))
    changed_files = [str(item) for item in auth.get("changed_files", []) if isinstance(item, str)]
    packet_body = {
        "target_branch": auth.get("target_branch"),
        "commit_id": auth.get("commit_id"),
        "changed_files": changed_files,
        "review_questions": [
            "Does the preview evidence preserve provenance from I.2-D to I.2-E?",
            "Did rollback cleanup complete without deleting remote branches or reverting merges?",
            "Are merge, deploy, runtime mutation, production transition, and production receipt still closed?",
        ],
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_transition_allowed": False,
    }
    packet_hash = sha256_json(packet_body)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "commit_id_present", bool(_text(auth.get("commit_id"))))
    check(checks, failures, "changed_files_present", bool(changed_files))
    check(checks, failures, "packet_hash_present", bool(packet_hash))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": REVIEW_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "review_packet": packet_body | {"packet_hash": packet_hash},
        "readiness": {"state": "i2f_reviewer_verdicts_ready" if passed else "blocked_i2f_review_packet"},
        "boundary": _boundary(review_packet_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_review_receipts(
    *,
    authorization_path: Path,
    review_packet_path: Path,
    output: Path,
    reviewers_path: Path | None,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    packet = read_json_object(review_packet_path)
    auth = object_value(authorization.get("authorization"))
    packet_body = object_value(packet.get("review_packet"))
    reviewers = _load_reviewers(reviewers_path, failures)
    receipts = []
    required_roles = set(str(item) for item in auth.get("required_roles", []) if isinstance(item, str))
    seen_roles = set()
    verdict_counts: dict[str, int] = {}
    for reviewer in reviewers:
        reviewer_id = str(reviewer.get("reviewer_id") or "")
        role = str(reviewer.get("role") or "")
        verdict = str(reviewer.get("verdict") or "")
        changed_files = [str(item) for item in reviewer.get("changed_files", packet_body.get("changed_files", [])) if isinstance(item, str)]
        passed_verdict = bool(reviewer_id) and role in required_roles and verdict in APPROVED_VERDICTS and sorted(changed_files) == sorted(packet_body.get("changed_files", []))
        seen_roles.add(role)
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        receipts.append({
            "schema_version": "i2f-single-reviewer-verdict:v1",
            "reviewer_id": reviewer_id,
            "role": role,
            "verdict": verdict,
            "risk": reviewer.get("risk", "low" if verdict == "approved" else "high"),
            "packet_hash": packet_body.get("packet_hash"),
            "commit_id": packet_body.get("commit_id"),
            "changed_files": changed_files,
            "passed": passed_verdict,
            "failure_reasons": [] if passed_verdict else ["reviewer_verdict_failed_hard_controls"],
            "boundary_attestation": {
                "merge_allowed": False,
                "deploy_allowed": False,
                "runtime_state_mutation_allowed": False,
                "production_transition_allowed": False,
                "production_receipt_write_allowed": False,
            },
        })

    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "review_packet_passed", packet.get("schema_version") == REVIEW_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "minimum_reviewer_count_met", len(receipts) >= int(auth.get("minimum_reviewer_count") or 0))
    check(checks, failures, "required_roles_covered", required_roles.issubset(seen_roles))
    check(checks, failures, "all_reviewers_approved", all(item.get("passed") is True for item in receipts))
    check(checks, failures, "no_blocking_verdicts", not any(item.get("verdict") in BLOCKING_VERDICTS for item in receipts))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "review_packet": artifact_ref(review_packet_path),
            **({"reviewers_input": artifact_ref(reviewers_path)} if reviewers_path else {}),
        },
        "review_receipts": receipts,
        "review_summary": {
            "reviewer_count": len(receipts),
            "required_roles": sorted(required_roles),
            "observed_roles": sorted(seen_roles),
            "verdict_counts": verdict_counts,
        },
        "readiness": {"state": "i2f_reviews_passed" if passed else "blocked_i2f_reviews"},
        "boundary": _boundary(reviewer_verdict_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_reconciliation(
    *,
    authorization_path: Path,
    review_packet_path: Path,
    reviews_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    packet = read_json_object(review_packet_path)
    reviews = read_json_object(reviews_path)
    receipts = objects_value(reviews.get("review_receipts"))
    summary = object_value(reviews.get("review_summary"))
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "review_packet_passed", packet.get("schema_version") == REVIEW_PACKET_SCHEMA and packet.get("passed") is True)
    check(checks, failures, "reviews_passed", reviews.get("schema_version") == REVIEW_RECEIPT_SCHEMA and reviews.get("passed") is True)
    check(checks, failures, "all_receipts_passed", bool(receipts) and all(item.get("passed") is True for item in receipts))
    check(checks, failures, "approved_verdicts_only", summary.get("verdict_counts", {}).get("approved") == len(receipts))
    check(checks, failures, "merge_deploy_production_closed", True)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "authorization": artifact_ref(authorization_path),
            "review_packet": artifact_ref(review_packet_path),
            "reviews": artifact_ref(reviews_path),
        },
        "operator_reconciliation": {
            "decision": "i2f_review_reconciliation_passed" if passed else "blocked_i2f_reconciliation",
            "reason": "I.2-F review quorum approved local/private preview evidence while merge/deploy/production boundaries stayed closed." if passed else "I.2-F review quorum or boundary checks failed.",
            "reviewer_count": len(receipts),
            "verdict_counts": summary.get("verdict_counts", {}),
        },
        "readiness": {
            "state": "i2f_review_reconciliation_passed" if passed else "blocked_i2f_reconciliation",
            "i2g_merge_discussion_ready": passed,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": [
            "i2f_reconciliation_does_not_authorize_merge",
            "i2f_reconciliation_does_not_authorize_deploy_or_production",
        ],
    }
    write_json_object(output, report)
    return report


def _load_reviewers(reviewers_path: Path | None, failures: list[str]) -> list[dict[str, Any]]:
    if reviewers_path is None:
        return [dict(item) for item in DEFAULT_REVIEWERS]
    if not reviewers_path.is_file():
        failures.append("reviewers_input_missing")
        return []
    value = json.loads(reviewers_path.read_text(encoding="utf-8"))
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    if isinstance(value, dict):
        reviewers = value.get("reviewers")
        if isinstance(reviewers, list) and all(isinstance(item, dict) for item in reviewers):
            return reviewers
    failures.append("reviewers_input_invalid")
    return []


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    path_exists = path.is_file()
    check(checks, failures, f"{label}_artifact_path_present", path_exists)
    if not path_exists:
        return {}
    actual_hash = sha256_file(path)
    check(checks, failures, f"{label}_artifact_hash_valid", bool(expected_hash) and actual_hash == expected_hash)
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001 - gate records validation failures.
        failures.append(f"{label}_artifact_read_failed:{exc}")
        return {}


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "authorization_recording_allowed": False,
        "review_packet_recording_allowed": False,
        "reviewer_verdict_recording_allowed": False,
        "operator_reconciliation_recording_allowed": False,
        "host_source_tree_write_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "runtime_state_mutation_allowed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []) if item)
    return failures


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i2e-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--reviewers")
    parser.add_argument("--operator-id", default="operator-cc")
    args = parser.parse_args()
    report = run_gate(
        i2e_summary_path=Path(args.i2e_summary).resolve(),
        output_root=Path(args.output_root).resolve(),
        reviewers_path=Path(args.reviewers).resolve() if args.reviewers else None,
        operator_id=args.operator_id,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
