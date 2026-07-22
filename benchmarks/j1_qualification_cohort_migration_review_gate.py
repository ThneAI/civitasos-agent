"""Promote a J1-D cohort migration plan after signed independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_cohort_migration_review import (
    approval_review_declaration,
    build_reviewed_migration_plan,
    validate_migration_review_receipt,
    validate_migration_review_request,
    validate_reviewed_migration_plan,
)
from benchmarks.j1_qualification_cohort_migration_review import (
    validate_candidate_bundle,
)
from benchmarks.j1_qualification_cohort_migration_review_sign import (
    review_implementation,
)


REPORT_SCHEMA = "j1-qualification-cohort-migration-review-gate:v1"


def run_gate(
    *,
    plan_path: Path,
    candidate_preflight_path: Path,
    review_request_path: Path,
    reviewer_profile_path: Path,
    review_receipt_path: Path,
    signing_report_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"migration review Gate output already exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    request, _ = _read_private(review_request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    receipt, receipt_raw = _read_private(review_receipt_path)
    signing_report, _ = _read_private(signing_report_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
    )
    request_failures = validate_migration_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_authorization_statement_sha256=request.get(
            "owner_authorization", {}
        ).get("statement_sha256", ""),
        expected_implementation=request.get("implementation", {}),
    )
    if request_failures:
        raise ValueError(f"cohort migration review request invalid: {request_failures}")
    implementation = review_implementation(repository_root)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    receipt_failures = validate_migration_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256=profile_sha256,
        expected_implementation=implementation,
    )
    if receipt_failures:
        raise ValueError(f"cohort migration review receipt invalid: {receipt_failures}")
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    if not (
        signing_report.get("passed") is True
        and signing_report.get("state")
        == "cohort_migration_review_signed_promotion_gate_required"
        and signing_report.get("review_request_sha256")
        == request.get("request_sha256")
        and signing_report.get("review_receipt", {}).get("sha256") == receipt_sha256
        and signing_report.get("review_declaration_sha256") == declaration_sha256
        and signing_report.get("private_key_exported") is False
        and signing_report.get("pin_recorded") is False
    ):
        raise ValueError("cohort migration review signing report invalid")
    reviewed = build_reviewed_migration_plan(
        plan=plan,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    reviewed_failures = validate_reviewed_migration_plan(
        reviewed,
        plan=plan,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    if reviewed_failures:
        raise ValueError(f"reviewed cohort migration plan invalid: {reviewed_failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewed_path = output_root / "cohort-migration-plan.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "cohort_migration_review_passed_amendment_generation_required",
            "review_request_sha256": request["request_sha256"],
            "review_receipt": _artifact(review_receipt_path),
            "review_receipt_signature_valid": True,
            "reviewed_plan": {
                **_artifact(reviewed_path),
                "canonical_sha256": reviewed["reviewed_plan_sha256"],
            },
            "readiness": {
                "protocol_design_amendment_plan_operator_reviewed": True,
                "protocol_design_amendment_generated": False,
                "participant_consent_extensions_complete": False,
                "downstream_bindings_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": {
                "review_promotion_only": True,
                "protocol_design_amendment_performed": False,
                "participant_consent_migrated": False,
                "container_created": False,
                "container_started": False,
                "provider_api_call_performed": False,
                "model_invocation_performed": False,
                "agent_execution_performed": False,
                "backend_fact_append_performed": False,
                "ledger_append_performed": False,
                "execution_authorization_issued": False,
            },
        }
        write_private_json(
            output_root / "cohort-migration-review-gate-report.json",
            report,
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--review-request", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--signing-report", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        plan_path=args.plan,
        candidate_preflight_path=args.candidate_preflight,
        review_request_path=args.review_request,
        reviewer_profile_path=args.reviewer_profile,
        review_receipt_path=args.review_receipt,
        signing_report_path=args.signing_report,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
