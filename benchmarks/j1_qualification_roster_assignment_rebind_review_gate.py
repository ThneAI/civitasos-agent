"""Promote J1-D roster/assignment after signed independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_roster_assignment_rebind_review import (
    PROMOTION_BOUNDARY,
    approval_review_declaration,
    build_reviewed_rebound_assignment,
    build_reviewed_rebound_roster,
    validate_rebind_review_receipt,
    validate_rebind_review_request,
    validate_reviewed_rebound_assignment,
    validate_reviewed_rebound_roster,
)
from benchmarks.j1_qualification_roster_assignment_rebind import _read_private
from benchmarks.j1_qualification_roster_assignment_rebind_review import (
    validate_candidate_bundle,
)
from benchmarks.j1_qualification_roster_assignment_rebind_review_sign import (
    review_implementation,
)


REPORT_SCHEMA = "j1-qualification-roster-assignment-rebind-review-gate:v1"


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
        raise ValueError(f"rebind review Gate output already exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    request, _ = _read_private(review_request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    receipt, receipt_raw = _read_private(review_receipt_path)
    signing_report, _ = _read_private(signing_report_path)
    roster_path = Path(plan["candidate_artifacts"]["rebound_roster"]["path"])
    assignment_path = Path(plan["candidate_artifacts"]["rebound_assignment"]["path"])
    candidate_roster, _ = _read_private(roster_path)
    candidate_assignment, _ = _read_private(assignment_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
        preflight_path=candidate_preflight_path,
    )
    request_failures = validate_rebind_review_request(
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
        raise ValueError(f"rebind review request invalid: {request_failures}")
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    implementation = review_implementation(repository_root)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    receipt_failures = validate_rebind_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256=profile_sha256,
        expected_implementation=implementation,
    )
    if receipt_failures:
        raise ValueError(f"rebind review receipt invalid: {receipt_failures}")
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    if not (
        signing_report.get("passed") is True
        and signing_report.get("state")
        == "rebind_review_signed_promotion_gate_required"
        and signing_report.get("review_request_sha256") == request.get("request_sha256")
        and signing_report.get("review_receipt", {}).get("sha256") == receipt_sha256
        and signing_report.get("review_declaration_sha256") == declaration_sha256
        and signing_report.get("private_key_exported") is False
        and signing_report.get("pin_recorded") is False
    ):
        raise ValueError("rebind review signing report invalid")
    reviewed_roster = build_reviewed_rebound_roster(
        candidate=candidate_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    roster_failures = validate_reviewed_rebound_roster(
        reviewed_roster,
        candidate=candidate_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    if roster_failures:
        raise ValueError(f"reviewed rebound roster invalid: {roster_failures}")
    reviewed_assignment = build_reviewed_rebound_assignment(
        candidate=candidate_assignment,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    assignment_failures = validate_reviewed_rebound_assignment(
        reviewed_assignment,
        candidate=candidate_assignment,
        reviewed_roster=reviewed_roster,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    if assignment_failures:
        raise ValueError(f"reviewed rebound assignment invalid: {assignment_failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        roster_output = (
            output_root / "qualification-roster.rebound.operator-reviewed.json"
        )
        assignment_output = (
            output_root / "cohort-assignment.rebound.operator-reviewed.json"
        )
        write_private_json(roster_output, reviewed_roster)
        write_private_json(assignment_output, reviewed_assignment)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "roster_assignment_rebind_passed_infrastructure_rebind_required",
            "review_request_sha256": request["request_sha256"],
            "review_receipt": _artifact(review_receipt_path),
            "review_receipt_signature_valid": True,
            "reviewed_artifacts": {
                "rebound_roster": {
                    **_artifact(roster_output),
                    "canonical_sha256": reviewed_roster[
                        "reviewed_rebound_roster_sha256"
                    ],
                },
                "rebound_assignment": {
                    **_artifact(assignment_output),
                    "canonical_sha256": reviewed_assignment[
                        "reviewed_rebound_assignment_sha256"
                    ],
                },
            },
            "inventory": plan["inventory"],
            "readiness": {
                "participant_consent_extensions_complete": True,
                "roster_rebound": True,
                "assignment_rebound": True,
                "infrastructure_rebound": False,
                "live_provider_admission_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "next_blocker": "runner_and_infrastructure_rebind_required",
            "execution_boundary": PROMOTION_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "roster-assignment-rebind-review-gate-report.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


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
