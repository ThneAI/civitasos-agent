"""Promote J1-D infrastructure rebind artifact after signed review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_rebind_review import (
    PROMOTION_BOUNDARY,
    approval_review_declaration,
    build_reviewed_infrastructure_rebind,
    validate_review_receipt,
    validate_review_request,
    validate_reviewed_infrastructure_rebind,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_infrastructure_rebind import (
    _read_private,
    _require_target_names_absent,
    _validate_runner_image_local,
)
from benchmarks.j1_qualification_infrastructure_rebind_review import (
    _validate_preflight,
)
from benchmarks.j1_qualification_infrastructure_rebind_review_sign import (
    review_implementation,
)


REPORT_SCHEMA = "j1-qualification-infrastructure-rebind-review-gate:v1"


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
        raise ValueError(f"infrastructure review Gate output exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    request, _ = _read_private(review_request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    receipt, receipt_raw = _read_private(review_receipt_path)
    signing_report, _ = _read_private(signing_report_path)
    runner_manifest_path = Path(
        request["candidate_artifacts"]["runner_image_manifest"]["path"]
    )
    runner_gate_path = Path(request["candidate_artifacts"]["runner_image_gate"]["path"])
    runner_manifest, runner_manifest_raw = _read_private(runner_manifest_path)
    runner_gate, runner_gate_raw = _read_private(runner_gate_path)
    _validate_preflight(
        preflight=preflight,
        preflight_raw=preflight_raw,
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
    )
    _validate_runner_image_local(runner_manifest)
    _require_target_names_absent(
        [item["target_isolation"]["container_name"] for item in plan["isolations"]]
    )
    request_failures = validate_review_request(
        request,
        plan=plan,
        plan_raw=plan_raw,
        preflight=preflight,
        preflight_raw=preflight_raw,
        runner_manifest=runner_manifest,
        runner_manifest_raw=runner_manifest_raw,
        runner_gate=runner_gate,
        runner_gate_raw=runner_gate_raw,
        expected_authorization_statement_sha256=request.get(
            "owner_authorization", {}
        ).get("statement_sha256", ""),
        expected_implementation=request.get("implementation", {}),
    )
    if request_failures:
        raise ValueError(
            f"infrastructure rebind review request invalid: {request_failures}"
        )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    implementation = review_implementation(repository_root)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    receipt_failures = validate_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256=profile_sha256,
        expected_implementation=implementation,
    )
    if receipt_failures:
        raise ValueError(
            f"infrastructure rebind review receipt invalid: {receipt_failures}"
        )
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    if not (
        signing_report.get("passed") is True
        and signing_report.get("state")
        == "infrastructure_review_signed_promotion_gate_required"
        and signing_report.get("review_request_sha256") == request.get("request_sha256")
        and signing_report.get("review_receipt", {}).get("sha256") == receipt_sha256
        and signing_report.get("review_declaration_sha256") == declaration_sha256
        and signing_report.get("private_key_exported") is False
        and signing_report.get("pin_recorded") is False
        and signing_report.get("readiness", {}).get("participant_containers_created")
        == 0
    ):
        raise ValueError("infrastructure rebind review signing report invalid")
    reviewed = build_reviewed_infrastructure_rebind(
        candidate=plan,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    reviewed_failures = validate_reviewed_infrastructure_rebind(
        reviewed,
        candidate=plan,
        receipt=receipt,
        receipt_artifact_sha256=receipt_sha256,
    )
    if reviewed_failures:
        raise ValueError(f"reviewed infrastructure rebind invalid: {reviewed_failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewed_path = output_root / "infrastructure-rebind.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "infrastructure_artifact_promoted_"
                "replacement_container_authorization_required"
            ),
            "review_request_sha256": request["request_sha256"],
            "review_receipt": _artifact(review_receipt_path),
            "review_receipt_signature_valid": True,
            "reviewed_artifact": {
                **_artifact(reviewed_path),
                "canonical_sha256": reviewed["reviewed_infrastructure_rebind_sha256"],
            },
            "inventory": plan["inventory"],
            "readiness": {
                "runner_image_qualified": True,
                "roster_assignment_rebound": True,
                "infrastructure_artifact_promoted": True,
                "participant_isolation_rebound": False,
                "participant_containers_created": 0,
                "participant_containers_started": 0,
                "live_provider_admission_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "next_blocker": "replacement_container_creation_authorization_required",
            "execution_boundary": PROMOTION_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "infrastructure-rebind-review-gate-report.json",
            report,
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
