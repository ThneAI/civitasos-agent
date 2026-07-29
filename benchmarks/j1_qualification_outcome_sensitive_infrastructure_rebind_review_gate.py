"""Promote outcome-sensitive infrastructure after signed independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_infrastructure_rebind_review import (
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
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _inspect_parent_containers,
    _read_private,
    _require_targets_absent,
    _target_names,
    _validate_runner_image_local,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind_review import (
    validate_candidate_bundle,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind_review_sign import (
    review_implementation,
)


REPORT_SCHEMA = "j1-qualification-outcome-sensitive-infrastructure-review-gate:v1"


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
        raise FileExistsError(
            f"outcome infrastructure review Gate exists: {output_root}"
        )
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    request, request_raw = _read_private(review_request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    receipt, receipt_raw = _read_private(review_receipt_path)
    signing_report, signing_report_raw = _read_private(signing_report_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
        preflight_path=candidate_preflight_path,
    )
    request_failures = validate_review_request(
        request,
        plan=plan,
        plan_raw=plan_raw,
        preflight=preflight,
        preflight_raw=preflight_raw,
        expected_plan_path=str(plan_path.resolve()),
        expected_preflight_path=str(candidate_preflight_path.resolve()),
        expected_authorization_statement_sha256=request.get(
            "owner_authorization", {}
        ).get("statement_sha256", ""),
        expected_implementation=request.get("implementation", {}),
    )
    if request_failures:
        raise ValueError(
            f"outcome infrastructure review request invalid: {request_failures}"
        )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    implementation = review_implementation(repository_root)
    request_raw_sha256 = hashlib.sha256(request_raw).hexdigest()
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request, request_raw_sha256).encode()
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
            f"outcome infrastructure review receipt invalid: {receipt_failures}"
        )
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    _validate_signing_report(
        signing_report,
        signing_report_raw=signing_report_raw,
        signing_report_path=signing_report_path,
        review_request_path=review_request_path,
        review_receipt_path=review_receipt_path,
        receipt_sha256=receipt_sha256,
        request=request,
        request_raw_sha256=request_raw_sha256,
        declaration_sha256=declaration_sha256,
        implementation=implementation,
    )
    values = {
        name: _read_private(Path(reference["path"]))[0]
        for name, reference in plan["source_binding"].items()
    }
    _validate_runner_image_local(values["runner_manifest"])
    current_sources = _inspect_parent_containers(
        parent_activation=values["parent_activation"],
        reviewed_roster=values["reviewed_roster"],
    )
    expected_sources = {
        item["participant_id"]: item["source_isolation"]["observed_state"]
        for item in plan["isolations"]
    }
    if current_sources != expected_sources:
        raise ValueError(
            "outcome infrastructure source container state changed after review"
        )
    target_root = Path(plan["isolations"][0]["target_isolation"]["input_root"]).parents[
        1
    ]
    _require_targets_absent(
        target_names=_target_names(plan["rebind_id"], values["reviewed_roster"]),
        target_state_root=target_root,
    )
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
        raise ValueError(
            f"outcome reviewed infrastructure invalid: {reviewed_failures}"
        )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        reviewed_path = (
            staging / "outcome-sensitive-infrastructure.operator-reviewed.json"
        )
        write_private_json(reviewed_path, reviewed)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "outcome_sensitive_infrastructure_artifact_promoted_"
                "replacement_container_authorization_required"
            ),
            "review_request": {
                "path": str(review_request_path.resolve()),
                "sha256": request_raw_sha256,
                "canonical_sha256": request["request_sha256"],
            },
            "review_receipt": _artifact(review_receipt_path),
            "review_receipt_signature_valid": True,
            "reviewed_artifact": {
                **_published_artifact(reviewed_path, output_root / reviewed_path.name),
                "canonical_sha256": reviewed["reviewed_infrastructure_rebind_sha256"],
            },
            "signing_report": _artifact(signing_report_path),
            "inventory": plan["inventory"],
            "current_source_set_sha256": canonical_sha256(current_sources),
            "disk_safety": preflight["disk_safety"],
            "readiness": {
                "outcome_sensitive_roster_assignment_reviewed": True,
                "mentor_advice_signatures_verified": True,
                "runner_image_qualified": True,
                "infrastructure_artifact_promoted": True,
                "participant_isolation_rebound": False,
                "participant_containers_created": 0,
                "participant_containers_started": 0,
                "live_provider_admission_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "next_blocker": (
                "exact_replacement_container_creation_authorization_required"
            ),
            "execution_boundary": PROMOTION_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "outcome-sensitive-infrastructure-review-gate-report.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_signing_report(
    report: dict[str, Any],
    *,
    signing_report_raw: bytes,
    signing_report_path: Path,
    review_request_path: Path,
    review_receipt_path: Path,
    receipt_sha256: str,
    request: dict[str, Any],
    request_raw_sha256: str,
    declaration_sha256: str,
    implementation: dict[str, str],
) -> None:
    del signing_report_raw, signing_report_path
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    if not (
        report.get("schema_version")
        == ("j1-qualification-outcome-sensitive-infrastructure-review-signing:v1")
        and report.get("passed") is True
        and report.get("failure_reasons") == []
        and report.get("state")
        == ("outcome_sensitive_infrastructure_review_signed_promotion_gate_required")
        and report.get("report_sha256") == canonical_sha256(body)
        and report.get("review_request")
        == {
            "path": str(review_request_path.resolve()),
            "sha256": request_raw_sha256,
            "canonical_sha256": request["request_sha256"],
        }
        and report.get("review_receipt", {}).get("path")
        == str(review_receipt_path.resolve())
        and report.get("review_receipt", {}).get("sha256") == receipt_sha256
        and report.get("review_declaration_sha256") == declaration_sha256
        and report.get("implementation") == implementation
        and report.get("pkcs11_session_count") == 1
        and report.get("private_key_exported") is False
        and report.get("pin_recorded") is False
        and report.get("readiness", {}).get("participant_container_created") is False
    ):
        raise ValueError("outcome infrastructure review signing report invalid")


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
