"""Promote J1-D evaluator/closeout artifacts after signed independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_evaluation_closeout_review import (
    approval_review_declaration,
    build_frozen_artifacts,
    build_frozen_bundle,
    validate_frozen_bundle,
    validate_review_receipt,
)
from benchmarks.j1_qualification_evaluation_closeout_review import (
    load_candidate_set,
)
from benchmarks.j1_qualification_evaluation_closeout_review_sign import (
    _validate_request,
    review_implementation,
)


REPORT_SCHEMA = "j1-qualification-evaluation-closeout-review-gate:v1"
EVALUATOR_SOURCE = Path(__file__).parent / "j1" / "qualification_real_evaluator.py"
CLOSEOUT_SOURCE = Path(__file__).parent / "j1" / "qualification_closeout_contracts.py"
OPERATION_SOURCE = Path(__file__)


def run_gate(
    *,
    candidate_bundle_path: Path,
    candidate_preflight_path: Path,
    review_request_path: Path,
    reviewer_profile_path: Path,
    review_receipt_path: Path,
    signing_report_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(
            f"evaluation/closeout review Gate output already exists: {output_root}"
        )
    candidate = load_candidate_set(
        candidate_bundle_path=candidate_bundle_path,
        candidate_preflight_path=candidate_preflight_path,
    )
    request, _ = _read_private(review_request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    receipt, receipt_raw = _read_private(review_receipt_path)
    signing_report, _ = _read_private(signing_report_path)
    request_failures = _validate_request(request, candidate)
    if request_failures:
        raise ValueError(
            f"evaluation/closeout review request invalid: {request_failures}"
        )
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
            f"evaluation/closeout review receipt invalid: {receipt_failures}"
        )
    receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
    if not (
        signing_report.get("passed") is True
        and signing_report.get("state")
        == "evaluation_closeout_review_signed_promotion_gate_required"
        and signing_report.get("review_request_sha256") == request.get("request_sha256")
        and signing_report.get("review_receipt", {}).get("sha256") == receipt_sha256
        and signing_report.get("review_declaration_sha256") == declaration_sha256
        and signing_report.get("private_key_exported") is False
        and signing_report.get("pin_recorded") is False
    ):
        raise ValueError("evaluation/closeout review signing report invalid")
    frozen_evaluator, frozen_post_run, frozen_closeout = build_frozen_artifacts(
        evaluator=candidate["evaluator"],
        post_run=candidate["post_run"],
        closeout=candidate["closeout"],
        promotion_implementation=promotion_implementation(repository_root),
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        evaluator_path = output_root / "real-evaluator.operator-reviewed-frozen.json"
        post_run_path = output_root / "post-run-contract.operator-reviewed-frozen.json"
        closeout_path = (
            output_root / "operator-closeout-contract.operator-reviewed-frozen.json"
        )
        write_private_json(evaluator_path, frozen_evaluator)
        write_private_json(post_run_path, frozen_post_run)
        write_private_json(closeout_path, frozen_closeout)
        frozen_refs = {
            "real_evaluator": _artifact(
                evaluator_path, frozen_evaluator["manifest_sha256"]
            ),
            "post_run_contract": _artifact(
                post_run_path, frozen_post_run["contract_sha256"]
            ),
            "operator_closeout_contract": _artifact(
                closeout_path, frozen_closeout["contract_sha256"]
            ),
        }
        frozen_bundle = build_frozen_bundle(
            candidate_bundle=candidate["bundle"],
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
            frozen_artifacts=frozen_refs,
        )
        failures = validate_frozen_bundle(
            frozen_bundle,
            candidate_bundle=candidate["bundle"],
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
            frozen_artifacts=frozen_refs,
        )
        if failures:
            raise ValueError(f"evaluation/closeout frozen bundle invalid: {failures}")
        bundle_path = output_root / "evaluation-closeout.operator-reviewed-frozen.json"
        write_private_json(bundle_path, frozen_bundle)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": ("evaluation_closeout_review_passed_execution_preflight_allowed"),
            "review_request_sha256": request["request_sha256"],
            "review_receipt": _artifact(review_receipt_path, canonical_sha256(receipt)),
            "review_receipt_signature_valid": True,
            "frozen_bundle": _artifact(
                bundle_path, frozen_bundle["frozen_bundle_sha256"]
            ),
            "frozen_artifacts": frozen_refs,
            "readiness": {
                "evaluation_closeout_frozen": True,
                "execution_preflight_allowed": True,
                "execution_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": frozen_bundle["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "evaluation-closeout-review-gate-report.json", report
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


def promotion_implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    return {
        "source_revision": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "evaluator_source_sha256": hashlib.sha256(
            EVALUATOR_SOURCE.read_bytes()
        ).hexdigest(),
        "closeout_source_sha256": hashlib.sha256(
            CLOSEOUT_SOURCE.read_bytes()
        ).hexdigest(),
        "freeze_operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _artifact(path: Path, canonical_sha256_value: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_sha256_value,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
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
        candidate_bundle_path=args.candidate_bundle,
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
