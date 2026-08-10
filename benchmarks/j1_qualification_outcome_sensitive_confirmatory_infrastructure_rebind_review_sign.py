"""Sign an approved prospective confirmatory infrastructure review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review import (
    APPROVAL_DECISION,
    DECISION_BOUNDARY,
    REVIEW_DECISION_SCHEMA,
    approval_review_declaration,
    build_review_receipt,
    validate_completed_review_decision,
    validate_review_receipt,
    validate_review_request,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review import (
    validate_candidate_bundle,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _read_private,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "infrastructure-review-signing:v1"
)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review.py"
)
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_"
    "infrastructure_rebind_review_gate.py"
)


def sign_review(
    *,
    review_id: str,
    reviewed_at: str,
    review_declaration: str,
    plan_path: Path,
    candidate_preflight_path: Path,
    review_request_path: Path,
    review_handoff_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    """Validate every non-secret input before opening one PKCS#11 session."""
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError(
            f"confirmatory infrastructure review output exists: {output_root}"
        )
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(candidate_preflight_path)
    request, request_raw = _read_private(review_request_path)
    handoff, _ = _read_private(review_handoff_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    validate_candidate_bundle(
        plan=plan,
        plan_raw=plan_raw,
        plan_path=plan_path,
        preflight=preflight,
        preflight_raw=preflight_raw,
    )
    request_failures = validate_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_plan_path=str(plan_path.resolve()),
        expected_candidate_preflight_path=str(candidate_preflight_path.resolve()),
        expected_authorization_statement_sha256=request.get(
            "owner_authorization", {}
        ).get("statement_sha256", ""),
        expected_implementation=request.get("implementation", {}),
    )
    if request_failures:
        raise ValueError(
            f"confirmatory infrastructure review request invalid: {request_failures}"
        )
    request_raw_sha256 = hashlib.sha256(request_raw).hexdigest()
    expected_declaration = approval_review_declaration(request, request_raw_sha256)
    if review_declaration != expected_declaration:
        raise ValueError(
            "confirmatory infrastructure independent review declaration mismatch"
        )
    _validate_handoff(
        handoff,
        request=request,
        request_raw_sha256=request_raw_sha256,
        review_declaration=review_declaration,
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    _validate_reviewer_configuration(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    declaration_sha256 = hashlib.sha256(review_declaration.encode()).hexdigest()
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    reviewer = profile["reviewer"]
    implementation = review_implementation(repository_root)
    decision = {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": review_id,
        "review_request_sha256": request["request_sha256"],
        "decision": APPROVAL_DECISION,
        "reviewed_at": reviewed_at,
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "custody_provenance_sha256": profile_sha256,
            "signer_attestation_sha256": profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_runner_and_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_REVIEW_CHECKS)},
        "execution_boundary": DECISION_BOUNDARY,
    }
    decision_failures = validate_completed_review_decision(decision, request=request)
    if decision_failures:
        raise ValueError(
            f"confirmatory infrastructure review decision invalid: {decision_failures}"
        )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            reviewer["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            receipt = build_review_receipt(
                request=request,
                decision=decision,
                review_declaration_sha256=declaration_sha256,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        receipt_failures = validate_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256=profile_sha256,
            expected_implementation=implementation,
        )
        if receipt_failures:
            raise ValueError(
                f"confirmatory infrastructure review receipt invalid: "
                f"{receipt_failures}"
            )
        decision_path = staging / "confirmatory-infrastructure-review-decision.json"
        receipt_path = staging / "confirmatory-infrastructure-review-receipt.json"
        write_private_json(decision_path, decision)
        write_private_json(receipt_path, receipt)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": (
                "confirmatory_infrastructure_review_signed_"
                "promotion_gate_required"
            ),
            "review_id": review_id,
            "reviewed_at": reviewed_at,
            "review_request": {
                "path": str(review_request_path.resolve()),
                "sha256": request_raw_sha256,
                "canonical_sha256": request["request_sha256"],
            },
            "review_declaration_sha256": declaration_sha256,
            "decision": _published_artifact(
                decision_path, output_root / decision_path.name
            ),
            "review_receipt": _published_artifact(
                receipt_path, output_root / receipt_path.name
            ),
            "reviewer_did": reviewer["did"],
            "reviewer_profile_sha256": profile_sha256,
            "implementation": implementation,
            "pkcs11_session_count": 1,
            "pin_recorded": False,
            "private_key_exported": False,
            "readiness": {
                "signed_review_receipt_present": True,
                "promotion_gate_required": True,
                "infrastructure_promoted": False,
                "participant_container_created": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": receipt["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "confirmatory-infrastructure-review-signing.json", report
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def review_implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before signing confirmatory infrastructure review"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError(
            "confirmatory infrastructure review signing revision is not pushed"
        )
    hashes = {
        str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in (DOMAIN_SOURCE, OPERATION_SOURCE, GATE_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(hashes),
    }


def _validate_handoff(
    handoff: dict[str, Any],
    *,
    request: dict[str, Any],
    request_raw_sha256: str,
    review_declaration: str,
) -> None:
    body = {key: item for key, item in handoff.items() if key != "report_sha256"}
    if not (
        handoff.get("passed") is True
        and handoff.get("failure_reasons") == []
        and handoff.get("state")
        == "confirmatory_infrastructure_owner_approved_independent_review_required"
        and handoff.get("report_sha256") == canonical_sha256(body)
        and handoff.get("review_request", {}).get("sha256") == request_raw_sha256
        and handoff.get("review_request", {}).get("canonical_sha256")
        == request.get("request_sha256")
        and handoff.get("review_declaration_request", {}).get(
            "required_exact_statement"
        )
        == review_declaration
        and handoff.get("readiness", {}).get("independent_review_decision_complete")
        is False
    ):
        raise ValueError("confirmatory infrastructure review handoff invalid")


def _validate_reviewer_configuration(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    module = Path(module_path).resolve()
    key = profile["pkcs11_key"]
    if not (
        key.get("module_path") == str(module)
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
        and key.get("module_sha256") == hashlib.sha256(module.read_bytes()).hexdigest()
    ):
        raise ValueError("reviewer PKCS#11 configuration mismatch")


def _published_artifact(path: Path, published_path: Path) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--reviewed-at", required=True)
    parser.add_argument("--review-declaration", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--review-request", type=Path, required=True)
    parser.add_argument("--review-handoff", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = sign_review(
        review_id=args.review_id,
        reviewed_at=args.reviewed_at,
        review_declaration=args.review_declaration,
        plan_path=args.plan,
        candidate_preflight_path=args.candidate_preflight,
        review_request_path=args.review_request,
        review_handoff_path=args.review_handoff,
        reviewer_profile_path=args.reviewer_profile,
        module_path=args.module,
        token_label=args.token_label,
        key_label=args.key_label,
        key_id_hex=args.key_id,
        repository_root=args.repository_root,
        pin=read_pin(args.pin_file),
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
