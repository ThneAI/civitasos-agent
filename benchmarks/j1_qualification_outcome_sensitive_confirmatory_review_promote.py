"""Sign and promote the independently reviewed confirmatory amendment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_amendment import (
    validate_bundle,
    validate_preflight,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_review import (
    REVIEW_HANDOFF_SCHEMA,
    build_frozen_review,
    build_promotion_gate,
    build_signed_review_receipt,
    reviewer_approval_statement,
    validate_review_request,
    validate_signed_review_receipt,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_review.py"
)
HANDOFF_SOURCE = (
    Path(__file__).parent / "j1_qualification_outcome_sensitive_confirmatory_review.py"
)
OPERATION_SOURCE = Path(__file__)
FROZEN_NAMES = {
    "confirmatory_method": "confirmatory-method.operator-reviewed-source.json",
    "protocol_addendum": "confirmatory-protocol-addendum.operator-reviewed-source.json",
    "evaluator_addendum": (
        "confirmatory-evaluator-addendum.operator-reviewed-source.json"
    ),
    "consent_impact": "confirmatory-consent-impact.operator-reviewed-source.json",
    "verification": "confirmatory-verification.operator-reviewed-source.json",
}


def promote_review(
    *,
    review_id: str,
    frozen_id: str,
    reviewed_at: str,
    approval_statement_sha256: str,
    reviewer_handoff_path: Path,
    request_path: Path,
    bundle_path: Path,
    preflight_path: Path,
    owner_gate_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    output_root: Path,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError(f"confirmatory review promotion exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    handoff, handoff_raw = _read_private(reviewer_handoff_path)
    request, request_raw = _read_private(request_path)
    bundle, bundle_raw = _read_private(bundle_path)
    preflight, preflight_raw = _read_private(preflight_path)
    owner_gate, owner_gate_raw = _read_private(owner_gate_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    request_ref = _ref(request_path, request["request_sha256"], request_raw)
    handoff_ref = _ref(
        reviewer_handoff_path,
        handoff["handoff_sha256"],
        handoff_raw,
    )
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"], bundle_raw)
    preflight_ref = _ref(preflight_path, preflight["report_sha256"], preflight_raw)
    owner_gate_ref = _ref(
        owner_gate_path,
        owner_gate["report_sha256"],
        owner_gate_raw,
    )
    implementation = {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "handoff_operation_source_sha256": hashlib.sha256(
            HANDOFF_SOURCE.read_bytes()
        ).hexdigest(),
        "promotion_operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }
    _validate_inputs(
        handoff=handoff,
        request=request,
        request_ref=request_ref,
        bundle=bundle,
        bundle_ref=bundle_ref,
        preflight=preflight,
        preflight_ref=preflight_ref,
        owner_gate_ref=owner_gate_ref,
        approval_statement_sha256=approval_statement_sha256,
        implementation=implementation,
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
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
            receipt = build_signed_review_receipt(
                review_id=review_id,
                reviewed_at=reviewed_at,
                request_ref=request_ref,
                bundle_ref=bundle_ref,
                preflight_ref=preflight_ref,
                owner_gate_ref=owner_gate_ref,
                materials=bundle["materials"],
                approval_statement_sha256=approval_statement_sha256,
                reviewer=reviewer,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        receipt_failures = validate_signed_review_receipt(
            receipt,
            expected_request_ref=request_ref,
            expected_bundle_ref=bundle_ref,
            expected_preflight_ref=preflight_ref,
            expected_owner_gate_ref=owner_gate_ref,
            expected_materials=bundle["materials"],
            expected_approval_statement_sha256=approval_statement_sha256,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256=profile_sha256,
            expected_implementation=implementation,
        )
        if receipt_failures:
            raise ValueError(f"confirmatory review receipt invalid: {receipt_failures}")
        receipt_path = staging / "confirmatory-amendment-signed-review-receipt.json"
        write_private_json(receipt_path, receipt)
        frozen_materials = _copy_materials(
            bundle["materials"],
            staging=staging,
            output_root=output_root,
        )
        receipt_ref = _published_ref(
            receipt_path,
            output_root / receipt_path.name,
            receipt["receipt_sha256"],
        )
        frozen = build_frozen_review(
            frozen_id=frozen_id,
            promoted_at=reviewed_at,
            source_materials=bundle["materials"],
            frozen_materials=frozen_materials,
            source_bundle_ref=bundle_ref,
            review_receipt_ref=receipt_ref,
            reviewer_did=reviewer["did"],
            implementation=implementation,
        )
        frozen_path = staging / "confirmatory-amendment.operator-reviewed.json"
        write_private_json(frozen_path, frozen)
        frozen_ref = _published_ref(
            frozen_path,
            output_root / frozen_path.name,
            frozen["frozen_review_sha256"],
        )
        gate = build_promotion_gate(
            request_ref=request_ref,
            handoff_ref=handoff_ref,
            owner_gate_ref=owner_gate_ref,
            receipt_ref=receipt_ref,
            frozen_review_ref=frozen_ref,
            frozen_review=frozen,
        )
        write_private_json(
            staging / "confirmatory-amendment-promotion-gate.json",
            gate,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return gate
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_inputs(
    *,
    handoff: dict[str, Any],
    request: dict[str, Any],
    request_ref: dict[str, str],
    bundle: dict[str, Any],
    bundle_ref: dict[str, str],
    preflight: dict[str, Any],
    preflight_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    approval_statement_sha256: str,
    implementation: dict[str, str],
) -> None:
    failures = validate_bundle(bundle) + validate_preflight(preflight)
    failures += validate_review_request(
        request,
        expected_bundle_ref=bundle_ref,
        expected_preflight_ref=preflight_ref,
        expected_owner_gate_ref=owner_gate_ref,
        expected_materials=bundle["materials"],
        expected_implementation=implementation,
    )
    statement = reviewer_approval_statement(request_ref=request_ref, request=request)
    handoff_body = {
        key: item for key, item in handoff.items() if key != "handoff_sha256"
    }
    if not (
        handoff.get("schema_version") == REVIEW_HANDOFF_SCHEMA
        and handoff.get("status") == "independent_reviewer_decision_required"
        and handoff.get("review_request") == request_ref
        and handoff.get("reviewed_bundle") == bundle_ref
        and handoff.get("owner_authorization_gate") == owner_gate_ref
        and handoff.get("required_exact_approval_statement") == statement
        and handoff.get("required_exact_approval_statement_sha256")
        == hashlib.sha256(statement.encode()).hexdigest()
        == approval_statement_sha256
        and handoff.get("implementation") == implementation
        and handoff.get("handoff_sha256") == canonical_sha256(handoff_body)
    ):
        failures.append("confirmatory review handoff declaration invalid")
    if failures:
        raise ValueError(f"confirmatory review input invalid: {failures}")


def _copy_materials(
    materials: dict[str, dict[str, str]],
    *,
    staging: Path,
    output_root: Path,
) -> dict[str, dict[str, str]]:
    frozen = {}
    for name, source_ref in materials.items():
        source_path = Path(source_ref["path"]).resolve()
        target = staging / FROZEN_NAMES[name]
        raw = source_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != source_ref["sha256"]:
            raise ValueError(f"confirmatory source material drift: {name}")
        shutil.copyfile(source_path, target)
        target.chmod(0o600)
        frozen[name] = _published_ref(
            target,
            output_root / target.name,
            source_ref["canonical_sha256"],
        )
    return frozen


def _validate_pkcs11(
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
        and key.get("module_sha256") == hashlib.sha256(module.read_bytes()).hexdigest()
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
    ):
        raise ValueError("reviewer PKCS#11 configuration mismatch")


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _ref(path: Path, canonical: str, raw: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical,
    }


def _published_ref(
    current_path: Path,
    published_path: Path,
    canonical: str,
) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before confirmatory review promotion"
        )
    revision = _git(root, "rev-parse", "HEAD")
    if revision != _git(root, "rev-parse", "@{upstream}"):
        raise ValueError("confirmatory review promotion revision must be pushed")
    return revision


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--frozen-id", required=True)
    parser.add_argument("--reviewed-at")
    parser.add_argument("--approval-statement-sha256", required=True)
    parser.add_argument("--reviewer-handoff", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--owner-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    gate = promote_review(
        review_id=args.review_id,
        frozen_id=args.frozen_id,
        reviewed_at=args.reviewed_at or datetime.now(UTC).isoformat(),
        approval_statement_sha256=args.approval_statement_sha256,
        reviewer_handoff_path=args.reviewer_handoff,
        request_path=args.request,
        bundle_path=args.bundle,
        preflight_path=args.preflight,
        owner_gate_path=args.owner_gate,
        reviewer_profile_path=args.reviewer_profile,
        module_path=args.module,
        token_label=args.token_label,
        key_label=args.key_label,
        key_id_hex=args.key_id,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pin=read_pin(args.pin_file),
    )
    print(json.dumps(gate, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
