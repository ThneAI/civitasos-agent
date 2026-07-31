"""Sign and promote independently reviewed transport reliability materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_transport_review import (
    build_frozen_review,
    build_promotion_gate,
    build_signed_review_receipt,
    reviewer_approval_statement,
    validate_review_request,
    validate_review_sources,
    validate_signed_review_receipt,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_transport_review.py"
PREPARE_SOURCE = Path(__file__).with_name("j1_qualification_transport_review.py")
OPERATION_SOURCE = Path(__file__)
CANONICAL_FIELDS = {
    "transport_contract": "contract_sha256",
    "fault_matrix": "report_sha256",
    "soak_plan": "plan_sha256",
    "soak_preflight": "preflight_sha256",
    "owner_handoff": "handoff_sha256",
}
FROZEN_NAMES = {
    "transport_contract": "transport-reliability-contract.operator-reviewed.json",
    "fault_matrix": "transport-fault-matrix.operator-reviewed.json",
    "soak_plan": "transport-admission-soak-plan.operator-reviewed.json",
    "soak_preflight": "transport-admission-soak-preflight.operator-reviewed.json",
    "owner_handoff": "transport-owner-review-handoff.source.json",
}


def promote_review(
    *,
    review_id: str,
    frozen_id: str,
    reviewed_at: str,
    approval_statement_sha256: str,
    handoff_path: Path,
    request_path: Path,
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
        raise FileExistsError(f"transport review promotion exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    handoff, handoff_raw = _read_private(handoff_path)
    request, request_raw = _read_private(request_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    request_ref = _ref(request_path, request["request_sha256"], request_raw)
    handoff_ref = _ref(handoff_path, handoff["handoff_sha256"], handoff_raw)
    materials = request.get("reviewed_materials", {})
    values = {
        name: _read_material(reference, canonical_field=CANONICAL_FIELDS[name])
        for name, reference in materials.items()
    }
    source_failures = validate_review_sources(
        materials=materials,
        values=values,
        owner_statement_sha256=request.get("owner_approval", {}).get(
            "statement_sha256", ""
        ),
    )
    implementation = _implementation(revision)
    request_failures = validate_review_request(
        request,
        expected_materials=materials,
        expected_owner_statement_sha256=request.get("owner_approval", {}).get(
            "statement_sha256", ""
        ),
        expected_candidate_implementation=request.get(
            "candidate_implementation", {}
        ),
        expected_review_implementation=implementation,
    )
    statement = reviewer_approval_statement(
        request=request,
        request_raw_sha256=hashlib.sha256(request_raw).hexdigest(),
    )
    expected_statement_sha256 = hashlib.sha256(statement.encode()).hexdigest()
    handoff_body = {
        key: item for key, item in handoff.items() if key != "handoff_sha256"
    }
    handoff_valid = (
        handoff.get("review_request") == request_ref
        and handoff.get("required_exact_approval_statement") == statement
        and handoff.get("required_exact_approval_statement_sha256")
        == expected_statement_sha256
        == approval_statement_sha256
        and handoff.get("handoff_sha256")
        == _canonical_sha256(handoff_body)
    )
    if source_failures or request_failures or not handoff_valid:
        raise ValueError(
            "transport review promotion inputs invalid: "
            f"{source_failures + request_failures + ([] if handoff_valid else ['handoff'])}"
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
                materials=materials,
                owner_statement_sha256=request["owner_approval"]["statement_sha256"],
                approval_statement_sha256=approval_statement_sha256,
                reviewer=reviewer,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        receipt_failures = validate_signed_review_receipt(
            receipt,
            expected_request_ref=request_ref,
            expected_materials=materials,
            expected_owner_statement_sha256=request["owner_approval"][
                "statement_sha256"
            ],
            expected_approval_statement_sha256=approval_statement_sha256,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256=profile_sha256,
            expected_implementation=implementation,
        )
        if receipt_failures:
            raise ValueError(
                f"signed transport review receipt invalid: {receipt_failures}"
            )
        receipt_path = staging / "transport-reliability-signed-review-receipt.json"
        write_private_json(receipt_path, receipt)
        frozen_materials = {}
        for name, source_ref in materials.items():
            source_path = Path(source_ref["path"]).resolve()
            raw = source_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != source_ref["sha256"]:
                raise ValueError(f"transport source material drift: {name}")
            target = staging / FROZEN_NAMES[name]
            shutil.copyfile(source_path, target)
            target.chmod(0o600)
            frozen_materials[name] = _published_ref(
                target,
                output_root / target.name,
                source_ref["canonical_sha256"],
            )
        receipt_ref = _published_ref(
            receipt_path,
            output_root / receipt_path.name,
            receipt["receipt_sha256"],
        )
        frozen = build_frozen_review(
            frozen_id=frozen_id,
            promoted_at=reviewed_at,
            source_materials=materials,
            frozen_materials=frozen_materials,
            review_receipt_ref=receipt_ref,
            reviewer_did=reviewer["did"],
            implementation=implementation,
        )
        frozen_path = staging / "transport-reliability.operator-reviewed.json"
        write_private_json(frozen_path, frozen)
        frozen_ref = _published_ref(
            frozen_path,
            output_root / frozen_path.name,
            frozen["frozen_review_sha256"],
        )
        gate = build_promotion_gate(
            request_ref=request_ref,
            handoff_ref=handoff_ref,
            receipt_ref=receipt_ref,
            frozen_review_ref=frozen_ref,
        )
        write_private_json(
            staging / "transport-reliability-promotion-gate.json",
            gate,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return gate
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _read_material(
    reference: dict[str, str], *, canonical_field: str
) -> dict[str, Any]:
    path = Path(reference["path"])
    value, raw = _read_private(path)
    if (
        hashlib.sha256(raw).hexdigest() != reference["sha256"]
        or value.get(canonical_field) != reference["canonical_sha256"]
    ):
        raise ValueError(f"transport review material drift: {path}")
    return value


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


def _implementation(revision: str) -> dict[str, str]:
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            PREPARE_SOURCE.read_bytes()
        ).hexdigest(),
        "promotion_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before transport review promotion")
    revision = _git(root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("transport review promotion revision is not pushed")
    return revision


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
    current_path: Path, published_path: Path, canonical: str
) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def _canonical_sha256(value: Any) -> str:
    from benchmarks.j1.controlled_comparison import canonical_sha256

    return canonical_sha256(value)


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
    parser.add_argument("--reviewed-at", required=True)
    parser.add_argument("--approval-statement-sha256", required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    datetime.fromisoformat(args.reviewed_at.replace("Z", "+00:00"))
    gate = promote_review(
        review_id=args.review_id,
        frozen_id=args.frozen_id,
        reviewed_at=args.reviewed_at,
        approval_statement_sha256=args.approval_statement_sha256,
        handoff_path=args.handoff,
        request_path=args.request,
        reviewer_profile_path=args.reviewer_profile,
        module_path=args.module,
        token_label=args.token_label,
        key_label=args.key_label,
        key_id_hex=args.key_id,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pin=read_pin(args.pin_file),
    )
    print(json.dumps(gate, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
