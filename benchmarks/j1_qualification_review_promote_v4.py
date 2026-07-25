"""Sign and promote the independently approved J1-D r4 execution stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_review_promotion_v4 import (
    build_frozen_stack,
    build_signed_review_receipt,
)
from benchmarks.j1.qualification_review_v4 import validate_review_bundle
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_review_promotion_v4.py"
)
OPERATION_SOURCE = Path(__file__)


def promote_reviewed_stack(
    *,
    review_id: str,
    frozen_id: str,
    reviewed_at: str,
    approval_statement_sha256: str,
    handoff_path: Path,
    request_path: Path,
    bundle_path: Path,
    contract_path: Path,
    offline_report_path: Path,
    offline_journal_path: Path,
    fault_report_path: Path,
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
        raise FileExistsError(f"r4 promotion output exists: {output_root}")
    handoff, handoff_raw = _read_private(handoff_path)
    request, request_raw = _read_private(request_path)
    bundle, bundle_raw = _read_private(bundle_path)
    contract, contract_raw = _read_private(contract_path)
    offline, offline_raw = _read_private(offline_report_path)
    fault, fault_raw = _read_private(fault_report_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    journal_raw = offline_journal_path.read_bytes()
    _validate_inputs(
        handoff=handoff,
        handoff_raw=handoff_raw,
        request=request,
        request_raw=request_raw,
        bundle=bundle,
        bundle_raw=bundle_raw,
        contract=contract,
        contract_raw=contract_raw,
        offline=offline,
        offline_raw=offline_raw,
        journal_raw=journal_raw,
        fault=fault,
        fault_raw=fault_raw,
        approval_statement_sha256=approval_statement_sha256,
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer profile invalid: {profile_failures}")
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    implementation = _implementation(repository_root)
    reviewer = profile["reviewer"]
    request_ref = _ref(request_path, request["request_sha256"])
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"])
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    temporary = output_root.with_name(
        f".{output_root.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    temporary.mkdir(parents=True, mode=0o700)
    temporary.chmod(0o700)
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
                contract_sha256=contract["contract_sha256"],
                approval_statement_sha256=approval_statement_sha256,
                reviewer=reviewer,
                reviewer_profile_sha256=profile_sha256,
                implementation=implementation,
                signer=signer,
            )
        receipt_path = temporary / "r4-signed-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_ref = _published_ref(
            receipt_path,
            output_root / receipt_path.name,
            receipt["receipt_sha256"],
        )
        copies = {
            "execution_contract": (
                contract_path,
                "execution-contract.operator-reviewed-frozen.json",
                contract["contract_sha256"],
            ),
            "offline_orchestrator_report": (
                offline_report_path,
                "offline-orchestrator-report.operator-reviewed-frozen.json",
                offline["report_sha256"],
            ),
            "offline_execution_journal": (
                offline_journal_path,
                "offline-execution-journal.operator-reviewed-frozen.sqlite3",
                offline["journal"]["journal_sha256"],
            ),
            "fault_matrix_report": (
                fault_report_path,
                "fault-matrix-report.operator-reviewed-frozen.json",
                fault["report_sha256"],
            ),
            "review_bundle": (
                bundle_path,
                "r4-execution-review-bundle.operator-reviewed-frozen.json",
                bundle["bundle_sha256"],
            ),
        }
        frozen_refs: dict[str, dict[str, str]] = {}
        for name, (source, filename, canonical_digest) in copies.items():
            target = temporary / filename
            shutil.copyfile(source, target)
            target.chmod(0o600)
            frozen_refs[name] = _published_ref(
                target, output_root / filename, canonical_digest
            )
        frozen = build_frozen_stack(
            frozen_id=frozen_id,
            promoted_at=reviewed_at,
            candidate_bundle_sha256=bundle["bundle_sha256"],
            review_receipt_ref=receipt_ref,
            frozen_artifacts=frozen_refs,
            implementation=implementation,
        )
        frozen_path = temporary / "r4-execution-stack.operator-reviewed-frozen.json"
        write_private_json(frozen_path, frozen)
        frozen_ref = _published_ref(
            frozen_path,
            output_root / frozen_path.name,
            frozen["frozen_stack_sha256"],
        )
        gate = {
            "schema_version": "j1-qualification-r4-review-promotion-gate:v1",
            "passed": True,
            "failure_reasons": [],
            "state": "r4_execution_stack_frozen_provider_refresh_required",
            "review_request": request_ref,
            "review_bundle": bundle_ref,
            "review_receipt": receipt_ref,
            "frozen_stack": frozen_ref,
            "signature_valid": True,
            "pin_recorded": False,
            "private_key_exported": False,
            "readiness": frozen["readiness"],
            "execution_boundary": frozen["execution_boundary"],
        }
        gate["report_sha256"] = canonical_sha256(gate)
        write_private_json(temporary / "r4-review-promotion-gate-report.json", gate)
        os.replace(temporary, output_root)
        _fsync_directory(output_root.parent)
        return gate
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _validate_inputs(
    *,
    handoff: dict[str, Any],
    handoff_raw: bytes,
    request: dict[str, Any],
    request_raw: bytes,
    bundle: dict[str, Any],
    bundle_raw: bytes,
    contract: dict[str, Any],
    contract_raw: bytes,
    offline: dict[str, Any],
    offline_raw: bytes,
    journal_raw: bytes,
    fault: dict[str, Any],
    fault_raw: bytes,
    approval_statement_sha256: str,
) -> None:
    del handoff_raw
    failures = validate_review_bundle(bundle)
    if failures:
        raise ValueError(f"r4 review bundle invalid: {failures}")
    if not (
        handoff.get("status") == "independent_reviewer_decision_required"
        and handoff.get("statement_sha256") == approval_statement_sha256
        and handoff.get("request", {}).get("sha256")
        == hashlib.sha256(request_raw).hexdigest()
        and handoff.get("request", {}).get("canonical_sha256")
        == request.get("request_sha256")
        and handoff.get("bundle", {}).get("sha256")
        == hashlib.sha256(bundle_raw).hexdigest()
        and handoff.get("bundle", {}).get("canonical_sha256")
        == bundle.get("bundle_sha256")
    ):
        raise ValueError("r4 review handoff or approval statement mismatch")
    refs = bundle["artifacts"]
    checks = {
        "execution_contract": (
            contract_raw,
            contract.get("contract_sha256"),
        ),
        "offline_orchestrator_report": (
            offline_raw,
            offline.get("report_sha256"),
        ),
        "offline_execution_journal": (
            journal_raw,
            offline.get("journal", {}).get("journal_sha256"),
        ),
        "fault_matrix_report": (fault_raw, fault.get("report_sha256")),
    }
    for name, (raw, canonical_digest) in checks.items():
        if (
            refs[name]["sha256"] != hashlib.sha256(raw).hexdigest()
            or refs[name]["canonical_sha256"] != canonical_digest
        ):
            raise ValueError(f"r4 review artifact binding mismatch: {name}")


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
        key["module_path"] == str(module)
        and key["module_sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()
        and key["token_label"] == token_label
        and key["key_label"] == key_label
        and key["key_id_hex"] == key_id_hex.lower()
    ):
        raise ValueError("r4 reviewer PKCS#11 configuration mismatch")


def _implementation(repository_root: Path) -> dict[str, str]:
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before r4 review promotion")
    return {
        "source_revision": _git(repository_root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _published_ref(
    current_path: Path, published_path: Path, canonical_digest: str
) -> dict[str, str]:
    return {
        "path": str(published_path.resolve()),
        "sha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--frozen-id", required=True)
    parser.add_argument("--reviewed-at", required=True)
    parser.add_argument("--approval-statement-sha256", required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--offline-report", type=Path, required=True)
    parser.add_argument("--offline-journal", type=Path, required=True)
    parser.add_argument("--fault-report", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.reviewed_at.replace("Z", "+00:00"))
    pin = read_pin(args.pin_file)
    report = promote_reviewed_stack(
        review_id=args.review_id,
        frozen_id=args.frozen_id,
        reviewed_at=args.reviewed_at,
        approval_statement_sha256=args.approval_statement_sha256,
        handoff_path=args.handoff,
        request_path=args.request,
        bundle_path=args.bundle,
        contract_path=args.contract,
        offline_report_path=args.offline_report,
        offline_journal_path=args.offline_journal,
        fault_report_path=args.fault_report,
        reviewer_profile_path=args.reviewer_profile,
        module_path=args.module,
        token_label=args.token_label,
        key_label=args.key_label,
        key_id_hex=args.key_id,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pin=pin,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
