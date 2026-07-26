"""Prepare or promote the J1-D r4 failed-closeout implementation review."""

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
from benchmarks.j1.qualification_failed_closeout_review_v4 import (
    build_review_bundle,
    build_review_gate,
    build_review_request,
    build_signed_receipt,
    reviewer_approval_statement,
    validate_review_bundle,
    validate_signed_receipt,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_failed_execution_closeout_v4 import _budget_summary
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_failed_closeout_review_v4.py"
)
OPERATION_SOURCE = Path(__file__)
SOURCE_PATHS = [
    "benchmarks/j1/qualification_failed_closeout_review_v4.py",
    "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
    "benchmarks/j1/qualification_provider_broker.py",
    "benchmarks/j1_qualification_failed_closeout_review_v4.py",
    "benchmarks/j1_qualification_failed_execution_closeout_v4.py",
]


def prepare_review(
    *,
    bundle_id: str,
    request_id: str,
    created_at: str,
    claim_path: Path,
    live_report_path: Path,
    budget_path: Path,
    repository_root: Path,
    output_root: Path,
    pytest_passed_count: int,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"failed closeout review output exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    claim, claim_raw = _read_private(claim_path)
    report, report_raw = _read_private(live_report_path)
    if not (
        claim.get("run_id") == "j1d-qualification-run-20260726-r8"
        and report.get("run_id") == claim["run_id"]
        and report.get("status") == "failed"
        and report.get("failure_reason") == "provider_outcome_unknown"
        and report.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in report.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("failed closeout review r8 evidence invalid")
    budget = _budget_summary(budget_path)
    states = report["journal"]["task_states"]
    bundle = build_review_bundle(
        bundle_id=bundle_id,
        created_at=created_at,
        run_evidence={
            "run_id": report["run_id"],
            "claim": _ref(claim_path, claim["claim_sha256"], raw=claim_raw),
            "live_report": _ref(
                live_report_path, report["report_sha256"], raw=report_raw
            ),
            "failure_state": report["failure_reason"],
            "provider_call_count": report["execution_scope"]["provider_call_count"],
            "committed_task_count": int(states.get("task_committed", 0)),
            "unattempted_task_count": int(states.get("planned", 0)),
            "budget_summary": budget,
        },
        source_implementation={
            "source_revision": revision,
            "source_files": {
                relative: hashlib.sha256(
                    (repository_root / relative).read_bytes()
                ).hexdigest()
                for relative in SOURCE_PATHS
            },
        },
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": pytest_passed_count,
            "remote_revision_verified": True,
            "provider_or_model_call_performed": False,
            "participant_container_started": False,
        },
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    bundle_path = output_root / "failed-closeout-implementation-review-bundle.json"
    write_private_json(bundle_path, bundle)
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"])
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        bundle_ref=bundle_ref,
        bundle=bundle,
    )
    request_path = output_root / "failed-closeout-implementation-review-request.json"
    write_private_json(request_path, request)
    request_raw_sha256 = hashlib.sha256(request_path.read_bytes()).hexdigest()
    exact_statement = reviewer_approval_statement(
        request_raw_sha256=request_raw_sha256,
        bundle_raw_sha256=bundle_ref["sha256"],
        bundle=bundle,
    )
    handoff = {
        "schema_version": "j1-qualification-r4-failed-closeout-review-handoff:v1",
        "status": "independent_reviewer_decision_required",
        "request": _ref(request_path, request["request_sha256"]),
        "bundle": bundle_ref,
        "required_exact_approval_statement": exact_statement,
        "statement_sha256": hashlib.sha256(exact_statement.encode()).hexdigest(),
        "execution_boundary": bundle["execution_boundary"],
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    write_private_json(
        output_root / "failed-closeout-implementation-review-handoff.json", handoff
    )
    return handoff


def promote_review(
    *,
    review_id: str,
    reviewed_at: str,
    approval_statement_sha256: str,
    handoff_path: Path,
    request_path: Path,
    bundle_path: Path,
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
        raise FileExistsError(f"failed closeout promotion output exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    handoff, handoff_raw = _read_private(handoff_path)
    request, request_raw = _read_private(request_path)
    bundle, bundle_raw = _read_private(bundle_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"], raw=bundle_raw)
    request_ref = _ref(request_path, request["request_sha256"], raw=request_raw)
    expected_statement = reviewer_approval_statement(
        request_raw_sha256=hashlib.sha256(request_raw).hexdigest(),
        bundle_raw_sha256=hashlib.sha256(bundle_raw).hexdigest(),
        bundle=bundle,
    )
    if not (
        validate_review_bundle(bundle) == []
        and bundle["source_implementation"]["source_revision"] == revision
        and handoff.get("request") == request_ref
        and handoff.get("bundle") == bundle_ref
        and handoff.get("required_exact_approval_statement") == expected_statement
        and handoff.get("statement_sha256")
        == hashlib.sha256(expected_statement.encode()).hexdigest()
        == approval_statement_sha256
        and handoff.get("handoff_sha256")
        == canonical_sha256(
            {key: item for key, item in handoff.items() if key != "handoff_sha256"}
        )
        and request.get("request_sha256")
        == canonical_sha256(
            {key: item for key, item in request.items() if key != "request_sha256"}
        )
    ):
        raise ValueError("failed closeout review approval or artifact binding invalid")
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"failed closeout reviewer profile invalid: {profile_failures}")
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    with Pkcs11Ed25519Signer(
        str(Path(module_path).resolve()),
        token_label,
        key_label,
        reviewer["public_key_hex"],
        pin,
        key_id=key_id_hex,
    ) as signer:
        receipt = build_signed_receipt(
            review_id=review_id,
            reviewed_at=reviewed_at,
            request_ref=request_ref,
            bundle_ref=bundle_ref,
            approval_statement_sha256=approval_statement_sha256,
            reviewer=reviewer,
            reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
            signer=signer,
        )
    failures = validate_signed_receipt(
        receipt,
        request_ref=request_ref,
        bundle_ref=bundle_ref,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
    )
    if failures:
        raise ValueError(f"failed closeout signed review invalid: {failures}")
    return _persist_promotion(
        output_root=output_root,
        bundle_path=bundle_path,
        bundle=bundle,
        receipt=receipt,
    )


def _persist_promotion(
    *,
    output_root: Path,
    bundle_path: Path,
    bundle: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        frozen_bundle = staging / "failed-closeout-review-bundle.operator-reviewed.json"
        shutil.copyfile(bundle_path, frozen_bundle)
        frozen_bundle.chmod(0o600)
        receipt_path = staging / "failed-closeout-signed-review-receipt.json"
        write_private_json(receipt_path, receipt)
        published_bundle = output_root / frozen_bundle.name
        published_receipt = output_root / receipt_path.name
        bundle_ref = _published_ref(
            frozen_bundle, published_bundle, bundle["bundle_sha256"]
        )
        receipt_ref = _published_ref(
            receipt_path,
            published_receipt,
            receipt["signature"]["signed_payload_sha256"],
        )
        gate = build_review_gate(bundle_ref=bundle_ref, receipt_ref=receipt_ref)
        write_private_json(
            staging / "failed-closeout-implementation-review-gate-report.json", gate
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return gate


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for failed closeout review")
    revision = _git(root, "rev-parse", "HEAD")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("failed closeout review revision is not pushed")
    return revision


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
        raise ValueError("failed closeout reviewer PKCS#11 configuration mismatch")


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"failed closeout private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("failed closeout review artifact must be an object")
    return value, raw


def _ref(
    path: Path, canonical_digest: str, *, raw: bytes | None = None
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(
            raw if raw is not None else path.read_bytes()
        ).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _published_ref(
    current: Path, published: Path, canonical_digest: str
) -> dict[str, str]:
    return {
        "path": str(published.resolve()),
        "sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--bundle-id", required=True)
    prepare.add_argument("--request-id", required=True)
    prepare.add_argument("--created-at", required=True)
    prepare.add_argument("--claim", type=Path, required=True)
    prepare.add_argument("--live-report", type=Path, required=True)
    prepare.add_argument("--budget", type=Path, required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--output-root", type=Path, required=True)
    prepare.add_argument("--pytest-passed-count", type=int, required=True)
    promote = subparsers.add_parser("promote")
    promote.add_argument("--review-id", required=True)
    promote.add_argument("--reviewed-at", required=True)
    promote.add_argument("--approval-statement-sha256", required=True)
    promote.add_argument("--handoff", type=Path, required=True)
    promote.add_argument("--request", type=Path, required=True)
    promote.add_argument("--bundle", type=Path, required=True)
    promote.add_argument("--reviewer-profile", type=Path, required=True)
    promote.add_argument("--module", default=DEFAULT_MODULE)
    promote.add_argument("--token-label", required=True)
    promote.add_argument("--key-label", required=True)
    promote.add_argument("--key-id", required=True)
    promote.add_argument("--pin-file", type=Path)
    promote.add_argument("--repository-root", type=Path, required=True)
    promote.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "prepare":
        result = prepare_review(
            bundle_id=args.bundle_id,
            request_id=args.request_id,
            created_at=args.created_at,
            claim_path=args.claim,
            live_report_path=args.live_report,
            budget_path=args.budget,
            repository_root=args.repository_root,
            output_root=args.output_root,
            pytest_passed_count=args.pytest_passed_count,
        )
    else:
        result = promote_review(
            review_id=args.review_id,
            reviewed_at=args.reviewed_at,
            approval_statement_sha256=args.approval_statement_sha256,
            handoff_path=args.handoff,
            request_path=args.request,
            bundle_path=args.bundle,
            reviewer_profile_path=args.reviewer_profile,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            repository_root=args.repository_root,
            output_root=args.output_root,
            pin=read_pin(args.pin_file),
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
