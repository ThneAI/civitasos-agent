"""Generate the independent-review handoff for the confirmatory amendment."""

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

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_review import (
    build_owner_gate,
    build_review_handoff,
    build_review_request,
    validate_review_request,
)


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_confirmatory_review.py"
)
OPERATION_SOURCE = Path(__file__)
PROMOTION_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_confirmatory_review_promote.py"
)


def generate_review_handoff(
    *,
    request_id: str,
    bundle_path: Path,
    preflight_path: Path,
    owner_statement_sha256: str,
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"confirmatory review output exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    bundle, bundle_raw = _read_private(bundle_path)
    preflight, preflight_raw = _read_private(preflight_path)
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"], bundle_raw)
    preflight_ref = _ref(preflight_path, preflight["report_sha256"], preflight_raw)
    owner_gate = build_owner_gate(
        bundle=bundle,
        bundle_ref=bundle_ref,
        preflight=preflight,
        preflight_ref=preflight_ref,
        owner_statement_sha256=owner_statement_sha256,
    )
    implementation = {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "handoff_operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "promotion_operation_source_sha256": hashlib.sha256(
            PROMOTION_SOURCE.read_bytes()
        ).hexdigest(),
    }
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        owner_gate_path = staging / "confirmatory-owner-authorization-gate.json"
        write_private_json(owner_gate_path, owner_gate)
        owner_gate_ref = _published_ref(
            owner_gate_path,
            output_root / owner_gate_path.name,
            owner_gate["report_sha256"],
        )
        request = build_review_request(
            request_id=request_id,
            created_at=created_at or datetime.now(UTC).isoformat(),
            bundle_ref=bundle_ref,
            bundle=bundle,
            preflight_ref=preflight_ref,
            owner_gate_ref=owner_gate_ref,
            implementation=implementation,
        )
        failures = validate_review_request(
            request,
            expected_bundle_ref=bundle_ref,
            expected_preflight_ref=preflight_ref,
            expected_owner_gate_ref=owner_gate_ref,
            expected_materials=bundle["materials"],
            expected_implementation=implementation,
        )
        if failures:
            raise ValueError(f"confirmatory review request invalid: {failures}")
        request_path = staging / "confirmatory-amendment-review-request.json"
        write_private_json(request_path, request)
        request_ref = _published_ref(
            request_path,
            output_root / request_path.name,
            request["request_sha256"],
        )
        handoff = build_review_handoff(request_ref=request_ref, request=request)
        write_private_json(
            staging / "confirmatory-amendment-review-handoff.json",
            handoff,
        )
        write_private_json(
            staging / "confirmatory-amendment-review-decision.template.json",
            handoff["decision_template"],
        )
        operation = {
            "schema_version": "j1-confirmatory-amendment-review-preflight:v1",
            "created_at": created_at or datetime.now(UTC).isoformat(),
            "passed": True,
            "failure_reasons": [],
            "state": "independent_reviewer_decision_required",
            "owner_authorization_gate": owner_gate_ref,
            "review_request": request_ref,
            "review_handoff_sha256": handoff["handoff_sha256"],
            "implementation": implementation,
            "external_effect_performed": False,
        }
        write_private_json(staging / "confirmatory-review-preflight.json", operation)
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return handoff
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


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
    staging_path: Path,
    final_path: Path,
    canonical: str,
) -> dict[str, str]:
    return {
        "path": str(final_path.resolve()),
        "sha256": hashlib.sha256(staging_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before confirmatory review handoff")
    revision = _git(root, "rev-parse", "HEAD")
    if revision != _git(root, "rev-parse", "@{upstream}"):
        raise ValueError("confirmatory review handoff revision must be pushed")
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
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--owner-statement-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--created-at")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    handoff = generate_review_handoff(
        request_id=args.request_id,
        bundle_path=args.bundle,
        preflight_path=args.preflight,
        owner_statement_sha256=args.owner_statement_sha256,
        output_root=args.output_root,
        repository_root=args.repository_root,
        created_at=args.created_at,
    )
    print(json.dumps(handoff, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
