"""Generate the independent reviewer handoff for the r4 postmortem."""

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
from benchmarks.j1.qualification_outcome_sensitive_postmortem_review import (
    build_owner_gate,
    build_reviewer_handoff,
)


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_postmortem_review.py"
)
OPERATION_SOURCE = Path(__file__)
PROMOTION_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_postmortem_review_promote.py"
)


def generate_reviewer_handoff(
    *,
    postmortem_path: Path,
    request_path: Path,
    owner_handoff_path: Path,
    owner_statement_sha256: str,
    repository_root: Path,
    output_root: Path,
    created_at: str,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"postmortem review output exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    postmortem, postmortem_raw = _read_private(postmortem_path)
    request, request_raw = _read_private(request_path)
    owner_handoff, owner_handoff_raw = _read_private(owner_handoff_path)
    postmortem_ref = _ref(
        postmortem_path, postmortem["report_sha256"], postmortem_raw
    )
    request_ref = _ref(request_path, request["request_sha256"], request_raw)
    owner_handoff_ref = _ref(
        owner_handoff_path, owner_handoff["handoff_sha256"], owner_handoff_raw
    )
    gate = build_owner_gate(
        postmortem=postmortem,
        postmortem_ref=postmortem_ref,
        request=request,
        request_ref=request_ref,
        handoff=owner_handoff,
        handoff_ref=owner_handoff_ref,
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
        gate_path = staging / "postmortem-owner-review-authorization-gate.json"
        write_private_json(gate_path, gate)
        gate_ref = _published_ref(
            gate_path,
            output_root / gate_path.name,
            gate["report_sha256"],
        )
        reviewer_handoff = build_reviewer_handoff(
            request=request,
            request_ref=request_ref,
            postmortem_ref=postmortem_ref,
            owner_gate_ref=gate_ref,
            implementation=implementation,
        )
        write_private_json(
            staging / "postmortem-independent-review-handoff.json",
            reviewer_handoff,
        )
        operation = {
            "schema_version": "j1-outcome-sensitive-postmortem-review-preflight:v1",
            "created_at": created_at,
            "passed": True,
            "failure_reasons": [],
            "state": "independent_reviewer_decision_required",
            "owner_authorization_gate": gate_ref,
            "reviewer_handoff_sha256": reviewer_handoff["handoff_sha256"],
            "implementation": implementation,
            "external_effect_performed": False,
        }
        write_private_json(staging / "postmortem-review-preflight.json", operation)
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return reviewer_handoff
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


def _ref(
    path: Path, canonical_sha256: str, raw: bytes
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


def _published_ref(
    staging_path: Path, final_path: Path, canonical_sha256: str
) -> dict[str, str]:
    return {
        "path": str(final_path.resolve()),
        "sha256": hashlib.sha256(staging_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


def _clean_pushed_revision(repository_root: Path) -> str:
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before review preflight")
    revision = _git(repository_root, "rev-parse", "HEAD")
    if revision != _git(repository_root, "rev-parse", "@{upstream}"):
        raise ValueError("review preflight revision must be pushed")
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
    parser.add_argument("--postmortem", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--owner-handoff", type=Path, required=True)
    parser.add_argument("--owner-statement-sha256", required=True)
    parser.add_argument("--created-at")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    handoff = generate_reviewer_handoff(
        postmortem_path=args.postmortem,
        request_path=args.request,
        owner_handoff_path=args.owner_handoff,
        owner_statement_sha256=args.owner_statement_sha256,
        repository_root=args.repository_root,
        output_root=args.output_root,
        created_at=args.created_at or datetime.now(UTC).isoformat(),
    )
    print(json.dumps(handoff, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
