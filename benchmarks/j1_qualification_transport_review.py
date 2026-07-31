"""Generate an unsigned independent-review handoff for transport reliability."""

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
from benchmarks.j1.qualification_transport_review import (
    build_review_handoff,
    build_review_request,
    validate_review_request,
)


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_transport_review.py"
OPERATION_SOURCE = Path(__file__)
PROMOTION_SOURCE = Path(__file__).with_name(
    "j1_qualification_transport_review_promote.py"
)
CANDIDATE_SOURCES = {
    "domain_source_sha256": (
        "benchmarks/j1/qualification_transport_reliability.py"
    ),
    "operation_source_sha256": "benchmarks/j1_qualification_transport_reliability.py",
    "transport_source_sha256": "benchmarks/j1/qualification_http_transport.py",
}
CANONICAL_FIELDS = {
    "transport_contract": "contract_sha256",
    "fault_matrix": "report_sha256",
    "soak_plan": "plan_sha256",
    "soak_preflight": "preflight_sha256",
    "owner_handoff": "handoff_sha256",
}


def generate_review_handoff(
    *,
    request_id: str,
    contract_path: Path,
    fault_matrix_path: Path,
    soak_plan_path: Path,
    soak_preflight_path: Path,
    owner_handoff_path: Path,
    owner_statement_sha256: str,
    repository_root: Path,
    output_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"transport review output exists: {output_root}")
    _require_clean_and_synchronized(repository_root)
    paths = {
        "transport_contract": contract_path,
        "fault_matrix": fault_matrix_path,
        "soak_plan": soak_plan_path,
        "soak_preflight": soak_preflight_path,
        "owner_handoff": owner_handoff_path,
    }
    values: dict[str, dict[str, Any]] = {}
    materials: dict[str, dict[str, str]] = {}
    for name, path in paths.items():
        value, raw = _read_private(path)
        values[name] = value
        materials[name] = _ref(
            path,
            canonical=value.get(CANONICAL_FIELDS[name], ""),
            raw=raw,
        )
    _validate_candidate_implementation(
        repository_root,
        values["transport_contract"].get("implementation"),
    )
    implementation = _implementation(repository_root)
    request = build_review_request(
        request_id=request_id,
        created_at=created_at or datetime.now(UTC).isoformat(),
        materials=materials,
        values=values,
        owner_statement_sha256=owner_statement_sha256,
        review_implementation=implementation,
    )
    failures = validate_review_request(
        request,
        expected_materials=materials,
        expected_owner_statement_sha256=owner_statement_sha256,
        expected_candidate_implementation=values["transport_contract"][
            "implementation"
        ],
        expected_review_implementation=implementation,
    )
    if failures:
        raise ValueError(f"transport review request invalid: {failures}")
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        request_path = staging / "transport-reliability-review-request.json"
        write_private_json(request_path, request)
        request_ref = _published_ref(
            request_path,
            output_root / request_path.name,
            request["request_sha256"],
        )
        handoff = build_review_handoff(
            request_ref=request_ref,
            request=request,
            request_raw_sha256=request_ref["sha256"],
        )
        write_private_json(
            staging / "transport-reliability-review-handoff.json",
            handoff,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return handoff
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_candidate_implementation(
    repository_root: Path, implementation: Any
) -> None:
    if not isinstance(implementation, dict):
        raise ValueError("transport candidate implementation invalid")
    revision = implementation.get("source_revision")
    if not isinstance(revision, str):
        raise ValueError("transport candidate source revision invalid")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
            cwd=repository_root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("transport candidate revision is not an ancestor of HEAD")
    for field, path in CANDIDATE_SOURCES.items():
        source = subprocess.run(
            ["git", "show", f"{revision}:{path}"],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout
        if hashlib.sha256(source).hexdigest() != implementation.get(field):
            raise ValueError(f"transport candidate source hash drift: {path}")


def _implementation(repository_root: Path) -> dict[str, str]:
    return {
        "source_revision": _git(repository_root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "promotion_source_sha256": hashlib.sha256(
            PROMOTION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _require_clean_and_synchronized(repository_root: Path) -> None:
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before transport review generation")
    branch = _git(repository_root, "branch", "--show-current")
    if not branch:
        raise ValueError("repository must be on a branch")
    if _git(repository_root, "rev-parse", "HEAD") != _git(
        repository_root, "rev-parse", f"origin/{branch}"
    ):
        raise ValueError("repository HEAD must equal the configured origin branch")


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _ref(path: Path, *, canonical: str, raw: bytes) -> dict[str, str]:
    if len(canonical) != 64:
        raise ValueError(f"artifact canonical SHA-256 invalid: {path}")
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


def _git(repository_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
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
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--fault-matrix", type=Path, required=True)
    parser.add_argument("--soak-plan", type=Path, required=True)
    parser.add_argument("--soak-preflight", type=Path, required=True)
    parser.add_argument("--owner-handoff", type=Path, required=True)
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
    if args.created_at:
        datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    handoff = generate_review_handoff(
        request_id=args.request_id,
        contract_path=args.contract,
        fault_matrix_path=args.fault_matrix,
        soak_plan_path=args.soak_plan,
        soak_preflight_path=args.soak_preflight,
        owner_handoff_path=args.owner_handoff,
        owner_statement_sha256=args.owner_statement_sha256,
        repository_root=args.repository_root,
        output_root=args.output_root,
        created_at=args.created_at,
    )
    print(json.dumps(handoff, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
