"""Generate the independent-review handoff for J1-D r11 null-result materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_null_result_postmortem_review import (
    build_review_handoff,
    build_review_request,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_null_result_postmortem_review.py"
)
OPERATION_SOURCE = Path(__file__)


def generate_review_handoff(
    *,
    request_id: str,
    postmortem_path: Path,
    candidate_path: Path,
    gate_path: Path,
    owner_statement_sha256: str,
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Validate frozen sources and write a private unsigned review packet."""
    if output_root.exists():
        raise ValueError(f"review output already exists: {output_root}")
    _require_clean_and_synchronized(repository_root)
    postmortem = _read_private_artifact(
        postmortem_path,
        canonical_field="report_sha256",
    )
    candidate = _read_private_artifact(
        candidate_path,
        canonical_field="candidate_sha256",
    )
    gate = _read_private_artifact(gate_path, canonical_field="report_sha256")
    implementation = _implementation(repository_root)
    request = build_review_request(
        request_id=request_id,
        created_at=created_at or datetime.now(UTC).isoformat(),
        postmortem_ref=postmortem["ref"],
        postmortem=postmortem["value"],
        candidate_ref=candidate["ref"],
        candidate=candidate["value"],
        gate_ref=gate["ref"],
        gate=gate["value"],
        owner_statement_sha256=owner_statement_sha256,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    request_path = output_root / "null-result-postmortem-review-request.json"
    write_private_json(request_path, request)
    request_raw_sha256 = hashlib.sha256(request_path.read_bytes()).hexdigest()
    request_ref = _artifact_ref(
        request_path,
        canonical_sha256=request["request_sha256"],
    )
    handoff = build_review_handoff(
        request_ref=request_ref,
        request=request,
        request_raw_sha256=request_raw_sha256,
    )
    write_private_json(
        output_root / "null-result-postmortem-review-handoff.json",
        handoff,
    )
    return handoff


def _read_private_artifact(
    path: Path,
    *,
    canonical_field: str,
) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"artifact must be a regular file: {resolved}")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"artifact must be mode 0600: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"artifact must be a JSON object: {resolved}")
    canonical_sha256 = value.get(canonical_field)
    if not _sha256(canonical_sha256):
        raise ValueError(f"artifact canonical SHA-256 invalid: {resolved}")
    return {
        "value": value,
        "ref": {
            "path": str(resolved),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": canonical_sha256,
        },
    }


def _artifact_ref(path: Path, *, canonical_sha256: str) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


def _implementation(repository_root: Path) -> dict[str, str]:
    return {
        "source_revision": _git(repository_root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _require_clean_and_synchronized(repository_root: Path) -> None:
    if _git(repository_root, "status", "--porcelain"):
        raise ValueError("repository must be clean before review handoff generation")
    branch = _git(repository_root, "branch", "--show-current")
    if not branch:
        raise ValueError("repository must be on a branch")
    head = _git(repository_root, "rev-parse", "HEAD")
    remote = _git(repository_root, "rev-parse", f"origin/{branch}")
    if head != remote:
        raise ValueError("repository HEAD must equal the configured origin branch")


def _git(repository_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--postmortem", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--gate", type=Path, required=True)
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
    if not _sha256(args.owner_statement_sha256):
        raise ValueError("owner statement SHA-256 invalid")
    handoff = generate_review_handoff(
        request_id=args.request_id,
        postmortem_path=args.postmortem,
        candidate_path=args.candidate,
        gate_path=args.gate,
        owner_statement_sha256=args.owner_statement_sha256,
        output_root=args.output_root,
        repository_root=args.repository_root,
        created_at=args.created_at,
    )
    print(json.dumps(handoff, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
