"""Generate an unsigned independent-review handoff for J1-D amendment materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_amendment_review import (
    build_review_handoff,
    build_review_request,
    validate_review_request,
)


OPERATION_SOURCE = Path(__file__)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_amendment_review.py"
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
        raise ValueError(f"review output already exists: {output_root}")
    _require_clean_and_synchronized(repository_root)
    bundle = _read_artifact(bundle_path, "bundle_sha256")
    preflight = _read_artifact(preflight_path, "report_sha256")
    _verify_material_files(bundle["value"]["materials"])
    implementation = _implementation(repository_root)
    request = build_review_request(
        request_id=request_id,
        created_at=created_at or datetime.now(UTC).isoformat(),
        bundle_ref=bundle["ref"],
        bundle=bundle["value"],
        preflight_ref=preflight["ref"],
        preflight=preflight["value"],
        owner_statement_sha256=owner_statement_sha256,
        implementation=implementation,
    )
    failures = validate_review_request(
        request,
        expected_bundle_ref=bundle["ref"],
        expected_preflight_ref=preflight["ref"],
        expected_materials=bundle["value"]["materials"],
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"amendment review request invalid: {failures}")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    request_path = output_root / "outcome-sensitive-amendment-review-request.json"
    write_private_json(request_path, request)
    request_ref = _ref(request_path, request["request_sha256"])
    handoff = build_review_handoff(
        request_ref=request_ref,
        request=request,
        request_raw_sha256=request_ref["sha256"],
    )
    write_private_json(
        output_root / "outcome-sensitive-amendment-review-handoff.json",
        handoff,
    )
    return handoff


def _verify_material_files(materials: dict[str, dict[str, str]]) -> None:
    for name, ref in materials.items():
        path = Path(ref["path"]).resolve()
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"review material is not a regular file: {name}")
        if path.stat().st_mode & 0o777 != 0o600:
            raise ValueError(f"review material must be mode 0600: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != ref["sha256"]:
            raise ValueError(f"review material raw SHA-256 drift: {name}")
        value = json.loads(path.read_bytes())
        canonical_fields = [
            key for key in value if key.endswith("_sha256") and key != "created_at"
        ]
        self_fields = [
            key
            for key in canonical_fields
            if key
            in {
                "plan_sha256",
                "fixture_sha256",
                "statistical_plan_sha256",
                "protocol_sha256",
                "evaluator_sha256",
                "assessment_sha256",
            }
        ]
        if len(self_fields) != 1 or value[self_fields[0]] != ref["canonical_sha256"]:
            raise ValueError(f"review material canonical SHA-256 drift: {name}")


def _read_artifact(path: Path, canonical_field: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"artifact must be a regular file: {resolved}")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"artifact must be mode 0600: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or not _sha256(value.get(canonical_field)):
        raise ValueError(f"artifact canonical SHA-256 invalid: {resolved}")
    return {"value": value, "ref": _ref(resolved, value[canonical_field])}


def _ref(path: Path, canonical: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
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
    if _git(repository_root, "rev-parse", "HEAD") != _git(
        repository_root, "rev-parse", f"origin/{branch}"
    ):
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
    print(json.dumps(handoff, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
