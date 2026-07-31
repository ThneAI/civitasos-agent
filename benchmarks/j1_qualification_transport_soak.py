"""Generate the offline authorization preflight for the transport admission soak."""

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
from benchmarks.j1.qualification_transport_soak import (
    build_authorization_preflight,
    build_execution_plan,
    validate_execution_plan,
    validate_reviewed_sources,
)


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_transport_soak.py"
OPERATION_SOURCE = Path(__file__)
EXECUTION_SOURCE = Path(__file__).with_name("j1_qualification_transport_soak_execute.py")


def generate_preflight(
    *,
    soak_id: str,
    promotion_gate_path: Path,
    frozen_review_path: Path,
    reviewed_soak_plan_path: Path,
    repository_root: Path,
    output_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"transport soak preflight output exists: {output_root}")
    _require_clean_and_synchronized(repository_root)
    promotion_gate, promotion_raw = _read_private(promotion_gate_path)
    frozen_review, frozen_raw = _read_private(frozen_review_path)
    reviewed_plan, reviewed_raw = _read_private(reviewed_soak_plan_path)
    refs = {
        "promotion_gate": _ref(
            promotion_gate_path,
            promotion_gate.get("report_sha256", ""),
            promotion_raw,
        ),
        "frozen_review": _ref(
            frozen_review_path,
            frozen_review.get("frozen_review_sha256", ""),
            frozen_raw,
        ),
        "reviewed_soak_plan": _ref(
            reviewed_soak_plan_path,
            reviewed_plan.get("plan_sha256", ""),
            reviewed_raw,
        ),
    }
    failures = validate_reviewed_sources(
        promotion_gate=promotion_gate,
        frozen_review=frozen_review,
        reviewed_plan=reviewed_plan,
        refs=refs,
    )
    if failures:
        raise ValueError(f"transport soak reviewed sources invalid: {failures}")
    provider_design_ref = reviewed_plan["source_binding"]["provider_design"]
    provider_design, provider_design_raw = _read_private(
        Path(provider_design_ref["path"])
    )
    canonical_candidates = {
        value
        for name, value in provider_design.items()
        if name.endswith("_sha256")
    }
    if not (
        hashlib.sha256(provider_design_raw).hexdigest()
        == provider_design_ref["sha256"]
        and provider_design_ref["canonical_sha256"] in canonical_candidates
    ):
        raise ValueError("transport soak provider design binding invalid")
    pricing = provider_design.get("preserved_pricing")
    if not isinstance(pricing, dict):
        raise ValueError("transport soak pricing is unavailable")
    now = created_at or datetime.now(UTC).isoformat()
    implementation = _implementation(repository_root)
    plan = build_execution_plan(
        soak_id=soak_id,
        created_at=now,
        source_artifacts=refs,
        reviewed_plan=reviewed_plan,
        pricing=pricing,
        implementation=implementation,
    )
    plan_failures = validate_execution_plan(plan)
    if plan_failures:
        raise ValueError(f"transport soak execution plan invalid: {plan_failures}")
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        plan_path = staging / "transport-admission-soak-execution-plan.json"
        write_private_json(plan_path, plan)
        plan_ref = _published_ref(
            plan_path,
            output_root / plan_path.name,
            plan["plan_sha256"],
        )
        preflight = build_authorization_preflight(
            plan_ref=plan_ref,
            plan=plan,
            created_at=now,
        )
        write_private_json(
            staging / "transport-admission-soak-authorization-preflight.json",
            preflight,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return preflight
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _implementation(root: Path) -> dict[str, str]:
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "preflight_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "execution_source_sha256": hashlib.sha256(
            EXECUTION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _require_clean_and_synchronized(root: Path) -> None:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before transport soak preflight")
    branch = _git(root, "branch", "--show-current")
    if not branch:
        raise ValueError("repository must be on a branch")
    if _git(root, "rev-parse", "HEAD") != _git(
        root, "rev-parse", f"origin/{branch}"
    ):
        raise ValueError("repository HEAD must equal configured origin branch")


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
    parser.add_argument("--soak-id", required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--frozen-review", type=Path, required=True)
    parser.add_argument("--reviewed-soak-plan", type=Path, required=True)
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
    preflight = generate_preflight(
        soak_id=args.soak_id,
        promotion_gate_path=args.promotion_gate,
        frozen_review_path=args.frozen_review,
        reviewed_soak_plan_path=args.reviewed_soak_plan,
        repository_root=args.repository_root,
        output_root=args.output_root,
        created_at=args.created_at,
    )
    print(json.dumps(preflight, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
