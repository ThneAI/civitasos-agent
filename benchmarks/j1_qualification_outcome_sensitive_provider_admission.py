"""Generate the offline outcome-sensitive J1-D provider-admission preflight."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_provider_admission import (
    SOURCE_NAMES,
    build_plan,
    build_preflight,
    canonical_source_sha256,
    validate_source_chain,
)
from benchmarks.j1_qualification_infrastructure_rebind import _read_private
from benchmarks.j1_qualification_provider_admission_refresh import (
    _inspect_current_inventory,
)


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_provider_admission.py"
)
OPERATION_SOURCE = Path(__file__)
PROBE_DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_provider_admission_probe.py"
)
PROBE_OPERATION_SOURCE = (
    Path(__file__).parent / "j1_qualification_provider_admission_probe.py"
)
OUTCOME_PROBE_OPERATION_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_provider_probe.py"
)


def generate_preflight(
    *,
    admission_id: str,
    created_at: str,
    source_paths: dict[str, Path],
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_rfc3339(created_at)
    if set(source_paths) != SOURCE_NAMES:
        raise ValueError("outcome-sensitive provider source path set invalid")
    if output_root.exists():
        raise FileExistsError(
            f"outcome-sensitive provider preflight output exists: {output_root}"
        )
    values: dict[str, dict[str, Any]] = {}
    raw_values: dict[str, bytes] = {}
    for name, path in source_paths.items():
        values[name], raw_values[name] = _read_private(path)
    raw_sha256 = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in raw_values.items()
    }
    failures = validate_source_chain(values, raw_sha256)
    if failures:
        raise ValueError(
            f"outcome-sensitive provider source chain invalid: {failures}"
        )
    inventory, inventory_failures = _inspect_current_inventory(
        infrastructure=values["infrastructure"],
        activation=values["activation"],
    )
    if inventory_failures:
        raise ValueError(
            f"outcome-sensitive provider inventory invalid: {inventory_failures}"
        )
    implementation = _implementation(repository_root)
    source_binding = {
        name: {
            "path": str(source_paths[name].resolve()),
            "sha256": raw_sha256[name],
            "canonical_sha256": canonical_source_sha256(name, values[name]),
        }
        for name in sorted(SOURCE_NAMES)
    }
    plan = build_plan(
        admission_id=admission_id,
        created_at=created_at,
        source_binding=source_binding,
        protocol=values["protocol"],
        evaluator=values["evaluator"],
        design=values["design"],
        activation=values["activation"],
        inventory_snapshot=inventory,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_path = (
        output_root
        / "outcome-sensitive-provider-admission-plan.review-required.json"
    )
    write_private_json(plan_path, plan)
    preflight = build_preflight(
        plan_path=str(plan_path.resolve()),
        plan_raw_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        plan=plan,
        created_at=created_at,
    )
    write_private_json(
        output_root / "outcome-sensitive-provider-admission-preflight.json",
        preflight,
    )
    return preflight


def replay_source_binding(
    plan: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    binding = plan.get("source_binding")
    if not isinstance(binding, dict) or set(binding) != SOURCE_NAMES:
        raise ValueError("outcome-sensitive provider source binding invalid")
    values: dict[str, dict[str, Any]] = {}
    raw_sha256: dict[str, str] = {}
    for name, reference in binding.items():
        path = Path(reference["path"])
        value, raw = _read_private(path)
        raw_digest = hashlib.sha256(raw).hexdigest()
        if raw_digest != reference["sha256"]:
            raise ValueError(f"outcome-sensitive provider source drift: {name}")
        if canonical_source_sha256(name, value) != reference["canonical_sha256"]:
            raise ValueError(
                f"outcome-sensitive provider canonical drift: {name}"
            )
        values[name] = value
        raw_sha256[name] = raw_digest
    failures = validate_source_chain(values, raw_sha256)
    if failures:
        raise ValueError(
            f"outcome-sensitive provider source replay invalid: {failures}"
        )
    return values


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "repository must be clean before outcome-sensitive provider preflight"
        )
    sources = {
        "domain_source_sha256": DOMAIN_SOURCE,
        "operation_source_sha256": OPERATION_SOURCE,
        "probe_domain_source_sha256": PROBE_DOMAIN_SOURCE,
        "probe_operation_source_sha256": PROBE_OPERATION_SOURCE,
        "outcome_probe_operation_source_sha256": OUTCOME_PROBE_OPERATION_SOURCE,
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        **{
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in sources.items()
        },
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _require_rfc3339(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("outcome-sensitive provider timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("outcome-sensitive provider timestamp requires timezone")


def _source_paths(args: argparse.Namespace) -> dict[str, Path]:
    return {name: Path(getattr(args, name)) for name in SOURCE_NAMES}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission-id", required=True)
    parser.add_argument("--created-at", required=True)
    for name in sorted(SOURCE_NAMES):
        parser.add_argument(f"--{name.replace('_', '-')}", dest=name, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    preflight = generate_preflight(
        admission_id=args.admission_id,
        created_at=args.created_at,
        source_paths=_source_paths(args),
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(preflight["owner_authorization"]["statement"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
