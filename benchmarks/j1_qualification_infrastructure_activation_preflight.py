"""Freeze a no-effect J1-D replacement-container authorization preflight."""

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

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_activation import (
    creation_authorization_statement,
    validate_reviewed_activation_source,
)
from benchmarks.j1_qualification_infrastructure_activate import (
    _validate_outcome_source_containers,
    _validate_runner_manifest_for_activation,
    _validate_target_paths,
)
from benchmarks.j1_qualification_outcome_sensitive_infrastructure_rebind import (
    _docker_census,
    _fsync_directory,
    _read_private,
    _require_targets_absent,
    _validate_runner_image_local,
)


REPORT_SCHEMA = "j1-qualification-infrastructure-activation-preflight:v1"
EXECUTION_BOUNDARY = {
    "authorization_preflight_only": True,
    "reviewed_source_replayed": True,
    "parent_container_mutated": False,
    "parent_container_removed": False,
    "target_directory_created": False,
    "participant_container_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}
DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_infrastructure_activation.py"
)
ACTIVATION_SOURCE = Path(__file__).parent / "j1_qualification_infrastructure_activate.py"
OPERATION_SOURCE = Path(__file__)


def prepare_activation_preflight(
    *,
    preflight_id: str,
    created_at: str,
    reviewed_artifact_path: Path,
    promotion_gate_path: Path,
    runner_manifest_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Replay the promoted source and emit only an exact authorization request."""
    _require_rfc3339(created_at)
    if output_root.exists():
        raise FileExistsError(f"infrastructure activation preflight exists: {output_root}")
    reviewed, reviewed_raw = _read_private(reviewed_artifact_path)
    gate, gate_raw = _read_private(promotion_gate_path)
    runner, runner_raw = _read_private(runner_manifest_path)
    failures = validate_reviewed_activation_source(
        reviewed=reviewed,
        reviewed_raw=reviewed_raw,
        gate=gate,
    )
    if failures:
        raise ValueError(f"infrastructure activation source invalid: {failures}")
    _validate_runner_binding(reviewed=reviewed, runner=runner, runner_raw=runner_raw)
    _validate_runner_image_local(runner)
    _validate_outcome_source_containers(reviewed)
    isolations = reviewed["isolations"]
    target_names = [item["target_isolation"]["container_name"] for item in isolations]
    target_root = Path(isolations[0]["target_isolation"]["input_root"]).parents[1]
    _require_targets_absent(
        target_names=target_names,
        target_state_root=target_root,
    )
    _validate_target_paths(isolations)
    census_before = _docker_census()
    if census_before.get("running_count") != 0:
        raise ValueError("J1-D participant container is running during activation preflight")
    implementation = _implementation(repository_root)
    reviewed_raw_sha256 = hashlib.sha256(reviewed_raw).hexdigest()
    gate_raw_sha256 = hashlib.sha256(gate_raw).hexdigest()
    statement = creation_authorization_statement(
        reviewed_raw_sha256=reviewed_raw_sha256,
        reviewed_canonical_sha256=reviewed["reviewed_infrastructure_rebind_sha256"],
        gate_raw_sha256=gate_raw_sha256,
        gate_canonical_sha256=gate["report_sha256"],
        image_id=reviewed["runner_image"]["image_id"],
    )
    census_after = _docker_census()
    if census_after != census_before:
        raise ValueError("J1-D Docker census changed during activation preflight")
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "exact_replacement_container_creation_authorization_required",
            "preflight_id": preflight_id,
            "created_at": created_at,
            "source_binding": {
                "reviewed_artifact": _ref(
                    reviewed_artifact_path,
                    reviewed_raw,
                    reviewed["reviewed_infrastructure_rebind_sha256"],
                ),
                "promotion_gate": _ref(
                    promotion_gate_path,
                    gate_raw,
                    gate["report_sha256"],
                ),
                "runner_manifest": _ref(
                    runner_manifest_path,
                    runner_raw,
                    runner["manifest_sha256"],
                ),
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "exact_replacement_container_creation_authorization_required": True,
            },
            "inventory": {
                "participant_count": len(isolations),
                "mentor_count": sum(item["cohort"] == "mentor" for item in isolations),
                "control_count": sum(item["cohort"] == "control" for item in isolations),
                "source_container_count": len(isolations),
                "target_container_count": len(target_names),
                "target_name_conflict_count": 0,
                "target_directory_conflict_count": 0,
            },
            "live_checks": {
                "runner_image_available": True,
                "source_container_set_unchanged": True,
                "target_names_absent": True,
                "target_state_root_absent": True,
                "docker_census": census_after,
            },
            "readiness": {
                "infrastructure_artifact_promoted": True,
                "runner_image_offline_qualified": True,
                "source_containers_verified_stopped": True,
                "replacement_container_creation_authorized": False,
                "participant_containers_created": 0,
                "participant_containers_started": 0,
                "live_provider_admission_refreshed": False,
                "controlled_experiment_execution_ready": False,
            },
            "implementation": implementation,
            "execution_boundary": EXECUTION_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            staging / "infrastructure-activation-authorization-preflight.json",
            report,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_runner_binding(
    *, reviewed: dict[str, Any], runner: dict[str, Any], runner_raw: bytes
) -> None:
    failures = _validate_runner_manifest_for_activation(
        runner_manifest=runner,
        reviewed=reviewed,
    )
    source = reviewed.get("source_binding", {}).get("runner_manifest", {})
    if not (
        not failures
        and hashlib.sha256(runner_raw).hexdigest() == source.get("sha256")
        and runner.get("manifest_sha256")
        == reviewed.get("runner_image", {}).get("manifest_sha256")
        and runner.get("image", {}).get("image_id")
        == reviewed.get("runner_image", {}).get("image_id")
    ):
        raise ValueError(f"activation runner manifest binding invalid: {failures}")


def _implementation(repository_root: Path) -> dict[str, Any]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before freezing activation preflight")
    revision = _git(root, "rev-parse", "HEAD").strip()
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    ).returncode:
        raise ValueError("activation preflight revision is not pushed")
    sources = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, ACTIVATION_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(sources),
        "source_files": sources,
    }


def _ref(path: Path, raw: bytes, canonical: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical,
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
        raise ValueError("activation preflight timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("activation preflight timestamp must include timezone")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-id", required=True)
    parser.add_argument("--created-at", default=datetime.now(UTC).isoformat())
    parser.add_argument("--reviewed-artifact", type=Path, required=True)
    parser.add_argument("--promotion-gate", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = prepare_activation_preflight(
        preflight_id=args.preflight_id,
        created_at=args.created_at,
        reviewed_artifact_path=args.reviewed_artifact,
        promotion_gate_path=args.promotion_gate,
        runner_manifest_path=args.runner_manifest,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
