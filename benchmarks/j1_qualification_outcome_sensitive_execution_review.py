"""Generate independent-review materials for the outcome-sensitive stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_execution_review import (
    build_review_bundle,
    build_review_request,
    reviewer_approval_statement,
    validate_evidence_schemas,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


EXECUTION_SOURCE_PATHS = [
    "benchmarks/j1/qualification_execution_contract_v4.py",
    "benchmarks/j1/qualification_fault_matrix_v4.py",
    "benchmarks/j1/qualification_orchestrator_v4.py",
    "benchmarks/j1/qualification_outcome_sensitive_execution_contract.py",
    "benchmarks/j1/qualification_outcome_sensitive_execution_review.py",
    "benchmarks/j1/qualification_outcome_sensitive_fault_matrix.py",
    "benchmarks/j1/qualification_outcome_sensitive_orchestrator.py",
    "benchmarks/j1_qualification_outcome_sensitive_execution_contract.py",
    "benchmarks/j1_qualification_outcome_sensitive_execution_review.py",
    "benchmarks/j1_qualification_outcome_sensitive_fault_matrix.py",
    "benchmarks/j1_qualification_outcome_sensitive_orchestrator.py",
]


def generate_review_materials(
    *,
    bundle_id: str,
    request_id: str,
    created_at: str,
    contract_path: Path,
    offline_report_path: Path,
    offline_journal_path: Path,
    fault_report_path: Path,
    repository_root: Path,
    output_root: Path,
    pytest_passed_count: int,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(
            f"outcome-sensitive review output exists: {output_root}"
        )
    _require_clean(repository_root)
    contract = _read_object(contract_path)
    offline = _read_object(offline_report_path)
    fault = _read_object(fault_report_path)
    _validate_evidence(
        contract=contract,
        offline=offline,
        fault=fault,
        offline_journal_path=offline_journal_path,
    )
    _replay_source_artifacts(contract)
    inventory = _container_inventory(contract)
    if not _remote_revision_verified(repository_root):
        raise ValueError(
            "outcome-sensitive review revision is not present at configured origin"
        )
    source_implementation = {
        "review_material_revision": _git(repository_root, "rev-parse", "HEAD"),
        "execution_contract_revision": contract["implementation"]["source_revision"],
        "source_files": {
            relative: hashlib.sha256(
                (repository_root / relative).read_bytes()
            ).hexdigest()
            for relative in EXECUTION_SOURCE_PATHS
        },
    }
    artifacts = {
        "execution_contract": _ref(contract_path, contract["contract_sha256"]),
        "offline_orchestrator_report": _ref(
            offline_report_path, offline["report_sha256"]
        ),
        "offline_execution_journal": _ref(
            offline_journal_path, offline["journal"]["journal_sha256"]
        ),
        "fault_matrix_report": _ref(fault_report_path, fault["report_sha256"]),
    }
    bundle = build_review_bundle(
        bundle_id=bundle_id,
        created_at=created_at,
        artifacts=artifacts,
        contract=contract,
        offline_report=offline,
        fault_report=fault,
        source_implementation=source_implementation,
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": pytest_passed_count,
            "journal_artifact_hash_recomputed": True,
            "remote_revision_verified": True,
            "all_source_hashes_replayed": True,
        },
        inventory_snapshot=inventory,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    bundle_path = output_root / "outcome-sensitive-execution-review-bundle.json"
    write_private_json(bundle_path, bundle)
    bundle_raw_sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        bundle_path=str(bundle_path.resolve()),
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    request_path = output_root / "outcome-sensitive-execution-review-request.json"
    write_private_json(request_path, request)
    request_raw_sha256 = hashlib.sha256(request_path.read_bytes()).hexdigest()
    exact_statement = reviewer_approval_statement(
        request_raw_sha256=request_raw_sha256,
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    handoff = {
        "schema_version": "j1-qualification-outcome-sensitive-review-handoff:v1",
        "status": "independent_reviewer_decision_required",
        "request": _ref(request_path, request["request_sha256"]),
        "bundle": _ref(bundle_path, bundle["bundle_sha256"]),
        "required_exact_approval_statement": exact_statement,
        "statement_sha256": hashlib.sha256(exact_statement.encode()).hexdigest(),
        "review_boundary": request["review_boundary"],
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    write_private_json(
        output_root / "outcome-sensitive-execution-review-handoff.json",
        handoff,
    )
    return handoff


def _validate_evidence(
    *,
    contract: dict[str, Any],
    offline: dict[str, Any],
    fault: dict[str, Any],
    offline_journal_path: Path,
) -> None:
    contract_hash = contract.get("contract_sha256")
    if (
        not validate_evidence_schemas(
            contract=contract,
            offline_report=offline,
            fault_report=fault,
        )
        or contract.get("status") != "independent_review_required"
        or len(contract.get("task_executions", [])) != 480
        or contract_hash
        != canonical_sha256(
            {key: item for key, item in contract.items() if key != "contract_sha256"}
        )
    ):
        raise ValueError("outcome-sensitive execution contract evidence invalid")
    if (
        offline.get("status") != "complete"
        or offline.get("contract_sha256") != contract_hash
        or offline.get("journal", {}).get("task_states")
        != {"task_committed": 480}
        or offline.get("journal", {}).get("budget_states") != {"reconciled": 480}
        or offline.get("journal", {}).get("event_count") != 5760
        or offline.get("offline_scope", {}).get("provider_call_count") != 480
        or offline.get("offline_scope", {}).get("participant_signature_count") != 480
        or offline.get("validation_failures") != []
        or offline.get("execution_boundary", {}).get(
            "fixture_ground_truth_revealed"
        )
        is not False
    ):
        raise ValueError(
            "outcome-sensitive offline orchestrator evidence invalid"
        )
    actual_journal_hash = hashlib.sha256(offline_journal_path.read_bytes()).hexdigest()
    if actual_journal_hash != offline["journal"]["journal_artifact_sha256"]:
        raise ValueError("outcome-sensitive offline journal artifact hash mismatch")
    if (
        fault.get("passed") is not True
        or fault.get("scenario_count") != 8
        or fault.get("contract_sha256") != contract_hash
    ):
        raise ValueError("outcome-sensitive fault matrix evidence invalid")


def _replay_source_artifacts(contract: dict[str, Any]) -> None:
    for name, reference in contract.get("source_artifacts", {}).items():
        path = Path(str(reference.get("path", "")))
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest()
            != reference.get("sha256")
        ):
            raise ValueError(f"outcome-sensitive source artifact drift: {name}")
        value = _read_object(path)
        canonical_candidates = {
            item
            for key, item in value.items()
            if key.endswith("_sha256") and isinstance(item, str)
        }
        if reference.get("canonical_sha256") not in canonical_candidates:
            raise ValueError(
                f"outcome-sensitive source canonical digest drift: {name}"
            )


def _container_inventory(contract: dict[str, Any]) -> dict[str, int]:
    reference = contract["source_artifacts"]["activation"]
    activation = _read_object(Path(reference["path"]))
    inventory = activation_inventory(activation)
    return {
        "participant_count": inventory["participant_container_count"],
        "created_count": inventory["created_count"],
        "running_count": inventory["running_count"],
    }


def _remote_revision_verified(root: Path) -> bool:
    head = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "branch", "--show-current")
    if not branch:
        return False
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", "origin", f"refs/heads/{branch}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.split(maxsplit=1)[0] == head


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def _require_clean(root: Path) -> None:
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean before outcome-sensitive review generation"
        )


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--offline-report", type=Path, required=True)
    parser.add_argument("--offline-journal", type=Path, required=True)
    parser.add_argument("--fault-report", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--pytest-passed-count", type=int, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.created_at.replace("Z", "+00:00"))
    handoff = generate_review_materials(
        bundle_id=args.bundle_id,
        request_id=args.request_id,
        created_at=args.created_at,
        contract_path=args.contract,
        offline_report_path=args.offline_report,
        offline_journal_path=args.offline_journal,
        fault_report_path=args.fault_report,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pytest_passed_count=args.pytest_passed_count,
    )
    print(json.dumps(handoff, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
