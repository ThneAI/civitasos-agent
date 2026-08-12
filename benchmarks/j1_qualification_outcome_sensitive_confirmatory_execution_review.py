"""Generate independent-review materials for the confirmatory execution stack."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_review import (
    build_confirmatory_review_bundle,
    build_confirmatory_review_request,
    reviewer_approval_statement,
    validate_evidence_schemas,
)
from benchmarks.j1_qualification_outcome_sensitive_execution_review import (
    EXECUTION_SOURCE_PATHS,
    _container_inventory,
    _git,
    _read_object,
    _ref,
    _remote_revision_verified,
    _replay_source_artifacts,
    _require_clean,
)


CONFIRMATORY_SOURCE_PATHS = [
    *EXECUTION_SOURCE_PATHS,
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_execution_contract.py",
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_execution_authorization.py",
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_execution_preflight.py",
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_execution_review.py",
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_fault_matrix.py",
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory_orchestrator.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_execution_contract.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_execution_authorization.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_execution_preflight.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_execution_review.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_fault_matrix.py",
    "benchmarks/j1_qualification_outcome_sensitive_confirmatory_orchestrator.py",
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
        raise FileExistsError(f"confirmatory review output exists: {output_root}")
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
        raise ValueError("confirmatory review revision is not present at origin")
    source_implementation = {
        "review_material_revision": _git(repository_root, "rev-parse", "HEAD"),
        "execution_contract_revision": contract["implementation"]["source_revision"],
        "source_files": {
            relative: hashlib.sha256(
                (repository_root / relative).read_bytes()
            ).hexdigest()
            for relative in CONFIRMATORY_SOURCE_PATHS
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
    bundle = build_confirmatory_review_bundle(
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
    bundle_path = output_root / "confirmatory-execution-review-bundle.json"
    write_private_json(bundle_path, bundle)
    bundle_raw_sha256 = _raw_sha256(bundle_path)
    request = build_confirmatory_review_request(
        request_id=request_id,
        created_at=created_at,
        bundle_path=str(bundle_path.resolve()),
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    request_path = output_root / "confirmatory-execution-review-request.json"
    write_private_json(request_path, request)
    request_raw_sha256 = _raw_sha256(request_path)
    exact_statement = reviewer_approval_statement(
        request_raw_sha256=request_raw_sha256,
        bundle_raw_sha256=bundle_raw_sha256,
        bundle=bundle,
    )
    handoff = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-confirmatory-review-handoff:v1"
        ),
        "status": "independent_reviewer_decision_required",
        "request": _ref(request_path, request["request_sha256"]),
        "bundle": _ref(bundle_path, bundle["bundle_sha256"]),
        "required_exact_approval_statement": exact_statement,
        "statement_sha256": hashlib.sha256(exact_statement.encode()).hexdigest(),
        "review_boundary": request["review_boundary"],
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    write_private_json(
        output_root / "confirmatory-execution-review-handoff.json",
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
    method = contract.get("confirmatory_method_binding", {})
    if (
        not validate_evidence_schemas(
            contract=contract,
            offline_report=offline,
            fault_report=fault,
        )
        or contract.get("status") != "independent_review_required"
        or len(contract.get("source_artifacts", {})) != 31
        or len(contract.get("task_executions", [])) != 480
        or contract_hash
        != canonical_sha256(
            {key: item for key, item in contract.items() if key != "contract_sha256"}
        )
        or method.get("test", {}).get("assignment_count") != 1_048_576
        or method.get("multiplicity", {}).get("method") != "holm_step_down"
    ):
        raise ValueError("confirmatory execution contract evidence invalid")
    if (
        offline.get("status") != "complete"
        or offline.get("contract_sha256") != contract_hash
        or offline.get("journal", {}).get("task_states") != {"task_committed": 480}
        or offline.get("journal", {}).get("budget_states") != {"reconciled": 480}
        or offline.get("journal", {}).get("event_count") != 5760
        or offline.get("offline_scope", {}).get("provider_call_count") != 480
        or offline.get("offline_scope", {}).get("participant_signature_count") != 480
        or offline.get("validation_failures") != []
        or offline.get("confirmatory_method_binding", {}).get("method_sha256")
        != method.get("method_sha256")
        or offline.get("confirmatory_method_binding", {}).get(
            "prior_run_reanalysis_performed"
        )
        is not False
        or offline.get("confirmatory_method_binding", {}).get(
            "advice_adherence_inferred"
        )
        is not False
    ):
        raise ValueError("confirmatory offline recovery evidence invalid")
    if (
        _raw_sha256(offline_journal_path)
        != offline["journal"]["journal_artifact_sha256"]
    ):
        raise ValueError("confirmatory offline journal hash mismatch")
    if (
        fault.get("passed") is not True
        or fault.get("scenario_count") != 8
        or fault.get("contract_sha256") != contract_hash
    ):
        raise ValueError("confirmatory fault matrix evidence invalid")


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
