from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_review_v4 import (
    BOUNDARY,
    CHECKLIST,
    build_review_bundle,
    build_review_request,
    validate_review_bundle,
)


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
        "canonical_sha256": hashlib.sha256(
            f"canonical:{name}".encode()
        ).hexdigest(),
    }


def _bundle() -> dict:
    contract = {
        "contract_sha256": "a" * 64,
        "implementation": {"source_revision": "b" * 40},
        "scope": {"task_execution_count": 320, "provider_call_count": 320},
        "state_machine": {"unknown_provider_outcome_is_terminal": True},
        "recovery_contract": {"automatic_provider_retry": False},
        "run_terminal_contract": {"operator_closeout_signature_required": True},
    }
    offline = {
        "status": "complete",
        "journal": {
            "task_states": {"task_committed": 320},
            "budget_states": {"reconciled": 320},
            "event_count": 3840,
        },
    }
    fault = {"passed": True, "scenario_count": 8}
    return build_review_bundle(
        bundle_id="r4-review-r1",
        created_at="2026-07-25T12:00:00+08:00",
        artifacts={
            "execution_contract": _ref("contract"),
            "offline_orchestrator_report": _ref("offline"),
            "offline_execution_journal": _ref("journal"),
            "fault_matrix_report": _ref("faults"),
        },
        contract=contract,
        offline_report=offline,
        fault_report=fault,
        source_implementation={"source_files": {"a.py": "c" * 64}},
        verification={
            "ruff_all_passed": True,
            "pytest_all_passed": True,
            "pytest_passed_count": 1447,
            "journal_artifact_hash_recomputed": True,
            "remote_revision_verified": True,
        },
        inventory_snapshot={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
    )


def test_review_bundle_binds_offline_evidence_and_promotion_boundary() -> None:
    bundle = _bundle()

    assert validate_review_bundle(bundle) == []
    assert bundle["review_checklist"] == CHECKLIST
    assert bundle["execution_boundary"] == BOUNDARY
    assert bundle["promotion_contract"]["independent_human_review_required"] is True
    assert len(bundle["known_limitations"]) == 4


def test_review_bundle_rejects_evidence_or_boundary_tamper() -> None:
    bundle = _bundle()
    tampered = copy.deepcopy(bundle)
    tampered["offline_evidence_summary"]["fault_scenario_count"] = 7
    tampered["execution_boundary"]["provider_api_call_performed"] = True

    failures = validate_review_bundle(tampered)
    assert "r4_review_bundle_offline_evidence_invalid" in failures
    assert "r4_review_bundle_boundary_invalid" in failures
    assert "r4_review_bundle_hash_invalid" in failures


def test_review_request_requires_independence_and_exact_scope() -> None:
    bundle = _bundle()
    request = build_review_request(
        request_id="r4-review-request-r1",
        created_at="2026-07-25T12:00:00+08:00",
        bundle_path="/private/bundle.json",
        bundle_raw_sha256="d" * 64,
        bundle=bundle,
    )

    assert request["required_checklist"] == CHECKLIST
    assert request["reviewer_requirements"]["independent_from_candidate_authoring"]
    assert request["allowed_decisions"] == [
        "approve_r4_execution_stack",
        "reject_r4_execution_stack",
    ]
    assert "does not start a participant container" in request[
        "approval_statement_template"
    ]
