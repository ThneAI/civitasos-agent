from __future__ import annotations

import copy

from nacl.signing import SigningKey

from benchmarks.j1.qualification_failed_execution_closeout_v4 import (
    build_closeout_artifacts,
    build_closeout_gate,
    build_preflight,
    validate_closeout_artifacts,
    validate_preflight,
)
from benchmarks.j1_qualification_failed_execution_closeout_v4 import (
    _journal_matches_report,
    _pre_orchestrator_failure_state,
)
from benchmarks.j1_qualification_live_execute_v4 import _failure_evidence


class Signer:
    def __init__(self) -> None:
        self.key = SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _ref(seed: str) -> dict[str, str]:
    return {
        "path": f"/private/{seed}.json",
        "sha256": seed * 64,
        "canonical_sha256": seed * 64,
    }


def _preflight() -> dict:
    return build_preflight(
        checked_at="2026-07-26T00:30:00+00:00",
        run_id="run-r6",
        authorization_id="authorization-r6",
        source_binding={
            "claim": _ref("a"),
            "entry_gate": _ref("b"),
            "live_report": _ref("c"),
        },
        execution_summary={
            "authorized_task_count": 320,
            "committed_task_count": 4,
            "failed_task_count": 1,
            "unattempted_task_count": 315,
            "provider_call_count": 4,
            "participant_signature_count": 4,
            "container_start_count": 5,
            "container_stop_count": 5,
        },
        failure={
            "state": "task_failed_before_dispatch",
            "reason": "JSONDecodeError",
            "task_execution_id": "task-5",
            "call_id": "call-5",
            "provider_call_performed": False,
            "provider_retry_performed": False,
            "event_sha256": "d" * 64,
        },
        budget_summary={
            "reconciled_provider_call_count": 4,
            "reserved_tokens": 10000,
            "reserved_cost_microunits": 6092,
            "actual_tokens": 2135,
            "actual_cost_microunits": 1688,
        },
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 39,
            "running_count": 0,
            "exited_count": 1,
        },
        output_root="/private/post-run-r6",
        implementation={
            "source_revision": "e" * 40,
            "domain_source_sha256": "f" * 64,
            "operation_source_sha256": "0" * 64,
        },
    )


def test_failed_execution_closeout_binds_partial_counts_and_signature() -> None:
    preflight = _preflight()
    signer = Signer()
    reviewer = {
        "reviewer_id": "reviewer-1",
        "public_key_hex": signer.public_key_hex,
    }
    preflight_ref = _ref("1")

    artifacts = build_closeout_artifacts(
        closed_at="2026-07-26T00:31:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        owner_authorization_id="owner-r6",
        owner_statement=preflight["owner_authorization"]["required_exact_statement"],
        reviewer=reviewer,
        reviewer_profile_sha256="2" * 64,
        implementation=preflight["implementation"],
        signer=signer,
    )

    assert validate_preflight(preflight) == []
    assert (
        validate_closeout_artifacts(
            artifacts,
            preflight_ref=preflight_ref,
            preflight=preflight,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256="2" * 64,
            expected_implementation=preflight["implementation"],
        )
        == []
    )
    assert artifacts["operator_closeout"]["decision"] == "record_failed_run"
    assert artifacts["evaluation_report"]["effectiveness_claim_authorized"] is False

    gate = build_closeout_gate(
        checked_at="2026-07-26T00:32:00+00:00",
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs={
            "post_run_receipt": _ref("3"),
            "evaluation_report": _ref("4"),
            "operator_closeout": _ref("5"),
        },
        artifacts=artifacts,
    )
    assert gate["passed"] is True
    assert gate["readiness"]["future_run_requires_new_reviewed_stack"] is True


def test_failed_execution_closeout_rejects_count_and_signature_tamper() -> None:
    preflight = _preflight()
    tampered = copy.deepcopy(preflight)
    tampered["execution_summary"]["unattempted_task_count"] = 314

    failures = validate_preflight(tampered)

    assert "failed_closeout_execution_summary_invalid" in failures
    assert "failed_closeout_preflight_hash_invalid" in failures


def test_failed_closeout_compares_logical_and_raw_journal_hashes_separately() -> None:
    logical = {
        "task_states": {"planned": 315, "task_committed": 4},
        "budget_states": {"reconciled": 4},
        "event_count": 50,
        "last_event_sha256": "a" * 64,
        "journal_sha256": "b" * 64,
    }
    journal = {"logical": logical, "raw_sha256": "c" * 64}
    report = {**logical, "journal_artifact_sha256": "c" * 64}

    assert _journal_matches_report(journal, report)

    report["journal_artifact_sha256"] = "d" * 64
    assert not _journal_matches_report(journal, report)


def test_failed_closeout_binds_pre_orchestrator_failure(tmp_path) -> None:
    execution_root = tmp_path / "run"
    execution_root.mkdir()
    report_path = execution_root / "live-execution-failure.json"
    report = {
        "failure_type": "ValueError",
        "report_sha256": "a" * 64,
    }
    report_path.write_text("{}", encoding="utf-8")

    state = _pre_orchestrator_failure_state(
        report=report,
        report_path=report_path,
        execution_root=execution_root,
    )
    preflight = build_preflight(
        checked_at="2026-07-26T01:31:00+00:00",
        run_id="run-r7",
        authorization_id="authorization-r7",
        source_binding={
            "claim": _ref("a"),
            "entry_gate": _ref("b"),
            "live_report": _ref("c"),
        },
        execution_summary=state["execution_summary"],
        failure=state["failure"],
        budget_summary=state["budget_summary"],
        terminal_inventory={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
            "exited_count": 0,
        },
        output_root="/private/post-run-r7",
        implementation={
            "source_revision": "e" * 40,
            "domain_source_sha256": "f" * 64,
            "operation_source_sha256": "0" * 64,
        },
    )

    assert validate_preflight(preflight) == []
    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert "0 committed, 0 failed, and 320 unattempted" in statement
    assert "1 provider credential reads" in statement
    assert "pre_orchestrator_error caused by ValueError" in statement


def test_failed_closeout_rejects_pre_orchestrator_execution_artifacts(
    tmp_path,
) -> None:
    execution_root = tmp_path / "run"
    execution_root.mkdir()
    report_path = execution_root / "live-execution-failure.json"
    report_path.write_text("{}", encoding="utf-8")
    (execution_root / "provider-budget.sqlite3").write_bytes(b"unexpected")

    try:
        _pre_orchestrator_failure_state(
            report={"failure_type": "ValueError", "report_sha256": "a" * 64},
            report_path=report_path,
            execution_root=execution_root,
        )
    except ValueError as error:
        assert "unexpected execution artifacts" in str(error)
    else:
        raise AssertionError("unexpected execution artifacts were accepted")


def test_live_failure_marker_uses_explicit_boundary_counts(tmp_path) -> None:
    execution_root = tmp_path / "run"
    execution_root.mkdir()
    authorization = tmp_path / "authorization.json"
    authorization.write_text("{}", encoding="utf-8")

    evidence = _failure_evidence(
        authorization_path=authorization,
        state="claimed_execution_failed_closeout_required",
        error=ValueError("participant profile inventory invalid"),
        claim_path="/private/run.claim.json",
        execution_started=True,
        execution_root=execution_root,
        failure_boundary={
            "provider_credential_read_count": 1,
            "provider_api_call_count": 0,
            "participant_container_start_count": 0,
            "participant_signature_count": 0,
        },
    )

    assert evidence["failure_stage"] == "pre_orchestrator"
    assert evidence["provider_credential_read_count"] == 1
    assert evidence["provider_api_call_count"] == 0
    assert evidence["failure_reason"] == "participant profile inventory invalid"
