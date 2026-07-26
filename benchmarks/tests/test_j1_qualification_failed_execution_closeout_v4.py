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
