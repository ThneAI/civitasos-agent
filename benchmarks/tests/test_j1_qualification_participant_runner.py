from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_participant_runner_image import (
    build_runner_image_manifest,
    validate_runner_image_manifest,
)
from benchmarks.j1_qualification_participant_runner import (
    INPUT_SCHEMA,
    process_envelope,
    validate_input_envelope,
    validate_output_envelope,
)


def _input(
    *, cohort: str = "mentor", operation: str = "prepare_provider_request"
) -> dict:
    task_input = "Produce one bounded action."
    advice = (
        {
            "advice_id": "advice-1",
            "artifact_sha256": "b" * 64,
            "canonical_sha256": "c" * 64,
            "template": "Preserve scope and receipts.",
            "authority": "advisory_only",
            "may_execute_for_participant": False,
            "may_override_constitution": False,
        }
        if cohort == "mentor"
        else None
    )
    response = None
    if operation == "finalize_provider_response":
        decision = "Take the bounded action and preserve rollback evidence."
        response = {
            "provider_request_sha256": "f" * 64,
            "provider_receipt_sha256": "0" * 64,
            "decision": decision,
            "decision_sha256": hashlib.sha256(decision.encode()).hexdigest(),
        }
    return {
        "schema_version": INPUT_SCHEMA,
        "operation": operation,
        "run_id": "run-1",
        "participant": {
            "participant_id": "participant-1",
            "execution_did": "did:civ:qualification:participant-1",
            "credential_version": 1,
            "pair_id": "pair-1",
            "cohort": cohort,
            "assignment_commitment_sha256": "a" * 64,
        },
        "task": {
            "task_id": "task-1",
            "input": task_input,
            "input_sha256": hashlib.sha256(task_input.encode()).hexdigest(),
            "verifier_case": "scope-and-delivery-contract",
            "event_script": ["apprentice_decision", "bounded_delivery"],
        },
        "advice_projection": advice,
        "authorization": {
            "authorization_id": "authorization-1",
            "artifact_sha256": "d" * 64,
        },
        "ipc": {
            "request_id": "request-1",
            "nonce": "e" * 64,
            "created_at": "2026-07-23T00:00:00+00:00",
        },
        "provider_response": response,
    }


def test_runner_prepares_mentor_and_control_requests_without_assertions() -> None:
    for cohort in ("mentor", "control"):
        source = _input(cohort=cohort)
        output = process_envelope(source)

        assert validate_output_envelope(output, source=source) == []
        assert output["provider_request"]["persist_as_evidence"] is False
        assert output["execution_boundary"]["provider_api_call_performed"] is False
        assert "verifier assertions" in output["provider_request"]["system"]


def test_runner_finalizes_provider_response_as_unsigned_host_bound_decision() -> None:
    source = _input(operation="finalize_provider_response")
    output = process_envelope(source)

    assert validate_output_envelope(output, source=source) == []
    assert output["participant_decision"]["signature_required_on_host"] is True
    assert output["participant_decision"]["verifier_assertions"] is None


def test_runner_rejects_control_advice_secret_fields_and_hash_tamper() -> None:
    control = _input(cohort="control")
    control["advice_projection"] = _input()["advice_projection"]
    assert "runner_control_advice_must_be_absent" in validate_input_envelope(control)

    secret = _input()
    secret["authorization"]["api_key"] = "not-allowed"
    failures = validate_input_envelope(secret)
    assert "runner_authorization_invalid" in failures
    assert "runner_secret_field_rejected" in failures

    tampered = _input()
    tampered["task"]["input"] = "changed"
    assert "runner_task_input_hash_invalid" in validate_input_envelope(tampered)


def test_runner_image_manifest_rejects_mutable_image_reference() -> None:
    implementation = {"source_revision": "a" * 40, "source_sha256": "b" * 64}
    smoke = {
        "positive_exit_code": 0,
        "positive_output_sha256": "c" * 64,
        "positive_repeat_output_sha256": "c" * 64,
        "deterministic_output": True,
        "negative_exit_code": 1,
        "negative_output_created": False,
        "synthetic_only": True,
    }
    manifest = build_runner_image_manifest(
        build_id="runner-r1",
        created_at="2026-07-23T00:00:00+00:00",
        dockerfile_sha256="d" * 64,
        runner_source_sha256="e" * 64,
        build_context_sha256="f" * 64,
        image_id=f"sha256:{'0' * 64}",
        image_tag="civitasos/j1d-participant-runner:r1",
        architecture="amd64",
        os_name="linux",
        implementation=implementation,
        smoke=smoke,
    )
    assert (
        validate_runner_image_manifest(manifest, expected_implementation=implementation)
        == []
    )

    mutable = copy.deepcopy(manifest)
    mutable["image"]["content_addressed_reference"] = "runner:latest"
    failures = validate_runner_image_manifest(
        mutable, expected_implementation=implementation
    )
    assert "runner_image_identity_invalid" in failures
    assert "runner_image_manifest_hash_invalid" in failures
