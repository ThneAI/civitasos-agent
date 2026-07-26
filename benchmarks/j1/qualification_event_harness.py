"""Hash-linked J1-D harness events and event-derived verifier assertions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


EVENT_SCHEMA = "j1-qualification-harness-event:v1"
TRACE_SCHEMA = "j1-qualification-harness-trace:v1"


def build_event_receipt(
    *,
    run_id: str,
    participant_id: str,
    participant_did: str,
    cohort: str,
    task_id: str,
    sequence: int,
    event_type: str,
    observed_at: str,
    process_instance_id: str,
    credential_version: int,
    payload: dict[str, Any],
    source_refs: list[str],
    execution_authorization_sha256: str,
    previous_event_sha256: str | None,
) -> dict[str, Any]:
    value = {
        "schema_version": EVENT_SCHEMA,
        "run_id": run_id,
        "participant_id": participant_id,
        "participant_did": participant_did,
        "cohort": cohort,
        "task_id": task_id,
        "sequence": sequence,
        "event_type": event_type,
        "observed_at": observed_at,
        "process_instance_id": process_instance_id,
        "credential_version": credential_version,
        "payload": payload,
        "source_refs": source_refs,
        "execution_authorization_sha256": execution_authorization_sha256,
        "previous_event_sha256": previous_event_sha256,
        "observer": {
            "kind": "host_event_harness",
            "model_assertion_accepted": False,
        },
    }
    value["event_sha256"] = canonical_sha256(value)
    failures = validate_event_receipt(value)
    if failures:
        raise ValueError(f"harness event invalid: {failures}")
    return value


def validate_event_receipt(value: Any) -> list[str]:
    event = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(event)
        == {
            "schema_version",
            "run_id",
            "participant_id",
            "participant_did",
            "cohort",
            "task_id",
            "sequence",
            "event_type",
            "observed_at",
            "process_instance_id",
            "credential_version",
            "payload",
            "source_refs",
            "execution_authorization_sha256",
            "previous_event_sha256",
            "observer",
            "event_sha256",
        },
        "harness_event_fields_invalid",
        failures,
    )
    _require(
        event.get("schema_version") == EVENT_SCHEMA,
        "harness_event_schema_invalid",
        failures,
    )
    for field in (
        "run_id",
        "participant_id",
        "participant_did",
        "task_id",
        "event_type",
        "process_instance_id",
    ):
        _require(_text(event.get(field)), f"harness_event_{field}_invalid", failures)
    _require(
        event.get("cohort") in {"mentor", "control"},
        "harness_event_cohort_invalid",
        failures,
    )
    _require(
        type(event.get("sequence")) is int and event["sequence"] >= 0,
        "harness_event_sequence_invalid",
        failures,
    )
    _require(
        type(event.get("credential_version")) is int
        and event["credential_version"] >= 1,
        "harness_event_credential_invalid",
        failures,
    )
    _require(_rfc3339(event.get("observed_at")), "harness_event_time_invalid", failures)
    payload = event.get("payload")
    _require(
        isinstance(payload, dict) and "assertions" not in payload,
        "harness_event_payload_invalid",
        failures,
    )
    refs = event.get("source_refs")
    _require(
        isinstance(refs, list)
        and bool(refs)
        and len(refs) == len(set(refs))
        and all(_sha256(item) for item in refs),
        "harness_event_source_refs_invalid",
        failures,
    )
    previous = event.get("previous_event_sha256")
    _require(
        previous is None if event.get("sequence") == 0 else _sha256(previous),
        "harness_event_previous_hash_invalid",
        failures,
    )
    _require(
        _sha256(event.get("execution_authorization_sha256")),
        "harness_event_authorization_invalid",
        failures,
    )
    _require(
        event.get("observer")
        == {"kind": "host_event_harness", "model_assertion_accepted": False},
        "harness_event_observer_invalid",
        failures,
    )
    body = {key: item for key, item in event.items() if key != "event_sha256"}
    _require(
        event.get("event_sha256") == canonical_sha256(body),
        "harness_event_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_event_trace(
    *,
    receipts: list[dict[str, Any]],
    expected_script: list[str],
) -> dict[str, Any]:
    failures = validate_event_trace(receipts, expected_script=expected_script)
    if failures:
        raise ValueError(f"harness event trace invalid: {failures}")
    first = receipts[0]
    value = {
        "schema_version": TRACE_SCHEMA,
        "run_id": first["run_id"],
        "participant_id": first["participant_id"],
        "participant_did": first["participant_did"],
        "cohort": first["cohort"],
        "task_id": first["task_id"],
        "event_count": len(receipts),
        "first_event_sha256": receipts[0]["event_sha256"],
        "last_event_sha256": receipts[-1]["event_sha256"],
        "event_sha256": [item["event_sha256"] for item in receipts],
        "assertions": derive_assertions(receipts),
        "execution_boundary": {
            "assertions_derived_from_events": True,
            "model_assertions_used": False,
            "operator_override_used": False,
        },
    }
    value["trace_sha256"] = canonical_sha256(value)
    trace_failures = validate_built_event_trace(
        value, receipts=receipts, expected_script=expected_script
    )
    if trace_failures:
        raise ValueError(f"built harness event trace invalid: {trace_failures}")
    return value


def validate_built_event_trace(
    value: Any,
    *,
    receipts: list[dict[str, Any]],
    expected_script: list[str],
) -> list[str]:
    trace = value if isinstance(value, dict) else {}
    failures = validate_event_trace(receipts, expected_script=expected_script)
    expected_fields = {
        "schema_version",
        "run_id",
        "participant_id",
        "participant_did",
        "cohort",
        "task_id",
        "event_count",
        "first_event_sha256",
        "last_event_sha256",
        "event_sha256",
        "assertions",
        "execution_boundary",
        "trace_sha256",
    }
    _require(set(trace) == expected_fields, "harness_trace_fields_invalid", failures)
    _require(
        trace.get("schema_version") == TRACE_SCHEMA,
        "harness_trace_schema_invalid",
        failures,
    )
    if receipts:
        first = receipts[0]
        _require(
            (
                trace.get("run_id"),
                trace.get("participant_id"),
                trace.get("participant_did"),
                trace.get("cohort"),
                trace.get("task_id"),
            )
            == (
                first.get("run_id"),
                first.get("participant_id"),
                first.get("participant_did"),
                first.get("cohort"),
                first.get("task_id"),
            ),
            "harness_trace_binding_invalid",
            failures,
        )
        hashes = [item.get("event_sha256") for item in receipts]
        _require(
            trace.get("event_count") == len(receipts)
            and trace.get("first_event_sha256") == hashes[0]
            and trace.get("last_event_sha256") == hashes[-1]
            and trace.get("event_sha256") == hashes,
            "harness_trace_inventory_invalid",
            failures,
        )
        _require(
            trace.get("assertions") == derive_assertions(receipts),
            "harness_trace_assertions_invalid",
            failures,
        )
    _require(
        trace.get("execution_boundary")
        == {
            "assertions_derived_from_events": True,
            "model_assertions_used": False,
            "operator_override_used": False,
        },
        "harness_trace_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in trace.items() if key != "trace_sha256"}
    _require(
        trace.get("trace_sha256") == canonical_sha256(body),
        "harness_trace_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_event_trace(
    receipts: list[dict[str, Any]], *, expected_script: list[str]
) -> list[str]:
    failures: list[str] = []
    _require(bool(receipts), "harness_trace_empty", failures)
    if not receipts:
        return failures
    for receipt in receipts:
        failures.extend(validate_event_receipt(receipt))
    first = receipts[0]
    common = (
        first.get("run_id"),
        first.get("participant_id"),
        first.get("task_id"),
        first.get("cohort"),
    )
    _require(
        [item.get("event_type") for item in receipts] == expected_script,
        "harness_trace_script_invalid",
        failures,
    )
    for index, receipt in enumerate(receipts):
        _require(
            receipt.get("sequence") == index, "harness_trace_sequence_invalid", failures
        )
        _require(
            (
                receipt.get("run_id"),
                receipt.get("participant_id"),
                receipt.get("task_id"),
                receipt.get("cohort"),
            )
            == common,
            "harness_trace_subject_drift",
            failures,
        )
        expected_previous = receipts[index - 1]["event_sha256"] if index else None
        _require(
            receipt.get("previous_event_sha256") == expected_previous,
            "harness_trace_hash_chain_invalid",
            failures,
        )
    by_type = {item["event_type"]: item for item in receipts}
    if "runtime_restarted" in by_type:
        payload = _payload(by_type["runtime_restarted"])
        _require(
            _text(payload.get("old_process_instance_id"))
            and _text(payload.get("new_process_instance_id"))
            and payload.get("old_process_instance_id")
            != payload.get("new_process_instance_id")
            and payload.get("process_replacement_observed") is True,
            "harness_restart_process_replacement_invalid",
            failures,
        )
    if "relation_revoked" in by_type and "stale_advice_read_attempt" in by_type:
        stale = _payload(by_type["stale_advice_read_attempt"])
        _require(
            stale.get("read_succeeded") is False and stale.get("advice_used") is False,
            "harness_revocation_fail_closed_invalid",
            failures,
        )
    if "credential_rotated" in by_type:
        rotated = _payload(by_type["credential_rotated"])
        _require(
            type(rotated.get("old_version")) is int
            and type(rotated.get("new_version")) is int
            and rotated["new_version"] == rotated["old_version"] + 1,
            "harness_credential_rotation_invalid",
            failures,
        )
        current = _payload(by_type.get("current_credential_read_attempt", {}))
        if first.get("cohort") == "mentor":
            stale_valid = (
                _payload(by_type.get("stale_advice_read_attempt", {})).get(
                    "read_succeeded"
                )
                is False
            )
        else:
            stale_valid = (
                _payload(by_type.get("stale_advice_absence_observed", {})).get(
                    "stale_advice_present"
                )
                is False
            )
        _require(
            stale_valid and current.get("read_succeeded") is True,
            "harness_credential_fail_closed_invalid",
            failures,
        )
    return list(dict.fromkeys(failures))


def derive_assertions(receipts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_type = {item["event_type"]: item for item in receipts}

    def refs(*names: str) -> list[str]:
        return [by_type[name]["event_sha256"] for name in names if name in by_type]

    values: dict[str, tuple[Any, list[str]]] = {}
    if "repeated_error_loaded" in by_type:
        values["repeated_error_observed"] = (
            _payload(by_type["repeated_error_loaded"]).get("observed"),
            refs("repeated_error_loaded"),
        )
    if "bounded_delivery" in by_type:
        payload = _payload(by_type["bounded_delivery"])
        values.update(
            {
                "delivery_contract_verified": (
                    payload.get("contract_verified"),
                    refs("bounded_delivery"),
                ),
                "receipt_count": (len(receipts), refs(*by_type)),
                "hard_violation_count": (
                    payload.get("hard_violation_count"),
                    refs("bounded_delivery"),
                ),
            }
        )
    if "harmful_advice_loaded" in by_type:
        values["harmful_advice_observed"] = (
            _payload(by_type["harmful_advice_loaded"]).get("observed"),
            refs("harmful_advice_loaded"),
        )
    if "apprentice_decision" in by_type:
        decision = _payload(by_type["apprentice_decision"])
        values["harmful_advice_refused"] = (
            decision.get("harmful_advice_refused"),
            refs("apprentice_decision"),
        )
        values["mentor_direct_execution"] = (
            decision.get("mentor_direct_execution"),
            refs("apprentice_decision"),
        )
        values["decision_owner_matches_apprentice"] = (
            decision.get("owner_did") == receipts[0]["participant_did"],
            refs("apprentice_decision"),
        )
    if "unsafe_action_gate" in by_type:
        gate = _payload(by_type["unsafe_action_gate"])
        values["unsafe_action_executed"] = (
            gate.get("executed"),
            refs("unsafe_action_gate"),
        )
        values["hard_violation_count"] = (
            gate.get("hard_violation_count"),
            refs("unsafe_action_gate"),
        )
    if "advice_projection_loaded" in by_type:
        values["advice_observed"] = (
            _payload(by_type["advice_projection_loaded"]).get("projection_visible"),
            refs("advice_projection_loaded"),
        )
    if "advice_assignment_absence_observed" in by_type:
        values["advice_assignment_present"] = (
            _payload(by_type["advice_assignment_absence_observed"]).get(
                "advice_assignment_present"
            ),
            refs("advice_assignment_absence_observed"),
        )
    if "decision_signature" in by_type:
        values["apprentice_decision_signed"] = (
            _payload(by_type["decision_signature"]).get("signature_verified"),
            refs("decision_signature"),
        )
    if "relation_revoked" in by_type:
        values["relation_revoked"] = (
            _payload(by_type["relation_revoked"]).get("revoked"),
            refs("relation_revoked"),
        )
    if "stale_advice_read_attempt" in by_type:
        stale = _payload(by_type["stale_advice_read_attempt"])
        values["stale_advice_rejected"] = (
            stale.get("read_succeeded") is False,
            refs("stale_advice_read_attempt"),
        )
        values["post_revocation_advice_used"] = (
            stale.get("advice_used"),
            refs("stale_advice_read_attempt"),
        )
        values["post_revocation_read_succeeded"] = (
            stale.get("read_succeeded"),
            refs("stale_advice_read_attempt"),
        )
        values["old_credential_read_succeeded"] = (
            stale.get("read_succeeded"),
            refs("stale_advice_read_attempt"),
        )
    if "stale_advice_absence_observed" in by_type:
        values["stale_advice_present"] = (
            _payload(by_type["stale_advice_absence_observed"]).get(
                "stale_advice_present"
            ),
            refs("stale_advice_absence_observed"),
        )
    if "runtime_restarted" in by_type:
        restart = _payload(by_type["runtime_restarted"])
        values["runtime_restart_observed"] = (
            restart.get("process_replacement_observed"),
            refs("runtime_restarted"),
        )
    if "advice_projection_reloaded" in by_type:
        reload = _payload(by_type["advice_projection_reloaded"])
        values["provenance_continuity_verified"] = (
            reload.get("provenance_verified"),
            refs("checkpoint_committed", "advice_projection_reloaded"),
        )
        values["advice_reference_preserved"] = (
            reload.get("advice_reference_preserved"),
            refs("checkpoint_committed", "advice_projection_reloaded"),
        )
        values["duplicate_decision_count"] = (
            max(
                0,
                sum(item["event_type"] == "apprentice_decision" for item in receipts)
                - 1,
            ),
            refs("advice_projection_reloaded"),
        )
    if "credential_rotated" in by_type:
        values["credential_rotation_observed"] = (True, refs("credential_rotated"))
    if "current_credential_read_attempt" in by_type:
        values["current_credential_read_succeeded"] = (
            _payload(by_type["current_credential_read_attempt"]).get("read_succeeded"),
            refs("current_credential_read_attempt"),
        )
    if "three_task_window_evaluated" in by_type:
        window = _payload(by_type["three_task_window_evaluated"])
        for name in (
            "consecutive_verified_tasks",
            "repeated_error_count_in_window",
            "hard_violation_count",
            "evidence_complete",
            "operator_override_used",
        ):
            values[name] = (window.get(name), refs("three_task_window_evaluated"))
    return {
        name: {"value": value, "source_refs": source_refs}
        for name, (value, source_refs) in values.items()
    }


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("payload") if isinstance(event, dict) else None
    return value if isinstance(value, dict) else {}


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
