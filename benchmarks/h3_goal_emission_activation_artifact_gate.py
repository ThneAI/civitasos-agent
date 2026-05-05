"""H.3 goal emission activation artifact gate.

This artifact-only gate reads H.3 goal emission activation review packets and
optional activation artifact records. It validates artifact completeness and
provenance but does not activate goal emission, emit goals, generate executable
plans, start runtime components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-activation-artifact-gate:v1"
ACTIVATION_GATE_SCHEMA_VERSION = "h3-goal-emission-activation-gate:v1"
ACTIVATION_ARTIFACTS_SCHEMA_VERSION = "h3-goal-emission-activation-artifacts:v1"
REQUIRED_ACTIVATION_ARTIFACT_KINDS = [
    "human_activation_record",
    "governance_activation_record",
    "h1_h2_replay_attestation",
    "rollback_activation_ack",
    "runtime_non_execution_ack",
]
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
ACTIVATION_BLOCKING_FLAGS = [
    "activation_allowed",
    "goal_emission_allowed",
    "emitted_goal_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
PRODUCTION_ACTIVATION_COMMON_FIELDS = [
    "artifact_id",
    "reviewer",
    "reviewer_role",
    "source",
    "attestation_ref",
]
PRODUCTION_ACTIVATION_KIND_REF_FIELDS = {
    "human_activation_record": "human_activation_ref",
    "governance_activation_record": "governance_activation_ref",
    "h1_h2_replay_attestation": "h1_h2_replay_ref",
    "rollback_activation_ack": "rollback_activation_ref",
    "runtime_non_execution_ack": "runtime_non_execution_ref",
}


def build_h3_goal_emission_activation_artifact_gate(
    *,
    activation_gate_path: Path,
    agent_root: Path,
    activation_artifacts_path: Path | None = None,
) -> dict[str, Any]:
    activation_gate_path = _resolve_path(activation_gate_path, agent_root)
    activation_artifacts_path = _resolve_path(activation_artifacts_path, agent_root) if activation_artifacts_path else None
    checks: dict[str, bool] = {}
    failures: list[str] = []
    activation_gate = _read_json(activation_gate_path, failures)

    activation_readiness: dict[str, Any] = {}
    activation_boundary: dict[str, Any] = {}
    activation_packets: list[dict[str, Any]] = []
    blocked_activation_candidates: list[dict[str, Any]] = []
    if activation_gate is None:
        _fail(checks, failures, "activation_gate_present", f"missing H3 activation gate: {activation_gate_path}")
    else:
        checks["activation_gate_present"] = True
        _require_equal(
            "activation_gate_schema_version",
            activation_gate.get("schema_version"),
            ACTIVATION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("activation_gate_passed", bool(activation_gate.get("passed")), checks=checks, failures=failures)
        activation_readiness = _object(activation_gate.get("readiness"))
        _require_activation_readiness(activation_readiness, checks=checks, failures=failures)
        activation_boundary = _object(activation_gate.get("activation_boundary"))
        _require_activation_boundary(activation_boundary, checks=checks, failures=failures)
        surface = _object(activation_gate.get("activation_surface"))
        _require_equal(
            "activation_surface_mode",
            surface.get("mode"),
            "activation_review_only_no_emission",
            checks=checks,
            failures=failures,
        )
        activation_packets = _record_list(surface.get("activation_packets"))
        blocked_activation_candidates = _record_list(surface.get("blocked_activation_candidates"))
        _require_activation_packet_consistency(
            activation_readiness,
            activation_packets,
            checks=checks,
            failures=failures,
        )
        _require_activation_packet_shape(activation_packets, checks=checks, failures=failures)
        _require_blocked_activation_shape(blocked_activation_candidates, checks=checks, failures=failures)

    activation_artifacts, activation_artifact_payload = _load_activation_artifacts(activation_artifacts_path, failures)
    synthetic_activation_fixture = _is_synthetic_activation_fixture(activation_artifact_payload, activation_artifacts)
    if activation_artifacts_path:
        checks["activation_artifacts_present"] = activation_artifact_payload is not None
        if activation_artifact_payload is not None:
            _require_equal(
                "activation_artifacts_schema_version",
                activation_artifact_payload.get("schema_version"),
                ACTIVATION_ARTIFACTS_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool(
                "activation_artifacts_records_present",
                bool(activation_artifacts),
                checks=checks,
                failures=failures,
            )
            _require_activation_artifact_shape(
                activation_artifacts,
                synthetic_activation_fixture=synthetic_activation_fixture,
                checks=checks,
                failures=failures,
            )
    else:
        checks["activation_artifacts_optional_absent"] = True

    reviewed_packets: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        reviewed_packets, pending_packets = _evaluate_activation_packets(
            activation_packets,
            activation_artifacts,
            synthetic_activation_fixture,
        )
    elif activation_packets:
        pending_packets = [_pending_packet(packet, {}) for packet in activation_packets]

    metrics = {
        "activation_packet_count": len(activation_packets),
        "activation_artifact_record_count": len(activation_artifacts),
        "reviewed_activation_packet_count": len(reviewed_packets),
        "pending_activation_packet_count": len(pending_packets),
        "blocked_activation_candidate_count": len(blocked_activation_candidates),
        "synthetic_activation_fixture_count": 1 if synthetic_activation_fixture else 0,
        "activation_ready_count": 0,
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("activation_blocked", metrics["activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _artifact_decision(
        passed,
        activation_packets,
        reviewed_packets,
        pending_packets,
        blocked_activation_candidates,
        synthetic_activation_fixture,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "activation_gate_path": str(activation_gate_path),
        "activation_artifacts_path": str(activation_artifacts_path) if activation_artifacts_path else None,
        "checks": checks,
        "readiness": {
            "activation_artifact_gate_evaluated": passed,
            "activation_artifacts_complete": passed and bool(reviewed_packets) and not pending_packets,
            "production_activation_artifacts_complete": (
                passed and bool(reviewed_packets) and not pending_packets and not synthetic_activation_fixture
            ),
            "synthetic_activation_artifacts_complete": (
                passed and bool(reviewed_packets) and not pending_packets and synthetic_activation_fixture
            ),
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, reviewed_packets, pending_packets, blocked_activation_candidates),
        },
        "activation_artifact_boundary": {
            "artifact_only": True,
            "activation_artifact_review_allowed": passed and bool(reviewed_packets),
            "production_activation_artifact_review_allowed": (
                passed and bool(reviewed_packets) and not pending_packets and not synthetic_activation_fixture
            ),
            "synthetic_activation_artifact_surface_allowed": (
                passed and bool(reviewed_packets) and synthetic_activation_fixture
            ),
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "activation_artifact_policy": {
            "required_activation_artifact_kinds": REQUIRED_ACTIVATION_ARTIFACT_KINDS,
            "accepted_activation_decisions": {
                "human_activation_record": "approved_for_emission_activation",
                "governance_activation_record": "approved_for_emission_activation",
                "h1_h2_replay_attestation": "valid",
                "rollback_activation_ack": "ready",
                "runtime_non_execution_ack": "acknowledged",
            },
            "production_activation_common_fields": PRODUCTION_ACTIVATION_COMMON_FIELDS,
            "production_activation_kind_ref_fields": PRODUCTION_ACTIVATION_KIND_REF_FIELDS,
            "blocked_after_artifact_review": [
                "activation_artifacts_reviewed -> emitted_goal_activated",
                "emitted_goal_activated -> executable_plan_generated",
                "executable_plan_generated -> runtime_execution_started",
            ],
        },
        "activation_artifact_surface": {
            "mode": "activation_artifacts_review_only_no_activation",
            "reviewed_activation_packet_count": len(reviewed_packets),
            "reviewed_activation_packets": reviewed_packets,
            "pending_activation_packet_count": len(pending_packets),
            "pending_activation_packets": pending_packets,
            "blocked_activation_candidate_count": len(blocked_activation_candidates),
            "blocked_activation_candidates": blocked_activation_candidates,
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "activation_readiness": activation_readiness,
            "activation_boundary": activation_boundary,
            "activation_artifact_summary": _activation_artifact_summary(activation_artifacts),
            "synthetic_activation_fixture": synthetic_activation_fixture,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_missing_activation_artifacts_as_activation",
            "does_not_treat_synthetic_fixture_as_production_activation",
        ],
    }


def _require_activation_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "goal_emission_activation_blocked_no_preflight",
        "goal_emission_activation_blocked_synthetic_or_blocked_emission",
        "goal_emission_activation_review_packets_ready_no_activation",
    }
    _require_bool(
        "activation_gate_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("activation_gate_activation_blocked", readiness.get("activation_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_gate_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_gate_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_gate_runtime_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)


def _require_activation_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("activation_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in ACTIVATION_BLOCKING_FLAGS:
        _require_bool(f"activation_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_activation_packet_consistency(
    readiness: dict[str, Any],
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    review_ready = str(readiness.get("decision") or "") == "goal_emission_activation_review_packets_ready_no_activation"
    _require_bool(
        "activation_packet_decision_consistent",
        bool(packets) == review_ready,
        checks=checks,
        failures=failures,
    )
    if review_ready:
        _require_bool(
            "activation_packet_readiness_consistent",
            readiness.get("activation_review_packets_ready") is True,
            checks=checks,
            failures=failures,
        )


def _require_activation_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not packets:
        checks["activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "activation_packet_state_valid",
        all(packet.get("state") == "goal_emission_activation_review_required" for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_packet_required_artifacts_declared",
        all(_required_activation_artifacts_declared(packet) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )


def _require_blocked_activation_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["blocked_activation_candidates_optional_or_present"] = True
        return
    _require_bool(
        "blocked_activation_candidate_state_valid",
        all(candidate.get("state") == "goal_emission_activation_blocked" for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _require_activation_artifact_shape(
    records: list[dict[str, Any]],
    *,
    synthetic_activation_fixture: bool,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool(
        "activation_artifact_kinds_known",
        all(str(record.get("artifact_kind") or "") in REQUIRED_ACTIVATION_ARTIFACT_KINDS for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_artifact_execution_disabled",
        all(_activation_record_execution_disabled(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_artifact_targets_present",
        all(str(record.get("activation_packet_id") or record.get("goal_id") or "").strip() for record in records),
        checks=checks,
        failures=failures,
    )
    if synthetic_activation_fixture:
        _require_bool(
            "activation_artifact_synthetic_fixture_marked",
            all(record.get("synthetic_fixture") is True for record in records),
            checks=checks,
            failures=failures,
        )
        return
    _require_bool(
        "activation_artifact_not_synthetic_fixture",
        all(record.get("synthetic_fixture") is not True for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_artifact_common_provenance_present",
        all(_string_fields_present(record, PRODUCTION_ACTIVATION_COMMON_FIELDS) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_artifact_kind_specific_provenance_present",
        all(_kind_specific_ref_present(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "activation_artifact_source_not_fixture",
        all(_production_source_eligible(record) for record in records),
        checks=checks,
        failures=failures,
    )


def _load_activation_artifacts(
    activation_artifacts_path: Path | None,
    failures: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if activation_artifacts_path is None:
        return [], None
    payload = _read_json(activation_artifacts_path, failures)
    if payload is None:
        return [], None
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append(f"activation artifact file missing records array: {activation_artifacts_path}")
        return [], payload
    return [record for record in records if isinstance(record, dict)], payload


def _evaluate_activation_packets(
    packets: list[dict[str, Any]],
    records: list[dict[str, Any]],
    synthetic_activation_fixture: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reviewed: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for packet in packets:
        artifacts = _artifacts_for_packet(packet, records)
        status = _activation_artifact_status(artifacts)
        if all(status.values()):
            reviewed.append(_reviewed_packet(packet, artifacts, synthetic_activation_fixture))
        else:
            pending.append(_pending_packet(packet, status))
    return reviewed, pending


def _activation_artifact_status(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {kind: _artifact_accepts_activation(kind, artifacts.get(kind)) for kind in REQUIRED_ACTIVATION_ARTIFACT_KINDS}


def _artifacts_for_packet(
    packet: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    activation_packet_id = str(packet.get("activation_packet_id") or "")
    goal_id = str(packet.get("goal_id") or "")
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        record_packet_id = str(record.get("activation_packet_id") or "")
        record_goal_id = str(record.get("goal_id") or "")
        if record_packet_id != activation_packet_id and record_goal_id != goal_id:
            continue
        artifact_kind = str(record.get("artifact_kind") or "")
        if artifact_kind in REQUIRED_ACTIVATION_ARTIFACT_KINDS and artifact_kind not in out:
            out[artifact_kind] = record
    return out


def _artifact_accepts_activation(kind: str, record: dict[str, Any] | None) -> bool:
    if not isinstance(record, dict):
        return False
    if kind in {"human_activation_record", "governance_activation_record"}:
        return record.get("decision") == "approved_for_emission_activation"
    if kind == "h1_h2_replay_attestation":
        return record.get("status") == "valid"
    if kind == "rollback_activation_ack":
        return record.get("status") == "ready"
    if kind == "runtime_non_execution_ack":
        return record.get("status") == "acknowledged"
    return False


def _reviewed_packet(
    packet: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    synthetic_activation_fixture: bool,
) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "artifact_review_id": f"h3-activation-artifact-review:{goal_id}",
        "activation_packet_id": packet.get("activation_packet_id"),
        "goal_id": goal_id,
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "state": "activation_artifacts_reviewed_no_activation",
        "synthetic_activation_fixture": synthetic_activation_fixture,
        "production_activation_artifacts_ready": not synthetic_activation_fixture,
        "activation_artifact_refs": _artifact_refs(artifacts),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "gate_status": {
            "activation_artifacts_complete": True,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "runtime_execution_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "activation_artifacts_reviewed -> emitted_goal_activated",
                "reason": "goal emission activation requires a later explicit production activation gate",
            },
            {
                "transition": "emitted_goal_activated -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 activation artifact gate",
            },
        ],
    }


def _pending_packet(packet: dict[str, Any], status: dict[str, bool]) -> dict[str, Any]:
    if not status:
        status = {kind: False for kind in REQUIRED_ACTIVATION_ARTIFACT_KINDS}
    missing = [kind for kind in REQUIRED_ACTIVATION_ARTIFACT_KINDS if not status.get(kind)]
    return {
        "activation_packet_id": packet.get("activation_packet_id"),
        "goal_id": packet.get("goal_id"),
        "state": "goal_emission_activation_review_required",
        "activation_artifacts_complete": False,
        "missing_or_rejected_activation_artifacts": missing,
        "blocked_transition": {
            "transition": "goal_emission_activation_review_required -> activation_artifacts_reviewed",
            "reason": "missing or rejected required activation artifacts",
        },
    }


def _artifact_decision(
    passed: bool,
    activation_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_activation_candidates: list[dict[str, Any]],
    synthetic_activation_fixture: bool,
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_activation_artifact_gate"
    if reviewed_packets and not pending_packets:
        if synthetic_activation_fixture:
            return "synthetic_activation_artifacts_reviewed_no_activation"
        return "production_activation_artifacts_reviewed_no_activation"
    if reviewed_packets:
        if synthetic_activation_fixture:
            return "partial_synthetic_activation_artifacts_reviewed_no_activation"
        return "partial_activation_artifacts_reviewed_no_activation"
    if pending_packets or activation_packets:
        return "activation_artifacts_blocked_pending_required_artifacts"
    if blocked_activation_candidates:
        return "activation_artifacts_blocked_synthetic_or_blocked_emission"
    return "activation_artifacts_blocked_no_activation_packets"


def _allowed_scope(
    passed: bool,
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_activation_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate activation artifacts until activation gate and artifact records are valid"
    if reviewed_packets and not pending_packets:
        return "activation artifact review only; activation, emission, execution, and runtime remain blocked"
    if pending_packets:
        return "activation packets remain pending required activation artifacts"
    if blocked_activation_candidates:
        return "blocked activation candidates only; no activation artifacts can advance"
    return "activation packets are not ready; activation artifacts remain blocked"


def _artifact_refs(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {
        kind: str(record.get("artifact_id") or f"{kind}:inline")
        for kind, record in sorted(artifacts.items())
    }


def _activation_artifact_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        artifact_kind = str(record.get("artifact_kind") or "unknown")
        counts[artifact_kind] = counts.get(artifact_kind, 0) + 1
    return dict(sorted(counts.items()))


def _is_synthetic_activation_fixture(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if isinstance(payload, dict):
        fixture_policy = _object(payload.get("fixture_policy"))
        if fixture_policy.get("synthetic_activation_fixture") is True:
            return True
        if fixture_policy.get("not_valid_for_production_activation") is True:
            return True
    return any(record.get("synthetic_fixture") is True for record in records)


def _required_activation_artifacts_declared(packet: dict[str, Any]) -> bool:
    required = _object(packet.get("required_activation_artifacts"))
    return all(kind in required for kind in REQUIRED_ACTIVATION_ARTIFACT_KINDS)


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _activation_record_execution_disabled(record: dict[str, Any]) -> bool:
    return all(record.get(flag) is False for flag in ACTIVATION_BLOCKING_FLAGS)


def _string_fields_present(record: dict[str, Any], fields: list[str]) -> bool:
    return all(str(record.get(field) or "").strip() for field in fields)


def _kind_specific_ref_present(record: dict[str, Any]) -> bool:
    artifact_kind = str(record.get("artifact_kind") or "")
    ref_field = PRODUCTION_ACTIVATION_KIND_REF_FIELDS.get(artifact_kind)
    return bool(ref_field and str(record.get(ref_field) or "").strip())


def _production_source_eligible(record: dict[str, Any]) -> bool:
    source = str(record.get("source") or "").strip().lower()
    return bool(source and "fixture" not in source)


def _record_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None
    return payload


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _require_equal(
    name: str,
    actual: object,
    expected: object,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _resolve_path(path: Path | None, agent_root: Path) -> Path:
    assert path is not None
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activation-gate", required=True)
    parser.add_argument("--activation-artifacts", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_activation_artifact_gate(
        activation_gate_path=Path(args.activation_gate),
        agent_root=agent_root,
        activation_artifacts_path=Path(args.activation_artifacts) if args.activation_artifacts else None,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())