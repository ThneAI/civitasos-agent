"""H.3 goal approval gate.

This artifact-only gate reads H.3 review lifecycle packets plus optional external
review artifacts. It can mark candidates as approved only when required review
artifacts are complete, but it still does not emit executable goals, generate
plans, start runtime components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-approval-gate:v1"
LIFECYCLE_GATE_SCHEMA_VERSION = "h3-goal-lifecycle-gate:v1"
REVIEW_ARTIFACTS_SCHEMA_VERSION = "h3-external-review-artifacts:v1"
REQUIRED_EXTERNAL_ARTIFACT_KINDS = [
    "human_review_record",
    "governance_review_record",
    "challenge_window_result",
    "rollback_plan_record",
    "r2r_accountability_record",
]
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
PRODUCTION_REVIEW_COMMON_FIELDS = ["artifact_id", "reviewer", "reviewer_role", "source", "attestation_ref"]
PRODUCTION_REVIEW_KIND_REF_FIELDS = {
    "human_review_record": "human_review_ref",
    "governance_review_record": "governance_ref",
    "challenge_window_result": "challenge_window_ref",
    "rollback_plan_record": "rollback_plan_ref",
    "r2r_accountability_record": "r2r_accountability_ref",
}


def build_h3_goal_approval_gate(
    *,
    lifecycle_gate_path: Path,
    agent_root: Path,
    review_artifacts_path: Path | None = None,
) -> dict[str, Any]:
    lifecycle_gate_path = _resolve_path(lifecycle_gate_path, agent_root)
    review_artifacts_path = _resolve_path(review_artifacts_path, agent_root) if review_artifacts_path else None
    checks: dict[str, bool] = {}
    failures: list[str] = []
    lifecycle = _read_json(lifecycle_gate_path, failures)

    lifecycle_boundary: dict[str, Any] = {}
    packets: list[dict[str, Any]] = []
    if lifecycle is None:
        _fail(checks, failures, "lifecycle_gate_present", f"missing H3 lifecycle gate: {lifecycle_gate_path}")
    else:
        checks["lifecycle_gate_present"] = True
        _require_equal(
            "lifecycle_gate_schema_version",
            lifecycle.get("schema_version"),
            LIFECYCLE_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("lifecycle_gate_passed", bool(lifecycle.get("passed")), checks=checks, failures=failures)
        readiness = _object(lifecycle.get("readiness"))
        _require_equal(
            "lifecycle_gate_decision",
            readiness.get("decision"),
            "h3_review_lifecycle_ready",
            checks=checks,
            failures=failures,
        )
        lifecycle_boundary = _object(lifecycle.get("lifecycle_boundary"))
        _require_lifecycle_boundary(lifecycle_boundary, checks=checks, failures=failures)
        surface = _object(lifecycle.get("review_packet_surface"))
        _require_equal("review_packet_surface_mode", surface.get("mode"), "review_only", checks=checks, failures=failures)
        packets = _packet_list(surface.get("review_packets"))
        _require_bool("review_packets_present", bool(packets), checks=checks, failures=failures)
        _require_packet_shape(packets, checks=checks, failures=failures)

    review_artifacts, review_artifact_payload = _load_review_artifacts(review_artifacts_path, failures)
    synthetic_review_fixture = _is_synthetic_review_fixture(review_artifact_payload, review_artifacts)
    if review_artifacts_path:
        checks["review_artifacts_present"] = review_artifact_payload is not None
        if review_artifact_payload is not None:
            _require_equal(
                "review_artifacts_schema_version",
                review_artifact_payload.get("schema_version"),
                REVIEW_ARTIFACTS_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool("review_artifacts_records_present", bool(review_artifacts), checks=checks, failures=failures)
            _require_review_artifact_shape(
                review_artifacts,
                synthetic_review_fixture=synthetic_review_fixture,
                checks=checks,
                failures=failures,
            )
    else:
        checks["review_artifacts_optional_absent"] = True

    approvals: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        approvals, pending_packets = _evaluate_packets(packets, review_artifacts, synthetic_review_fixture)
    elif packets:
        pending_packets = [_pending_packet(packet, {}) for packet in packets]

    metrics = {
        "review_packet_count": len(packets),
        "external_review_artifact_count": len(review_artifacts),
        "approved_candidate_count": len(approvals),
        "pending_review_packet_count": len(pending_packets),
        "synthetic_review_fixture_count": 1 if synthetic_review_fixture else 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("goal_emission_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_execution_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _approval_decision(passed, approvals, pending_packets, synthetic_review_fixture)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "lifecycle_gate_path": str(lifecycle_gate_path),
        "review_artifacts_path": str(review_artifacts_path) if review_artifacts_path else None,
        "checks": checks,
        "readiness": {
            "approval_gate_evaluated": passed,
            "approved_candidate_ready": passed and bool(approvals),
            "production_approved_candidate_ready": passed and bool(approvals) and not synthetic_review_fixture,
            "synthetic_approved_candidate_ready": passed and bool(approvals) and synthetic_review_fixture,
            "executable_goal_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, approvals, synthetic_review_fixture),
        },
        "approval_boundary": {
            "artifact_only": True,
            "candidate_approval_allowed": passed and bool(approvals) and not synthetic_review_fixture,
            "synthetic_candidate_surface_allowed": passed and bool(approvals) and synthetic_review_fixture,
            "production_candidate_approval_allowed": passed and bool(approvals) and not synthetic_review_fixture,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "approval_policy": {
            "required_external_artifact_kinds": REQUIRED_EXTERNAL_ARTIFACT_KINDS,
            "accepted_review_decisions": {
                "human_review_record": "approved_for_candidate",
                "governance_review_record": "approved_for_candidate",
                "challenge_window_result": "closed_no_blocking_challenge",
                "rollback_plan_record": "ready",
                "r2r_accountability_record": "ready",
            },
            "production_review_common_fields": PRODUCTION_REVIEW_COMMON_FIELDS,
            "production_review_kind_ref_fields": PRODUCTION_REVIEW_KIND_REF_FIELDS,
            "blocked_after_approval": [
                "approved_candidate -> executable_goal_emitted",
                "executable_goal_emitted -> runtime_execution_started",
            ],
        },
        "approval_surface": {
            "mode": "approval_only_no_execution",
            "approved_candidate_count": len(approvals),
            "approved_candidates": approvals,
            "pending_review_packet_count": len(pending_packets),
            "pending_review_packets": pending_packets,
        },
        "metrics": metrics,
        "evidence": {
            "lifecycle_boundary": lifecycle_boundary,
            "review_artifact_summary": _review_artifact_summary(review_artifacts),
            "synthetic_review_fixture": synthetic_review_fixture,
        },
        "non_claims": [
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_missing_review_artifacts_as_approval",
            "does_not_treat_synthetic_fixture_as_production_approval",
        ],
    }


def _require_lifecycle_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("lifecycle_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    _require_bool("lifecycle_review_packets_allowed", boundary.get("review_packets_allowed") is True, checks=checks, failures=failures)
    _require_bool("lifecycle_approval_blocked", boundary.get("approval_allowed") is False, checks=checks, failures=failures)
    for flag in EXECUTION_POLICY_FLAGS:
        _require_bool(f"lifecycle_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool(
        "review_packet_state_ready",
        all(packet.get("lifecycle_state") == "review_packet_ready" for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_packet_required_artifacts_declared",
        all(_required_artifacts_declared(packet) for packet in packets),
        checks=checks,
        failures=failures,
    )


def _require_review_artifact_shape(
    records: list[dict[str, Any]],
    *,
    synthetic_review_fixture: bool,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool(
        "review_artifact_kinds_known",
        all(str(record.get("artifact_kind") or "") in REQUIRED_EXTERNAL_ARTIFACT_KINDS for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_artifact_execution_disabled",
        all(_execution_policy_disabled(record) for record in records),
        checks=checks,
        failures=failures,
    )
    if synthetic_review_fixture:
        _require_bool(
            "review_artifact_synthetic_fixture_marked",
            all(record.get("synthetic_fixture") is True for record in records),
            checks=checks,
            failures=failures,
        )
        return
    _require_bool(
        "review_artifact_not_synthetic_fixture",
        all(record.get("synthetic_fixture") is not True for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_artifact_common_provenance_present",
        all(_string_fields_present(record, PRODUCTION_REVIEW_COMMON_FIELDS) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_artifact_kind_specific_provenance_present",
        all(_kind_specific_ref_present(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_artifact_source_not_fixture",
        all(_production_source_eligible(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_artifact_targets_present",
        all(str(record.get("packet_id") or record.get("goal_id") or "").strip() for record in records),
        checks=checks,
        failures=failures,
    )


def _load_review_artifacts(
    review_artifacts_path: Path | None,
    failures: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if review_artifacts_path is None:
        return [], None
    payload = _read_json(review_artifacts_path, failures)
    if payload is None:
        return [], None
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append(f"review artifact file missing records array: {review_artifacts_path}")
        return [], payload
    return [record for record in records if isinstance(record, dict)], payload


def _evaluate_packets(
    packets: list[dict[str, Any]],
    review_artifacts: list[dict[str, Any]],
    synthetic_review_fixture: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    approvals: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for packet in packets:
        artifacts = _artifacts_for_packet(packet, review_artifacts)
        status = _approval_status(artifacts)
        if all(status.values()):
            approvals.append(_approved_candidate(packet, artifacts, synthetic_review_fixture))
        else:
            pending.append(_pending_packet(packet, status))
    return approvals, pending


def _is_synthetic_review_fixture(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if isinstance(payload, dict):
        fixture_policy = _object(payload.get("fixture_policy"))
        if fixture_policy.get("synthetic_review_fixture") is True:
            return True
        if fixture_policy.get("not_valid_for_production_approval") is True:
            return True
    return any(record.get("synthetic_fixture") is True for record in records)


def _approval_status(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {kind: _artifact_accepts_candidate(kind, artifacts.get(kind)) for kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS}


def _artifacts_for_packet(
    packet: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    packet_id = str(packet.get("packet_id") or "")
    goal_id = str(packet.get("goal_id") or "")
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        record_packet_id = str(record.get("packet_id") or "")
        record_goal_id = str(record.get("goal_id") or "")
        if record_packet_id != packet_id and record_goal_id != goal_id:
            continue
        artifact_kind = str(record.get("artifact_kind") or "")
        if artifact_kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS and artifact_kind not in out:
            out[artifact_kind] = record
    return out


def _artifact_accepts_candidate(kind: str, record: dict[str, Any] | None) -> bool:
    if not isinstance(record, dict):
        return False
    if kind in {"human_review_record", "governance_review_record"}:
        return record.get("decision") == "approved_for_candidate"
    if kind == "challenge_window_result":
        return record.get("status") == "closed_no_blocking_challenge"
    if kind in {"rollback_plan_record", "r2r_accountability_record"}:
        return record.get("status") == "ready"
    return False


def _approved_candidate(
    packet: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    synthetic_review_fixture: bool,
) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "packet_id": packet.get("packet_id"),
        "state": "approved_candidate",
        "identity": packet.get("identity"),
        "trigger_event_kind": packet.get("trigger_event_kind"),
        "risk_class": packet.get("risk_class"),
        "synthetic_review_fixture": synthetic_review_fixture,
        "production_approval_ready": not synthetic_review_fixture,
        "external_artifact_refs": _artifact_refs(artifacts),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "blocked_transitions": [
            {
                "transition": "approved_candidate -> executable_goal_emitted",
                "reason": "goal emission remains disabled in H3 approval gate",
            },
            {
                "transition": "executable_goal_emitted -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 approval gate",
            },
        ],
        "gate_status": {
            "approved_candidate_ready": True,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _pending_packet(packet: dict[str, Any], status: dict[str, bool]) -> dict[str, Any]:
    if not status:
        status = {kind: False for kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS}
    missing = [kind for kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS if not status.get(kind)]
    return {
        "packet_id": packet.get("packet_id"),
        "goal_id": packet.get("goal_id"),
        "lifecycle_state": "review_packet_ready",
        "approval_ready": False,
        "missing_or_rejected_external_artifacts": missing,
        "blocked_transition": {
            "transition": "review_packet_ready -> approved_candidate",
            "reason": "missing or rejected required external review artifacts",
        },
    }


def _artifact_refs(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {
        kind: str(record.get("artifact_id") or f"{kind}:inline")
        for kind, record in sorted(artifacts.items())
    }


def _review_artifact_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        artifact_kind = str(record.get("artifact_kind") or "unknown")
        counts[artifact_kind] = counts.get(artifact_kind, 0) + 1
    return dict(sorted(counts.items()))


def _approval_decision(
    passed: bool,
    approvals: list[dict[str, Any]],
    pending: list[dict[str, Any]],
    synthetic_review_fixture: bool,
) -> str:
    if not passed:
        return "blocked_before_h3_approval_gate"
    if approvals and not pending:
        if synthetic_review_fixture:
            return "synthetic_approved_candidate_surface_ready"
        return "approved_candidate_surface_ready"
    if approvals:
        if synthetic_review_fixture:
            return "partial_synthetic_approved_candidate_surface_ready"
        return "partial_approved_candidate_surface_ready"
    return "approval_blocked_pending_external_review_artifacts"


def _allowed_scope(passed: bool, approvals: list[dict[str, Any]], synthetic_review_fixture: bool) -> str:
    if not passed:
        return "do not evaluate approval until lifecycle gate and review artifacts are valid"
    if approvals and synthetic_review_fixture:
        return "synthetic approved candidate records only; production approval still requires real external artifacts"
    if approvals:
        return "approved candidate records only; goal emission and execution remain blocked"
    return "approval gate evaluated; review packets remain pending external artifacts"


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _required_artifacts_declared(packet: dict[str, Any]) -> bool:
    required = _object(packet.get("required_external_artifacts"))
    return all(kind in required for kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS)


def _string_fields_present(record: dict[str, Any], fields: list[str]) -> bool:
    return all(str(record.get(field) or "").strip() for field in fields)


def _kind_specific_ref_present(record: dict[str, Any]) -> bool:
    artifact_kind = str(record.get("artifact_kind") or "")
    ref_field = PRODUCTION_REVIEW_KIND_REF_FIELDS.get(artifact_kind)
    return bool(ref_field and str(record.get(ref_field) or "").strip())


def _production_source_eligible(record: dict[str, Any]) -> bool:
    source = str(record.get("source") or "").strip().lower()
    return bool(source and "fixture" not in source)


def _packet_list(value: object) -> list[dict[str, Any]]:
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
    parser.add_argument("--lifecycle-gate", required=True)
    parser.add_argument("--review-artifacts", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_approval_gate(
        lifecycle_gate_path=Path(args.lifecycle_gate),
        agent_root=agent_root,
        review_artifacts_path=Path(args.review_artifacts) if args.review_artifacts else None,
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