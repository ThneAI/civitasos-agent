"""H.3 external review artifact fixture generator.

This artifact-only helper reads H.3 review lifecycle packets and generates a
synthetic `h3-external-review-artifacts:v1` payload for schema and approval-gate
path validation. It does not represent real human or governance approval, emit
goals, generate plans, start runtime components, call LLMs, or mutate state.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-external-review-artifacts:v1"
LIFECYCLE_GATE_SCHEMA_VERSION = "h3-goal-lifecycle-gate:v1"
FIXTURE_MODES = {"pending", "approved"}
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


def build_h3_external_review_artifacts_fixture(
    *,
    lifecycle_gate_path: Path,
    agent_root: Path,
    fixture_mode: str = "pending",
    reviewer_prefix: str = "h3-fixture-reviewer",
    acknowledged_synthetic_approval_fixture: bool = False,
) -> dict[str, Any]:
    lifecycle_gate_path = _resolve_path(lifecycle_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    fixture_mode = str(fixture_mode or "").strip()
    _require_bool("fixture_mode_known", fixture_mode in FIXTURE_MODES, checks=checks, failures=failures)
    if fixture_mode == "approved":
        _require_bool(
            "synthetic_approval_fixture_acknowledged",
            acknowledged_synthetic_approval_fixture,
            checks=checks,
            failures=failures,
        )

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

    records: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        records = [
            _review_artifact_record(
                packet=packet,
                artifact_kind=artifact_kind,
                fixture_mode=fixture_mode,
                reviewer_prefix=reviewer_prefix,
            )
            for packet in packets
            for artifact_kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS
        ]
    _require_bool("fixture_records_present", bool(records), checks=checks, failures=failures)
    _require_bool(
        "fixture_records_execution_disabled",
        all(_execution_policy_disabled(record) for record in records),
        checks=checks,
        failures=failures,
    )

    accepted_like_records = sum(1 for record in records if _record_accepts_candidate(record))
    metrics = {
        "review_packet_count": len(packets),
        "external_review_record_count": len(records),
        "accepted_like_record_count": accepted_like_records,
        "synthetic_fixture_packet_count": len({str(record.get("packet_id") or "") for record in records}),
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("goal_emission_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_execution_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "lifecycle_gate_path": str(lifecycle_gate_path),
        "checks": checks,
        "fixture_policy": {
            "synthetic_review_fixture": True,
            "fixture_mode": fixture_mode,
            "acknowledged_synthetic_approval_fixture": acknowledged_synthetic_approval_fixture,
            "not_real_human_or_governance_approval": True,
            "not_valid_for_production_approval": True,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "records": records,
        "metrics": metrics,
        "evidence": {
            "lifecycle_boundary": lifecycle_boundary,
            "required_external_artifact_kinds": REQUIRED_EXTERNAL_ARTIFACT_KINDS,
        },
        "non_claims": [
            "does_not_create_real_human_review",
            "does_not_create_real_governance_review",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
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
        "review_packet_required_artifacts_declared",
        all(_required_artifacts_declared(packet) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "review_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )


def _review_artifact_record(
    *,
    packet: dict[str, Any],
    artifact_kind: str,
    fixture_mode: str,
    reviewer_prefix: str,
) -> dict[str, Any]:
    packet_id = str(packet.get("packet_id") or "unknown-packet")
    goal_id = str(packet.get("goal_id") or "unknown-goal")
    record: dict[str, Any] = {
        "artifact_id": f"h3-review-fixture:{fixture_mode}:{artifact_kind}:{_stable_suffix(goal_id)}",
        "artifact_kind": artifact_kind,
        "packet_id": packet_id,
        "goal_id": goal_id,
        "trigger_event_kind": packet.get("trigger_event_kind"),
        "identity": packet.get("identity"),
        "risk_class": packet.get("risk_class"),
        "reviewer": f"{reviewer_prefix}:{artifact_kind}",
        "reviewer_role": artifact_kind,
        "source": "h3_external_review_artifacts_fixture",
        "synthetic_fixture": True,
        "attestation_ref": f"synthetic-attestation:{_stable_suffix(packet_id)}:{artifact_kind}",
        "evidence_ref": _object(packet.get("evidence_ref")),
        "goal_emission_allowed": False,
        "executable_plan_allowed": False,
        "runtime_execution_allowed": False,
        "llm_planning_allowed": False,
        "iem_value_mutation_allowed": False,
        "normative_local_mutation_allowed": False,
        "notes": "synthetic fixture record for schema and gate-path validation only",
    }
    if artifact_kind in {"human_review_record", "governance_review_record"}:
        record["decision"] = "approved_for_candidate" if fixture_mode == "approved" else "pending_fixture_review"
    elif artifact_kind == "challenge_window_result":
        record["status"] = "closed_no_blocking_challenge" if fixture_mode == "approved" else "challenge_window_pending_fixture"
    else:
        record["status"] = "ready" if fixture_mode == "approved" else "pending_fixture_review"
    return record


def _record_accepts_candidate(record: dict[str, Any]) -> bool:
    artifact_kind = str(record.get("artifact_kind") or "")
    if artifact_kind in {"human_review_record", "governance_review_record"}:
        return record.get("decision") == "approved_for_candidate"
    if artifact_kind == "challenge_window_result":
        return record.get("status") == "closed_no_blocking_challenge"
    if artifact_kind in {"rollback_plan_record", "r2r_accountability_record"}:
        return record.get("status") == "ready"
    return False


def _execution_policy_disabled(value: dict[str, Any]) -> bool:
    return all(value.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _required_artifacts_declared(packet: dict[str, Any]) -> bool:
    required = _object(packet.get("required_external_artifacts"))
    return all(kind in required for kind in REQUIRED_EXTERNAL_ARTIFACT_KINDS)


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


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def _stable_suffix(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-")
    return sanitized[:160] or "unknown"


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle-gate", required=True)
    parser.add_argument("--fixture-mode", choices=sorted(FIXTURE_MODES), default="pending")
    parser.add_argument("--reviewer-prefix", default="h3-fixture-reviewer")
    parser.add_argument("--ack-synthetic-approval-fixture", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_external_review_artifacts_fixture(
        lifecycle_gate_path=Path(args.lifecycle_gate),
        agent_root=agent_root,
        fixture_mode=args.fixture_mode,
        reviewer_prefix=args.reviewer_prefix,
        acknowledged_synthetic_approval_fixture=args.ack_synthetic_approval_fixture,
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