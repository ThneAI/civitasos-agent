"""Create local H.3 runtime-start inputs for controlled execution proof.

This helper is deliberately explicit: it requires an acknowledgement and writes
local, production-shaped runtime-start inputs that can drive the runtime start
artifact gate, execution gate, and controlled executor in a development run. It
does not claim external production deployment, dual-operator reality beyond the
recorded refs, or governance finality.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-execution-local-fixture:v1"
RUNTIME_START_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-start-gate:v1"
RUNTIME_START_ARTIFACTS_SCHEMA_VERSION = "h3-goal-emission-runtime-start-artifacts:v1"
REQUIRED_RUNTIME_START_CONTROL_KINDS = [
    "runtime_start_change_ticket",
    "runtime_start_dual_operator_ack",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_check",
    "runtime_start_rollback_checkpoint",
    "runtime_start_audit_sink_ready",
]


def build_h3_goal_emission_runtime_execution_local_fixture(
    *,
    output_dir: Path,
    agent_root: Path,
    event_kind: str = "post_delivery_failure",
    reviewer: str = "did:civ:local-operator:runtime-execution",
    ack_local_production_shaped_start: bool = False,
) -> dict[str, Any]:
    output_dir = _resolve_path(output_dir, agent_root)
    goal_id = f"h3-draft-goal:{event_kind}:local-execution"
    start_gate_path = output_dir / "h3_goal_emission_runtime_start_gate.json"
    start_artifacts_path = output_dir / "h3_goal_emission_runtime_start_artifacts.json"
    checks = {
        "local_start_fixture_acknowledged": ack_local_production_shaped_start,
        "event_kind_present": bool(event_kind.strip()),
        "reviewer_present": bool(reviewer.strip()),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if not failures:
        output_dir.mkdir(parents=True, exist_ok=True)
        start_gate_path.write_text(
            json.dumps(_runtime_start_gate(goal_id), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        start_artifacts_path.write_text(
            json.dumps(_runtime_start_artifacts(goal_id, reviewer), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    passed = not failures
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "readiness": {
            "local_runtime_start_inputs_ready": passed,
            "decision": "local_runtime_start_inputs_ready" if passed else "blocked_before_local_runtime_start_inputs",
            "allowed_scope": "local controlled execution input generation only" if passed else "do not generate local start inputs without ack",
        },
        "paths": {
            "output_dir": str(output_dir),
            "runtime_start_gate": str(start_gate_path) if passed else None,
            "runtime_start_artifacts": str(start_artifacts_path) if passed else None,
        },
        "fixture_policy": {
            "local_controlled_execution_fixture": True,
            "requires_explicit_ack": True,
            "not_external_production_deployment": True,
            "not_chain_or_backend_mutation": True,
            "not_llm_execution": True,
        },
        "non_claims": [
            "does_not_claim_external_production_deployment",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_replace_real_dual_operator_or_governance_process",
        ],
    }


def _runtime_start_gate(goal_id: str) -> dict[str, Any]:
    packet = {
        "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
        "runtime_activation_artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "approval_id": f"h3-approved-candidate:{goal_id}",
        "goal_id": goal_id,
        "state": "runtime_start_review_required",
        "production_runtime_activation_artifacts_ready": True,
        "required_runtime_start_controls": {
            kind: "required_before_runtime_start"
            for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS
        },
        "runtime_activation_artifact_refs": {
            "runtime_safety_envelope": f"runtime-activation:runtime_safety_envelope:{goal_id}",
            "rollout_window_approval": f"runtime-activation:rollout_window_approval:{goal_id}",
            "live_monitoring_attestation": f"runtime-activation:live_monitoring_attestation:{goal_id}",
            "rollback_drill_attestation": f"runtime-activation:rollback_drill_attestation:{goal_id}",
            "operator_oncall_ack": f"runtime-activation:operator_oncall_ack:{goal_id}",
            "kill_switch_attestation": f"runtime-activation:kill_switch_attestation:{goal_id}",
            "post_activation_audit_plan": f"runtime-activation:post_activation_audit_plan:{goal_id}",
        },
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "gate_status": {
            "runtime_start_review_ready": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
    }
    return {
        "schema_version": RUNTIME_START_GATE_SCHEMA_VERSION,
        "passed": True,
        "failure_reasons": [],
        "readiness": {
            "runtime_start_gate_evaluated": True,
            "runtime_start_review_packets_ready": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "decision": "runtime_start_review_packets_ready_no_runtime",
        },
        "runtime_start_boundary": {
            "artifact_only": True,
            "runtime_start_review_packets_allowed": True,
            "runtime_start_allowed": False,
            "runtime_activation_allowed": False,
            "runtime_execution_allowed": False,
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_start_surface": {
            "mode": "runtime_start_review_only_no_runtime",
            "runtime_start_review_packet_count": 1,
            "runtime_start_review_packets": [packet],
            "blocked_runtime_start_candidate_count": 0,
            "blocked_runtime_start_candidates": [],
            "runtime_executions": [],
            "emitted_goals": [],
        },
    }


def _runtime_start_artifacts(goal_id: str, reviewer: str) -> dict[str, Any]:
    records = []
    for artifact_kind in REQUIRED_RUNTIME_START_CONTROL_KINDS:
        record = {
            "artifact_id": f"runtime-start:{artifact_kind}:{goal_id}",
            "artifact_kind": artifact_kind,
            "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
            "goal_id": goal_id,
            "runtime_start_allowed": False,
            "runtime_activation_allowed": False,
            "runtime_execution_allowed": False,
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
            "reviewer": reviewer,
            "reviewer_role": artifact_kind,
            "source": "h3_local_operator_start_registry",
            "attestation_ref": f"local-runtime-start-attestation:{artifact_kind}:{goal_id}",
        }
        if artifact_kind == "runtime_start_change_ticket":
            record["decision"] = "approved_for_runtime_start"
            record["change_ticket_ref"] = f"local-change-ticket:{goal_id}"
        elif artifact_kind == "runtime_start_dual_operator_ack":
            record["status"] = "acknowledged"
            record["dual_operator_ack_ref"] = f"local-dual-operator-ack:{goal_id}"
        elif artifact_kind == "runtime_start_final_monitoring_green":
            record["status"] = "green"
            record["final_monitoring_ref"] = f"local-final-monitoring:{goal_id}"
        elif artifact_kind == "runtime_start_final_kill_switch_check":
            record["status"] = "armed"
            record["final_kill_switch_ref"] = f"local-final-kill-switch:{goal_id}"
        elif artifact_kind == "runtime_start_rollback_checkpoint":
            record["status"] = "ready"
            record["rollback_checkpoint_ref"] = f"local-rollback-checkpoint:{goal_id}"
        elif artifact_kind == "runtime_start_audit_sink_ready":
            record["status"] = "ready"
            record["audit_sink_ref"] = f"local-audit-sink:{goal_id}"
        records.append(record)
    return {
        "schema_version": RUNTIME_START_ARTIFACTS_SCHEMA_VERSION,
        "records": records,
        "local_fixture_policy": {
            "local_controlled_execution_fixture": True,
            "not_external_production_deployment": True,
        },
    }


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--event-kind", default="post_delivery_failure")
    parser.add_argument("--reviewer", default="did:civ:local-operator:runtime-execution")
    parser.add_argument("--ack-local-production-shaped-start", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_execution_local_fixture(
        output_dir=Path(args.output_dir),
        agent_root=agent_root,
        event_kind=args.event_kind,
        reviewer=args.reviewer,
        ack_local_production_shaped_start=args.ack_local_production_shaped_start,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())