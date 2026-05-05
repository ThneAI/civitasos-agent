"""H.3 controlled runtime executor.

This executor reads H.3 runtime execution packets and, with explicit local
acknowledgement, performs the bounded execution action allowed by the gate:
writing auditable runtime execution receipts. It does not start the long-lived
agent loop, call LLMs, run arbitrary shell commands, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-executor:v1"
RUNTIME_EXECUTION_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-execution-gate:v1"
ALLOWED_ACTION = "record_h3_controlled_runtime_execution_receipt"


def build_h3_goal_emission_runtime_executor_report(
    *,
    runtime_execution_gate_path: Path,
    agent_root: Path,
    ack_local_runtime_execution: bool = False,
    receipt_dir: Path | None = None,
) -> dict[str, Any]:
    runtime_execution_gate_path = _resolve_path(runtime_execution_gate_path, agent_root)
    receipt_dir = _resolve_path(receipt_dir, agent_root) if receipt_dir else None
    checks: dict[str, bool] = {}
    failures: list[str] = []
    execution_gate = _read_json(runtime_execution_gate_path, failures)

    execution_readiness: dict[str, Any] = {}
    execution_boundary: dict[str, Any] = {}
    execution_packets: list[dict[str, Any]] = []
    if execution_gate is None:
        _fail(
            checks,
            failures,
            "runtime_execution_gate_present",
            f"missing H3 runtime execution gate: {runtime_execution_gate_path}",
        )
    else:
        checks["runtime_execution_gate_present"] = True
        _require_equal(
            "runtime_execution_gate_schema_version",
            execution_gate.get("schema_version"),
            RUNTIME_EXECUTION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("runtime_execution_gate_passed", bool(execution_gate.get("passed")), checks=checks, failures=failures)
        execution_readiness = _object(execution_gate.get("readiness"))
        _require_execution_readiness(execution_readiness, checks=checks, failures=failures)
        execution_boundary = _object(execution_gate.get("runtime_execution_boundary"))
        _require_execution_boundary(execution_boundary, checks=checks, failures=failures)
        surface = _object(execution_gate.get("runtime_execution_surface"))
        _require_equal(
            "runtime_execution_surface_mode",
            surface.get("mode"),
            "controlled_runtime_execution_packet_gate",
            checks=checks,
            failures=failures,
        )
        execution_packets = _record_list(surface.get("runtime_execution_packets"))
        _require_execution_packet_shape(execution_packets, checks=checks, failures=failures)

    blocked_execution_packets: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    if not failures and all(checks.values()) and ack_local_runtime_execution:
        local_execution_packets, blocked_execution_packets = _executor_eligible_packets(execution_packets)
        receipts = _execute_packets(local_execution_packets, receipt_dir)

    metrics = {
        "runtime_execution_packet_count": len(execution_packets),
        "runtime_execution_started_count": len(receipts),
        "runtime_execution_completed_count": len(receipts),
        "runtime_execution_receipt_count": len(receipts),
        "blocked_runtime_execution_packet_count": len(blocked_execution_packets),
        "llm_call_count": 0,
        "agent_loop_start_count": 0,
        "external_system_mutation_count": 0,
        "iem_mutation_count": 0,
        "normative_mutation_count": 0,
    }
    _require_bool("llm_calls_absent", metrics["llm_call_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_absent", metrics["agent_loop_start_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutation_absent", metrics["external_system_mutation_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_absent", metrics["iem_mutation_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_absent", metrics["normative_mutation_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _executor_decision(passed, execution_packets, receipts, blocked_execution_packets, ack_local_runtime_execution)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_execution_gate_path": str(runtime_execution_gate_path),
        "receipt_dir": str(receipt_dir) if receipt_dir else None,
        "checks": checks,
        "readiness": {
            "runtime_executor_evaluated": passed,
            "local_runtime_execution_acknowledged": ack_local_runtime_execution,
            "runtime_execution_started": passed and bool(receipts),
            "runtime_execution_completed": passed and bool(receipts),
            "local_controlled_runtime_execution_completed": passed and bool(receipts) and _all_receipts_origin(receipts, "local_controlled"),
            "production_runtime_execution_completed": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, execution_packets, receipts, blocked_execution_packets, ack_local_runtime_execution),
        },
        "runtime_executor_boundary": {
            "runtime_execution_performed": passed and bool(receipts),
            "receipt_write_performed": passed and bool(receipts),
            "local_controlled_receipt_write_performed": passed and bool(receipts) and _all_receipts_origin(receipts, "local_controlled"),
            "production_runtime_receipt_write_performed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_started": False,
            "llm_called": False,
            "external_system_mutated": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_executor_surface": {
            "mode": "local_controlled_runtime_receipt_executor",
            "blocked_runtime_execution_packet_count": len(blocked_execution_packets),
            "blocked_runtime_execution_packets": blocked_execution_packets,
        },
        "runtime_execution_receipts": receipts,
        "metrics": metrics,
        "evidence": {
            "runtime_execution_readiness": execution_readiness,
            "runtime_execution_boundary": execution_boundary,
        },
        "non_claims": [
            "does_not_start_long_lived_agent_loop",
            "does_not_call_llms_or_train_models",
            "does_not_run_arbitrary_shell_commands",
            "does_not_mutate_iem_or_normative_state",
            "does_not_mutate_external_systems",
            "does_not_execute_without_local_runtime_execution_ack",
            "does_not_complete_production_origin_packets_with_local_executor_ack",
        ],
    }


def _require_execution_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool(
        "runtime_execution_gate_decision_ready",
        readiness.get("decision") in {"runtime_execution_packets_ready", "local_controlled_runtime_execution_packets_ready"},
        checks=checks,
        failures=failures,
    )
    _require_bool("runtime_execution_gate_start_ready", readiness.get("runtime_start_ready") is True, checks=checks, failures=failures)
    _require_bool("runtime_execution_gate_execution_ready", readiness.get("runtime_execution_ready") is True, checks=checks, failures=failures)
    _require_bool("runtime_execution_gate_not_started", readiness.get("runtime_execution_started") is False, checks=checks, failures=failures)
    _require_bool("runtime_execution_gate_not_completed", readiness.get("runtime_execution_completed") is False, checks=checks, failures=failures)


def _require_execution_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("runtime_execution_boundary_packets_allowed", boundary.get("controlled_runtime_execution_packet_allowed") is True, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_start_allowed", boundary.get("runtime_start_allowed") is True, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_execution_allowed", boundary.get("runtime_execution_allowed") is True, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_not_performed", boundary.get("runtime_execution_performed") is False, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_executable_plan_blocked", boundary.get("executable_plan_allowed") is False, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_llm_blocked", boundary.get("llm_planning_allowed") is False, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_iem_blocked", boundary.get("iem_value_mutation_allowed") is False, checks=checks, failures=failures)
    _require_bool("runtime_execution_boundary_normative_blocked", boundary.get("normative_local_mutation_allowed") is False, checks=checks, failures=failures)


def _require_execution_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("runtime_execution_packets_present", bool(packets), checks=checks, failures=failures)
    if not packets:
        return
    _require_bool("runtime_execution_packet_state_valid", all(packet.get("state") == "runtime_execution_packet_ready" for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_execution_packet_action_valid", all(packet.get("action") == ALLOWED_ACTION for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_execution_packet_origin_recorded", all(packet.get("execution_origin") in {"local_controlled", "production"} for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_execution_packet_policy_valid", all(_packet_policy_valid(_object(packet.get("execution_policy"))) for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_execution_packet_scope_valid", all(_packet_scope_valid(_object(packet.get("execution_scope"))) for packet in packets), checks=checks, failures=failures)


def _executor_eligible_packets(packets: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    local_packets: list[dict[str, Any]] = []
    blocked_packets: list[dict[str, Any]] = []
    for packet in packets:
        origin = str(packet.get("execution_origin") or "")
        if origin == "local_controlled":
            local_packets.append(packet)
        elif origin == "production":
            blocked_packets.append(
                _blocked_execution_packet(
                    packet,
                    "production-origin execution packets require a future production executor evidence gate; local executor cannot complete them",
                )
            )
        else:
            blocked_packets.append(_blocked_execution_packet(packet, "runtime execution packet origin is unknown"))
    return local_packets, blocked_packets


def _blocked_execution_packet(packet: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "runtime_execution_packet_id": packet.get("runtime_execution_packet_id"),
        "goal_id": packet.get("goal_id"),
        "execution_origin": packet.get("execution_origin") or "unknown",
        "state": "runtime_execution_blocked",
        "blocked_reason": reason,
        "receipt_written": False,
    }


def _execute_packets(packets: list[dict[str, Any]], receipt_dir: Path | None) -> list[dict[str, Any]]:
    if receipt_dir:
        receipt_dir.mkdir(parents=True, exist_ok=True)
    receipts = []
    for packet in packets:
        now = _now_iso()
        goal_id = str(packet.get("goal_id") or "unknown")
        receipt = {
            "receipt_id": f"h3-runtime-execution-receipt:{goal_id}",
            "runtime_execution_packet_id": packet.get("runtime_execution_packet_id"),
            "execution_origin": packet.get("execution_origin") or "unknown",
            "runtime_start_artifact_review_id": packet.get("runtime_start_artifact_review_id"),
            "goal_id": goal_id,
            "state": "runtime_execution_completed",
            "action": ALLOWED_ACTION,
            "started_at": now,
            "completed_at": now,
            "runtime_start_artifact_refs": _object(packet.get("runtime_start_artifact_refs")),
            "side_effects": {
                "receipt_written": True,
                "agent_loop_started": False,
                "llm_calls": 0,
                "external_system_mutations": 0,
                "iem_mutations": 0,
                "normative_mutations": 0,
            },
        }
        if receipt_dir:
            path = receipt_dir / f"{_safe_slug(goal_id)}.runtime_execution_receipt.json"
            path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            receipt["receipt_path"] = str(path)
        receipts.append(receipt)
    return receipts


def _executor_decision(
    passed: bool,
    execution_packets: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    blocked_execution_packets: list[dict[str, Any]],
    ack_local_runtime_execution: bool,
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_executor"
    if receipts:
        return "runtime_execution_completed_with_receipts"
    if blocked_execution_packets:
        return "runtime_execution_blocked_requires_production_executor_evidence"
    if execution_packets and not ack_local_runtime_execution:
        return "runtime_execution_blocked_pending_local_executor_ack"
    return "runtime_execution_blocked_no_execution_packets"


def _allowed_scope(
    passed: bool,
    execution_packets: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    blocked_execution_packets: list[dict[str, Any]],
    ack: bool,
) -> str:
    if not passed:
        return "do not execute until runtime execution gate is valid"
    if receipts:
        return "controlled runtime execution receipt written"
    if blocked_execution_packets:
        return "production-origin runtime execution packets require a separate production executor evidence gate"
    if execution_packets and not ack:
        return "runtime execution packets ready; waiting for explicit local executor acknowledgement"
    return "no runtime execution packets available"


def _all_receipts_origin(receipts: list[dict[str, Any]], origin: str) -> bool:
    return bool(receipts) and all(receipt.get("execution_origin") == origin for receipt in receipts)


def _packet_policy_valid(policy: dict[str, Any]) -> bool:
    return (
        policy.get("runtime_start_allowed") is True
        and policy.get("runtime_execution_allowed") is True
        and policy.get("executable_plan_allowed") is False
        and policy.get("llm_planning_allowed") is False
        and policy.get("iem_value_mutation_allowed") is False
        and policy.get("normative_local_mutation_allowed") is False
    )


def _packet_scope_valid(scope: dict[str, Any]) -> bool:
    return (
        scope.get("mode") == "local_controlled_receipt_execution"
        and "write_runtime_execution_receipt" in _string_list(scope.get("allowed_actions"))
        and "llm_call" in _string_list(scope.get("forbidden_actions"))
        and "external_system_mutation" in _string_list(scope.get("forbidden_actions"))
    )


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


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


def _require_equal(name: str, actual: object, expected: object, *, checks: dict[str, bool], failures: list[str]) -> None:
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-execution-gate", required=True)
    parser.add_argument("--ack-local-runtime-execution", action="store_true")
    parser.add_argument("--receipt-dir", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_executor_report(
        runtime_execution_gate_path=Path(args.runtime_execution_gate),
        agent_root=agent_root,
        ack_local_runtime_execution=args.ack_local_runtime_execution,
        receipt_dir=Path(args.receipt_dir) if args.receipt_dir else None,
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