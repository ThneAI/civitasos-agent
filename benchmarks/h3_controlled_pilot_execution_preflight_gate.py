"""Validate one-time H.3 authorization before any controlled runner dispatch."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_evidence import (
    artifact_ref,
    object_value,
    objects_value,
    read_json_object,
    resolve_under_root,
    sha256_file,
    write_json_object,
)
from benchmarks.h3_controlled_pilot_receipts import (
    AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
)
from benchmarks.h3_controlled_pilot_authorization_decision_gate import (
    BOUNDARY as AUTHORIZATION_BOUNDARY,
)
from benchmarks.h3_controlled_pilot_authorization_decision_gate import (
    PACKET_SCHEMA_VERSION,
    RECONCILIATION_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-controlled-pilot-execution-preflight-gate:v1"
ROLLBACK_SCHEMA_VERSION = "h3-controlled-pilot-rollback-checkpoint:v1"
BOUNDARY = {
    "artifact_only": True,
    "execution_preflight_validation_allowed": True,
    "controlled_runner_input_ready": False,
    "controlled_pilot_execution_allowed": False,
    "goal_emission_allowed": False,
    "runtime_execution_allowed": False,
    "llm_planning_allowed": False,
    "agent_dispatch_allowed": False,
    "external_side_effect_allowed": False,
    "iem_mutation_allowed": False,
    "relation_mutation_allowed": False,
    "authorization_mutation_allowed": False,
    "normative_local_mutation_allowed": False,
    "production_transition_allowed": False,
}


def build_execution_preflight(
    *,
    authorization_reconciliation_path: Path,
    authorization_receipt_id: str,
    output_path: Path,
    agent_root: Path,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    reconciliation_path = resolve_under_root(authorization_reconciliation_path, agent_root)
    output = resolve_under_root(output_path, agent_root)
    now = _as_utc(current_time or datetime.now(timezone.utc))
    failures: list[str] = []
    checks: dict[str, bool] = {}

    reconciliation = read_json_object(
        reconciliation_path,
        failures,
        "authorization reconciliation",
    )
    profile = str(object_value(reconciliation).get("validation_profile") or "qualification")
    receipt = _validate_reconciliation(
        reconciliation,
        receipt_id=authorization_receipt_id,
        failures=failures,
        checks=checks,
    )
    packet_path = _source_packet_path(reconciliation)
    packet = read_json_object(packet_path, failures, "authorization decision packet")
    _validate_packet_binding(
        packet,
        packet_path=packet_path,
        reconciliation=reconciliation,
        receipt=receipt,
        failures=failures,
        checks=checks,
    )
    _validate_receipt_window(
        receipt,
        profile=profile,
        current_time=now,
        failures=failures,
        checks=checks,
    )
    controls = object_value(receipt.get("controls"))
    _require_equal(
        checks,
        failures,
        "preflight_output_binding",
        _resolve_ref(controls.get("preflight_ref"), agent_root),
        output,
    )
    rollback_path = _resolve_ref(controls.get("rollback_checkpoint_ref"), agent_root)
    post_run_receipt_path = _resolve_ref(
        controls.get("post_run_receipt_sink_ref"),
        agent_root,
    )
    _require(
        checks,
        failures,
        "rollback_checkpoint_path_valid",
        rollback_path is not None,
    )
    _require(
        checks,
        failures,
        "post_run_receipt_sink_path_valid",
        post_run_receipt_path is not None,
    )
    _require(
        checks,
        failures,
        "post_run_receipt_not_preexisting",
        bool(post_run_receipt_path is not None and not post_run_receipt_path.exists()),
    )
    _require(
        checks,
        failures,
        "operator_kill_switch_valid",
        str(controls.get("kill_switch_ref") or "").startswith("operator://")
        and str(controls.get("kill_switch_ref") or "").endswith("/stop"),
    )

    structural_passed = not failures and all(checks.values())
    rollback_checkpoint = None
    if structural_passed and rollback_path is not None:
        rollback_checkpoint = _write_rollback_checkpoint(
            path=rollback_path,
            receipt=receipt,
            authorization_reconciliation_path=reconciliation_path,
            created_at=now,
            profile=profile,
        )
        _require(
            checks,
            failures,
            "rollback_checkpoint_written",
            rollback_path.is_file(),
        )
        _require_equal(
            checks,
            failures,
            "rollback_checkpoint_schema",
            rollback_checkpoint.get("schema_version"),
            ROLLBACK_SCHEMA_VERSION,
        )

    passed = not failures and all(checks.values())
    boundary = dict(BOUNDARY)
    boundary["controlled_runner_input_ready"] = passed
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": now.isoformat(),
        "validation_profile": object_value(reconciliation).get("validation_profile"),
        "development_only": object_value(reconciliation).get("development_only"),
        "valid_for_qualification": object_value(reconciliation).get(
            "valid_for_qualification"
        ),
        "source_authorization_reconciliation": (
            artifact_ref(reconciliation_path)
            if reconciliation_path.is_file()
            else None
        ),
        "authorization_receipt": receipt if passed else None,
        "rollback_checkpoint": (
            artifact_ref(rollback_path)
            if passed and rollback_path is not None and rollback_path.is_file()
            else None
        ),
        "post_run_receipt_sink": (
            str(post_run_receipt_path) if post_run_receipt_path is not None else None
        ),
        "readiness": {
            "execution_preflight_passed": passed,
            "controlled_runner_input_ready": passed,
            "controlled_pilot_execution_ready": False,
            "decision": (
                (
                    "h3_development_controlled_runner_input_ready"
                    if profile == "development"
                    else "h3_qualification_controlled_runner_input_ready"
                )
                if passed
                else "blocked_h3_controlled_pilot_execution_preflight"
            ),
            "next_action": (
                "A8 may consume the single-use receipt exactly once and must write a post-run receipt"
                if passed
                else "repair authorization, expiry, or control evidence"
            ),
        },
        "boundary": boundary,
        "non_claims": _non_claims(profile=profile),
    }
    write_json_object(output, report)
    return report


def _validate_reconciliation(
    value: dict[str, Any] | None,
    *,
    receipt_id: str,
    failures: list[str],
    checks: dict[str, bool],
) -> dict[str, Any]:
    if value is None:
        _require(checks, failures, "authorization_reconciliation_present", False)
        return {}
    checks["authorization_reconciliation_present"] = True
    _require_equal(
        checks,
        failures,
        "authorization_reconciliation_schema",
        value.get("schema_version"),
        RECONCILIATION_SCHEMA_VERSION,
    )
    _require(checks, failures, "authorization_reconciliation_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "authorization_reconciliation_boundary",
        value.get("boundary"),
        AUTHORIZATION_BOUNDARY,
    )
    profile = str(value.get("validation_profile") or "qualification")
    _require(
        checks,
        failures,
        "authorization_reconciliation_profile_supported",
        profile in {"development", "qualification"},
    )
    _require_equal(
        checks,
        failures,
        "authorization_reconciliation_development_flag",
        value.get("development_only"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "authorization_reconciliation_qualification_flag",
        value.get("valid_for_qualification"),
        profile == "qualification",
    )
    readiness = object_value(value.get("readiness"))
    _require(
        checks,
        failures,
        "authorization_receipts_ready",
        readiness.get("one_time_authorization_receipts_ready") is True
        and readiness.get("controlled_pilot_execution_preflight_input_ready") is True
        and readiness.get("controlled_pilot_execution_ready") is False,
    )
    receipts = [
        item
        for item in objects_value(value.get("authorization_receipts"))
        if item.get("authorization_receipt_id") == receipt_id
    ]
    _require(
        checks,
        failures,
        "authorization_receipt_unique",
        len(receipts) == 1,
    )
    return receipts[0] if len(receipts) == 1 else {}


def _validate_packet_binding(
    value: dict[str, Any] | None,
    *,
    packet_path: Path,
    reconciliation: dict[str, Any] | None,
    receipt: dict[str, Any],
    failures: list[str],
    checks: dict[str, bool],
) -> None:
    if value is None:
        _require(checks, failures, "authorization_decision_packet_present", False)
        return
    checks["authorization_decision_packet_present"] = True
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_schema",
        value.get("schema_version"),
        PACKET_SCHEMA_VERSION,
    )
    source_ref = object_value(object_value(reconciliation).get("source_decision_packet"))
    _require_equal(
        checks,
        failures,
        "authorization_decision_packet_hash",
        sha256_file(packet_path) if packet_path.is_file() else None,
        source_ref.get("sha256"),
    )
    _require_equal(
        checks,
        failures,
        "authorization_receipt_packet_hash",
        receipt.get("decision_packet_sha256"),
        source_ref.get("sha256"),
    )
    matching = [
        item
        for item in objects_value(value.get("decisions"))
        if item.get("request_id") == receipt.get("request_id")
        and item.get("decision") == "authorize_once"
    ]
    _require(
        checks,
        failures,
        "authorization_decision_matches_receipt",
        len(matching) == 1
        and matching[0].get("request_sha256") == receipt.get("request_sha256"),
    )


def _validate_receipt_window(
    receipt: dict[str, Any],
    *,
    profile: str,
    current_time: datetime,
    failures: list[str],
    checks: dict[str, bool],
) -> None:
    valid_from = _timestamp(receipt.get("valid_from"))
    valid_until = _timestamp(receipt.get("valid_until"))
    scope = object_value(receipt.get("authorized_scope"))
    _require(
        checks,
        failures,
        "authorization_receipt_schema",
        receipt.get("schema_version") == AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
    )
    _require(
        checks,
        failures,
        "authorization_receipt_single_use_unconsumed",
        receipt.get("single_use") is True
        and receipt.get("consumed") is False
        and receipt.get("controlled_pilot_execution_allowed") is False,
    )
    _require(
        checks,
        failures,
        "authorization_receipt_currently_valid",
        bool(
            valid_from is not None
            and valid_until is not None
            and valid_from <= current_time < valid_until
        ),
    )
    scope_valid = _authorization_scope_valid(scope, profile=profile)
    _require(checks, failures, "authorization_scope_profile_valid", scope_valid)
    _require(
        checks,
        failures,
        "authorization_roles_present",
        all(
            bool(str(receipt.get(field) or "").strip())
            for field in ("operator_id", "monitoring_owner_id", "audit_owner_id")
        ),
    )


def _write_rollback_checkpoint(
    *,
    path: Path,
    receipt: dict[str, Any],
    authorization_reconciliation_path: Path,
    created_at: datetime,
    profile: str,
) -> dict[str, Any]:
    checkpoint = {
        "schema_version": ROLLBACK_SCHEMA_VERSION,
        "state": "baseline_captured_before_controlled_runner",
        "created_at": created_at.isoformat(),
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "source_authorization_reconciliation": artifact_ref(
            authorization_reconciliation_path
        ),
        "baseline": {
            "controlled_runner_started": False,
            "production_state_mutated": False,
            "iem_state_mutated": False,
            "relation_state_mutated": False,
            "authorization_state_mutated": False,
            "normative_state_mutated": False,
        },
        "rollback_actions": [
            f"stop the {profile} controlled runner through the operator kill switch",
            "discard transient pilot outputs while retaining audit evidence",
            "restore the preflight baseline without changing production state",
        ],
    }
    write_json_object(path, checkpoint)
    return checkpoint


def _authorization_scope_valid(
    scope: dict[str, Any],
    *,
    profile: str,
) -> bool:
    if profile == "development":
        limits = {
            "environment": "development_local_controlled_only",
            "max_tasks": 1,
            "max_agents": 3,
            "max_duration_seconds": 1800,
        }
    elif profile == "qualification":
        limits = {
            "environment": "controlled_pilot_only",
            "max_tasks": 3,
            "max_agents": 3,
            "max_duration_seconds": 3600,
        }
    else:
        return False
    return (
        scope.get("environment") == limits["environment"]
        and 1 <= _integer(scope.get("max_tasks")) <= limits["max_tasks"]
        and 1 <= _integer(scope.get("max_agents")) <= limits["max_agents"]
        and 1
        <= _integer(scope.get("max_duration_seconds"))
        <= limits["max_duration_seconds"]
        and scope.get("production_use_allowed") is False
        and scope.get("automatic_rollout_allowed") is False
    )


def _non_claims(*, profile: str) -> list[str]:
    claims = [
        "preflight_is_not_a_runner_execution_receipt",
        "preflight_does_not_consume_the_single_use_authorization",
        "preflight_does_not_dispatch_agents_or_start_runtime",
        "preflight_does_not_create_external_side_effects",
        "preflight_does_not_mutate_iem_relation_authorization_or_normative_state",
        "preflight_does_not_authorize_production_transition",
    ]
    claims.append(
        "development_preflight_is_not_qualification_evidence"
        if profile == "development"
        else "qualification_preflight_does_not_itself_execute_the_controlled_pilot"
    )
    return claims


def _source_packet_path(value: dict[str, Any] | None) -> Path:
    raw = object_value(object_value(value).get("source_decision_packet")).get("path")
    return Path(str(raw or "/missing-authorization-decision-packet"))


def _resolve_ref(value: Any, root: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return value.astimezone(timezone.utc)

def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    condition: bool,
) -> None:
    checks[name] = bool(condition)
    if not condition:
        failures.append(name)


def _require_equal(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    actual: Any,
    expected: Any,
) -> None:
    condition = actual == expected
    checks[name] = condition
    if not condition:
        failures.append(f"{name}: expected {expected!r}, got {actual!r}")

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-reconciliation", type=Path, required=True)
    parser.add_argument("--authorization-receipt-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    report = build_execution_preflight(
        authorization_reconciliation_path=args.authorization_reconciliation,
        authorization_receipt_id=args.authorization_receipt_id,
        output_path=args.output,
        agent_root=agent_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
