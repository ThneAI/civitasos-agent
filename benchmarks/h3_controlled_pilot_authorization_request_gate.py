"""Build review-only H.3 controlled-pilot authorization request artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
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
from benchmarks.h3_bounded_plan_challenge_review_gate import (
    RECONCILIATION_SCHEMA_VERSION,
)
from benchmarks.h3_bounded_plan_draft_gate import (
    GATE_BOUNDARY as BOUNDED_PLAN_BOUNDARY,
)
from benchmarks.h3_bounded_plan_draft_gate import (
    SCHEMA_VERSION as BOUNDED_PLAN_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-controlled-pilot-authorization-request-gate:v1"
BOUNDARY = {
    "artifact_only": True,
    "authorization_request_generation_allowed": True,
    "authorization_granted": False,
    "controlled_pilot_execution_allowed": False,
    "goal_emission_allowed": False,
    "executable_plan_allowed": False,
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


def build_authorization_request_gate(
    *,
    bounded_plan_report_path: Path,
    challenge_reconciliation_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    bounded_path = resolve_under_root(bounded_plan_report_path, agent_root)
    reconciliation_path = resolve_under_root(challenge_reconciliation_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    bounded = read_json_object(bounded_path, failures, "bounded plan report")
    reconciliation = read_json_object(
        reconciliation_path,
        failures,
        "challenge reconciliation",
    )
    drafts = _validate_bounded_plan(
        bounded,
        failures=failures,
        checks=checks,
    )
    profile, approved_ids = _validate_reconciliation(
        reconciliation,
        bounded_path=bounded_path,
        failures=failures,
        checks=checks,
    )
    draft_by_id = {str(draft.get("draft_id") or ""): draft for draft in drafts}
    _require(
        checks,
        failures,
        "approved_drafts_exist",
        bool(approved_ids) and set(approved_ids).issubset(draft_by_id),
    )

    requests = []
    if not failures and all(checks.values()):
        requests = [
            _build_request(
                draft=draft_by_id[draft_id],
                profile=profile,
                reconciliation_path=reconciliation_path,
            )
            for draft_id in sorted(approved_ids)
        ]
    _require(
        checks,
        failures,
        "one_request_per_approved_draft",
        bool(requests) and len(requests) == len(approved_ids),
    )

    passed = not failures and all(checks.values())
    development = profile == "development"
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "validation_profile": profile,
        "development_only": development,
        "valid_for_qualification": not development,
        "source_bounded_plan_report": (
            artifact_ref(bounded_path) if bounded_path.is_file() else None
        ),
        "source_challenge_reconciliation": (
            artifact_ref(reconciliation_path)
            if reconciliation_path.is_file()
            else None
        ),
        "authorization_request_surface": {
            "mode": (
                "development_review_only"
                if development
                else "qualification_review_only"
            ),
            "request_count": len(requests),
            "requests": requests,
        },
        "readiness": {
            "authorization_requests_ready_for_review": passed,
            "authorization_granted": False,
            "controlled_pilot_execution_ready": False,
            "decision": (
                (
                    "h3_development_authorization_requests_ready_for_review"
                    if development
                    else "h3_controlled_pilot_authorization_requests_ready_for_review"
                )
                if passed
                else "blocked_h3_controlled_pilot_authorization_request_gate"
            ),
            "next_action": (
                "run a separate one-time authorization decision gate; do not execute"
                if passed
                else "repair bounded plan or challenge reconciliation evidence"
            ),
        },
        "boundary": dict(BOUNDARY),
        "non_claims": _non_claims(development=development),
    }


def _validate_bounded_plan(
    value: dict[str, Any] | None,
    *,
    failures: list[str],
    checks: dict[str, bool],
) -> list[dict[str, Any]]:
    if value is None:
        _require(checks, failures, "bounded_plan_present", False)
        return []
    checks["bounded_plan_present"] = True
    _require_equal(
        checks,
        failures,
        "bounded_plan_schema",
        value.get("schema_version"),
        BOUNDED_PLAN_SCHEMA_VERSION,
    )
    _require(checks, failures, "bounded_plan_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "bounded_plan_boundary",
        value.get("boundary"),
        BOUNDED_PLAN_BOUNDARY,
    )
    drafts = objects_value(object_value(value.get("draft_surface")).get("drafts"))
    _require(checks, failures, "bounded_plan_drafts_present", bool(drafts))
    _require(
        checks,
        failures,
        "bounded_plan_drafts_non_executable",
        all(
            draft.get("state") == "bounded_plan_draft_review_required"
            and object_value(draft.get("execution_policy")).get("draft_only") is True
            and not any(
                setting
                for name, setting in object_value(
                    draft.get("execution_policy")
                ).items()
                if name != "draft_only"
            )
            for draft in drafts
        ),
    )
    return drafts


def _validate_reconciliation(
    value: dict[str, Any] | None,
    *,
    bounded_path: Path,
    failures: list[str],
    checks: dict[str, bool],
) -> tuple[str, list[str]]:
    if value is None:
        _require(checks, failures, "challenge_reconciliation_present", False)
        return "qualification", []
    checks["challenge_reconciliation_present"] = True
    _require_equal(
        checks,
        failures,
        "challenge_reconciliation_schema",
        value.get("schema_version"),
        RECONCILIATION_SCHEMA_VERSION,
    )
    _require(
        checks,
        failures,
        "challenge_reconciliation_passed",
        value.get("passed") is True,
    )
    _require_equal(
        checks,
        failures,
        "challenge_reconciliation_source_binding",
        value.get("source_bounded_plan_report"),
        artifact_ref(bounded_path) if bounded_path.is_file() else None,
    )
    profile = str(value.get("validation_profile") or "qualification")
    _require(
        checks,
        failures,
        "challenge_reconciliation_profile_supported",
        profile in {"qualification", "development"},
    )
    readiness = object_value(value.get("readiness"))
    if profile == "development":
        profile_ready = (
            value.get("development_only") is True
            and value.get("valid_for_qualification") is False
            and readiness.get("development_authorization_request_input_ready")
            is True
            and readiness.get("controlled_pilot_authorization_request_ready")
            is False
        )
    else:
        profile_ready = (
            value.get("development_only", False) is False
            and value.get("valid_for_qualification", True) is True
            and readiness.get("controlled_pilot_authorization_request_ready")
            is True
        )
    _require(
        checks,
        failures,
        "challenge_reconciliation_profile_ready",
        profile_ready,
    )
    boundary = object_value(value.get("boundary"))
    _require(
        checks,
        failures,
        "challenge_reconciliation_execution_blocked",
        boundary.get("controlled_pilot_execution_allowed") is False
        and boundary.get("goal_emission_allowed") is False
        and boundary.get("runtime_execution_allowed") is False
        and boundary.get("agent_dispatch_allowed") is False
        and boundary.get("authorization_mutation_allowed") is False
        and boundary.get("production_transition_allowed") is False,
    )
    approved = [
        str(item)
        for item in object_value(value.get("reconciliation")).get(
            "approved_draft_ids",
            [],
        )
    ]
    _require(
        checks,
        failures,
        "approved_draft_ids_unique",
        all(approved) and len(approved) == len(set(approved)),
    )
    return profile, approved


def _build_request(
    *,
    draft: dict[str, Any],
    profile: str,
    reconciliation_path: Path,
) -> dict[str, Any]:
    development = profile == "development"
    source_scope = object_value(draft.get("bounded_scope"))
    requested_scope = {
        "environment": (
            "development_local_controlled_only"
            if development
            else "controlled_pilot_only"
        ),
        "max_tasks": (
            1 if development else _integer(source_scope.get("max_tasks_per_trial"))
        ),
        "max_agents": _integer(source_scope.get("max_agents_per_trial")),
        "max_duration_seconds": (
            min(1800, _integer(source_scope.get("max_trial_duration_seconds")))
            if development
            else _integer(source_scope.get("max_trial_duration_seconds"))
        ),
        "production_use_allowed": False,
        "automatic_rollout_allowed": False,
    }
    seed = {
        "draft_id": draft["draft_id"],
        "draft_sha256": _canonical_sha256(draft),
        "challenge_reconciliation_sha256": sha256_file(reconciliation_path),
        "validation_profile": profile,
        "requested_scope": requested_scope,
    }
    return {
        "request_id": f"h3-pilot-request:{_canonical_sha256(seed)[:20]}",
        "state": (
            "development_authorization_request_review_required"
            if development
            else "controlled_pilot_authorization_request_review_required"
        ),
        "validation_profile": profile,
        "development_only": development,
        "valid_for_qualification": not development,
        "source_binding": {
            "draft_id": draft["draft_id"],
            "draft_sha256": _canonical_sha256(draft),
            "challenge_reconciliation_sha256": sha256_file(reconciliation_path),
            "proposal_kind": draft["proposal_kind"],
            "evidence_refs": object_value(draft.get("source_binding")).get(
                "evidence_refs",
                [],
            ),
        },
        "requested_scope": requested_scope,
        "requested_controls": {
            "one_time_authorization_required": True,
            "authorization_expiry_required": True,
            "named_operator_required": True,
            "named_monitoring_owner_required": True,
            "named_audit_owner_required": True,
            "kill_switch_required": True,
            "rollback_checkpoint_required": True,
            "preflight_required": True,
            "post_run_receipt_required": True,
            "automatic_approval_allowed": False,
        },
        "stop_conditions": draft.get("stop_conditions", []),
        "rollback_plan": draft.get("rollback_plan", []),
        "success_metrics": draft.get("success_metrics", []),
        "authorization_state": {
            "authorization_granted": False,
            "authorization_receipt_present": False,
            "execution_allowed": False,
        },
    }

def _non_claims(*, development: bool) -> list[str]:
    claims = [
        "request_is_not_an_authorization_receipt",
        "request_does_not_emit_goals_or_create_executable_plans",
        "request_does_not_dispatch_agents_or_start_runtime",
        "request_does_not_create_external_side_effects",
        "request_does_not_mutate_iem_relation_authorization_or_normative_state",
        "request_does_not_authorize_production_transition",
    ]
    claims.append(
        "development_request_is_not_qualification_evidence"
        if development
        else "qualification_request_does_not_grant_execution_authorization"
    )
    return claims

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
    parser.add_argument("--bounded-plan-report", type=Path, required=True)
    parser.add_argument("--challenge-reconciliation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    report = build_authorization_request_gate(
        bounded_plan_report_path=args.bounded_plan_report,
        challenge_reconciliation_path=args.challenge_reconciliation,
        agent_root=agent_root,
    )
    output = resolve_under_root(args.output, agent_root)
    write_json_object(output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
