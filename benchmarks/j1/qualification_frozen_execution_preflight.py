"""Frozen-stack execution preflight contract for J1-D qualification."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-frozen-stack-execution-plan:v1"
PREFLIGHT_SCHEMA = "j1-qualification-frozen-stack-execution-preflight:v1"
MAX_TTL_SECONDS = 1800
SOURCE_NAMES = {
    "amended_protocol",
    "amended_design",
    "reviewed_verifier",
    "rebound_roster",
    "rebound_assignment",
    "signed_advice_manifest",
    "signed_advice_gate",
    "reviewed_infrastructure",
    "infrastructure_promotion_gate",
    "infrastructure_activation",
    "infrastructure_activation_gate",
    "provider_admission_receipt",
    "provider_admission_gate",
    "frozen_real_evaluator",
    "frozen_post_run_contract",
    "frozen_operator_closeout_contract",
    "frozen_evaluation_closeout_bundle",
    "evaluation_closeout_promotion_gate",
}
PLAN_BOUNDARY = {
    "execution_preflight_only": True,
    "single_use_authorization_issued": False,
    "single_use_authorization_consumed": False,
    "participant_container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}


def build_execution_plan(
    *,
    run_id: str,
    created_at: str,
    ttl_seconds: int,
    source_artifacts: dict[str, dict[str, str]],
    execution_scope: dict[str, Any],
    cost_acknowledgement: dict[str, Any],
    controls: dict[str, Any],
    implementation: dict[str, str],
    superseded_execution_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "run_id": run_id,
        "status": "owner_authorization_required",
        "created_at": created_at,
        "ttl_seconds": ttl_seconds,
        "source_artifacts": copy.deepcopy(source_artifacts),
        "execution_scope": copy.deepcopy(execution_scope),
        "cost_acknowledgement": copy.deepcopy(cost_acknowledgement),
        "controls": copy.deepcopy(controls),
        "superseded_execution_evidence": copy.deepcopy(
            superseded_execution_evidence or _base_supersession()
        ),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(PLAN_BOUNDARY),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_execution_plan(value)
    if failures:
        raise ValueError(f"frozen-stack execution plan invalid: {failures}")
    return value


def validate_execution_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(plan)
        == {
            "schema_version",
            "run_id",
            "status",
            "created_at",
            "ttl_seconds",
            "source_artifacts",
            "execution_scope",
            "cost_acknowledgement",
            "controls",
            "superseded_execution_evidence",
            "implementation",
            "execution_boundary",
            "plan_sha256",
        },
        "frozen_execution_plan_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == "owner_authorization_required"
        and _text(plan.get("run_id"))
        and _rfc3339(plan.get("created_at"))
        and plan.get("ttl_seconds") == MAX_TTL_SECONDS,
        "frozen_execution_plan_identity_invalid",
        failures,
    )
    sources = _object(plan.get("source_artifacts"))
    _require(
        set(sources) == SOURCE_NAMES
        and all(_valid_artifact_ref(item) for item in sources.values()),
        "frozen_execution_source_inventory_invalid",
        failures,
    )
    scope = _object(plan.get("execution_scope"))
    _require(
        scope
        == {
            "provider_id": "openai_compatible",
            "provider_host": "api.deepseek.com",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "matched_pair_count": 20,
            "task_count_per_participant": 8,
            "authorized_task_executions": 320,
            "same_stack_for_both_cohorts": True,
            "cohort_source": "reviewed_rebound_assignment",
            "outcome_evaluator_status": "operator_reviewed_frozen",
            "post_run_contract_status": "operator_reviewed_frozen",
            "operator_closeout_contract_status": "operator_reviewed_frozen",
        },
        "frozen_execution_scope_invalid",
        failures,
    )
    cost = _object(plan.get("cost_acknowledgement"))
    _require(
        cost
        == {
            "currency": "usd_microunit",
            "authorized_provider_calls": 320,
            "aggregate_reserved_tokens": 800000,
            "aggregate_reserved_cost_microunits": 487360,
            "aggregate_protocol_max_cost_microunits": 4000000,
            "reservation_required_before_each_call": True,
            "actual_usage_reconciliation_required": True,
            "budget_overrun_fail_stop_required": True,
        },
        "frozen_execution_cost_invalid",
        failures,
    )
    controls = _object(plan.get("controls"))
    expected_true = {
        "single_use",
        "atomic_claim_create_exclusive",
        "claimed_failure_requires_new_authorization",
        "unclaimed_expiry_requires_new_authorization",
        "container_state_recheck_before_claim",
        "provider_admission_recheck_before_claim",
        "post_run_receipt_required",
        "operator_closeout_required",
    }
    expected_controls = expected_true | {
        "backend_fact_append_allowed",
        "ledger_append_allowed",
        "effectiveness_claim_before_closeout_allowed",
        "execution_root",
        "authorization_output_root",
        "authorization_consumption_path",
        "post_run_output_root",
    }
    _require(
        set(controls) == expected_controls
        and all(controls.get(field) is True for field in expected_true)
        and controls.get("backend_fact_append_allowed") is False
        and controls.get("ledger_append_allowed") is False
        and controls.get("effectiveness_claim_before_closeout_allowed") is False
        and all(
            _absolute_path(controls.get(field))
            for field in (
                "execution_root",
                "authorization_output_root",
                "authorization_consumption_path",
                "post_run_output_root",
            )
        ),
        "frozen_execution_controls_invalid",
        failures,
    )
    _require(
        _valid_supersession(plan.get("superseded_execution_evidence")),
        "frozen_execution_supersession_invalid",
        failures,
    )
    implementation = _object(plan.get("implementation"))
    _require(
        set(implementation)
        == {"source_revision", "domain_source_sha256", "operation_source_sha256"}
        and _git_revision(implementation.get("source_revision"))
        and _sha256(implementation.get("domain_source_sha256"))
        and _sha256(implementation.get("operation_source_sha256")),
        "frozen_execution_implementation_invalid",
        failures,
    )
    _require(
        plan.get("execution_boundary") == PLAN_BOUNDARY,
        "frozen_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "frozen_execution_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_preflight(
    *,
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    created_at: str,
    inventory_snapshot: dict[str, Any],
) -> dict[str, Any]:
    failures = validate_execution_plan(plan)
    if failures:
        raise ValueError(f"frozen-stack execution plan invalid: {failures}")
    statement = owner_authorization_statement(
        plan_artifact_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        plan=plan,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "run_id": plan["run_id"],
        "passed": True,
        "failure_reasons": [],
        "state": "frozen_stack_execution_preflight_passed_owner_authorization_required",
        "created_at": created_at,
        "plan": {
            "path": plan_path,
            "sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "canonical_sha256": plan["plan_sha256"],
        },
        "inventory_snapshot": copy.deepcopy(inventory_snapshot),
        "checks": {
            "active_amended_stack_bound": True,
            "rebound_roster_assignment_bound": True,
            "signed_treatment_advice_bound": True,
            "forty_stopped_replacement_containers_verified": True,
            "live_provider_admission_bound": True,
            "frozen_evaluator_post_run_closeout_bound": True,
            "exact_320_task_scope_bound": True,
            "cost_and_token_ceilings_bound": True,
            "superseded_v2_authorization_rejected": True,
            "expired_unclaimed_v3_authorization_bound": _is_renewal(plan),
            "no_execution_or_external_write_performed": True,
        },
        "owner_authorization": {
            "required": True,
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "execution_preflight_passed": True,
            "single_use_authorization_issued": False,
            "single_use_authorization_consumed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(PLAN_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    failures = validate_preflight(
        value,
        plan_path=plan_path,
        plan_bytes=plan_bytes,
        plan=plan,
        expected_inventory_snapshot=inventory_snapshot,
    )
    if failures:
        raise ValueError(f"frozen-stack execution preflight invalid: {failures}")
    return value


def validate_preflight(
    value: Any,
    *,
    plan_path: str,
    plan_bytes: bytes,
    plan: dict[str, Any],
    expected_inventory_snapshot: dict[str, Any],
) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    failures = validate_execution_plan(plan)
    expected_statement = owner_authorization_statement(
        plan_artifact_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        plan=plan,
    )
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("run_id") == plan.get("run_id")
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("state")
        == "frozen_stack_execution_preflight_passed_owner_authorization_required"
        and _rfc3339(preflight.get("created_at")),
        "frozen_execution_preflight_identity_invalid",
        failures,
    )
    _require(
        preflight.get("plan")
        == {
            "path": plan_path,
            "sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "canonical_sha256": plan.get("plan_sha256"),
        },
        "frozen_execution_preflight_plan_binding_invalid",
        failures,
    )
    _require(
        preflight.get("inventory_snapshot") == expected_inventory_snapshot,
        "frozen_execution_preflight_inventory_invalid",
        failures,
    )
    expected_checks = {
        "active_amended_stack_bound": True,
        "rebound_roster_assignment_bound": True,
        "signed_treatment_advice_bound": True,
        "forty_stopped_replacement_containers_verified": True,
        "live_provider_admission_bound": True,
        "frozen_evaluator_post_run_closeout_bound": True,
        "exact_320_task_scope_bound": True,
        "cost_and_token_ceilings_bound": True,
        "superseded_v2_authorization_rejected": True,
        "expired_unclaimed_v3_authorization_bound": _is_renewal(plan),
        "no_execution_or_external_write_performed": True,
    }
    legacy_checks = {
        key: item
        for key, item in expected_checks.items()
        if key != "expired_unclaimed_v3_authorization_bound"
    }
    _require(
        preflight.get("checks") == expected_checks
        or (not _is_renewal(plan) and preflight.get("checks") == legacy_checks),
        "frozen_execution_preflight_checks_invalid",
        failures,
    )
    _require(
        preflight.get("owner_authorization")
        == {
            "required": True,
            "required_exact_statement": expected_statement,
            "statement_sha256": hashlib.sha256(expected_statement.encode()).hexdigest(),
        },
        "frozen_execution_preflight_owner_request_invalid",
        failures,
    )
    _require(
        preflight.get("readiness")
        == {
            "execution_preflight_passed": True,
            "single_use_authorization_issued": False,
            "single_use_authorization_consumed": False,
            "controlled_experiment_execution_ready": False,
        }
        and preflight.get("execution_boundary") == PLAN_BOUNDARY,
        "frozen_execution_preflight_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    _require(
        preflight.get("preflight_sha256") == canonical_sha256(body),
        "frozen_execution_preflight_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def owner_authorization_statement(
    *, plan_artifact_sha256: str, plan: dict[str, Any]
) -> str:
    sources = plan["source_artifacts"]
    scope = plan["execution_scope"]
    cost = plan["cost_acknowledgement"]
    supersession = plan["superseded_execution_evidence"]
    renewal = (
        " This renewal supersedes expired, unclaimed, non-reusable authorization "
        f"{supersession['prior_v3_authorization']['authorization_id']} raw SHA-256 "
        f"{supersession['prior_v3_authorization']['sha256']} and Gate canonical "
        f"SHA-256 {supersession['prior_v3_gate']['canonical_sha256']}."
        if _is_renewal(plan)
        else ""
    )
    return (
        f"I authorize issuance of exactly one 1800-second single-use J1-D "
        f"qualification execution authorization for run {plan['run_id']} from plan "
        f"artifact raw SHA-256 {plan_artifact_sha256}, canonical SHA-256 "
        f"{plan['plan_sha256']}, binding amended protocol "
        f"{sources['amended_protocol']['canonical_sha256']}, amended design "
        f"{sources['amended_design']['canonical_sha256']}, rebound assignment "
        f"{sources['rebound_assignment']['canonical_sha256']}, infrastructure "
        f"activation {sources['infrastructure_activation']['canonical_sha256']}, "
        f"provider-admission receipt "
        f"{sources['provider_admission_receipt']['canonical_sha256']}, and frozen "
        f"evaluation/closeout bundle "
        f"{sources['frozen_evaluation_closeout_bundle']['canonical_sha256']}. The "
        f"scope is exactly {scope['participant_count']} participants, "
        f"{scope['matched_pair_count']} pairs, and "
        f"{scope['authorized_task_executions']} provider calls using "
        f"{scope['provider_id']} / {scope['model_id']} at temperature 0. I "
        f"acknowledge reservation of {cost['aggregate_reserved_tokens']} tokens and "
        f"{cost['aggregate_reserved_cost_microunits']} USD microunits, an absolute "
        f"protocol ceiling of {cost['aggregate_protocol_max_cost_microunits']} USD "
        "microunits, atomic single-use claim before execution, and that any claimed "
        f"failure requires a new authorization.{renewal} This authorization does not "
        "itself "
        "start a container or execute a provider, model, Agent, or experiment; "
        "Backend Fact and Ledger append remain prohibited, and no effectiveness "
        "claim is authorized before signed closeout."
    )


def _base_supersession() -> dict[str, Any]:
    return {
        "prior_v2_preflight_reusable": False,
        "prior_v2_authorization_reusable": False,
        "reason": "active_stack_and_frozen_evaluator_binding_changed",
    }


def _valid_supersession(value: Any) -> bool:
    supersession = _object(value)
    if supersession == _base_supersession():
        return True
    return (
        set(supersession)
        == {
            *set(_base_supersession()),
            "prior_v3_authorization",
            "prior_v3_gate",
            "prior_v3_authorization_expired",
            "prior_v3_authorization_consumed",
            "prior_v3_authorization_reusable",
            "renewal_reason",
        }
        and all(
            supersession.get(key) == expected
            for key, expected in _base_supersession().items()
        )
        and _valid_prior_authorization_ref(supersession.get("prior_v3_authorization"))
        and _valid_artifact_ref(supersession.get("prior_v3_gate"))
        and supersession.get("prior_v3_authorization_expired") is True
        and supersession.get("prior_v3_authorization_consumed") is False
        and supersession.get("prior_v3_authorization_reusable") is False
        and supersession.get("renewal_reason") == "expired_unclaimed"
    )


def _valid_prior_authorization_ref(value: Any) -> bool:
    ref = _object(value)
    return (
        set(ref)
        == {
            "path",
            "sha256",
            "signed_payload_sha256",
            "authorization_id",
            "valid_until",
        }
        and _absolute_path(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("signed_payload_sha256"))
        and _text(ref.get("authorization_id"))
        and _rfc3339(ref.get("valid_until"))
    )


def _is_renewal(plan: dict[str, Any]) -> bool:
    return "prior_v3_authorization" in _object(
        plan.get("superseded_execution_evidence")
    )


def _valid_artifact_ref(value: Any) -> bool:
    ref = _object(value)
    return (
        set(ref) == {"path", "sha256", "canonical_sha256"}
        and _absolute_path(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _git_revision(value: Any) -> bool:
    text = _text(value)
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _absolute_path(value: Any) -> bool:
    text = _text(value)
    return bool(text) and text.startswith("/")


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _require(condition: Any, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
