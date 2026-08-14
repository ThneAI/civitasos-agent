"""Shared contracts for the V1-A2 offline cost attribution pipeline."""

from __future__ import annotations

import hashlib
import json
import stat
from copy import deepcopy
from pathlib import Path
from typing import Any


SOURCE_MANIFEST_SCHEMA = "civitasos-v1a-cost-source-manifest:v1"
COHORT_PLAN_SCHEMA = "civitasos-v1a-cost-cohort-plan:v1"
PREFLIGHT_SCHEMA = "civitasos-v1a-cost-cohort-preflight:v1"
ENTRY_SET_SCHEMA = "civitasos-v1a-cost-entry-set:v1"
FACT_BATCH_SCHEMA = "civitasos-v1a-offline-cost-fact-batch:v1"
GATE_SCHEMA = "civitasos-v1a-offline-reconciliation-gate:v1"
COST_FACT_SCHEMA = "civitasos-cost-fact:v1"
COST_RATE_SCHEMA = "civitasos-cost-rate:v1"

HASH_FIELDS = {
    SOURCE_MANIFEST_SCHEMA: "manifest_sha256",
    COHORT_PLAN_SCHEMA: "plan_sha256",
    PREFLIGHT_SCHEMA: "preflight_sha256",
    ENTRY_SET_SCHEMA: "entry_set_sha256",
    FACT_BATCH_SCHEMA: "batch_sha256",
    GATE_SCHEMA: "report_sha256",
}

CATEGORY_UNITS = {
    "provider_input_tokens": "tokens",
    "provider_output_tokens": "tokens",
    "compute_time": "seconds",
    "container_time": "seconds",
    "storage": "byte_seconds",
    "network": "bytes",
    "operator_review_time": "seconds",
    "failure_recovery": "seconds",
    "ambiguous_provider_reservation": "requests",
}

PROVENANCE_CLASSES = {
    "external_invoice",
    "meter_export",
    "operator_signed_policy",
    "provider_usage_receipt",
    "dry_run_fixture",
}

OFFLINE_BOUNDARY = {
    "credential_file_accessed": False,
    "provider_or_model_call_performed": False,
    "participant_or_agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "external_payment_effect_performed": False,
    "effectiveness_or_sustainability_claim_authorized": False,
    "si12_or_si15_maturity_upgrade_authorized": False,
}


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finalize_artifact(value: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(value)
    schema = str(result.get("schema_version", ""))
    field = HASH_FIELDS.get(schema)
    if field is None:
        raise ValueError(f"unsupported V1-A2 artifact schema: {schema}")
    result.pop(field, None)
    result[field] = canonical_sha256(result)
    return result


def validate_self_hash(value: dict[str, Any], failures: list[str], label: str) -> None:
    schema = str(value.get("schema_version", ""))
    field = HASH_FIELDS.get(schema)
    if field is None:
        failures.append(f"{label}_schema_invalid")
        return
    body = {key: item for key, item in value.items() if key != field}
    if value.get(field) != canonical_sha256(body):
        failures.append(f"{label}_self_hash_invalid")


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def read_private_json(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve(strict=True)
    if stat.S_IMODE(resolved.stat().st_mode) != 0o600:
        raise ValueError(f"{label} must use mode 0600")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def artifact_ref(path: Path, value: dict[str, Any]) -> dict[str, str]:
    schema = str(value.get("schema_version", ""))
    field = HASH_FIELDS.get(schema)
    if field is None:
        raise ValueError("artifact reference schema is unsupported")
    return {
        "uri": f"artifact:v1a:{path.name}",
        "sha256": raw_sha256(path),
        "canonical_sha256": str(value.get(field, "")),
    }


def build_source_manifest(
    *,
    manifest_id: str,
    created_at: int,
    sources: list[dict[str, Any]],
    rate_requests: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact = {
        "schema_version": SOURCE_MANIFEST_SCHEMA,
        "manifest_id": manifest_id,
        "created_at": created_at,
        "status": "candidate",
        "sources": sorted(deepcopy(sources), key=lambda item: str(item["source_id"])),
        "rate_requests": sorted(
            deepcopy(rate_requests), key=lambda item: str(item["operation_id"])
        ),
        "source_payload_or_credential_recorded": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    failures = validate_source_manifest(result)
    if failures:
        raise ValueError(f"source manifest invalid: {failures}")
    return result


def validate_source_manifest(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != SOURCE_MANIFEST_SCHEMA:
        failures.append("source_manifest_schema_invalid")
        return failures
    validate_self_hash(value, failures, "source_manifest")
    _require(_text(value.get("manifest_id")), "manifest_id_missing", failures)
    _require(_nonnegative_int(value.get("created_at")), "created_at_invalid", failures)
    _require(value.get("status") == "candidate", "manifest_status_invalid", failures)
    _require(
        value.get("source_payload_or_credential_recorded") is False,
        "source_payload_or_credential_must_not_be_recorded",
        failures,
    )
    _validate_boundary(value.get("offline_boundary"), failures)

    sources = value.get("sources")
    source_values = sources if isinstance(sources, list) else []
    _require(bool(source_values), "source_set_empty", failures)
    source_ids: list[str] = []
    source_by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(source_values):
        source = item if isinstance(item, dict) else {}
        source_id = _text(source.get("source_id"))
        source_ids.append(source_id)
        source_by_id[source_id] = source
        category = _text(source.get("category"))
        _require(bool(source_id), f"source_{index}_id_missing", failures)
        _require(category in CATEGORY_UNITS, f"source_{index}_category_invalid", failures)
        provenance_class = source.get("provenance_class")
        _require(
            provenance_class in PROVENANCE_CLASSES,
            f"source_{index}_provenance_invalid",
            failures,
        )
        _require(
            _text(source.get("measurement_scope")),
            f"source_{index}_measurement_scope_missing",
            failures,
        )
        _require(
            type(source.get("real_external_source")) is bool,
            f"source_{index}_real_source_flag_invalid",
            failures,
        )
        _require(
            type(source.get("independently_reviewed")) is bool,
            f"source_{index}_review_flag_invalid",
            failures,
        )
        real_external_source = source.get("real_external_source")
        independently_reviewed = source.get("independently_reviewed")
        evidence = _object(source.get("evidence"))
        evidence_uri = _text(evidence.get("uri"))
        _validate_evidence_ref(evidence, failures, f"source_{index}")
        if provenance_class == "dry_run_fixture":
            _require(
                real_external_source is False,
                f"source_{index}_fixture_marked_real",
                failures,
            )
            _require(
                independently_reviewed is False,
                f"source_{index}_fixture_marked_reviewed",
                failures,
            )
            _require(
                evidence_uri.startswith("fixture:"),
                f"source_{index}_fixture_evidence_uri_invalid",
                failures,
            )
        elif evidence_uri.startswith("fixture:"):
            failures.append(f"source_{index}_non_fixture_uses_fixture_evidence")
    _require(
        len(source_ids) == len(set(source_ids)), "source_ids_not_unique", failures
    )

    requests = value.get("rate_requests")
    rate_values = requests if isinstance(requests, list) else []
    _require(bool(rate_values), "rate_request_set_empty", failures)
    rate_ids: list[str] = []
    operation_ids: list[str] = []
    for index, request in enumerate(rate_values):
        prefix = f"rate_{index}"
        _validate_cost_request(request, failures, prefix, expected_kind="rate_published")
        operation_ids.append(_text(_object(request).get("operation_id")))
        data = _event_data(request)
        rate_id = _text(data.get("rate_id"))
        rate_ids.append(rate_id)
        category = _text(data.get("category"))
        _require(
            data.get("schema_version") == COST_RATE_SCHEMA,
            f"{prefix}_schema_invalid",
            failures,
        )
        _require(
            CATEGORY_UNITS.get(category) == data.get("unit"),
            f"{prefix}_category_unit_invalid",
            failures,
        )
        _require(_currency(data.get("currency")), f"{prefix}_currency_invalid", failures)
        _require(
            _nonnegative_int(data.get("price_microunits")),
            f"{prefix}_price_invalid",
            failures,
        )
        _require(
            _positive_int(data.get("per_quantity")),
            f"{prefix}_per_quantity_invalid",
            failures,
        )
        _require(
            _nonnegative_int(data.get("effective_from")),
            f"{prefix}_effective_from_invalid",
            failures,
        )
        until = data.get("effective_until")
        _require(
            until is None
            or (_nonnegative_int(until) and until > data.get("effective_from", -1)),
            f"{prefix}_effective_until_invalid",
            failures,
        )
        rate_source = _object(data.get("source"))
        matching_source = next(
            (
                source
                for source in source_by_id.values()
                if _object(source.get("evidence")) == rate_source
                and source.get("category") == category
            ),
            None,
        )
        _require(matching_source is not None, f"{prefix}_source_unbound", failures)
    _require(len(rate_ids) == len(set(rate_ids)), "rate_ids_not_unique", failures)
    _require(
        len(operation_ids) == len(set(operation_ids)),
        "rate_operation_ids_not_unique",
        failures,
    )
    return sorted(set(failures))


def build_cohort_plan(
    *,
    cohort_id: str,
    created_at: int,
    observation_started_at: int,
    observation_ended_at: int,
    actor: str,
    task_ids: list[str],
    accepted_task_ids: list[str],
    expected_categories: list[str],
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    artifact = {
        "schema_version": COHORT_PLAN_SCHEMA,
        "cohort_id": cohort_id,
        "created_at": created_at,
        "observation_window": {
            "started_at": observation_started_at,
            "ended_at": observation_ended_at,
        },
        "actor": actor,
        "task_ids": sorted(task_ids),
        "accepted_task_ids": sorted(accepted_task_ids),
        "expected_categories": sorted(expected_categories),
        "source_manifest_canonical_sha256": source_manifest.get("manifest_sha256"),
        "unknown_cost_policy": "block_real_cohort_gate",
        "reservation_terminal_coverage_required": 1.0,
        "backend_fact_append_allowed": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    failures = validate_cohort_plan(result, source_manifest)
    if failures:
        raise ValueError(f"cohort plan invalid: {failures}")
    return result


def validate_cohort_plan(
    value: dict[str, Any], source_manifest: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != COHORT_PLAN_SCHEMA:
        failures.append("cohort_plan_schema_invalid")
        return failures
    validate_self_hash(value, failures, "cohort_plan")
    _require(_text(value.get("cohort_id")), "cohort_id_missing", failures)
    _require(_text(value.get("actor")), "cohort_actor_missing", failures)
    _require(_nonnegative_int(value.get("created_at")), "cohort_created_at_invalid", failures)
    window = _object(value.get("observation_window"))
    started = window.get("started_at")
    ended = window.get("ended_at")
    _require(
        _nonnegative_int(started) and _nonnegative_int(ended) and ended >= started,
        "observation_window_invalid",
        failures,
    )
    tasks = _strings(value.get("task_ids"))
    accepted = _strings(value.get("accepted_task_ids"))
    _require(bool(tasks), "cohort_task_set_empty", failures)
    _require(len(tasks) == len(set(tasks)), "cohort_task_ids_not_unique", failures)
    _require(set(accepted) <= set(tasks), "accepted_tasks_outside_cohort", failures)
    categories = _strings(value.get("expected_categories"))
    _require(
        bool(categories) and set(categories) <= set(CATEGORY_UNITS),
        "expected_categories_invalid",
        failures,
    )
    _require(
        value.get("source_manifest_canonical_sha256")
        == source_manifest.get("manifest_sha256"),
        "cohort_source_manifest_binding_invalid",
        failures,
    )
    _require(
        value.get("unknown_cost_policy") == "block_real_cohort_gate",
        "unknown_cost_policy_invalid",
        failures,
    )
    _require(
        value.get("reservation_terminal_coverage_required") == 1.0,
        "terminal_coverage_requirement_invalid",
        failures,
    )
    _require(
        value.get("backend_fact_append_allowed") is False,
        "cohort_plan_must_not_allow_fact_append",
        failures,
    )
    _validate_boundary(value.get("offline_boundary"), failures)
    return sorted(set(failures))


def validate_cost_request(
    request: Any, *, expected_kind: str | None = None
) -> list[str]:
    failures: list[str] = []
    _validate_cost_request(request, failures, "cost_request", expected_kind)
    return failures


def _validate_cost_request(
    request: Any,
    failures: list[str],
    prefix: str,
    expected_kind: str | None = None,
) -> None:
    value = _object(request)
    _require(
        value.get("schema_version") == COST_FACT_SCHEMA,
        f"{prefix}_schema_invalid",
        failures,
    )
    _require(_text(value.get("operation_id")), f"{prefix}_operation_id_missing", failures)
    _require(_text(value.get("actor")), f"{prefix}_actor_missing", failures)
    event = _object(value.get("event"))
    kind = _text(event.get("kind"))
    if expected_kind is not None:
        _require(kind == expected_kind, f"{prefix}_kind_invalid", failures)
    _require(isinstance(event.get("data"), dict), f"{prefix}_data_invalid", failures)
    if kind == "rate_published":
        _require(value.get("task_id") is None, f"{prefix}_task_id_must_be_null", failures)
    else:
        _require(_text(value.get("task_id")), f"{prefix}_task_id_missing", failures)


def event_kind(request: dict[str, Any]) -> str:
    return _text(_object(request.get("event")).get("kind"))


def event_data(request: dict[str, Any]) -> dict[str, Any]:
    return _event_data(request)


def evidence_reference(value: Any) -> dict[str, str]:
    failures: list[str] = []
    _validate_evidence_ref(value, failures, "evidence")
    if failures:
        raise ValueError(f"evidence reference invalid: {failures}")
    reference = _object(value)
    return {"uri": str(reference["uri"]), "sha256": str(reference["sha256"])}


def _validate_evidence_ref(value: Any, failures: list[str], prefix: str) -> None:
    reference = _object(value)
    _require(_text(reference.get("uri")), f"{prefix}_evidence_uri_missing", failures)
    digest = reference.get("sha256")
    _require(_sha256(digest), f"{prefix}_evidence_sha256_invalid", failures)


def _validate_boundary(value: Any, failures: list[str]) -> None:
    boundary = _object(value)
    if boundary != OFFLINE_BOUNDARY:
        failures.append("offline_boundary_invalid")


def _event_data(request: Any) -> dict[str, Any]:
    return _object(_object(_object(request).get("event")).get("data"))


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _text(value: Any) -> str:
    return value if isinstance(value, str) and value.strip() else ""


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _currency(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 16
        and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for char in value)
    )


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
