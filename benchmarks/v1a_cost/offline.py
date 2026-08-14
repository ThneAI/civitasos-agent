"""Offline V1-A2 source intake, Fact batch, and reconciliation Gate."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from civitasos_runtime import (
    EvidenceReference,
    StorageEntry,
    StorageSnapshot,
    network_bytes_request,
    operator_time_request,
    rate_publication_request,
    reconciliation_request,
    reservation_request,
    storage_byte_seconds_request,
)
from civitasos_runtime.cost_measurement import canonical_sha256 as runtime_sha256

from .contracts import (
    CATEGORY_UNITS,
    ENTRY_SET_SCHEMA,
    FACT_BATCH_SCHEMA,
    GATE_SCHEMA,
    OFFLINE_BOUNDARY,
    PREFLIGHT_SCHEMA,
    artifact_ref,
    build_cohort_plan,
    build_source_manifest,
    canonical_sha256,
    event_data,
    event_kind,
    finalize_artifact,
    raw_sha256,
    read_private_json,
    validate_cohort_plan,
    validate_cost_request,
    validate_self_hash,
    validate_source_manifest,
    write_private_json,
)


def build_entry_set(
    *,
    entry_set_id: str,
    created_at: int,
    source_manifest: dict[str, Any],
    cohort_plan: dict[str, Any],
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact = {
        "schema_version": ENTRY_SET_SCHEMA,
        "entry_set_id": entry_set_id,
        "created_at": created_at,
        "source_manifest_canonical_sha256": source_manifest.get("manifest_sha256"),
        "cohort_plan_canonical_sha256": cohort_plan.get("plan_sha256"),
        "entries": sorted(deepcopy(entries), key=_entry_sort_key),
        "backend_fact_append_allowed": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    failures = validate_entry_set(result, source_manifest, cohort_plan)
    if failures:
        raise ValueError(f"entry set invalid: {failures}")
    return result


def validate_entry_set(
    value: dict[str, Any],
    source_manifest: dict[str, Any],
    cohort_plan: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != ENTRY_SET_SCHEMA:
        return ["entry_set_schema_invalid"]
    validate_self_hash(value, failures, "entry_set")
    if value.get("source_manifest_canonical_sha256") != source_manifest.get(
        "manifest_sha256"
    ):
        failures.append("entry_set_source_binding_invalid")
    if value.get("cohort_plan_canonical_sha256") != cohort_plan.get("plan_sha256"):
        failures.append("entry_set_cohort_binding_invalid")
    if value.get("backend_fact_append_allowed") is not False:
        failures.append("entry_set_must_not_allow_fact_append")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("entry_set_offline_boundary_invalid")
    entries = value.get("entries")
    values = entries if isinstance(entries, list) else []
    if not values:
        failures.append("entry_set_empty")
    expected_tasks = set(_strings(cohort_plan.get("task_ids")))
    sources = {
        str(item.get("source_id")): item
        for item in source_manifest.get("sources", [])
        if isinstance(item, dict)
    }
    seen_pairs: list[tuple[str, str]] = []
    seen_operations: list[str] = []
    for index, item in enumerate(values):
        entry = item if isinstance(item, dict) else {}
        prefix = f"entry_{index}"
        reservation = _object(entry.get("reservation"))
        source_id = str(entry.get("source_id", ""))
        source = _object(sources.get(source_id))
        measurement = entry.get("measurement")
        terminal = _object(entry.get("terminal"))
        failures.extend(
            f"{prefix}_{failure}"
            for failure in validate_cost_request(
                reservation, expected_kind="reserved"
            )
        )
        if measurement is not None:
            failures.extend(
                f"{prefix}_{failure}"
                for failure in validate_cost_request(
                    measurement, expected_kind="measured"
                )
            )
        terminal_kind = event_kind(terminal)
        if terminal_kind not in {"reconciled", "unknown", "waived"}:
            failures.append(f"{prefix}_terminal_kind_invalid")
        failures.extend(
            f"{prefix}_{failure}" for failure in validate_cost_request(terminal)
        )
        task_id = str(reservation.get("task_id", ""))
        entry_id = str(event_data(reservation).get("entry_id", ""))
        category = str(event_data(reservation).get("category", ""))
        seen_pairs.append((task_id, entry_id))
        if not source_id:
            failures.append(f"{prefix}_source_id_missing")
        elif not source:
            failures.append(f"{prefix}_source_id_unknown")
        elif source.get("category") != category:
            failures.append(f"{prefix}_source_category_mismatch")
        if task_id not in expected_tasks:
            failures.append(f"{prefix}_task_outside_cohort")
        actor = reservation.get("actor")
        if actor != cohort_plan.get("actor"):
            failures.append(f"{prefix}_actor_mismatch")
        requests = [reservation, terminal]
        if isinstance(measurement, dict):
            requests.append(measurement)
        for request in requests:
            seen_operations.append(str(request.get("operation_id", "")))
            if request.get("task_id") != task_id:
                failures.append(f"{prefix}_task_binding_mismatch")
            if request.get("actor") != actor:
                failures.append(f"{prefix}_request_actor_mismatch")
            if event_data(request).get("entry_id") != entry_id:
                failures.append(f"{prefix}_entry_id_mismatch")
        if terminal_kind == "reconciled":
            if not isinstance(measurement, dict):
                failures.append(f"{prefix}_reconciliation_missing_measurement")
            else:
                data = event_data(terminal)
                if data.get("measurement_operation_id") != measurement.get(
                    "operation_id"
                ):
                    failures.append(f"{prefix}_measurement_reference_mismatch")
                if data.get("reservation_operation_id") != reservation.get(
                    "operation_id"
                ):
                    failures.append(f"{prefix}_reservation_reference_mismatch")
        elif measurement is not None:
            failures.append(f"{prefix}_non_reconciled_measurement_forbidden")
    if len(seen_pairs) != len(set(seen_pairs)):
        failures.append("entry_task_pairs_not_unique")
    if len(seen_operations) != len(set(seen_operations)):
        failures.append("entry_operation_ids_not_unique")
    covered_tasks = {task_id for task_id, _ in seen_pairs}
    if covered_tasks != expected_tasks:
        failures.append("entry_set_task_coverage_incomplete")
    return sorted(set(failures))


def build_preflight(
    *,
    source_manifest_path: Path,
    cohort_plan_path: Path,
) -> dict[str, Any]:
    source = read_private_json(source_manifest_path, "source manifest")
    plan = read_private_json(cohort_plan_path, "cohort plan")
    failures = validate_source_manifest(source)
    failures.extend(validate_cohort_plan(plan, source))
    real_source_failures = _real_source_failures(source)
    structural_passed = not failures
    artifact = {
        "schema_version": PREFLIGHT_SCHEMA,
        "source_manifest": artifact_ref(source_manifest_path, source),
        "cohort_plan": artifact_ref(cohort_plan_path, plan),
        "structural_passed": structural_passed,
        "real_source_review_ready": structural_passed and not real_source_failures,
        "fact_batch_generation_allowed": structural_passed,
        "backend_fact_append_allowed": False,
        "structural_failures": sorted(set(failures)),
        "real_source_blockers": real_source_failures,
        "decision": (
            "offline_fact_batch_generation_ready"
            if structural_passed
            else "offline_preflight_failed"
        ),
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    return finalize_artifact(artifact)


def validate_preflight(
    value: dict[str, Any], source: dict[str, Any], plan: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != PREFLIGHT_SCHEMA:
        return ["preflight_schema_invalid"]
    validate_self_hash(value, failures, "preflight")
    structural_failures = sorted(
        set(validate_source_manifest(source) + validate_cohort_plan(plan, source))
    )
    real_source_failures = _real_source_failures(source)
    expected_structural = not structural_failures
    expected_real = expected_structural and not _real_source_failures(source)
    if _canonical_ref(value.get("source_manifest")) != source.get("manifest_sha256"):
        failures.append("preflight_source_binding_invalid")
    if _canonical_ref(value.get("cohort_plan")) != plan.get("plan_sha256"):
        failures.append("preflight_plan_binding_invalid")
    if value.get("structural_passed") is not expected_structural:
        failures.append("preflight_structural_decision_invalid")
    if value.get("real_source_review_ready") is not expected_real:
        failures.append("preflight_real_source_decision_invalid")
    if value.get("fact_batch_generation_allowed") is not expected_structural:
        failures.append("preflight_batch_permission_invalid")
    if value.get("structural_failures") != structural_failures:
        failures.append("preflight_structural_failures_invalid")
    if value.get("real_source_blockers") != real_source_failures:
        failures.append("preflight_real_source_blockers_invalid")
    expected_decision = (
        "offline_fact_batch_generation_ready"
        if expected_structural
        else "offline_preflight_failed"
    )
    if value.get("decision") != expected_decision:
        failures.append("preflight_decision_invalid")
    if value.get("backend_fact_append_allowed") is not False:
        failures.append("preflight_must_not_allow_fact_append")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("preflight_offline_boundary_invalid")
    return sorted(set(failures))


def build_fact_batch(
    *,
    source_manifest_path: Path,
    cohort_plan_path: Path,
    preflight_path: Path,
    entry_set_path: Path,
) -> dict[str, Any]:
    source = read_private_json(source_manifest_path, "source manifest")
    plan = read_private_json(cohort_plan_path, "cohort plan")
    preflight = read_private_json(preflight_path, "preflight")
    entries = read_private_json(entry_set_path, "entry set")
    failures = validate_source_manifest(source)
    failures.extend(validate_cohort_plan(plan, source))
    failures.extend(validate_preflight(preflight, source, plan))
    failures.extend(validate_entry_set(entries, source, plan))
    if preflight.get("fact_batch_generation_allowed") is not True:
        failures.append("preflight_does_not_allow_fact_batch_generation")
    if failures:
        raise ValueError(f"offline Fact batch inputs invalid: {sorted(set(failures))}")

    requests = _expected_batch_requests(source, entries)
    source_bindings = _expected_source_bindings(entries)
    artifact = {
        "schema_version": FACT_BATCH_SCHEMA,
        "batch_id": f"v1a-batch:{canonical_sha256(requests)[:24]}",
        "source_manifest": artifact_ref(source_manifest_path, source),
        "cohort_plan": artifact_ref(cohort_plan_path, plan),
        "preflight": artifact_ref(preflight_path, preflight),
        "entry_set": artifact_ref(entry_set_path, entries),
        "request_count": len(requests),
        "requests_sha256": canonical_sha256(requests),
        "requests": requests,
        "entry_source_bindings": source_bindings,
        "backend_fact_append_allowed": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    return finalize_artifact(artifact)


def validate_fact_batch(
    value: dict[str, Any],
    source: dict[str, Any],
    plan: dict[str, Any],
    preflight: dict[str, Any],
    entries: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != FACT_BATCH_SCHEMA:
        return ["fact_batch_schema_invalid"]
    validate_self_hash(value, failures, "fact_batch")
    requests = value.get("requests")
    values = requests if isinstance(requests, list) else []
    if value.get("request_count") != len(values):
        failures.append("fact_batch_request_count_invalid")
    if value.get("requests_sha256") != canonical_sha256(values):
        failures.append("fact_batch_requests_hash_invalid")
    if value.get("backend_fact_append_allowed") is not False:
        failures.append("fact_batch_must_not_allow_append")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("fact_batch_offline_boundary_invalid")
    if _canonical_ref(value.get("source_manifest")) != source.get("manifest_sha256"):
        failures.append("fact_batch_source_binding_invalid")
    if _canonical_ref(value.get("cohort_plan")) != plan.get("plan_sha256"):
        failures.append("fact_batch_plan_binding_invalid")
    if _canonical_ref(value.get("preflight")) != preflight.get("preflight_sha256"):
        failures.append("fact_batch_preflight_binding_invalid")
    if _canonical_ref(value.get("entry_set")) != entries.get("entry_set_sha256"):
        failures.append("fact_batch_entry_set_binding_invalid")
    if values != _expected_batch_requests(source, entries):
        failures.append("fact_batch_request_set_invalid")
    if value.get("entry_source_bindings") != _expected_source_bindings(entries):
        failures.append("fact_batch_entry_source_bindings_invalid")
    operation_ids: list[str] = []
    rate_requests = source.get("rate_requests")
    expected_rates = {
        str(request.get("operation_id")) for request in rate_requests or []
    }
    actual_rates: set[str] = set()
    for index, request in enumerate(values):
        request_failures = validate_cost_request(request)
        failures.extend(f"request_{index}_{failure}" for failure in request_failures)
        operation_ids.append(str(_object(request).get("operation_id", "")))
        if event_kind(_object(request)) == "rate_published":
            actual_rates.add(str(_object(request).get("operation_id", "")))
    if len(operation_ids) != len(set(operation_ids)):
        failures.append("fact_batch_operation_ids_not_unique")
    if actual_rates != expected_rates:
        failures.append("fact_batch_rate_set_invalid")
    task_ids = {
        str(_object(request).get("task_id"))
        for request in values
        if event_kind(_object(request)) != "rate_published"
    }
    if task_ids != set(_strings(plan.get("task_ids"))):
        failures.append("fact_batch_task_set_invalid")
    _validate_fact_batch_source_bindings(value, source, failures)
    return sorted(set(failures))


def build_reconciliation_gate(
    *,
    source_manifest_path: Path,
    cohort_plan_path: Path,
    preflight_path: Path,
    entry_set_path: Path,
    fact_batch_path: Path,
) -> dict[str, Any]:
    source = read_private_json(source_manifest_path, "source manifest")
    plan = read_private_json(cohort_plan_path, "cohort plan")
    preflight = read_private_json(preflight_path, "preflight")
    entries = read_private_json(entry_set_path, "entry set")
    batch = read_private_json(fact_batch_path, "Fact batch")
    failures = validate_source_manifest(source)
    failures.extend(validate_cohort_plan(plan, source))
    failures.extend(validate_preflight(preflight, source, plan))
    failures.extend(validate_entry_set(entries, source, plan))
    failures.extend(validate_fact_batch(batch, source, plan, preflight, entries))
    projection = _project_batch(batch, plan)
    failures.extend(projection.pop("failures"))
    failures = sorted(set(failures))
    structural_passed = not failures
    real_source_ready = not _real_source_failures(source)
    unknown_free = projection["unknown_count"] == 0
    coverage_complete = projection["reservation_terminal_coverage"] == 1.0
    real_gate_passed = (
        structural_passed
        and real_source_ready
        and unknown_free
        and coverage_complete
    )
    if not structural_passed:
        decision = "offline_reconciliation_failed"
    elif real_gate_passed:
        decision = "real_cohort_inputs_ready_separate_append_authorization_required"
    else:
        decision = "offline_dry_run_passed_real_source_review_required"
    artifact = {
        "schema_version": GATE_SCHEMA,
        "source_manifest": artifact_ref(source_manifest_path, source),
        "cohort_plan": artifact_ref(cohort_plan_path, plan),
        "preflight": artifact_ref(preflight_path, preflight),
        "entry_set": artifact_ref(entry_set_path, entries),
        "fact_batch": artifact_ref(fact_batch_path, batch),
        "offline_structural_passed": structural_passed,
        "real_source_review_ready": real_source_ready,
        "unknown_cost_free": unknown_free,
        "reservation_terminal_coverage_complete": coverage_complete,
        "real_cohort_gate_passed": real_gate_passed,
        "decision": decision,
        **projection,
        "failure_reasons": failures,
        "backend_fact_append_allowed": False,
        "separate_single_use_append_authorization_required": True,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    return finalize_artifact(artifact)


def validate_reconciliation_gate(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != GATE_SCHEMA:
        return ["gate_schema_invalid"]
    validate_self_hash(value, failures, "gate")
    if value.get("backend_fact_append_allowed") is not False:
        failures.append("gate_must_not_allow_fact_append")
    if value.get("separate_single_use_append_authorization_required") is not True:
        failures.append("gate_append_authorization_boundary_invalid")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("gate_offline_boundary_invalid")
    if value.get("real_cohort_gate_passed") is True and not all(
        value.get(field) is True
        for field in (
            "offline_structural_passed",
            "real_source_review_ready",
            "unknown_cost_free",
            "reservation_terminal_coverage_complete",
        )
    ):
        failures.append("gate_real_pass_without_required_conditions")
    return failures


def generate_dry_run_fixture(output_root: Path) -> dict[str, Any]:
    root = output_root.expanduser().resolve()
    if root.exists():
        raise ValueError(f"V1-A2 output root already exists: {root}")
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    actor = "did:civ:v1a-offline-meter"
    evidence = {
        category: EvidenceReference(
            uri=f"fixture:v1a:rate:{category}",
            sha256=seed * 64,
        )
        for category, seed in (
            ("storage", "a"),
            ("network", "b"),
            ("operator_review_time", "c"),
        )
    }
    source_values = [
        {
            "source_id": f"source:fixture:{category}",
            "category": category,
            "provenance_class": "dry_run_fixture",
            "measurement_scope": scope,
            "real_external_source": False,
            "independently_reviewed": False,
            "evidence": evidence[category].as_dict(),
        }
        for category, scope in (
            ("storage", "allocated_byte_seconds"),
            ("network", "application_payload_bytes"),
            ("operator_review_time", "signed_active_seconds"),
        )
    ]
    rates = [
        rate_publication_request(
            operation_id=f"v1a:fixture:rate:{category}",
            actor=actor,
            rate_id=f"rate:v1a:fixture:{category}",
            category=category,
            unit=CATEGORY_UNITS[category],
            currency="USD" if category == "network" else "CNY",
            price_microunits=price,
            per_quantity=per_quantity,
            effective_from=1,
            effective_until=None,
            source=evidence[category],
        )
        for category, price, per_quantity in (
            ("storage", 1, 1_000_000),
            ("network", 1, 1_000),
            ("operator_review_time", 100_000, 3_600),
        )
    ]
    source = build_source_manifest(
        manifest_id="v1a-source-manifest:dry-run-20260814",
        created_at=10,
        sources=source_values,
        rate_requests=rates,
    )
    source_path = root / "source-manifest.json"
    write_private_json(source_path, source)

    task_ids = [f"v1a-dry-task-{index:02d}" for index in range(1, 6)]
    plan = build_cohort_plan(
        cohort_id="v1a-cohort:dry-run-20260814",
        created_at=10,
        observation_started_at=10,
        observation_ended_at=200,
        actor=actor,
        task_ids=task_ids,
        accepted_task_ids=task_ids[:4],
        expected_categories=["storage", "network", "operator_review_time"],
        source_manifest=source,
    )
    plan_path = root / "cohort-plan.json"
    write_private_json(plan_path, plan)

    measurement_root = root / "measurement-artifacts"
    entries: list[dict[str, Any]] = []
    for index, task_id in enumerate(task_ids, start=1):
        category = ("storage", "network", "operator_review_time")[
            (index - 1) % 3
        ]
        entry_id = f"cost:v1a:{task_id}:{category}"
        reserve_op = f"v1a:{task_id}:{category}:reserve"
        measure_op = f"v1a:{task_id}:{category}:measure"
        reconcile_op = f"v1a:{task_id}:{category}:reconcile"
        reservation = reservation_request(
            operation_id=reserve_op,
            task_id=task_id,
            actor=actor,
            entry_id=entry_id,
            category=category,
            currency="USD" if category == "network" else "CNY",
            reserved_microunits=10_000,
            source_refs=[evidence[category]],
        )
        artifact, measurement = _fixture_measurement(
            category=category,
            index=index,
            operation_id=measure_op,
            task_id=task_id,
            actor=actor,
            entry_id=entry_id,
            transport_ref=evidence[category],
        )
        artifact_path = measurement_root / f"{task_id}-{category}.json"
        write_private_json(artifact_path, artifact)
        terminal = reconciliation_request(
            operation_id=reconcile_op,
            task_id=task_id,
            actor=actor,
            entry_id=entry_id,
            measurement_operation_id=measure_op,
            reservation_operation_id=reserve_op,
            rate_id=f"rate:v1a:fixture:{category}",
            source_refs=[
                EvidenceReference(
                    uri=f"artifact:v1a:{artifact_path.name}",
                    sha256=raw_sha256(artifact_path),
                )
            ],
        )
        entries.append(
            {
                "source_id": f"source:fixture:{category}",
                "reservation": reservation,
                "measurement": measurement,
                "terminal": terminal,
            }
        )
    entry_set = build_entry_set(
        entry_set_id="v1a-entry-set:dry-run-20260814",
        created_at=200,
        source_manifest=source,
        cohort_plan=plan,
        entries=entries,
    )
    entry_set_path = root / "entry-set.json"
    write_private_json(entry_set_path, entry_set)

    preflight = build_preflight(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
    )
    preflight_path = root / "preflight.json"
    write_private_json(preflight_path, preflight)
    batch = build_fact_batch(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
        preflight_path=preflight_path,
        entry_set_path=entry_set_path,
    )
    batch_path = root / "offline-fact-batch.json"
    write_private_json(batch_path, batch)
    gate = build_reconciliation_gate(
        source_manifest_path=source_path,
        cohort_plan_path=plan_path,
        preflight_path=preflight_path,
        entry_set_path=entry_set_path,
        fact_batch_path=batch_path,
    )
    gate_path = root / "offline-reconciliation-gate.json"
    write_private_json(gate_path, gate)
    return {
        "output_root": str(root),
        "source_manifest": artifact_ref(source_path, source),
        "cohort_plan": artifact_ref(plan_path, plan),
        "entry_set": artifact_ref(entry_set_path, entry_set),
        "preflight": artifact_ref(preflight_path, preflight),
        "fact_batch": artifact_ref(batch_path, batch),
        "gate": artifact_ref(gate_path, gate),
        "decision": gate["decision"],
    }


def _project_batch(
    batch: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    failures: list[str] = []
    rates: dict[str, dict[str, Any]] = {}
    conflicting_rate_ids: set[str] = set()
    task_entries: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for request in batch.get("requests", []):
        value = _object(request)
        kind = event_kind(value)
        data = event_data(value)
        if kind == "rate_published":
            rate_id = str(data.get("rate_id", ""))
            if rate_id in conflicting_rate_ids:
                continue
            if rate_id in rates and rates[rate_id] != data:
                failures.append(f"conflicting_rate:{rate_id}")
                conflicting_rate_ids.add(rate_id)
                rates.pop(rate_id, None)
            elif rate_id not in rates:
                rates[rate_id] = data
            continue
        key = (str(value.get("task_id", "")), str(data.get("entry_id", "")))
        states = task_entries.setdefault(key, {})
        if kind in states:
            failures.append(f"duplicate_{kind}:{key[0]}:{key[1]}")
        else:
            states[kind] = value

    totals: dict[str, dict[str, int]] = {}
    reservations = 0
    terminals = 0
    reconciled = 0
    unknown = 0
    waived = 0
    task_actual: dict[str, dict[str, int]] = {
        task_id: {} for task_id in _strings(plan.get("task_ids"))
    }
    categories_seen: set[str] = set()
    for (task_id, entry_id), states in sorted(task_entries.items()):
        reservation = states.get("reserved")
        if reservation is None:
            failures.append(f"reservation_missing:{task_id}:{entry_id}")
            continue
        reservations += 1
        reserved_data = event_data(reservation)
        category = str(reserved_data.get("category", ""))
        currency = str(reserved_data.get("currency", ""))
        categories_seen.add(category)
        summary = totals.setdefault(
            currency,
            {
                "reserved_microunits": 0,
                "actual_microunits": 0,
                "unknown_upper_bound_microunits": 0,
            },
        )
        reserved_microunits = _cost_int(
            reserved_data.get("reserved_microunits"),
            f"reservation_amount_invalid:{task_id}:{entry_id}",
            failures,
        )
        summary["reserved_microunits"] += reserved_microunits
        terminal_kinds = set(states) & {"reconciled", "unknown", "waived"}
        if len(terminal_kinds) != 1:
            failures.append(f"terminal_state_invalid:{task_id}:{entry_id}")
            continue
        terminals += 1
        terminal_kind = next(iter(terminal_kinds))
        terminal_data = event_data(states[terminal_kind])
        if terminal_kind in {"unknown", "waived"} and (
            terminal_data.get("category") != category
            or terminal_data.get("currency") != currency
        ):
            failures.append(f"terminal_category_currency_mismatch:{task_id}:{entry_id}")
        if terminal_kind == "unknown":
            unknown += 1
            upper = _cost_int(
                terminal_data.get("upper_bound_microunits"),
                f"unknown_upper_bound_invalid:{task_id}:{entry_id}",
                failures,
            )
            if upper <= 0:
                failures.append(f"unknown_upper_bound_invalid:{task_id}:{entry_id}")
            summary["unknown_upper_bound_microunits"] += upper
            continue
        if terminal_kind == "waived":
            waived += 1
            continue
        reconciled += 1
        measurement = states.get("measured")
        if measurement is None:
            failures.append(f"measurement_missing:{task_id}:{entry_id}")
            continue
        measurement_data = event_data(measurement)
        rate_id = str(terminal_data.get("rate_id", ""))
        rate = rates.get(rate_id)
        if rate is None:
            failures.append(f"rate_missing:{task_id}:{entry_id}:{rate_id}")
            continue
        if category != measurement_data.get("category") or category != rate.get(
            "category"
        ):
            failures.append(f"category_mismatch:{task_id}:{entry_id}")
        if measurement_data.get("unit") != rate.get("unit"):
            failures.append(f"unit_mismatch:{task_id}:{entry_id}")
        if currency != rate.get("currency"):
            failures.append(f"currency_mismatch:{task_id}:{entry_id}")
        measured_at = _cost_int(
            measurement_data.get("measured_at"),
            f"measurement_time_invalid:{task_id}:{entry_id}",
            failures,
        )
        effective_from = _cost_int(
            rate.get("effective_from"),
            f"rate_effective_from_invalid:{task_id}:{entry_id}",
            failures,
        )
        effective_until = rate.get("effective_until")
        if measured_at < effective_from or (
            isinstance(effective_until, int) and measured_at >= effective_until
        ):
            failures.append(f"rate_window_invalid:{task_id}:{entry_id}")
        actual = _priced_amount(
            _cost_int(
                measurement_data.get("quantity"),
                f"measurement_quantity_invalid:{task_id}:{entry_id}",
                failures,
            ),
            _cost_int(
                rate.get("price_microunits"),
                f"rate_price_invalid:{task_id}:{entry_id}",
                failures,
            ),
            _cost_int(
                rate.get("per_quantity"),
                f"rate_per_quantity_invalid:{task_id}:{entry_id}",
                failures,
                positive=True,
            ),
        )
        if actual > reserved_microunits:
            failures.append(f"actual_exceeds_reservation:{task_id}:{entry_id}")
        summary["actual_microunits"] += actual
        task_actual.setdefault(task_id, {}).setdefault(currency, 0)
        task_actual[task_id][currency] += actual

    expected_categories = set(_strings(plan.get("expected_categories")))
    if categories_seen != expected_categories:
        failures.append("expected_category_coverage_invalid")
    coverage = terminals / reservations if reservations else 0.0
    accepted_count = len(_strings(plan.get("accepted_task_ids")))
    per_accepted = {
        currency: (
            None
            if accepted_count == 0
            else _div_ceil(summary["actual_microunits"], accepted_count)
        )
        for currency, summary in sorted(totals.items())
    }
    return {
        "task_count": len(_strings(plan.get("task_ids"))),
        "accepted_outcome_count": accepted_count,
        "reservation_count": reservations,
        "terminal_count": terminals,
        "reconciled_count": reconciled,
        "unknown_count": unknown,
        "waived_count": waived,
        "reservation_terminal_coverage": coverage,
        "totals_by_currency": dict(sorted(totals.items())),
        "task_actual_by_currency": dict(sorted(task_actual.items())),
        "cost_per_accepted_outcome_by_currency": per_accepted,
        "failures": failures,
    }


def _fixture_measurement(
    *,
    category: str,
    index: int,
    operation_id: str,
    task_id: str,
    actor: str,
    entry_id: str,
    transport_ref: EvidenceReference,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if category == "network":
        return network_bytes_request(
            operation_id=operation_id,
            task_id=task_id,
            actor=actor,
            entry_id=entry_id,
            call_id=f"v1a-dry-call-{index}",
            request_bytes=100 + index,
            response_bytes=200 + index,
            connect_attempts=1,
            request_dispatched=True,
            measured_at=100 + index,
            transport_receipt=transport_ref,
        )
    if category == "operator_review_time":
        return operator_time_request(
            operation_id=operation_id,
            task_id=task_id,
            actor=actor,
            entry_id=entry_id,
            operator_role="cost_reviewer",
            activity_code="cohort_cost_review",
            started_at=20 + index,
            ended_at=80 + index,
            attestation_signature=transport_ref,
        )
    entry = StorageEntry(
        path_sha256=str(index) * 64,
        kind="file",
        logical_bytes=100,
        allocated_bytes=4_096,
        mtime_ns=index,
    )
    snapshot = StorageSnapshot(
        measured_at=10,
        root_sha256="d" * 64,
        logical_bytes=100,
        allocated_bytes=4_096,
        regular_file_count=1,
        directory_count=0,
        entry_manifest_sha256=runtime_sha256([entry.__dict__]),
        entries=(entry,),
    )
    return storage_byte_seconds_request(
        operation_id=operation_id,
        task_id=task_id,
        actor=actor,
        entry_id=entry_id,
        snapshot=snapshot,
        retention_started_at=10,
        retention_ended_at=100 + index,
    )


def _real_source_failures(source: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for item in source.get("sources", []):
        value = _object(item)
        source_id = str(value.get("source_id", "unknown"))
        if value.get("real_external_source") is not True:
            failures.append(f"source_not_real_external:{source_id}")
        if value.get("independently_reviewed") is not True:
            failures.append(f"source_not_independently_reviewed:{source_id}")
        if value.get("provenance_class") == "dry_run_fixture":
            failures.append(f"fixture_source_not_promotable:{source_id}")
    return sorted(set(failures))


def _validate_fact_batch_source_bindings(
    batch: dict[str, Any],
    source: dict[str, Any],
    failures: list[str],
) -> None:
    sources = {
        str(item.get("source_id")): item
        for item in source.get("sources", [])
        if isinstance(item, dict)
    }
    reservation_categories: dict[tuple[str, str], str] = {}
    for request in batch.get("requests", []):
        value = _object(request)
        if event_kind(value) != "reserved":
            continue
        data = event_data(value)
        key = (str(value.get("task_id", "")), str(data.get("entry_id", "")))
        reservation_categories[key] = str(data.get("category", ""))
    bindings = batch.get("entry_source_bindings")
    binding_values = bindings if isinstance(bindings, list) else []
    bound_pairs: list[tuple[str, str]] = []
    for index, item in enumerate(binding_values):
        binding = _object(item)
        key = (str(binding.get("task_id", "")), str(binding.get("entry_id", "")))
        bound_pairs.append(key)
        source_id = str(binding.get("source_id", ""))
        source_value = _object(sources.get(source_id))
        if not source_value:
            failures.append(f"fact_batch_binding_{index}_source_unknown")
        elif source_value.get("category") != reservation_categories.get(key):
            failures.append(f"fact_batch_binding_{index}_source_category_mismatch")
    if len(bound_pairs) != len(set(bound_pairs)):
        failures.append("fact_batch_source_bindings_not_unique")
    if set(bound_pairs) != set(reservation_categories):
        failures.append("fact_batch_source_binding_coverage_invalid")


def _expected_batch_requests(
    source: dict[str, Any], entries: dict[str, Any]
) -> list[dict[str, Any]]:
    requests = deepcopy(source.get("rate_requests", []))
    for entry in entries.get("entries", []):
        value = _object(entry)
        requests.append(_object(value.get("reservation")))
        if value.get("measurement") is not None:
            requests.append(_object(value.get("measurement")))
        requests.append(_object(value.get("terminal")))
    requests.sort(key=_request_sort_key)
    return requests


def _expected_source_bindings(entries: dict[str, Any]) -> list[dict[str, str]]:
    bindings = [
        {
            "task_id": str(_object(entry.get("reservation")).get("task_id", "")),
            "entry_id": str(event_data(_object(entry.get("reservation"))).get("entry_id", "")),
            "source_id": str(entry.get("source_id", "")),
        }
        for entry in entries.get("entries", [])
        if isinstance(entry, dict)
    ]
    bindings.sort(key=lambda item: (item["task_id"], item["entry_id"]))
    return bindings


def _priced_amount(quantity: int, price: int, per_quantity: int) -> int:
    if quantity < 0 or price < 0 or per_quantity <= 0:
        raise ValueError("cost arithmetic input is invalid")
    return _div_ceil(quantity * price, per_quantity)


def _cost_int(
    value: Any,
    failure: str,
    failures: list[str],
    *,
    positive: bool = False,
) -> int:
    valid = type(value) is int and (value > 0 if positive else value >= 0)
    if valid:
        return value
    failures.append(failure)
    return 1 if positive else 0


def _div_ceil(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def _entry_sort_key(entry: dict[str, Any]) -> tuple[str, str]:
    reservation = _object(entry.get("reservation"))
    return (
        str(reservation.get("task_id", "")),
        str(event_data(reservation).get("entry_id", "")),
    )


def _request_sort_key(request: dict[str, Any]) -> tuple[int, str, str]:
    return (
        0 if event_kind(request) == "rate_published" else 1,
        str(request.get("task_id") or ""),
        str(request.get("operation_id", "")),
    )


def _canonical_ref(value: Any) -> str:
    return str(_object(value).get("canonical_sha256", ""))


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _write_result(path: Path, value: dict[str, Any]) -> None:
    write_private_json(path.expanduser().resolve(), value)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("--output-root", type=Path, required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--source-manifest", type=Path, required=True)
    preflight.add_argument("--cohort-plan", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    batch = commands.add_parser("batch")
    batch.add_argument("--source-manifest", type=Path, required=True)
    batch.add_argument("--cohort-plan", type=Path, required=True)
    batch.add_argument("--preflight", type=Path, required=True)
    batch.add_argument("--entry-set", type=Path, required=True)
    batch.add_argument("--output", type=Path, required=True)
    gate = commands.add_parser("gate")
    gate.add_argument("--source-manifest", type=Path, required=True)
    gate.add_argument("--cohort-plan", type=Path, required=True)
    gate.add_argument("--preflight", type=Path, required=True)
    gate.add_argument("--entry-set", type=Path, required=True)
    gate.add_argument("--fact-batch", type=Path, required=True)
    gate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "fixture":
        result = generate_dry_run_fixture(args.output_root)
    elif args.command == "preflight":
        result = build_preflight(
            source_manifest_path=args.source_manifest,
            cohort_plan_path=args.cohort_plan,
        )
        _write_result(args.output, result)
    elif args.command == "batch":
        result = build_fact_batch(
            source_manifest_path=args.source_manifest,
            cohort_plan_path=args.cohort_plan,
            preflight_path=args.preflight,
            entry_set_path=args.entry_set,
        )
        _write_result(args.output, result)
    else:
        result = build_reconciliation_gate(
            source_manifest_path=args.source_manifest,
            cohort_plan_path=args.cohort_plan,
            preflight_path=args.preflight,
            entry_set_path=args.entry_set,
            fact_batch_path=args.fact_batch,
        )
        _write_result(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
