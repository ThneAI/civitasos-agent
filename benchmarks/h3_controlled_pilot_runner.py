"""Execute one H.3 profile-bound controlled pilot with local Agent roles."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    BOUNDARY as PREFLIGHT_BOUNDARY,
)
from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    SCHEMA_VERSION as PREFLIGHT_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-controlled-pilot-runner:v1"
CONSUMPTION_SCHEMA_VERSION = "h3-controlled-pilot-authorization-consumption:v1"
POST_RUN_RECEIPT_SCHEMA_VERSION = "h3-controlled-pilot-post-run-receipt:v1"
TASK_SCHEMA_VERSION = "h3-relation-evidence-analysis-pilot-task:v2"
LEGACY_TASK_SCHEMA_VERSION = "h3-successful-relation-conditions-pilot-task:v1"
SUPPORTED_PROPOSAL_TASK_KINDS = {
    "review_conditions_for_preserving_successful_relations": (
        "successful_relation_conditions_analysis"
    ),
    "validate_relation_learning_replication": (
        "relation_learning_replication_analysis"
    ),
}
AGENT_ROLES = (
    "relation_evidence_analyst",
    "counterexample_challenger",
    "audit_verifier",
)
REQUIRED_RESPONSE_FIELDS = {
    "verdict",
    "supported_conditions",
    "counterexamples",
    "unresolved_assumptions",
    "evidence_refs",
    "boundary_attestation",
}
RESPONSE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string"},
        "supported_conditions": {"type": "array", "items": {"type": "string"}},
        "counterexamples": {"type": "array", "items": {"type": "string"}},
        "unresolved_assumptions": {"type": "array", "items": {"type": "string"}},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "boundary_attestation": {"type": "boolean"},
    },
    "required": sorted(REQUIRED_RESPONSE_FIELDS),
    "additionalProperties": True,
}
AgentCall = Callable[[str, str], tuple[dict[str, Any], dict[str, Any]]]


def run_controlled_pilot(
    *,
    preflight_path: Path,
    bounded_plan_report_path: Path,
    agent_root: Path,
    model: str,
    ollama_url: str = "http://localhost:11434",
    timeout_seconds: int = 300,
    evidence_report_paths: list[Path] | None = None,
    ack_kill_switch_armed: bool = False,
    kill_switch_file: Path | None = None,
    current_time: datetime | None = None,
    agent_call: AgentCall | None = None,
) -> dict[str, Any]:
    preflight_file = _resolve(preflight_path, agent_root)
    bounded_file = _resolve(bounded_plan_report_path, agent_root)
    now = _as_utc(current_time or datetime.now(timezone.utc))
    failures: list[str] = []
    checks: dict[str, bool] = {}
    preflight = _read_json(preflight_file, failures, "execution preflight")
    profile = str(_object(preflight).get("validation_profile") or "development")
    draft = _validate_inputs(
        preflight=preflight,
        bounded_plan_report_path=bounded_file,
        ack_kill_switch_armed=ack_kill_switch_armed,
        current_time=now,
        failures=failures,
        checks=checks,
    )
    receipt = _object(_object(preflight).get("authorization_receipt"))
    controls = _object(receipt.get("controls"))
    sink = _resolve_ref(controls.get("post_run_receipt_sink_ref"), agent_root)
    kill_file = _resolve(kill_switch_file, agent_root) if kill_switch_file else None
    _require(checks, failures, "post_run_receipt_sink_valid", sink is not None)
    _require(
        checks,
        failures,
        "post_run_receipt_absent",
        bool(sink is not None and not sink.exists()),
    )
    _require(
        checks,
        failures,
        "kill_switch_not_triggered",
        kill_file is None or not kill_file.exists(),
    )
    if failures or not all(checks.values()) or sink is None:
        return _blocked_report(
            failures=failures,
            checks=checks,
            preflight_file=preflight_file,
            bounded_file=bounded_file,
        )

    consumption_path = sink.with_name(
        f"{sink.stem}.authorization_consumption.json"
    )
    started_at = datetime.now(timezone.utc)
    try:
        consumption = _claim_authorization(
            path=consumption_path,
            receipt=receipt,
            preflight_file=preflight_file,
            started_at=started_at,
            profile=profile,
        )
    except RuntimeError as exc:
        failures.append(str(exc))
        return _blocked_report(
            failures=failures,
            checks=checks,
            preflight_file=preflight_file,
            bounded_file=bounded_file,
        )
    try:
        task = _build_task(
            draft=draft,
            bounded_file=bounded_file,
            evidence_report_paths=evidence_report_paths or [],
            agent_root=agent_root,
            profile=profile,
        )
    except Exception as exc:
        task = {
            "schema_version": TASK_SCHEMA_VERSION,
            "state": "task_construction_failed",
        }
        run_failures = [f"controlled task construction failed: {exc}"]
    else:
        run_failures = []
    task_path = sink.with_name(f"{sink.stem}.task.json")
    _write_json(task_path, task)
    generation_dir = sink.with_name(f"{sink.stem}.generations")
    generation_dir.mkdir(parents=True, exist_ok=True)

    call = agent_call or _ollama_agent_call(
        model=model,
        ollama_url=ollama_url,
        timeout_seconds=timeout_seconds,
    )
    generation_reports: list[dict[str, Any]] = []
    try:
        if run_failures:
            raise RuntimeError(run_failures[0])
        if kill_file is not None and kill_file.exists():
            raise RuntimeError("operator kill switch triggered before Agent dispatch")
        generation_reports = _run_agents(
            call=call,
            task=task,
            generation_dir=generation_dir,
            kill_switch_file=kill_file,
            profile=profile,
        )
        _require(
            checks,
            run_failures,
            "agent_count_within_authorized_scope",
            1 <= len(generation_reports) <= int(
                _object(receipt.get("authorized_scope")).get("max_agents", 0)
            ),
        )
        _require(
            checks,
            run_failures,
            "all_agent_generations_valid",
            len(generation_reports) == len(AGENT_ROLES)
            and all(item.get("passed") is True for item in generation_reports),
        )
    except Exception as exc:  # Always close the single-use receipt with evidence.
        run_failures.append(f"controlled runner failed: {exc}")

    completed_at = datetime.now(timezone.utc)
    duration_seconds = (completed_at - started_at).total_seconds()
    _require(
        checks,
        run_failures,
        "runner_duration_within_authorized_scope",
        duration_seconds
        <= int(_object(receipt.get("authorized_scope")).get("max_duration_seconds", 0)),
    )
    passed = not run_failures and all(checks.values())
    reconciliation = _reconcile_generations(generation_reports)
    post_run_receipt = {
        "schema_version": POST_RUN_RECEIPT_SCHEMA_VERSION,
        "passed": passed,
        "state": (
            "controlled_pilot_completed"
            if passed
            else "controlled_pilot_failed_closed"
        ),
        "failure_reasons": run_failures,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "authorization_consumption": _artifact_ref(consumption_path),
        "source_preflight": _artifact_ref(preflight_file),
        "source_bounded_plan_report": _artifact_ref(bounded_file),
        "task": _artifact_ref(task_path),
        "generation_reports": [
            _artifact_ref(Path(item["report_path"])) for item in generation_reports
        ],
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": duration_seconds,
        "model": model,
        "agent_roles": list(AGENT_ROLES),
        "task_count": 1,
        "agent_count": len(generation_reports),
        "reconciliation": reconciliation,
        "side_effects": {
            "authorization_consumed": True,
            "post_run_receipt_written": True,
            "production_state_mutated": False,
            "iem_state_mutated": False,
            "relation_state_mutated": False,
            "authorization_state_mutated": False,
            "normative_state_mutated": False,
            "external_system_mutations": 0,
        },
        "boundary": {
            "development_only": profile == "development",
            "qualification_controlled_only": profile == "qualification",
            "result_valid_for_qualification": False,
            "production_use_allowed": False,
            "automatic_rollout_allowed": False,
            "result_requires_operator_review": True,
            "result_may_directly_change_trust": False,
            "result_may_directly_change_authorization": False,
            "result_may_directly_change_normative_state": False,
        },
    }
    _write_json(sink, post_run_receipt)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": run_failures,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "checks": checks,
        "authorization_consumption": _artifact_ref(consumption_path),
        "post_run_receipt": _artifact_ref(sink),
        "task": _artifact_ref(task_path),
        "generation_report_count": len(generation_reports),
        "reconciliation": reconciliation,
        "readiness": {
            "controlled_pilot_completed": passed,
            "operator_review_required": True,
            "automatic_state_change_allowed": False,
            "decision": (
                f"h3_{profile}_controlled_pilot_completed_pending_operator_review"
                if passed
                else f"h3_{profile}_controlled_pilot_failed_closed"
            ),
        },
    }


def _validate_inputs(
    *,
    preflight: dict[str, Any] | None,
    bounded_plan_report_path: Path,
    ack_kill_switch_armed: bool,
    current_time: datetime,
    failures: list[str],
    checks: dict[str, bool],
) -> dict[str, Any]:
    if preflight is None:
        _require(checks, failures, "execution_preflight_present", False)
        return {}
    checks["execution_preflight_present"] = True
    _require_equal(
        checks,
        failures,
        "execution_preflight_schema",
        preflight.get("schema_version"),
        PREFLIGHT_SCHEMA_VERSION,
    )
    _require(checks, failures, "execution_preflight_passed", preflight.get("passed") is True)
    expected_boundary = dict(PREFLIGHT_BOUNDARY)
    expected_boundary["controlled_runner_input_ready"] = True
    _require_equal(
        checks,
        failures,
        "execution_preflight_boundary",
        preflight.get("boundary"),
        expected_boundary,
    )
    readiness = _object(preflight.get("readiness"))
    _require(
        checks,
        failures,
        "controlled_runner_input_ready",
        readiness.get("controlled_runner_input_ready") is True
        and readiness.get("controlled_pilot_execution_ready") is False,
    )
    profile = str(preflight.get("validation_profile") or "development")
    _require(
        checks,
        failures,
        "execution_preflight_profile_supported",
        profile in {"development", "qualification"},
    )
    _require_equal(
        checks,
        failures,
        "execution_preflight_development_flag",
        preflight.get("development_only"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "execution_preflight_qualification_flag",
        preflight.get("valid_for_qualification"),
        profile == "qualification",
    )
    receipt = _object(preflight.get("authorization_receipt"))
    valid_from = _timestamp(receipt.get("valid_from"))
    valid_until = _timestamp(receipt.get("valid_until"))
    _require(
        checks,
        failures,
        "authorization_receipt_valid_at_start",
        bool(
            receipt.get("single_use") is True
            and receipt.get("consumed") is False
            and valid_from is not None
            and valid_until is not None
            and valid_from <= current_time < valid_until
        ),
    )
    scope = _object(receipt.get("authorized_scope"))
    _require(
        checks,
        failures,
        "authorized_scope_valid",
        _authorized_scope_valid(scope, profile=profile),
    )
    _require(
        checks,
        failures,
        "kill_switch_explicitly_armed",
        ack_kill_switch_armed,
    )
    bounded = _read_json(bounded_plan_report_path, failures, "bounded plan report")
    drafts = _objects(_object(bounded).get("draft_surface", {}).get("drafts"))
    matches = [
        item
        for item in drafts
        if item.get("proposal_kind") in SUPPORTED_PROPOSAL_TASK_KINDS
    ]
    _require(checks, failures, "authorized_bounded_draft_unique", len(matches) == 1)
    return matches[0] if len(matches) == 1 else {}


def _build_task(
    *,
    draft: dict[str, Any],
    bounded_file: Path,
    evidence_report_paths: list[Path],
    agent_root: Path,
    profile: str,
) -> dict[str, Any]:
    evidence_refs = _objects(_object(draft.get("source_binding")).get("evidence_refs"))
    task_evidence_refs = [
        {
            "record_id": item.get("record_id"),
            "task_id": item.get("task_id"),
            "source_report_sha256": item.get("source_report_sha256"),
        }
        for item in evidence_refs
    ]
    evidence_snapshots = _load_evidence_snapshots(
        evidence_refs=task_evidence_refs,
        evidence_report_paths=evidence_report_paths,
        agent_root=agent_root,
    )
    return {
        "schema_version": TASK_SCHEMA_VERSION,
        "task_id": f"h3-controlled-task:{_canonical_sha256(draft)[:20]}",
        "task_kind": SUPPORTED_PROPOSAL_TASK_KINDS[str(draft["proposal_kind"])],
        "proposal_kind": draft.get("proposal_kind"),
        "title": draft.get("title"),
        "objective": draft.get("objective"),
        "hypotheses": draft.get("hypotheses"),
        "failure_conditions": draft.get("failure_conditions"),
        "success_metrics": draft.get("success_metrics"),
        "stop_conditions": draft.get("stop_conditions"),
        "negative_control_checks": _object(
            draft.get("source_binding")
        ).get("negative_control_checks", {}),
        "evidence_refs": task_evidence_refs,
        "evidence_snapshots": evidence_snapshots,
        "source_bounded_plan_report": _artifact_ref(bounded_file),
        "required_agent_roles": list(AGENT_ROLES),
        "required_output": sorted(REQUIRED_RESPONSE_FIELDS),
        "constraints": {
            "one_task_only": True,
            "validation_profile": profile,
            "development_only": profile == "development",
            "qualification_controlled_only": profile == "qualification",
            "read_only_analysis": True,
            "no_trust_mutation": True,
            "no_authorization_mutation": True,
            "no_normative_mutation": True,
            "no_production_use": True,
        },
    }


def _load_evidence_snapshots(
    *,
    evidence_refs: list[dict[str, Any]],
    evidence_report_paths: list[Path],
    agent_root: Path,
) -> list[dict[str, Any]]:
    expected_hashes = {
        str(item.get("source_report_sha256") or "") for item in evidence_refs
    }
    ref_by_record_id = {
        str(item.get("record_id") or ""): item for item in evidence_refs
    }
    supplied: dict[str, Any] = {}
    for raw_path in evidence_report_paths:
        path = _resolve(raw_path, agent_root)
        digest = _sha256(path)
        if digest not in expected_hashes:
            raise ValueError(f"evidence report is not authorized by the draft: {path}")
        supplied[digest] = json.loads(path.read_text(encoding="utf-8"))
    missing_hashes = expected_hashes - set(supplied)
    if missing_hashes:
        raise ValueError(
            "missing authorized evidence report(s): " + ", ".join(sorted(missing_hashes))
        )
    snapshots: list[dict[str, Any]] = []
    for record_id, evidence_ref in sorted(ref_by_record_id.items()):
        task_id = str(evidence_ref.get("task_id") or "")
        matches: list[tuple[str, dict[str, Any]]] = []
        for digest, value in supplied.items():
            summaries = _object(value).get("worker_summaries")
            for record in _object(summaries).values():
                if isinstance(record, dict) and record.get("task_id") == task_id:
                    matches.append((digest, record))
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one evidence task {task_id}, found {len(matches)}"
            )
        digest, record = matches[0]
        snapshots.append(
            {
                "record_id": record_id,
                "task_id": task_id,
                "source_report_sha256": digest,
                "record": _compact_worker_summary(record),
            }
        )
    return snapshots


def _compact_worker_summary(record: dict[str, Any]) -> dict[str, Any]:
    relation = _object(record.get("relation_update"))
    iem = _object(record.get("iem_update"))
    expectation_updates = _objects(relation.get("expectation_updates"))
    full_provenance = next(
        (
            _object(_object(item.get("update_params")).get("delta_provenance"))
            for item in expectation_updates
            if _object(_object(item.get("update_params")).get("delta_provenance"))
        ),
        {},
    )
    provenance = _compact_learning_provenance(full_provenance)
    return {
        "task_id": record.get("task_id"),
        "event_kind": record.get("event_kind"),
        "observed_at": record.get("observed_at"),
        "authorization_changed": _object(
            record.get("authorization_change")
        ).get("changed"),
        "relation_update": {
            "before": relation.get("before"),
            "after": relation.get("after"),
            "action_bias": _compact_action_bias(
                _object(relation.get("action_bias"))
            ),
            "learning_provenance": provenance,
            "normative_guard_observed": any(
                item.get("parameter_name") == "normative_relation"
                and item.get("local_update_blocked") is True
                for item in expectation_updates
            ),
        },
        "iem_update": {
            "relation_entry_persisted": iem.get("relation_entry_persisted"),
        },
    }


def _compact_learning_provenance(value: dict[str, Any]) -> dict[str, Any]:
    components = [
        {
            key: item.get(key)
            for key in (
                "outcome_kind",
                "task_kind",
                "provider",
                "owner_id",
                "risk_class",
                "confidence",
                "risk_weight",
                "history_adaptation",
                "surprise_weight",
                "effective_weight",
                "upstream_event_id",
            )
        }
        for item in _objects(value.get("components"))
    ]
    compact = {
        key: value.get(key)
        for key in (
            "schema_version",
            "prior_sample_count",
            "sample_count",
            "identity_neutral_dimensions",
            "raw_deltas",
            "bounded_deltas",
            "applied_deltas",
            "per_step_abs_caps",
        )
    }
    source_event_ids = [
        str(item) for item in value.get("source_event_ids", []) if str(item)
    ]
    duplicate_ids = [
        str(item)
        for item in value.get("duplicate_source_event_ids", [])
        if str(item)
    ]
    compact.update(
        {
            "source_event_count": len(source_event_ids),
            "source_event_id_sha256": [
                hashlib.sha256(item.encode("utf-8")).hexdigest()
                for item in source_event_ids
            ],
            "duplicate_source_event_count": len(duplicate_ids),
            "duplicate_source_event_id_sha256": [
                hashlib.sha256(item.encode("utf-8")).hexdigest()
                for item in duplicate_ids
            ],
            "components": components,
        }
    )
    return compact


def _compact_action_bias(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value.get(key)
        for key in (
            "verification_level",
            "required_stake_multiplier",
            "direct_match_allowed",
            "trust_hint",
            "claim_priority_delta",
            "evidence_outcome_kinds",
        )
    }


def _run_agents(
    *,
    call: AgentCall,
    task: dict[str, Any],
    generation_dir: Path,
    kill_switch_file: Path | None,
    profile: str,
) -> list[dict[str, Any]]:
    prompt = _task_prompt(task)
    reports: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(AGENT_ROLES)) as pool:
        futures = {
            pool.submit(call, role, _role_bound_prompt(role, prompt, profile)): role
            for role in AGENT_ROLES
        }
        for future in concurrent.futures.as_completed(futures):
            role = futures[future]
            if kill_switch_file is not None and kill_switch_file.exists():
                raise RuntimeError("operator kill switch triggered during Agent execution")
            payload, raw = future.result()
            raw_reports = [raw]
            valid = _valid_agent_payload(
                payload,
                task,
                strict_evidence_refs=profile == "qualification",
            )
            if not valid:
                payload, repair_raw = call(
                    role,
                    _repair_prompt(
                        task=task,
                        previous_payload=payload,
                        profile=profile,
                    ),
                )
                raw_reports.append(repair_raw)
                valid = _valid_agent_payload(
                    payload,
                    task,
                    strict_evidence_refs=profile == "qualification",
                )
            report = {
                "schema_version": "h3-controlled-pilot-agent-generation:v1",
                "passed": valid,
                "agent_role": role,
                "task_id": task["task_id"],
                "response": payload,
                "raw_provider_report": raw_reports[-1],
                "raw_provider_reports": raw_reports,
                "generation_attempt_count": len(raw_reports),
                "repair_attempted": len(raw_reports) > 1,
                "boundary": {
                    "read_only_analysis": True,
                    "state_mutation_allowed": False,
                    "operator_review_required": True,
                },
            }
            report_path = generation_dir / f"{role}.json"
            _write_json(report_path, report)
            report["report_path"] = str(report_path.resolve())
            reports.append(report)
    return sorted(reports, key=lambda item: str(item["agent_role"]))


def _ollama_agent_call(
    *,
    model: str,
    ollama_url: str,
    timeout_seconds: int,
) -> AgentCall:
    endpoint = f"{ollama_url.rstrip('/')}/api/chat"

    def call(role: str, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        body = {
            "model": model,
            "stream": False,
            "think": False,
            "format": RESPONSE_JSON_SCHEMA,
            "messages": [
                {
                    "role": "system",
                    "content": _role_instruction(role),
                },
                {"role": "user", "content": prompt},
            ],
            "options": {
                "temperature": 0.2,
                "num_ctx": 8192,
                "num_predict": 1200,
            },
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                provider = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {exc.code}: {detail}") from exc
        content = str(_object(provider.get("message")).get("content") or "")
        if not content.strip():
            raise RuntimeError(
                "Ollama returned an empty response "
                f"(done_reason={provider.get('done_reason')!r}, "
                f"prompt_eval_count={provider.get('prompt_eval_count')!r}, "
                f"eval_count={provider.get('eval_count')!r})"
            )
        payload = _parse_json_response(content)
        return payload, {
            "provider": "ollama",
            "model": model,
            "duration_seconds": time.monotonic() - started,
            "prompt_eval_count": provider.get("prompt_eval_count"),
            "eval_count": provider.get("eval_count"),
            "done_reason": provider.get("done_reason"),
            "raw_content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "raw_content_chars": len(content),
        }

    return call


def _role_instruction(role: str) -> str:
    instructions = {
        "relation_evidence_analyst": (
            "Audit whether the supplied relation evidence supports the claimed delta. "
            "Trace before, after, raw, bounded, and applied values to source events."
        ),
        "counterexample_challenger": (
            "Challenge the relation-learning claims. Find template fallback, identity bias, "
            "replay, cap bypass, hidden state, confounders, and unsafe generalizations."
        ),
        "audit_verifier": (
            "Audit traceability, falsifiability, rollback boundaries, and whether any claim "
            "would improperly change trust, authorization, or normative state."
        ),
    }
    return (
        "You are the CivitasOS controlled-pilot Agent role "
        f"{role}. {instructions[role]} Return JSON only with keys: "
        "verdict, supported_conditions, counterexamples, unresolved_assumptions, "
        "evidence_refs, boundary_attestation. evidence_refs must be a non-empty list "
        "containing only exact record_id strings from task.evidence_refs. Set "
        "boundary_attestation to boolean true to attest that no trust, authorization, "
        "relation, IEM, or normative mutation is requested."
    )


def _role_bound_prompt(role: str, prompt: str, profile: str) -> str:
    return (
        f"Execution profile: {profile}. "
        "This is read-only analysis and the result requires operator review.\n\n"
        + prompt
    )


def _task_prompt(task: dict[str, Any]) -> str:
    return (
        "Analyze this single bounded task. Do not invent evidence and do not propose direct "
        "state changes.\n\n"
        + json.dumps(
            task,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _repair_prompt(
    *,
    task: dict[str, Any],
    previous_payload: dict[str, Any],
    profile: str,
) -> str:
    evidence_ids = sorted(
        str(item.get("record_id") or "")
        for item in _objects(task.get("evidence_refs"))
        if str(item.get("record_id") or "")
    )
    return (
        f"Repair this {profile} controlled-pilot response to satisfy the exact JSON "
        "contract. Preserve the substantive analysis, but return only these required "
        "fields: verdict as string; supported_conditions, counterexamples, and "
        "unresolved_assumptions as arrays of strings; evidence_refs as a non-empty "
        f"array containing only exact values from {json.dumps(evidence_ids)}; and "
        "boundary_attestation as the literal JSON boolean true only because this "
        "analysis requests no trust, relation, IEM, authorization, normative, or "
        "production mutation. Do not describe historical observed changes as changes "
        "requested by this analysis. The authorized task remains hash-bound by the "
        f"runner; task_id={task.get('task_id')}.\n\nPrevious response:\n"
        + json.dumps(previous_payload, ensure_ascii=False, indent=2, sort_keys=True)
    )


def _parse_json_response(content: str) -> dict[str, Any]:
    cleaned = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as original:
        decoder = json.JSONDecoder()
        for index, character in enumerate(cleaned):
            if character != "{":
                continue
            try:
                candidate, _ = decoder.raw_decode(cleaned[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict):
                return candidate
        excerpt = cleaned[:200].replace("\n", "\\n")
        raise ValueError(
            f"Agent response did not contain a JSON object; excerpt={excerpt!r}"
        ) from original
    if not isinstance(value, dict):
        raise ValueError("Agent response must be a JSON object")
    return value


def _valid_agent_payload(
    payload: dict[str, Any],
    task: dict[str, Any],
    *,
    strict_evidence_refs: bool = False,
) -> bool:
    if not REQUIRED_RESPONSE_FIELDS.issubset(payload):
        return False
    boundary = payload.get("boundary_attestation")
    evidence_ids = {
        str(item.get("record_id") or "")
        for item in _objects(task.get("evidence_refs"))
    }
    claimed_refs = _normalize_evidence_refs(
        payload.get("evidence_refs"),
        evidence_ids=evidence_ids,
        reject_unknown=strict_evidence_refs,
    )
    return (
        isinstance(payload.get("supported_conditions"), list)
        and isinstance(payload.get("counterexamples"), list)
        and isinstance(payload.get("unresolved_assumptions"), list)
        and bool(str(payload.get("verdict") or "").strip())
        and bool(claimed_refs)
        and claimed_refs.issubset(evidence_ids)
        and _boundary_attested(boundary)
    )


def _normalize_evidence_refs(
    value: Any,
    *,
    evidence_ids: set[str],
    reject_unknown: bool = False,
) -> set[str]:
    if not isinstance(value, list):
        return set()
    normalized: set[str] = set()
    for item in value:
        text = str(item)
        matches = {evidence_id for evidence_id in evidence_ids if evidence_id in text}
        if len(matches) > 1:
            return set()
        if reject_unknown and len(matches) != 1:
            return set()
        normalized.update(matches)
    return normalized


def _boundary_attested(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        lowered = value.lower()
        return "no" in lowered and (
            "mutation" in lowered
            or all(
                token in lowered
                for token in ("trust", "authorization", "normative")
            )
        )
    if not isinstance(value, dict):
        return False
    if value.get("attested") is True:
        return True
    if (
        value.get("state_unchanged") is True
        and value.get("no_auto_modification") is True
    ):
        return True
    text = json.dumps(value, ensure_ascii=False).lower()
    return "no " in text and (
        "mutation" in text
        or all(token in text for token in ("trust", "authorization", "normative"))
    )


def _reconcile_generations(reports: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [item for item in reports if item.get("passed") is True]
    conditions: dict[str, int] = {}
    counterexamples: list[str] = []
    assumptions: list[str] = []
    for report in valid:
        response = _object(report.get("response"))
        for condition in response.get("supported_conditions", []):
            normalized = str(condition).strip()
            if normalized:
                conditions[normalized] = conditions.get(normalized, 0) + 1
        counterexamples.extend(
            str(item).strip()
            for item in response.get("counterexamples", [])
            if str(item).strip()
        )
        assumptions.extend(
            str(item).strip()
            for item in response.get("unresolved_assumptions", [])
            if str(item).strip()
        )
    return {
        "state": "operator_review_required",
        "valid_agent_report_count": len(valid),
        "candidate_conditions": [
            {"condition": condition, "support_count": count}
            for condition, count in sorted(
                conditions.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
        "counterexamples": sorted(set(counterexamples)),
        "unresolved_assumptions": sorted(set(assumptions)),
        "automatic_adoption_allowed": False,
        "trust_or_authorization_change_allowed": False,
    }


def _claim_authorization(
    *,
    path: Path,
    receipt: dict[str, Any],
    preflight_file: Path,
    started_at: datetime,
    profile: str,
) -> dict[str, Any]:
    value = {
        "schema_version": CONSUMPTION_SCHEMA_VERSION,
        "state": "authorization_consumed",
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "source_preflight": _artifact_ref(preflight_file),
        "consumed_at": started_at.isoformat(),
        "single_use": True,
        "immutable": True,
        "validation_profile": profile,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"single-use authorization already claimed: {path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return value


def _blocked_report(
    *,
    failures: list[str],
    checks: dict[str, bool],
    preflight_file: Path,
    bounded_file: Path,
) -> dict[str, Any]:
    profile = "development"
    if preflight_file.is_file():
        try:
            profile = str(
                _object(json.loads(preflight_file.read_text(encoding="utf-8"))).get(
                    "validation_profile"
                )
                or "development"
            )
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": False,
        "failure_reasons": failures,
        "validation_profile": profile,
        "checks": checks,
        "source_preflight": (
            _artifact_ref(preflight_file) if preflight_file.is_file() else None
        ),
        "source_bounded_plan_report": (
            _artifact_ref(bounded_file) if bounded_file.is_file() else None
        ),
        "readiness": {
            "controlled_pilot_completed": False,
            "operator_review_required": False,
            "automatic_state_change_allowed": False,
            "decision": f"blocked_before_h3_{profile}_controlled_pilot",
        },
    }


def _authorized_scope_valid(scope: dict[str, Any], *, profile: str) -> bool:
    common = (
        1 <= int(scope.get("max_agents", 0)) <= 3
        and scope.get("production_use_allowed") is False
        and scope.get("automatic_rollout_allowed") is False
    )
    if profile == "development":
        return (
            common
            and scope.get("environment") == "development_local_controlled_only"
            and scope.get("max_tasks") == 1
            and 1 <= int(scope.get("max_duration_seconds", 0)) <= 1800
        )
    if profile == "qualification":
        return (
            common
            and scope.get("environment") == "controlled_pilot_only"
            and 1 <= int(scope.get("max_tasks", 0)) <= 3
            and 1 <= int(scope.get("max_duration_seconds", 0)) <= 3600
        )
    return False


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _read_json(
    path: Path,
    failures: list[str],
    label: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    return value


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


def _resolve(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _resolve_ref(value: Any, root: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return _resolve(Path(value), root)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--bounded-plan-report", type=Path, required=True)
    parser.add_argument("--model", default="qwen3.6:latest")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--evidence-report", type=Path, action="append", required=True)
    parser.add_argument("--kill-switch-file", type=Path)
    parser.add_argument("--ack-kill-switch-armed", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    report = run_controlled_pilot(
        preflight_path=args.preflight,
        bounded_plan_report_path=args.bounded_plan_report,
        agent_root=agent_root,
        model=args.model,
        ollama_url=args.ollama_url,
        timeout_seconds=args.timeout_seconds,
        evidence_report_paths=args.evidence_report,
        ack_kill_switch_armed=args.ack_kill_switch_armed,
        kill_switch_file=args.kill_switch_file,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
