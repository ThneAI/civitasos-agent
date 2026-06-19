"""Execute one H.3 profile-bound controlled pilot with local Agent roles."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_controlled_pilot_generation import (
    AGENT_ROLES,
    AgentCall,
    REQUIRED_RESPONSE_FIELDS,
    ollama_agent_call,
    parse_json_response as _parse_json_response,
    run_agent_generations,
    valid_agent_payload as _valid_agent_payload,
)
from benchmarks.h3_controlled_pilot_reconciliation import (
    reconcile_generations as _reconcile_generations,
)
from benchmarks.h3_controlled_pilot_receipts import (
    CONSUMPTION_SCHEMA_VERSION,
    POST_RUN_RECEIPT_SCHEMA_VERSION,
    claim_authorization as _claim_authorization,
    write_post_run_receipt,
)
from benchmarks.h3_evidence import (
    artifact_ref,
    object_value,
    objects_value,
    read_json_object,
    resolve_under_root,
    sha256_file,
    write_json_object,
)
from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    BOUNDARY as PREFLIGHT_BOUNDARY,
)
from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    SCHEMA_VERSION as PREFLIGHT_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-controlled-pilot-runner:v1"
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
    preflight_file = resolve_under_root(preflight_path, agent_root)
    bounded_file = resolve_under_root(bounded_plan_report_path, agent_root)
    now = _as_utc(current_time or datetime.now(timezone.utc))
    failures: list[str] = []
    checks: dict[str, bool] = {}
    preflight = read_json_object(preflight_file, failures, "execution preflight")
    profile = str(object_value(preflight).get("validation_profile") or "development")
    draft = _validate_inputs(
        preflight=preflight,
        bounded_plan_report_path=bounded_file,
        ack_kill_switch_armed=ack_kill_switch_armed,
        current_time=now,
        failures=failures,
        checks=checks,
    )
    receipt = object_value(object_value(preflight).get("authorization_receipt"))
    controls = object_value(receipt.get("controls"))
    sink = _resolve_ref(controls.get("post_run_receipt_sink_ref"), agent_root)
    kill_file = resolve_under_root(kill_switch_file, agent_root) if kill_switch_file else None
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
    write_json_object(task_path, task)
    generation_dir = sink.with_name(f"{sink.stem}.generations")
    generation_dir.mkdir(parents=True, exist_ok=True)

    call = agent_call or ollama_agent_call(
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
        generation_reports = run_agent_generations(
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
                object_value(receipt.get("authorized_scope")).get("max_agents", 0)
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
        <= int(object_value(receipt.get("authorized_scope")).get("max_duration_seconds", 0)),
    )
    passed = not run_failures and all(checks.values())
    reconciliation = _reconcile_generations(generation_reports)
    write_post_run_receipt(
        path=sink,
        passed=passed,
        failures=run_failures,
        profile=profile,
        receipt=receipt,
        consumption_path=consumption_path,
        preflight_file=preflight_file,
        bounded_file=bounded_file,
        task_path=task_path,
        generation_reports=generation_reports,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
        model=model,
        agent_roles=list(AGENT_ROLES),
        reconciliation=reconciliation,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": run_failures,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "checks": checks,
        "authorization_consumption": artifact_ref(consumption_path),
        "post_run_receipt": artifact_ref(sink),
        "task": artifact_ref(task_path),
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
    readiness = object_value(preflight.get("readiness"))
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
    receipt = object_value(preflight.get("authorization_receipt"))
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
    scope = object_value(receipt.get("authorized_scope"))
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
    bounded = read_json_object(bounded_plan_report_path, failures, "bounded plan report")
    drafts = objects_value(object_value(bounded).get("draft_surface", {}).get("drafts"))
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
    evidence_refs = objects_value(object_value(draft.get("source_binding")).get("evidence_refs"))
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
        "negative_control_checks": object_value(
            draft.get("source_binding")
        ).get("negative_control_checks", {}),
        "evidence_refs": task_evidence_refs,
        "evidence_snapshots": evidence_snapshots,
        "source_bounded_plan_report": artifact_ref(bounded_file),
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
        path = resolve_under_root(raw_path, agent_root)
        digest = sha256_file(path)
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
            summaries = object_value(value).get("worker_summaries")
            for record in object_value(summaries).values():
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
    relation = object_value(record.get("relation_update"))
    iem = object_value(record.get("iem_update"))
    expectation_updates = objects_value(relation.get("expectation_updates"))
    full_provenance = next(
        (
            object_value(object_value(item.get("update_params")).get("delta_provenance"))
            for item in expectation_updates
            if object_value(object_value(item.get("update_params")).get("delta_provenance"))
        ),
        {},
    )
    provenance = _compact_learning_provenance(full_provenance)
    return {
        "task_id": record.get("task_id"),
        "event_kind": record.get("event_kind"),
        "observed_at": record.get("observed_at"),
        "authorization_changed": object_value(
            record.get("authorization_change")
        ).get("changed"),
        "relation_update": {
            "before": relation.get("before"),
            "after": relation.get("after"),
            "action_bias": _compact_action_bias(
                object_value(relation.get("action_bias"))
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
        for item in objects_value(value.get("components"))
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
                object_value(json.loads(preflight_file.read_text(encoding="utf-8"))).get(
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
            artifact_ref(preflight_file) if preflight_file.is_file() else None
        ),
        "source_bounded_plan_report": (
            artifact_ref(bounded_file) if bounded_file.is_file() else None
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


def _resolve_ref(value: Any, root: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return resolve_under_root(Path(value), root)


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
