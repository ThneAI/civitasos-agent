"""H.2 outcome ledger diagnostic report.

Builds a post-delivery outcome ledger from existing benchmark artifacts. The
report is intentionally low-cost: it reads summary, backend terminal state,
H1 judge rows, raw ticks, and optional delayed outcome seeds; it does not start
backend, agents, or LLMs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-outcome-report:v1"
BACKEND_OUTCOME_EVENTS_SCHEMA_VERSION = "h2-delayed-outcome-events:v1"
REPEATED_DELAYED_PATTERN_MIN_COUNT = 2
_DESIRED_SLOW_DRIFT_EVENT_KINDS = {
    "post_delivery_dispute",
    "post_delivery_failure",
    "relation_repair_relapse",
    "governance_rollback",
    "economic_deviation",
}


@dataclass(frozen=True)
class TaskOutcomeRecord:
    record_id: str
    task_id: str
    agent_alias: str
    agent_id: str
    delivered_at: str | None
    h1_judge_ref: list[dict[str, Any]]
    verifier_evidence_ref: list[dict[str, Any]]
    immediate_result: dict[str, Any]
    delayed_events: list[dict[str, Any]]
    dispute_refs: list[str]
    reuse_refs: list[str]
    relation_delta: dict[str, Any]
    reputation_delta: dict[str, Any]
    economic_delta: dict[str, Any]
    governance_delta: dict[str, Any]
    telos_outcome_score: float | None
    iem_update_candidates: list[dict[str, Any]]
    normative_update_blocked_or_governed: dict[str, Any]
    evidence_status: dict[str, Any]


@dataclass
class RawTaskEvidence:
    agent_id: str = ""
    delivered_at: str | None = None
    actions: list[str] = field(default_factory=list)
    verifier_refs: list[dict[str, Any]] = field(default_factory=list)
    relation_context_ids: set[str] = field(default_factory=set)
    relation_memory_refs: set[str] = field(default_factory=set)
    delayed_events: list[dict[str, Any]] = field(default_factory=list)
    dispute_refs: set[str] = field(default_factory=set)
    normative_required: bool = False
    normative_local_update_blocked: bool = False
    governed_revision_present: bool = False
    predicted_update_present: bool = False
    desired_slow_drift_present: bool = False
    reputation_signal_present: bool = False
    economic_signal_present: bool = False
    governance_signal_present: bool = False


def build_h2_outcome_report(
    *,
    run_root: Path,
    judge_report_path: Path | None,
    agent_root: Path,
    delayed_outcomes_path: Path | None = None,
    backend_outcome_events_path: Path | None = None,
    min_outcome_ledger_coverage_ratio: float = 1.0,
    min_h1_evidence_ref_ratio: float = 1.0,
    min_normative_local_update_blocked_ratio: float = 1.0,
    min_delayed_verifier_coverage_ratio: float | None = None,
) -> dict[str, Any]:
    run_root = _resolve_path(run_root, agent_root)
    judge_report_path = (
        run_root / "h1_llm_judge_report.json"
        if judge_report_path is None
        else _resolve_path(judge_report_path, agent_root)
    )
    failures: list[str] = []
    judge_refs = _load_h1_judge_refs(judge_report_path, failures)
    delayed_outcomes_path = (
        None if delayed_outcomes_path is None
        else _resolve_path(delayed_outcomes_path, agent_root)
    )
    backend_outcome_events_path = (
        None if backend_outcome_events_path is None
        else _resolve_path(backend_outcome_events_path, agent_root)
    )
    delayed_events = _merge_delayed_event_maps(
        _load_delayed_outcome_events(delayed_outcomes_path, failures),
        _load_backend_outcome_events(backend_outcome_events_path, failures),
    )
    records, expected_task_count = _build_records(run_root, judge_refs, delayed_events, failures)
    metrics = _metrics(records, expected_task_count)
    checks = _checks(
        metrics,
        min_outcome_ledger_coverage_ratio=min_outcome_ledger_coverage_ratio,
        min_h1_evidence_ref_ratio=min_h1_evidence_ref_ratio,
        min_normative_local_update_blocked_ratio=min_normative_local_update_blocked_ratio,
        min_delayed_verifier_coverage_ratio=min_delayed_verifier_coverage_ratio,
        failures=failures,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "failure_reasons": failures,
        "run_root": str(run_root),
        "judge_report_path": str(judge_report_path),
        "delayed_outcomes_path": None if delayed_outcomes_path is None else str(delayed_outcomes_path),
        "backend_outcome_events_path": (
            None if backend_outcome_events_path is None else str(backend_outcome_events_path)
        ),
        "thresholds": {
            "min_outcome_ledger_coverage_ratio": min_outcome_ledger_coverage_ratio,
            "min_h1_evidence_ref_ratio": min_h1_evidence_ref_ratio,
            "min_normative_local_update_blocked_ratio": min_normative_local_update_blocked_ratio,
            "min_delayed_verifier_coverage_ratio": min_delayed_verifier_coverage_ratio,
        },
        "checks": checks,
        "metrics": metrics,
        "record_schema": _record_schema(),
        "records": [asdict(record) for record in records],
    }


def _build_records(
    run_root: Path,
    judge_refs: dict[tuple[str, str], list[dict[str, Any]]],
    delayed_events: dict[tuple[str, str], list[dict[str, Any]]],
    failures: list[str],
) -> tuple[list[TaskOutcomeRecord], int]:
    records: list[TaskOutcomeRecord] = []
    expected_task_count = 0
    repeated_pattern_counts = _repeated_delayed_pattern_counts(delayed_events)
    for run_dir in _discover_run_dirs(run_root):
        alias = _agent_alias_from_run_dir(run_dir)
        summary = _read_json(run_dir / "summary.json", failures)
        tasks = _summary_tasks(summary)
        expected_task_count += len(tasks)
        run_finished_at = summary.get("finished_at") if isinstance(summary, dict) else None
        for task in tasks:
            task_id = str(task.get("task_id") or "")
            if not task_id:
                continue
            raw = _load_raw_task_evidence(run_dir, task_id)
            terminal_state = _load_terminal_state(run_dir, task_id)
            backend_task_id = _backend_task_id(run_dir, task_id, terminal_state)
            refs = judge_refs.get((alias, task_id), [])
            final_output = _final_output(task, terminal_state)
            records.append(
                _make_record(
                    alias=alias,
                    run_dir=run_dir,
                    task_id=task_id,
                    task=task,
                    raw=raw,
                    terminal_state=terminal_state,
                    h1_judge_refs=refs,
                    seeded_delayed_events=_delayed_events_for_task(
                        delayed_events,
                        alias=alias,
                        task_id=task_id,
                        backend_task_id=backend_task_id,
                    ),
                    repeated_pattern_counts=repeated_pattern_counts,
                    final_output=final_output,
                    fallback_delivered_at=str(run_finished_at) if run_finished_at else None,
                )
            )
    return records, expected_task_count


def _make_record(
    *,
    alias: str,
    run_dir: Path,
    task_id: str,
    task: dict[str, Any],
    raw: RawTaskEvidence,
    terminal_state: dict[str, Any],
    h1_judge_refs: list[dict[str, Any]],
    seeded_delayed_events: list[dict[str, Any]],
    repeated_pattern_counts: dict[tuple[str, str], int],
    final_output: str | None,
    fallback_delivered_at: str | None,
) -> TaskOutcomeRecord:
    verifier_required = _verifier_required(task_id, h1_judge_refs, raw)
    delayed_events = [*raw.delayed_events, *seeded_delayed_events]
    normative_status = _normative_status(raw, delayed_events)
    immediate_result = _immediate_result(task, terminal_state, h1_judge_refs, final_output)
    relation_delta = _relation_delta(task_id, raw, delayed_events)
    delayed_reputation_signal = _delayed_signal(delayed_events, "reputation")
    delayed_economic_signal = _delayed_signal(delayed_events, "economic")
    reputation_delta = _signal_delta(
        raw.reputation_signal_present or delayed_reputation_signal,
        "reputation",
        source="delayed_outcome" if delayed_reputation_signal else "raw_h0_trace",
    )
    economic_delta = _signal_delta(
        raw.economic_signal_present or delayed_economic_signal,
        "economic",
        source="delayed_outcome" if delayed_economic_signal else "raw_h0_trace",
    )
    governance_delta = _governance_delta(raw, delayed_events)
    iem_candidates = _iem_update_candidates(
        alias=alias,
        task_id=task_id,
        h1_judge_refs=h1_judge_refs,
        relation_delta=relation_delta,
        normative_status=normative_status,
        raw=raw,
        delayed_events=delayed_events,
        repeated_pattern_counts=repeated_pattern_counts,
    )
    evidence_status = {
        "h1_judge_ref_present": bool(h1_judge_refs),
        "verifier_required": verifier_required,
        "verifier_ref_present": bool(raw.verifier_refs),
        "h1_evidence_ref_ok": (
            bool(h1_judge_refs or raw.verifier_refs)
            and (not verifier_required or bool(raw.verifier_refs))
        ),
    }
    return TaskOutcomeRecord(
        record_id=f"{alias}:{task_id}",
        task_id=task_id,
        agent_alias=alias,
        agent_id=_record_agent_id(raw, delayed_events),
        delivered_at=raw.delivered_at or fallback_delivered_at,
        h1_judge_ref=h1_judge_refs,
        verifier_evidence_ref=raw.verifier_refs,
        immediate_result=immediate_result,
        delayed_events=delayed_events,
        dispute_refs=sorted(raw.dispute_refs | _delayed_refs(delayed_events, "dispute_ref")),
        reuse_refs=sorted(raw.relation_memory_refs | _delayed_refs(delayed_events, "reuse_ref")),
        relation_delta=relation_delta,
        reputation_delta=reputation_delta,
        economic_delta=economic_delta,
        governance_delta=governance_delta,
        telos_outcome_score=_telos_outcome_score(h1_judge_refs),
        iem_update_candidates=iem_candidates,
        normative_update_blocked_or_governed=normative_status,
        evidence_status=evidence_status,
    )


def _load_h1_judge_refs(
    path: Path,
    failures: list[str],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    payload = _read_json(path, failures)
    refs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    if not payload:
        return refs
    rows = payload.get("rows")
    if not isinstance(rows, list):
        failures.append(f"H1 judge report missing rows: {path}")
        return refs
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        alias = str(row.get("agent_alias") or _agent_alias_from_run_ref(row.get("run_dir")))
        task_id = str(row.get("task_id") or "")
        if not alias or not task_id:
            continue
        ref = {
            "ref_id": f"h1_judge:{alias}:{task_id}:{row.get('criterion_index')}:{row_index}",
            "report_path": str(path),
            "row_index": row_index,
            "criterion_index": row.get("criterion_index"),
            "criterion_desc": row.get("criterion_desc"),
            "passed": row.get("passed"),
            "score": row.get("score"),
            "model": row.get("model"),
            "prompt_version": row.get("prompt_version"),
            "prompt_hash": row.get("prompt_hash"),
        }
        refs.setdefault((alias, task_id), []).append(ref)
    return refs


def _load_delayed_outcome_events(
    path: Path | None,
    failures: list[str],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    if path is None:
        return {}
    if not path.is_file():
        failures.append(f"missing delayed outcome seed file: {path}")
        return {}
    events: dict[tuple[str, str], list[dict[str, Any]]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        failures.append(f"cannot read delayed outcome seed file {path}: {exc}")
        return {}
    for line_no, line in enumerate(lines, start=1):
        raw = line.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            failures.append(f"invalid delayed outcome JSONL {path}:{line_no}: {exc}")
            continue
        event = _normalize_delayed_event(payload, path=path, line_no=line_no, failures=failures)
        if event is None:
            continue
        events.setdefault((event["agent_alias"], event["task_id"]), []).append(event)
    return events


def _load_backend_outcome_events(
    path: Path | None,
    failures: list[str],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    if path is None:
        return {}
    if not path.is_file():
        failures.append(f"missing backend outcome events file: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid backend outcome events JSON {path}: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"backend outcome events payload must be object: {path}")
        return {}
    schema_version = payload.get("schema_version")
    if schema_version != BACKEND_OUTCOME_EVENTS_SCHEMA_VERSION:
        failures.append(
            "backend outcome events schema_version mismatch: "
            f"{schema_version!r} != {BACKEND_OUTCOME_EVENTS_SCHEMA_VERSION!r} at {path}"
        )
        return {}
    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        failures.append(f"backend outcome events missing events array: {path}")
        return {}
    events: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for index, raw_event in enumerate(raw_events, start=1):
        event = _normalize_delayed_event(
            raw_event,
            path=path,
            line_no=index,
            failures=failures,
        )
        if event is None:
            continue
        events.setdefault((event["agent_alias"], event["task_id"]), []).append(event)
    return events


def _merge_delayed_event_maps(
    *maps: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    merged: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen: set[tuple[tuple[str, str], str]] = set()
    for event_map in maps:
        for key, events in event_map.items():
            for event in events:
                event_id = str(event.get("event_id") or "")
                dedupe_key = (key, event_id)
                if event_id and dedupe_key in seen:
                    continue
                if event_id:
                    seen.add(dedupe_key)
                merged.setdefault(key, []).append(event)
    return merged


def _delayed_events_for_task(
    delayed_events: dict[tuple[str, str], list[dict[str, Any]]],
    *,
    alias: str,
    task_id: str,
    backend_task_id: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    keys = [(alias, task_id), (alias, backend_task_id)]
    if backend_task_id:
        keys.extend(
            key for key in delayed_events
            if key[1] == backend_task_id and key[0] != alias
        )
    for key in keys:
        if not key[1]:
            continue
        for event in delayed_events.get(key, []):
            event_id = str(event.get("event_id") or "")
            if event_id and event_id in seen:
                continue
            if event_id:
                seen.add(event_id)
            linked = dict(event)
            if linked.get("task_id") != task_id:
                linked.setdefault("backend_task_id", linked.get("task_id"))
                linked["task_id"] = task_id
            out.append(linked)
    return out


def _normalize_delayed_event(
    payload: object,
    *,
    path: Path,
    line_no: int,
    failures: list[str],
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        failures.append(f"delayed outcome event must be object at {path}:{line_no}")
        return None
    required = (
        "event_id",
        "agent_alias",
        "task_id",
        "event_kind",
        "observed_at",
        "source",
        "subject",
        "evidence_ref",
        "verifier_or_settlement_read",
    )
    missing = [key for key in required if key not in payload or payload.get(key) in (None, "")]
    if missing:
        failures.append(f"delayed outcome event missing {missing} at {path}:{line_no}")
        return None
    evidence_ref = payload.get("evidence_ref")
    if isinstance(evidence_ref, str):
        evidence_ref = {"ref_id": evidence_ref, "source": payload.get("source")}
    if not isinstance(evidence_ref, dict) or not evidence_ref.get("ref_id"):
        failures.append(f"delayed outcome evidence_ref must include ref_id at {path}:{line_no}")
        return None
    event = {
        "event_id": str(payload["event_id"]),
        "agent_alias": str(payload["agent_alias"]),
        "task_id": str(payload["task_id"]),
        "event_kind": str(payload["event_kind"]),
        "observed_at": str(payload["observed_at"]),
        "source": str(payload["source"]),
        "subject": str(payload["subject"]),
        "evidence_ref": evidence_ref,
        "verifier_or_settlement_read": bool(payload.get("verifier_or_settlement_read")),
    }
    for key in (
        "agent_id",
        "requester",
        "requester_id",
        "outcome_status",
        "dispute_ref",
        "reuse_ref",
        "relation_id",
        "r2r_relation_id",
        "r2r_relation",
        "relation_memory_ref",
        "governance_ref",
        "economic_ref",
        "reputation_ref",
        "notes",
    ):
        if payload.get(key) not in (None, ""):
            event[key] = payload[key]
    return event


def _load_raw_task_evidence(run_dir: Path, task_id: str) -> RawTaskEvidence:
    evidence = RawTaskEvidence()
    path = run_dir / "raw_ticks" / f"{task_id}.csv"
    if not path.is_file():
        return evidence
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                _consume_raw_row(evidence, row, path)
    except OSError:
        return evidence
    return evidence


def _consume_raw_row(evidence: RawTaskEvidence, row: dict[str, str], path: Path) -> None:
    action = str(row.get("decision_action") or "")
    reasoning = str(row.get("decision_reasoning") or "")
    timestamp = str(row.get("timestamp") or "")
    if row.get("agent_id") and not evidence.agent_id:
        evidence.agent_id = str(row.get("agent_id"))
    if action:
        evidence.actions.append(action)
    if action == "task_execute" and timestamp:
        evidence.delivered_at = timestamp
    if "H1 verifier-before-delivery bridge" in reasoning:
        evidence.verifier_refs.append(_raw_ref(path, row, action, reasoning))
    _consume_relation_row(evidence, row)
    _consume_h0_row(evidence, row)
    _consume_delayed_row(evidence, row, path, action)


def _consume_relation_row(evidence: RawTaskEvidence, row: dict[str, str]) -> None:
    relation_context_id = str(row.get("relation_context_id") or "").strip()
    if relation_context_id:
        evidence.relation_context_ids.add(relation_context_id)
    for ref in _split_refs(row.get("relation_memory_refs")):
        evidence.relation_memory_refs.add(ref)
    if _bool(row.get("relation_pair_failure_ref_present")):
        evidence.dispute_refs.add("relation_pair_failure_ref")


def _consume_h0_row(evidence: RawTaskEvidence, row: dict[str, str]) -> None:
    evidence.normative_required = evidence.normative_required or any(
        _bool(row.get(field))
        for field in (
            "h0_constitutional_surprise_present",
            "h0_normative_governance_trigger_present",
            "h0_governed_revision_present",
            "h0_normative_local_update_blocked",
        )
    )
    evidence.normative_local_update_blocked = (
        evidence.normative_local_update_blocked
        or _bool(row.get("h0_normative_local_update_blocked"))
    )
    evidence.governed_revision_present = (
        evidence.governed_revision_present or _bool(row.get("h0_governed_revision_present"))
    )
    evidence.predicted_update_present = (
        evidence.predicted_update_present or _bool(row.get("h0_predicted_update_present"))
    )
    evidence.desired_slow_drift_present = (
        evidence.desired_slow_drift_present or _bool(row.get("h0_desired_slow_drift_present"))
    )
    evidence.reputation_signal_present = (
        evidence.reputation_signal_present or _bool(row.get("h0_reputation_surprise_present"))
    )
    evidence.economic_signal_present = (
        evidence.economic_signal_present or _bool(row.get("h0_economic_surprise_present"))
    )
    evidence.governance_signal_present = evidence.governance_signal_present or any(
        _bool(row.get(field))
        for field in ("h0_governance_surprise_present", "h0_normative_governance_trigger_present")
    )


def _consume_delayed_row(
    evidence: RawTaskEvidence,
    row: dict[str, str],
    path: Path,
    action: str,
) -> None:
    if action not in {"pool_fail", "pool_failures", "challenge", "dispute", "settle", "confirm"}:
        return
    event_ref = _raw_ref(path, row, action, str(row.get("decision_reasoning") or ""))
    evidence.delayed_events.append({
        "event_kind": action,
        "source": "raw_tick",
        "observed_at": row.get("timestamp"),
        "subject": row.get("agent_id"),
        "evidence_ref": event_ref,
        "verifier_or_settlement_read": action in {"settle", "confirm", "pool_failures"},
    })


def _raw_ref(path: Path, row: dict[str, str], action: str, reasoning: str) -> dict[str, Any]:
    return {
        "ref_id": f"raw_tick:{path.stem}:{row.get('tick_seq')}",
        "raw_tick_path": str(path),
        "tick_seq": _int(row.get("tick_seq")),
        "tick_id": row.get("tick_id"),
        "timestamp": row.get("timestamp"),
        "action": action,
        "reasoning": reasoning,
    }


def _immediate_result(
    task: dict[str, Any],
    terminal_state: dict[str, Any],
    h1_judge_refs: list[dict[str, Any]],
    final_output: str | None,
) -> dict[str, Any]:
    judge_values = [ref.get("passed") for ref in h1_judge_refs]
    h1_judge_passed = all(value is True for value in judge_values) if judge_values else None
    return {
        "terminal_status": terminal_state.get("status"),
        "sentinel_kind": task.get("sentinel_kind"),
        "sentinel_reason": task.get("sentinel_reason"),
        "agent_self_reported_success": task.get("agent_self_reported_success"),
        "h1_judge_passed": h1_judge_passed,
        "final_output_present": final_output is not None,
        "final_output_sha256": _sha256(final_output),
        "failure_reason": terminal_state.get("failure_reason"),
        "challenge_deadline_at": terminal_state.get("challenge_deadline_at"),
    }


def _relation_delta(
    task_id: str,
    raw: RawTaskEvidence,
    delayed_events: list[dict[str, Any]],
) -> dict[str, Any]:
    delayed_relation_refs = _delayed_refs(delayed_events, "relation_memory_ref")
    delayed_relation_kinds = {
        event.get("event_kind") for event in delayed_events
        if str(event.get("event_kind") or "").startswith("relation_")
    }
    relation_task = task_id.startswith("G") or bool(
        raw.relation_context_ids or raw.relation_memory_refs or delayed_relation_refs or delayed_relation_kinds
    )
    feedback_recorded = bool(raw.relation_context_ids or raw.relation_memory_refs or delayed_relation_refs)
    return {
        "relation_task": relation_task,
        "feedback_recorded": feedback_recorded,
        "relation_context_ids": sorted(raw.relation_context_ids),
        "relation_memory_refs": sorted(raw.relation_memory_refs | delayed_relation_refs),
        "delayed_relation_event_kinds": sorted(str(kind) for kind in delayed_relation_kinds if kind),
    }


def _signal_delta(observed: bool, name: str, *, source: str) -> dict[str, Any]:
    return {"signal": name, "observed": observed, "source": source if observed else None}


def _governance_delta(raw: RawTaskEvidence, delayed_events: list[dict[str, Any]]) -> dict[str, Any]:
    delayed_governance = _delayed_signal(delayed_events, "governance")
    return {
        "observed": raw.governance_signal_present or raw.governed_revision_present or delayed_governance,
        "governed_revision_present": raw.governed_revision_present,
        "source": "delayed_outcome" if delayed_governance else ("raw_h0_trace" if raw.governance_signal_present else None),
        "delayed_governance_refs": sorted(_delayed_refs(delayed_events, "governance_ref")),
    }


def _normative_status(raw: RawTaskEvidence, delayed_events: list[dict[str, Any]]) -> dict[str, Any]:
    delayed_normative = any(
        str(event.get("event_kind") or "").startswith(("governance_", "normative_"))
        for event in delayed_events
    )
    delayed_governed = bool(_delayed_refs(delayed_events, "governance_ref"))
    blocked_or_governed = (
        not (raw.normative_required or delayed_normative)
        or raw.normative_local_update_blocked
        or raw.governed_revision_present
        or delayed_governed
    )
    return {
        "required": raw.normative_required or delayed_normative,
        "local_update_blocked": raw.normative_local_update_blocked,
        "governed_revision_present": raw.governed_revision_present or delayed_governed,
        "blocked_or_governed": blocked_or_governed,
        "local_mutation_allowed": False,
    }


def _iem_update_candidates(
    *,
    alias: str,
    task_id: str,
    h1_judge_refs: list[dict[str, Any]],
    relation_delta: dict[str, Any],
    normative_status: dict[str, Any],
    raw: RawTaskEvidence,
    delayed_events: list[dict[str, Any]],
    repeated_pattern_counts: dict[tuple[str, str], int],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if h1_judge_refs:
        candidates.append({
            "state": "Predicted",
            "update_kind": "post_delivery_telos_observation",
            "task_id": task_id,
            "source_refs": [ref["ref_id"] for ref in h1_judge_refs],
        })
    else:
        candidates.append({
            "state": "Predicted",
            "update_kind": "post_delivery_terminal_observation",
            "task_id": task_id,
            "source_refs": [f"terminal_state:{task_id}"],
        })
    if relation_delta.get("feedback_recorded"):
        candidates.append({
            "state": "Predicted",
            "update_kind": "relation_outcome_feedback",
            "task_id": task_id,
            "source_refs": relation_delta.get("relation_memory_refs", []),
        })
    if delayed_events:
        candidates.append({
            "state": "Predicted",
            "update_kind": "delayed_outcome_observation",
            "task_id": task_id,
            "source_refs": [event["evidence_ref"]["ref_id"] for event in delayed_events],
            "event_kinds": [event["event_kind"] for event in delayed_events],
        })
    for event_kind, pattern_count in _record_repeated_pattern_counts(
        alias=alias,
        delayed_events=delayed_events,
        repeated_pattern_counts=repeated_pattern_counts,
    ).items():
        candidates.append({
            "state": "Desired",
            "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
            "task_id": task_id,
            "event_kind": event_kind,
            "pattern_count": pattern_count,
            "source_refs": [
                event["evidence_ref"]["ref_id"] for event in delayed_events
                if event.get("event_kind") == event_kind
            ],
            "requires_repeated_pattern": True,
            "local_mutation_allowed": False,
        })
    if raw.desired_slow_drift_present:
        candidates.append({
            "state": "Desired",
            "update_kind": "slow_drift_candidate",
            "task_id": task_id,
            "requires_repeated_pattern": True,
        })
    if normative_status.get("required"):
        candidates.append({
            "state": "Normative",
            "update_kind": "governance_trace_only",
            "task_id": task_id,
            "local_mutation_allowed": False,
            "blocked_or_governed": normative_status.get("blocked_or_governed"),
        })
    return candidates


def _record_repeated_pattern_counts(
    *,
    alias: str,
    delayed_events: list[dict[str, Any]],
    repeated_pattern_counts: dict[tuple[str, str], int],
) -> dict[str, int]:
    out: dict[str, int] = {}
    for event in delayed_events:
        event_kind = str(event.get("event_kind") or "")
        if not event_kind:
            continue
        pattern_count = max(
            repeated_pattern_counts.get((identity, event_kind), 0)
            for identity in _delayed_event_identity_keys(event, fallback_alias=alias)
        )
        if pattern_count >= REPEATED_DELAYED_PATTERN_MIN_COUNT:
            out[event_kind] = max(out.get(event_kind, 0), pattern_count)
    return dict(sorted(out.items()))


def _repeated_delayed_pattern_counts(
    delayed_events: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}
    for (alias, _task_id), events in delayed_events.items():
        for event in events:
            event_kind = str(event.get("event_kind") or "")
            if not _is_desired_slow_drift_event_kind(event_kind):
                continue
            key = (alias, event_kind)
            counts[key] = counts.get(key, 0) + 1
    return {
        key: count for key, count in counts.items()
        if count >= REPEATED_DELAYED_PATTERN_MIN_COUNT
    }


def _delayed_event_identity_keys(
    event: dict[str, Any],
    *,
    fallback_alias: str,
) -> set[str]:
    keys = {fallback_alias}
    for field_name in ("agent_alias", "agent_id", "subject"):
        value = str(event.get(field_name) or "").strip()
        if value:
            keys.add(value)
    return keys


def _is_desired_slow_drift_event_kind(event_kind: str) -> bool:
    if event_kind in _DESIRED_SLOW_DRIFT_EVENT_KINDS:
        return True
    return event_kind.startswith(("post_delivery_failure", "post_delivery_dispute"))


def _record_agent_id(raw: RawTaskEvidence, delayed_events: list[dict[str, Any]]) -> str:
    if raw.agent_id:
        return raw.agent_id
    for event in delayed_events:
        for key in ("agent_id", "subject"):
            value = str(event.get(key) or "").strip()
            if value:
                return value
    return ""


def _delayed_signal(delayed_events: list[dict[str, Any]], name: str) -> bool:
    return any(
        str(event.get("event_kind") or "").startswith(f"{name}_")
        or event.get(f"{name}_ref") not in (None, "")
        for event in delayed_events
    )


def _delayed_refs(delayed_events: list[dict[str, Any]], key: str) -> set[str]:
    return {str(event[key]) for event in delayed_events if event.get(key) not in (None, "")}


def _metrics(records: list[TaskOutcomeRecord], expected_task_count: int) -> dict[str, Any]:
    total = len(records)
    h1_evidence_required = [
        record for record in records
        if record.evidence_status["h1_judge_ref_present"]
        or record.evidence_status["verifier_required"]
    ]
    evidence_ok = sum(
        1 for record in h1_evidence_required
        if record.evidence_status["h1_evidence_ref_ok"]
    )
    iem_candidates = sum(1 for record in records if record.iem_update_candidates)
    delayed_records = [record for record in records if record.delayed_events]
    delayed_covered = sum(1 for record in delayed_records if _delayed_events_covered(record))
    normative_records = [record for record in records if record.normative_update_blocked_or_governed["required"]]
    normative_ok = sum(
        1 for record in normative_records
        if record.normative_update_blocked_or_governed["blocked_or_governed"]
    )
    relation_records = [record for record in records if record.relation_delta["relation_task"]]
    relation_feedback = sum(1 for record in relation_records if record.relation_delta["feedback_recorded"])
    verifier_required = [record for record in records if record.evidence_status["verifier_required"]]
    verifier_ref = sum(1 for record in verifier_required if record.evidence_status["verifier_ref_present"])
    return {
        "expected_task_count": expected_task_count,
        "outcome_record_count": total,
        "outcome_ledger_coverage_ratio": _ratio(total, expected_task_count),
        "h1_evidence_required_record_count": len(h1_evidence_required),
        "h1_evidence_ref_ratio": _ratio(evidence_ok, len(h1_evidence_required)),
        "verifier_required_record_count": len(verifier_required),
        "verifier_evidence_ref_ratio": _ratio(verifier_ref, len(verifier_required)),
        "delayed_event_count": sum(len(record.delayed_events) for record in records),
        "delayed_event_record_count": len(delayed_records),
        "delayed_event_kind_counts": _delayed_event_kind_counts(records),
        "delayed_verifier_coverage_ratio": (
            _ratio(delayed_covered, len(delayed_records)) if delayed_records else None
        ),
        "iem_update_candidate_ratio": _ratio(iem_candidates, total),
        "normative_record_count": len(normative_records),
        "normative_local_update_blocked_ratio": _ratio(normative_ok, len(normative_records), empty=1.0),
        "relation_record_count": len(relation_records),
        "relation_outcome_feedback_ratio": (
            _ratio(relation_feedback, len(relation_records)) if relation_records else None
        ),
    }


def _checks(
    metrics: dict[str, Any],
    *,
    min_outcome_ledger_coverage_ratio: float,
    min_h1_evidence_ref_ratio: float,
    min_normative_local_update_blocked_ratio: float,
    min_delayed_verifier_coverage_ratio: float | None,
    failures: list[str],
) -> dict[str, bool]:
    checks = {
        "outcome_ledger_coverage_ratio": _meets(
            metrics.get("outcome_ledger_coverage_ratio"),
            min_outcome_ledger_coverage_ratio,
        ),
        "h1_evidence_ref_ratio": _meets(
            metrics.get("h1_evidence_ref_ratio"),
            min_h1_evidence_ref_ratio,
        ),
        "normative_local_update_blocked_ratio": _meets(
            metrics.get("normative_local_update_blocked_ratio"),
            min_normative_local_update_blocked_ratio,
        ),
    }
    if min_delayed_verifier_coverage_ratio is not None:
        checks["delayed_verifier_coverage_ratio"] = _meets(
            metrics.get("delayed_verifier_coverage_ratio"),
            min_delayed_verifier_coverage_ratio,
        )
    for name, passed in checks.items():
        if not passed:
            failures.append(f"{name} below H2 threshold")
    return checks


def _delayed_event_kind_counts(records: list[TaskOutcomeRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        for event in record.delayed_events:
            key = str(event.get("event_kind") or "unknown")
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _delayed_events_covered(record: TaskOutcomeRecord) -> bool:
    return all(bool(event.get("verifier_or_settlement_read")) for event in record.delayed_events)


def _verifier_required(
    task_id: str,
    h1_judge_refs: list[dict[str, Any]],
    raw: RawTaskEvidence,
) -> bool:
    if raw.verifier_refs or "verifier" in task_id.lower():
        return True
    text = " ".join(
        str(ref.get("criterion_desc") or "") for ref in h1_judge_refs
    ).lower()
    return "verifier" in text or "验证" in text


def _telos_outcome_score(h1_judge_refs: list[dict[str, Any]]) -> float | None:
    scores = [_float(ref.get("score")) for ref in h1_judge_refs]
    materialized = [score for score in scores if score is not None]
    return sum(materialized) / len(materialized) if materialized else None


def _discover_run_dirs(run_root: Path) -> list[Path]:
    return sorted(path for path in run_root.iterdir() if path.is_dir() and path.name.startswith("baseline-"))


def _summary_tasks(summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(summary, dict) or not isinstance(summary.get("tasks"), list):
        return []
    return [task for task in summary["tasks"] if isinstance(task, dict)]


def _load_terminal_state(run_dir: Path, task_id: str) -> dict[str, Any]:
    path = run_dir / "tasks" / task_id / "backend_terminal_state.json"
    payload = _read_json(path, [])
    return payload or {}


def _backend_task_id(run_dir: Path, task_id: str, terminal_state: dict[str, Any]) -> str:
    path = run_dir / "tasks" / task_id / "backend_task_id.txt"
    if path.is_file():
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if value:
            return value
    value = str(terminal_state.get("task_id") or "").strip()
    return value if value and value != task_id else ""


def _final_output(task: dict[str, Any], terminal_state: dict[str, Any]) -> str | None:
    output = terminal_state.get("output") if terminal_state else None
    if output not in (None, ""):
        return _output_to_text(output)
    return _output_to_text(task.get("final_output"))


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        if failures is not None:
            failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if failures is not None:
            failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    return payload if isinstance(payload, dict) else None


def _record_schema() -> dict[str, Any]:
    fields = [field_name for field_name in TaskOutcomeRecord.__dataclass_fields__]
    return {
        "name": "TaskOutcomeRecord",
        "required_fields": fields,
        "normative_boundary": "Normative State may only emit governance_trace_only candidates; local_mutation_allowed is false.",
    }


def _agent_alias_from_run_dir(run_dir: Path) -> str:
    return _agent_alias_from_run_ref(str(run_dir))


def _agent_alias_from_run_ref(value: object) -> str:
    name = Path(str(value or "")).name
    parts = name.split("-")
    return parts[1] if len(parts) >= 3 and parts[0] == "baseline" else "unknown"


def _split_refs(value: object) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    normalized = raw.replace(";", ",").replace("|", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]


def _output_to_text(output: object) -> str | None:
    if output is None or output == "":
        return None
    if isinstance(output, str):
        return output
    return json.dumps(output, ensure_ascii=False, sort_keys=True, default=str)


def _sha256(value: str | None) -> str | None:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ratio(numerator: int, denominator: int, *, empty: float = 0.0) -> float:
    return numerator / denominator if denominator else empty


def _meets(value: object, minimum: float) -> bool:
    parsed = _float(value)
    return parsed is not None and parsed >= minimum


def _bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--judge-report", default="")
    parser.add_argument("--delayed-outcomes", default="")
    parser.add_argument("--backend-outcome-events", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--min-outcome-ledger-coverage-ratio", type=float, default=1.0)
    parser.add_argument("--min-h1-evidence-ref-ratio", type=float, default=1.0)
    parser.add_argument("--min-normative-local-update-blocked-ratio", type=float, default=1.0)
    parser.add_argument("--min-delayed-verifier-coverage-ratio", type=float, default=None)
    args = parser.parse_args()
    report = build_h2_outcome_report(
        run_root=Path(args.run_root),
        judge_report_path=Path(args.judge_report) if args.judge_report else None,
        delayed_outcomes_path=Path(args.delayed_outcomes) if args.delayed_outcomes else None,
        backend_outcome_events_path=(
            Path(args.backend_outcome_events) if args.backend_outcome_events else None
        ),
        agent_root=agent_root,
        min_outcome_ledger_coverage_ratio=args.min_outcome_ledger_coverage_ratio,
        min_h1_evidence_ref_ratio=args.min_h1_evidence_ref_ratio,
        min_normative_local_update_blocked_ratio=args.min_normative_local_update_blocked_ratio,
        min_delayed_verifier_coverage_ratio=args.min_delayed_verifier_coverage_ratio,
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