"""Task construction for H.3 controlled-pilot runner."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_controlled_pilot_generation import (
    AGENT_ROLES,
    REQUIRED_RESPONSE_FIELDS,
)
from benchmarks.h3_evidence import (
    artifact_ref,
    object_value,
    objects_value,
    resolve_under_root,
    sha256_file,
)


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


def build_controlled_pilot_task(
    *,
    draft: dict[str, Any],
    bounded_file: Path,
    evidence_report_paths: list[Path],
    agent_root: Path,
    profile: str,
) -> dict[str, Any]:
    evidence_refs = objects_value(
        object_value(draft.get("source_binding")).get("evidence_refs")
    )
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


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
