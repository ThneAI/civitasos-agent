"""Prepare private J1-D qualification materials for independent review."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .controlled_comparison import (
    REQUIRED_SCENARIOS,
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from .qualification_protocol_freeze import CORPUS_SCHEMA
from .qualification_verifier import CASE_IDS, build_verifier_candidate


TASK_SOURCE_SCHEMA = "j1-qualification-task-authoring-source:v1"
REVIEW_PACKET_SCHEMA = "j1-qualification-material-review-packet:v1"
TASK_FIELDS = {
    "task_id",
    "input",
    "input_sha256",
    "verifier_case",
    "scenario_tags",
}


def build_task_source_candidate(
    *, corpus_id: str, tasks: list[dict[str, Any]]
) -> dict[str, Any]:
    task_values: list[dict[str, Any]] = []
    for task in tasks:
        value = dict(task)
        prompt = value.get("input")
        if isinstance(prompt, str):
            value["input_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()
        task_values.append(value)
    return {
        "schema_version": TASK_SOURCE_SCHEMA,
        "corpus_id": corpus_id,
        "tasks": task_values,
    }


def prepare_materials(
    *,
    task_source_path: Path,
    verifier_source_path: Path,
    source_revision: str,
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    output_root.chmod(0o700)
    packet_path = output_root / "material-review-packet.json"
    failures: list[str] = []
    source: dict[str, Any] = {}
    verifier_source = b""
    try:
        source = read_json_object(task_source_path)
    except (OSError, ValueError):
        failures.append("task_source_unreadable")
    if source:
        failures.extend(validate_task_source(source))
        try:
            if task_source_path.stat().st_mode & 0o077:
                failures.append("task_source_permissions_too_open")
        except OSError:
            failures.append("task_source_unreadable")
    if not _git_revision(source_revision):
        failures.append("source_revision_invalid")
    try:
        verifier_source = verifier_source_path.read_bytes()
    except OSError:
        failures.append("verifier_source_unreadable")
    if not verifier_source:
        failures.append("verifier_source_empty")
    if failures:
        packet = _blocked_packet(list(dict.fromkeys(failures)))
        write_private_json(packet_path, packet)
        return packet
    tasks = source["tasks"]
    corpus = {
        "schema_version": CORPUS_SCHEMA,
        "status": "review_required",
        "corpus_id": source["corpus_id"],
        "synthetic": False,
        "confidential": True,
        "authoring_provenance": "ai_assisted_draft_requires_independent_operator_review",
        "tasks": tasks,
        "tasks_sha256": canonical_sha256(tasks),
    }
    implementation_sha256 = hashlib.sha256(verifier_source).hexdigest()
    verifier = build_verifier_candidate(
        source_revision=source_revision,
        implementation_sha256=implementation_sha256,
    )
    corpus_path = output_root / "qualification-corpus.review-required.json"
    verifier_path = output_root / "qualification-verifier.review-required.json"
    write_private_json(corpus_path, corpus)
    write_private_json(verifier_path, verifier)
    packet = {
        "schema_version": REVIEW_PACKET_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "j1d_qualification_materials_prepared_operator_review_required",
        "corpus": _artifact(corpus_path),
        "verifier": _artifact(verifier_path),
        "source_task_authoring_sha256": hashlib.sha256(
            task_source_path.read_bytes()
        ).hexdigest(),
        "review": {
            "decision": "pending_independent_operator_review",
            "reviewer_did": None,
            "review_receipt_sha256": None,
            "corpus_operator_reviewed": False,
            "verifier_operator_reviewed": False,
        },
        "readiness": {
            "qualification_protocol_freeze_ready": False,
            "real_participant_roster_binding_ready": False,
            "execution_authorization_ready": False,
        },
        "execution_boundary": {
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(packet_path, packet)
    return packet


def validate_task_source(value: Any) -> list[str]:
    failures: list[str] = []
    source = value if isinstance(value, dict) else {}
    _require(
        source.get("schema_version") == TASK_SOURCE_SCHEMA,
        "task_source_schema_invalid",
        failures,
    )
    _require(
        _real_text(source.get("corpus_id")), "task_source_corpus_id_invalid", failures
    )
    tasks = source.get("tasks")
    if not isinstance(tasks, list) or len(tasks) < 8:
        failures.append("task_source_requires_at_least_8_tasks")
        tasks = tasks if isinstance(tasks, list) else []
    scenarios: set[str] = set()
    verifier_cases: set[str] = set()
    ids: list[str] = []
    for index, value in enumerate(tasks):
        task = value if isinstance(value, dict) else {}
        _require(
            set(task) == TASK_FIELDS,
            f"task_{index}_fields_invalid",
            failures,
        )
        task_id = task.get("task_id")
        ids.append(task_id)
        _require(_real_text(task_id), f"task_{index}_id_invalid", failures)
        prompt = task.get("input")
        _require(
            isinstance(prompt, str) and len(prompt.strip()) >= 80,
            f"task_{index}_input_too_short",
            failures,
        )
        expected_hash = (
            hashlib.sha256(prompt.encode()).hexdigest()
            if isinstance(prompt, str)
            else None
        )
        _require(
            task.get("input_sha256") == expected_hash,
            f"task_{index}_input_hash_mismatch",
            failures,
        )
        _require(
            task.get("verifier_case") in CASE_IDS,
            f"task_{index}_verifier_case_invalid",
            failures,
        )
        if task.get("verifier_case") in CASE_IDS:
            verifier_cases.add(task["verifier_case"])
        tags = task.get("scenario_tags")
        if (
            isinstance(tags, list)
            and bool(tags)
            and all(isinstance(tag, str) for tag in tags)
        ):
            scenarios.update(tags)
        else:
            failures.append(f"task_{index}_scenario_tags_invalid")
    _require(len(ids) == len(set(ids)), "task_source_ids_duplicate", failures)
    _require(
        scenarios == REQUIRED_SCENARIOS,
        "task_source_scenario_coverage_invalid",
        failures,
    )
    _require(
        verifier_cases == CASE_IDS,
        "task_source_verifier_case_coverage_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _blocked_packet(failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_PACKET_SCHEMA,
        "passed": False,
        "failure_reasons": failures,
        "state": "blocked_j1d_qualification_material_preparation",
    }


def _real_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "test", "demo")
    )


def _git_revision(value: Any) -> bool:
    text = value.strip() if isinstance(value, str) else ""
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
