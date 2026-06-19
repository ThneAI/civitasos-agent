"""Beta-FE-2.6 task-pool mediation contracts.

This module keeps the FE-2.6 script focused on orchestration. It owns the
stable task payload, delivery output, participant selection, and boundary
validation structures used by CivitasOS-mediated Agent runner flows.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

try:
    from beta_evidence import artifact_ref, require_schema, validate_ref
except ModuleNotFoundError:
    from scripts.beta_evidence import artifact_ref, require_schema, validate_ref


FE2_PACKET_SCHEMA = "beta-fe2-frontend-patch-proposal-packet:v1"

FALSE_BOUNDARY_FIELDS = (
    "frontend_code_modified",
    "apply_allowed",
    "commit_allowed",
    "push_allowed",
    "merge_allowed",
    "deploy_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
)

NON_CLAIMS = (
    "beta_fe26_uses_civitasos_task_pool_before_agent_generation",
    "beta_fe26_agent_runner_claims_task_before_generating_response",
    "beta_fe26_does_not_replay_existing_fe2_response_records",
    "beta_fe26_does_not_modify_frontend_repo",
    "beta_fe26_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe26_does_not_claim_h3_production_readiness",
    "beta_fe26_does_not_write_production_receipts",
)


def boundary() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARY_FIELDS}


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def task_payload(
    requester: dict[str, Any],
    worker: dict[str, Any],
    participant: dict[str, Any],
    fe2_packet: dict[str, Any],
    fe2_packet_summary_path: Path,
    prompt_path: Path,
) -> dict[str, Any]:
    participant_id = str(participant.get("participant_id") or "unknown")
    return {
        "requester": requester["did"],
        "required_capability": "frontend_review",
        "reward": 10,
        "min_reputation": 0.0,
        "deadline_secs": 3600,
        "allowed_agents": [worker["did"]],
        "blocked_agents": [],
        "required_stake": 0,
        "input": {
            "civitasos_task_kind": "beta_fe26_agent_runner_frontend_patch_proposal",
            "participant_id": participant_id,
            "participant_role": participant.get("role"),
            "patch_slice_id": fe2_packet.get("patch_slice_id"),
            "instruction": (
                "Claim this task, then generate a fresh non-mutating frontend patch proposal/review. "
                "Do not replay existing FE-2 response records. Preserve no-apply/no-deploy/H3-blocked boundaries."
            ),
            "source_fe2_packet_summary": artifact_ref(fe2_packet_summary_path),
            "prompt_ref": artifact_ref(prompt_path),
            "expected_boundary": boundary(),
            "h3_boundary": h3_boundary(),
        },
    }


def runner_prompt(
    *,
    prompt: str,
    task_id: str,
    participant: dict[str, Any],
    worker: dict[str, Any],
    claimed_task: dict[str, Any],
) -> str:
    return f"""
CivitasOS claimed task context:
- task_id: {task_id}
- worker_did: {worker.get('did')}
- claimed_status: {claimed_task.get('status')}
- claimed_by: {claimed_task.get('claimed_by')}
- participant_id: {participant.get('participant_id')}
- role: {participant.get('role')}

You must generate a fresh response for this claimed task. Do not copy a prior
FE-2 response record. Keep all boundaries false: no frontend mutation, no apply,
no commit, no push, no merge, no deploy, no production runtime, no production
receipt. H.3 remains blocked.

Original FE-2 prompt:
{prompt}
""".strip()


def delivery_output(
    participant_id: str,
    fe2_packet: dict[str, Any],
    prompt_path: Path,
    generation_path: Path,
    generation_report_path: Path,
) -> dict[str, Any]:
    content = generation_path.read_text(encoding="utf-8")
    return {
        "schema_version": "beta-fe26-agent-runner-delivery-output:v1",
        "participant_id": participant_id,
        "patch_slice_id": fe2_packet.get("patch_slice_id"),
        "prompt_ref": artifact_ref(prompt_path),
        "generation_response": artifact_ref(generation_path),
        "generation_report": artifact_ref(generation_report_path),
        "response_excerpt": content[:4000],
        "generated_after_claim": True,
        "boundary": boundary(),
        "h3_boundary": h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def validate_fe2_packet(
    packet: Any,
    failures: list[str],
    expected_patch_slice_id: str = "task_read_adapter_extraction",
) -> None:
    if not require_schema(packet, FE2_PACKET_SCHEMA, failures, "FE-2 packet"):
        return
    if packet.get("passed") is not True:
        failures.append("FE-2 packet must be passed")
    if packet.get("decision") != "beta_fe2_patch_proposal_packet_ready":
        failures.append("FE-2 packet must be patch-proposal-packet-ready")
    if expected_patch_slice_id and packet.get("patch_slice_id") != expected_patch_slice_id:
        failures.append(f"FE-2 patch_slice_id must be {expected_patch_slice_id}")
    validate_boundary(packet.get("collaboration_boundary"), failures, "FE-2 collaboration_boundary")
    h3 = packet.get("h3_boundary")
    if not isinstance(h3, dict) or h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("FE-2 h3_boundary must keep H.3 blocked and not claim readiness")
    participants = packet.get("participants")
    if not isinstance(participants, list) or len(participants) < 3:
        failures.append("FE-2 packet participants must contain at least 3 entries")
        return
    prompt_refs = packet.get("agent_prompt_refs") if isinstance(packet.get("agent_prompt_refs"), dict) else {}
    ids: list[str] = []
    for item in participants:
        if not isinstance(item, dict):
            failures.append("FE-2 participant entry must be an object")
            continue
        participant_id = str(item.get("participant_id") or "")
        if not participant_id:
            failures.append("FE-2 participant_id must be non-empty")
            continue
        ids.append(participant_id)
        if item.get("direct_mutation_allowed") is not False:
            failures.append(f"FE-2 participant {participant_id} direct_mutation_allowed must be false")
        validate_ref(prompt_refs.get(participant_id), failures, f"agent_prompt_refs.{participant_id}")
    if len(set(ids)) != len(ids):
        failures.append("FE-2 participant ids must be unique")


def participant_ids(packet: dict[str, Any]) -> list[str]:
    return [str(item.get("participant_id") or "") for item in packet.get("participants", []) if isinstance(item, dict)]


def select_participants(packet_ids: list[str], allowlist: list[str] | None, failures: list[str]) -> list[str]:
    if not allowlist:
        return packet_ids
    requested = [item.strip() for item in allowlist if item.strip()]
    unknown = sorted(set(requested) - set(packet_ids))
    if unknown:
        failures.append(f"participant allowlist contains unknown participant(s): {', '.join(unknown)}")
    return [participant_id for participant_id in packet_ids if participant_id in set(requested)]


def task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id"),
        "requester": task.get("requester"),
        "required_capability": task.get("required_capability"),
        "status": task.get("status"),
        "claimed_by": task.get("claimed_by"),
        "posted_at": task.get("posted_at"),
        "claimed_at": task.get("claimed_at"),
        "delivered_at": task.get("delivered_at"),
        "challenge_deadline_at": task.get("challenge_deadline_at"),
        "challenge_window_secs": task.get("challenge_window_secs"),
        "has_output": task.get("output") not in (None, "", {}, []),
    }


def validate_boundary(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    for field in FALSE_BOUNDARY_FIELDS:
        packet_field = "direct_mutation_allowed" if field == "frontend_code_modified" else field
        if packet_field in value and value.get(packet_field) is not False:
            failures.append(f"{label}.{packet_field} must be false")


def safe_alias(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in value).strip("_")[:48] or "beta_fe26_runner"


def run_alias_suffix(output_root: Path) -> str:
    return hashlib.sha256(str(output_root.resolve()).encode("utf-8")).hexdigest()[:16]
