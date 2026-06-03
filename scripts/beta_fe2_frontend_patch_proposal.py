#!/usr/bin/env python3
"""Create and validate a Beta-FE-2 frontend patch proposal packet.

Beta-FE-2 turns the Beta-FE-1 multi-Agent review into a bounded patch proposal.
It does not modify civitasos-frontend. It only prepares context, records
Agent proposals/critiques, and reconciles them before an operator may decide
whether to open a separate apply gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKET_SCHEMA = "beta-fe2-frontend-patch-proposal-packet:v1"
PACKET_VALIDATION_SCHEMA = "beta-fe2-frontend-patch-proposal-packet-validation:v1"
RESPONSE_SCHEMA = "beta-fe2-agent-proposal-response-record:v1"
RESPONSE_VALIDATION_SCHEMA = "beta-fe2-agent-proposal-response-record-validation:v1"
RECONCILIATION_SCHEMA = "beta-fe2-patch-proposal-reconciliation:v1"
FE1_RECONCILIATION_SCHEMA = "beta-fe1-multi-agent-reconciliation:v1"

DEFAULT_PARTICIPANTS: tuple[tuple[str, str, str], ...] = (
    ("deepseek-api-agent", "implementation_proposer", "minimal TaskReadAdapter patch shape and file plan"),
    ("claude-cli-agent", "architecture_reviewer", "risk critique and architecture boundary validation"),
    ("hermes-cli-agent", "ux_product_reviewer", "product/UX impact and operator workflow critique"),
    ("local-gpu-agent", "smoke_verifier", "build/test/smoke checklist and regression risks"),
)
RECOMMENDATIONS = ("proceed", "revise", "reject", "inconclusive")
PATCH_SLICE_ID = "task_read_adapter_extraction"
FORBIDDEN_TEXT = ("TODO_REPLACE", "REPLACE_ME", "TEMPLATE_ONLY", "PLACEHOLDER_SECRET")
NON_CLAIMS = (
    "beta_fe2_packet_is_l1_controlled_pilot_evidence_only",
    "beta_fe2_packet_does_not_modify_frontend_repo",
    "beta_fe2_packet_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe2_packet_does_not_claim_h3_production_readiness",
    "beta_fe2_packet_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-packet", help="create a FE-2 proposal packet")
    create.add_argument("--frontend-root", required=True)
    create.add_argument("--fe1-reconciliation", required=True)
    create.add_argument("--output-root", required=True)
    create.add_argument("--participant", action="append", default=[])
    create.add_argument("--operator-id", default="local-operator-cc")
    create.add_argument("--min-fe1-responses", type=int, default=3)

    validate_packet = subparsers.add_parser("validate-packet", help="validate a FE-2 packet")
    validate_packet.add_argument("--packet-summary", required=True)
    validate_packet.add_argument("--output")

    record = subparsers.add_parser("record-response", help="record a non-mutating FE-2 Agent response")
    record.add_argument("--packet-summary", required=True)
    record.add_argument("--participant-id", required=True)
    record.add_argument("--response-file", required=True)
    record.add_argument("--recommendation", choices=RECOMMENDATIONS, required=True)
    record.add_argument("--observer-actor-id", default="external_agent_observer")
    record.add_argument("--output", required=True)

    reconcile = subparsers.add_parser("reconcile", help="reconcile FE-2 Agent response records")
    reconcile.add_argument("--packet-summary", required=True)
    reconcile.add_argument("--response-record", action="append", required=True)
    reconcile.add_argument("--output", required=True)
    reconcile.add_argument("--min-responses", type=int, default=3)

    args = parser.parse_args(argv)
    if args.command == "create-packet":
        report = create_packet(
            frontend_root=Path(args.frontend_root),
            fe1_reconciliation_path=Path(args.fe1_reconciliation),
            output_root=Path(args.output_root),
            participant_specs=args.participant,
            operator_id=args.operator_id,
            min_fe1_responses=args.min_fe1_responses,
        )
    elif args.command == "validate-packet":
        report = validate_packet_summary(Path(args.packet_summary))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "record-response":
        report = record_response(
            packet_summary_path=Path(args.packet_summary),
            participant_id=args.participant_id,
            response_file=Path(args.response_file),
            recommendation=args.recommendation,
            observer_actor_id=args.observer_actor_id,
            output_path=Path(args.output),
        )
    elif args.command == "reconcile":
        report = reconcile_responses(
            packet_summary_path=Path(args.packet_summary),
            response_record_paths=[Path(path) for path in args.response_record],
            output_path=Path(args.output),
            min_responses=args.min_responses,
        )
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if _report_passed(report) else 1


def create_packet(
    *,
    frontend_root: Path,
    fe1_reconciliation_path: Path,
    output_root: Path,
    participant_specs: list[str] | None = None,
    operator_id: str = "local-operator-cc",
    min_fe1_responses: int = 3,
) -> dict[str, Any]:
    failures: list[str] = []
    frontend_root = frontend_root.resolve()
    fe1_reconciliation_path = fe1_reconciliation_path.resolve()
    output_root = output_root.resolve()
    if not frontend_root.is_dir():
        failures.append(f"frontend_root is not a directory: {frontend_root}")
    for rel in ("package.json", "src/services/apiClient.ts", "src/components/TaskPoolPanel.tsx"):
        if not (frontend_root / rel).is_file():
            failures.append(f"required frontend file missing: {rel}")
    fe1 = _read_json(fe1_reconciliation_path, failures, "FE-1 reconciliation")
    if isinstance(fe1, dict):
        if fe1.get("schema_version") != FE1_RECONCILIATION_SCHEMA:
            failures.append(f"FE-1 reconciliation schema_version must be {FE1_RECONCILIATION_SCHEMA}")
        if fe1.get("passed") is not True:
            failures.append("FE-1 reconciliation must be passed")
        if fe1.get("decision") != "beta_fe1_operator_decision_ready":
            failures.append("FE-1 reconciliation must be operator-decision-ready")
        if int(fe1.get("unique_participant_count") or 0) < min_fe1_responses:
            failures.append(f"FE-1 unique participant count must be >= {min_fe1_responses}")
        _validate_false_boundary(fe1.get("collaboration_boundary"), failures, "FE-1 collaboration_boundary")
        _validate_h3_boundary(fe1, failures)
    if failures:
        raise ValueError(f"Beta-FE-2 packet creation blocked: {failures}")

    participants = _parse_participants(participant_specs or [])
    response_dir = output_root / "agent_responses"
    prompt_dir = output_root / "agent_prompts"
    output_root.mkdir(parents=True, exist_ok=True)
    response_dir.mkdir(parents=True, exist_ok=True)
    prompt_dir.mkdir(parents=True, exist_ok=True)

    context_path = output_root / "beta_fe2_frontend_patch_context.md"
    brief_path = output_root / "beta_fe2_patch_proposal_brief.md"
    decision_path = output_root / "beta_fe2_operator_decision_required.json"
    summary_path = output_root / "beta_fe2_packet_summary.json"

    snapshot = _frontend_snapshot(frontend_root)
    context_path.write_text(_render_context(frontend_root, snapshot), encoding="utf-8")
    brief_path.write_text(_render_brief(fe1, participants), encoding="utf-8")
    _write_json(decision_path, _operator_decision_payload(operator_id, summary_path))

    prompt_refs = {}
    for participant in participants:
        prompt_path = prompt_dir / f"{participant['participant_id']}.prompt.txt"
        prompt_path.write_text(_render_agent_prompt(participant, context_path, brief_path), encoding="utf-8")
        prompt_refs[participant["participant_id"]] = _artifact_ref(prompt_path)

    summary = {
        "schema_version": PACKET_SCHEMA,
        "created_at": _now(),
        "passed": True,
        "decision": "beta_fe2_patch_proposal_packet_ready",
        "frontend_root": str(frontend_root),
        "patch_slice_id": PATCH_SLICE_ID,
        "patch_slice": _patch_slice(),
        "frontend_snapshot": snapshot,
        "fe1_reconciliation": _artifact_ref(fe1_reconciliation_path),
        "fe1_unique_participant_count": fe1.get("unique_participant_count"),
        "fe1_recommendation_counts": fe1.get("recommendation_counts"),
        "participants": participants,
        "artifact_refs": {
            "frontend_patch_context": _artifact_ref(context_path),
            "patch_proposal_brief": _artifact_ref(brief_path),
            "operator_decision_required": _artifact_ref(decision_path),
        },
        "agent_prompt_refs": prompt_refs,
        "response_dir": str(response_dir),
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(summary_path, summary)
    validation = validate_packet_summary(summary_path)
    if validation["passed"] is not True:
        raise ValueError(f"written Beta-FE-2 packet failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": "beta-fe2-frontend-patch-proposal-packet-write-report:v1",
        "passed": True,
        "packet_summary_path": str(summary_path),
        "packet_summary_sha256": _sha256(summary_path),
        "participant_count": len(participants),
        "patch_slice_id": PATCH_SLICE_ID,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_packet_summary(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _read_json(path, failures, "packet summary")
    if not isinstance(packet, dict):
        return _validation_report(PACKET_VALIDATION_SCHEMA, path, failures or ["packet summary must be an object"])
    if packet.get("schema_version") != PACKET_SCHEMA:
        failures.append(f"schema_version must be {PACKET_SCHEMA}")
    if packet.get("decision") != "beta_fe2_patch_proposal_packet_ready":
        failures.append("decision must be beta_fe2_patch_proposal_packet_ready")
    if packet.get("passed") is not True:
        failures.append("packet passed must be true")
    if packet.get("patch_slice_id") != PATCH_SLICE_ID:
        failures.append(f"patch_slice_id must be {PATCH_SLICE_ID}")
    if int(packet.get("fe1_unique_participant_count") or 0) < 3:
        failures.append("fe1_unique_participant_count must be >= 3")
    participants = packet.get("participants")
    if not isinstance(participants, list) or len(participants) < 3:
        failures.append("participants must contain at least 3 entries")
    else:
        ids = [str(item.get("participant_id") or "") for item in participants if isinstance(item, dict)]
        if len(set(ids)) != len(ids):
            failures.append("participant_id values must be unique")
        for item in participants:
            if not isinstance(item, dict):
                failures.append("participant entry must be an object")
                continue
            for field in ("participant_id", "role", "focus"):
                if not _text(item.get(field)):
                    failures.append(f"participant.{field} must be non-empty")
            if item.get("direct_mutation_allowed") is not False:
                failures.append("participant.direct_mutation_allowed must be false")
    refs = packet.get("artifact_refs") if isinstance(packet.get("artifact_refs"), dict) else {}
    for label in ("frontend_patch_context", "patch_proposal_brief", "operator_decision_required"):
        _validate_ref(refs.get(label), failures, label)
    prompt_refs = packet.get("agent_prompt_refs") if isinstance(packet.get("agent_prompt_refs"), dict) else {}
    for participant_id, value in prompt_refs.items():
        _validate_ref(value, failures, f"agent_prompt_refs.{participant_id}")
    _validate_ref(packet.get("fe1_reconciliation"), failures, "fe1_reconciliation")
    _validate_false_boundary(packet.get("collaboration_boundary"), failures, "collaboration_boundary")
    _validate_h3_boundary(packet, failures)
    return _validation_report(PACKET_VALIDATION_SCHEMA, path, failures)


def record_response(
    *,
    packet_summary_path: Path,
    participant_id: str,
    response_file: Path,
    recommendation: str,
    observer_actor_id: str,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    packet_validation = validate_packet_summary(packet_summary_path)
    if packet_validation["passed"] is not True:
        failures.extend(f"packet invalid: {reason}" for reason in packet_validation["failure_reasons"])
    packet = _read_json(packet_summary_path, failures, "packet summary")
    participant = _participant_by_id(packet, participant_id) if isinstance(packet, dict) else None
    if participant is None:
        failures.append(f"participant_id not found in packet: {participant_id}")
        participant = {}
    if recommendation not in RECOMMENDATIONS:
        failures.append(f"recommendation must be one of {list(RECOMMENDATIONS)}")
    if not response_file.is_file():
        failures.append(f"response_file must be a file: {response_file}")
    elif response_file.stat().st_size == 0:
        failures.append("response_file must be non-empty")
    _reject_forbidden_text([participant_id, observer_actor_id], failures)
    if failures:
        raise ValueError(f"Beta-FE-2 response record blocked: {failures}")

    response = {
        "schema_version": RESPONSE_SCHEMA,
        "recorded_at": _now(),
        "response_scope": "beta_fe2_frontend_patch_proposal_response_only",
        "source_packet": _artifact_ref(packet_summary_path),
        "participant_id": participant_id,
        "role": participant["role"],
        "focus": participant["focus"],
        "response_file": _artifact_ref(response_file),
        "recommendation": recommendation,
        "observer_actor_id": observer_actor_id,
        "patch_slice_id": packet.get("patch_slice_id"),
        "external_agent_response_observed": True,
        "operator_decision_required": True,
        "direct_mutation_allowed": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, response)
    validation = validate_response_record(output_path)
    return {
        "schema_version": "beta-fe2-agent-proposal-response-record-write-report:v1",
        "passed": validation["passed"],
        "response_record_path": str(output_path.resolve()),
        "response_record_sha256": _sha256(output_path),
        "participant_id": participant_id,
        "recommendation": recommendation,
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_response_record(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    response = _read_json(path, failures, "response record")
    if not isinstance(response, dict):
        return _validation_report(RESPONSE_VALIDATION_SCHEMA, path, failures or ["response record must be an object"])
    if response.get("schema_version") != RESPONSE_SCHEMA:
        failures.append(f"schema_version must be {RESPONSE_SCHEMA}")
    for field in ("participant_id", "role", "focus", "observer_actor_id"):
        if not _text(response.get(field)):
            failures.append(f"{field} must be non-empty")
    if response.get("patch_slice_id") != PATCH_SLICE_ID:
        failures.append(f"patch_slice_id must be {PATCH_SLICE_ID}")
    if response.get("recommendation") not in RECOMMENDATIONS:
        failures.append(f"recommendation must be one of {list(RECOMMENDATIONS)}")
    _validate_ref(response.get("source_packet"), failures, "source_packet")
    _validate_ref(response.get("response_file"), failures, "response_file")
    for field in _false_boundary_fields():
        if response.get(field) is not False:
            failures.append(f"{field} must be false")
    if response.get("operator_decision_required") is not True:
        failures.append("operator_decision_required must be true")
    _validate_h3_boundary(response, failures)
    return _validation_report(RESPONSE_VALIDATION_SCHEMA, path, failures)


def reconcile_responses(
    *,
    packet_summary_path: Path,
    response_record_paths: list[Path],
    output_path: Path,
    min_responses: int = 3,
) -> dict[str, Any]:
    failures: list[str] = []
    if min_responses < 1:
        failures.append("min_responses must be >= 1")
    packet_validation = validate_packet_summary(packet_summary_path)
    if packet_validation["passed"] is not True:
        failures.extend(f"packet invalid: {reason}" for reason in packet_validation["failure_reasons"])
    packet = _read_json(packet_summary_path, failures, "packet summary")
    packet_ref = _artifact_ref(packet_summary_path)
    responses = []
    for path in response_record_paths:
        validation = validate_response_record(path)
        if validation["passed"] is not True:
            failures.extend(f"{path}: {reason}" for reason in validation["failure_reasons"])
        response = _read_json(path, failures, "response record")
        if not isinstance(response, dict):
            continue
        if response.get("source_packet") != packet_ref:
            failures.append(f"{path}: source_packet must match packet summary hash")
        responses.append((path, response))
    unique_participants = sorted({str(response.get("participant_id")) for _, response in responses if response.get("participant_id")})
    if len(unique_participants) < min_responses:
        failures.append(f"unique response participant count must be >= {min_responses}")
    recommendation_counts: dict[str, int] = {}
    for _, response in responses:
        recommendation = str(response.get("recommendation") or "unknown")
        recommendation_counts[recommendation] = recommendation_counts.get(recommendation, 0) + 1
    hard_reject = recommendation_counts.get("reject", 0) > 0
    passed = not failures
    decision = "blocked"
    if passed and hard_reject:
        decision = "beta_fe2_revision_required"
    elif passed:
        decision = "beta_fe2_operator_decision_ready"
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": decision,
        "failure_reasons": failures,
        "source_packet": packet_ref,
        "frontend_root": packet.get("frontend_root") if isinstance(packet, dict) else None,
        "patch_slice_id": PATCH_SLICE_ID,
        "recommended_patch_slice": _patch_slice(),
        "response_count": len(responses),
        "unique_participant_count": len(unique_participants),
        "unique_participants": unique_participants,
        "recommendation_counts": recommendation_counts,
        "hard_reject_observed": hard_reject,
        "response_records": [_artifact_ref(path) for path, _ in responses if path.is_file()],
        "operator_decision_required": True,
        "allowed_operator_next_decisions": [
            "approve_beta_fe3_apply_gate",
            "request_beta_fe2_revision",
            "reject_beta_fe2_patch_proposal",
        ],
        "safe_next_step": "operator_review_before_any_frontend_code_change" if passed else "collect_or_fix_response_records",
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _frontend_snapshot(frontend_root: Path) -> dict[str, Any]:
    package = _read_json(frontend_root / "package.json", [], "package.json")
    target_files = []
    for rel in ("src/services/apiClient.ts", "src/components/TaskPoolPanel.tsx", "src/App.tsx", "package.json"):
        path = frontend_root / rel
        if path.is_file():
            target_files.append({"path": rel, "lines": _line_count(path), "sha256": _sha256(path)})
    return {
        "git_commit": _git(["rev-parse", "--short", "HEAD"], cwd=frontend_root),
        "git_dirty": bool(_git(["status", "--short"], cwd=frontend_root).strip()),
        "package_name": package.get("name"),
        "package_version": package.get("version"),
        "scripts": package.get("scripts", {}),
        "dependencies": sorted((package.get("dependencies") or {}).keys()),
        "target_files": target_files,
    }


def _render_context(frontend_root: Path, snapshot: dict[str, Any]) -> str:
    api = frontend_root / "src/services/apiClient.ts"
    panel = frontend_root / "src/components/TaskPoolPanel.tsx"
    targets = "\n".join(f"- `{item['path']}`: {item['lines']} lines" for item in snapshot["target_files"])
    return f"""# Beta-FE-2 Frontend Patch Context

## Scope

This context supports a non-mutating patch proposal for `civitasos-frontend`.
It is not authorization to apply the patch.

## Repository

- Root: `{frontend_root}`
- Git commit: `{snapshot['git_commit']}`
- Dirty worktree observed: `{str(snapshot['git_dirty']).lower()}`
- Package: `{snapshot['package_name']}@{snapshot['package_version']}`

## Target Patch Slice

`{PATCH_SLICE_ID}`: introduce a typed Task read-model adapter around task-pool
read/write methods before any visual redesign.

## Target Files

{targets}

## Relevant `apiClient.ts` Task Methods

```ts
{_excerpt(api, 820, 895)}
```

## Relevant `TaskPoolPanel.tsx` Fetch/Mutation Section

```tsx
{_excerpt(panel, 240, 320)}
```

## Constraints

- Preserve backend API request/response shapes.
- Preserve AuthContext and token behavior.
- Do not migrate CRA/Vite/build tooling in this slice.
- Do not redesign the visual shell in this slice.
- Do not apply, commit, push, merge, deploy, run production, or write production receipts.
"""


def _render_brief(fe1: dict[str, Any], participants: list[dict[str, Any]]) -> str:
    participant_lines = "\n".join(
        f"- `{item['participant_id']}` ({item['role']}): {item['focus']}" for item in participants
    )
    return f"""# Beta-FE-2 Patch Proposal Brief

## Objective

Convert Beta-FE-1 review evidence into one minimal, testable frontend patch
proposal. The recommended first slice is `{PATCH_SLICE_ID}`.

## FE-1 Evidence Summary

- FE-1 decision: `{fe1.get('decision')}`
- FE-1 participant count: `{fe1.get('unique_participant_count')}`
- FE-1 recommendations: `{fe1.get('recommendation_counts')}`
- FE-1 safe next step: `{fe1.get('safe_next_step')}`

## Proposed Patch Shape

1. Add `src/adapters/taskReadModel.ts` with typed TaskPool/read-model types.
2. Add `src/adapters/TaskReadAdapter.ts` that wraps the existing `apiClient`.
3. Add adapter unit tests using a fake raw client; no backend/network calls.
4. Rewire only `TaskPoolPanel` to consume the adapter through a small seam.
5. Preserve current panel behavior and visual structure.

## Required Agent Response Sections

1. `Patch proposal verdict`
2. `Files to add/change`
3. `Type/API boundary`
4. `Tests and smoke checks`
5. `Risks and rollback`
6. `What must not change`

## Participants

{participant_lines}

## Hard Boundaries

- Proposal only; do not mutate files.
- No apply/commit/push/merge/deploy authorization.
- No production runtime execution or production receipt.
- Keep H.3 blocked.
"""


def _render_agent_prompt(participant: dict[str, Any], context_path: Path, brief_path: Path) -> str:
    return f"""You are `{participant['participant_id']}` for CivitasOS Beta-FE-2.
Role: {participant['role']}
Focus: {participant['focus']}

Produce a non-mutating patch proposal/critique for the frontend first slice:
`{PATCH_SLICE_ID}`.

Hard constraints:
- Do not mutate files.
- Do not recommend direct commit, push, merge, deploy, production runtime, or production receipt.
- Preserve backend API contracts, AuthContext behavior, current visual behavior, and H.3 blocked state.
- Keep the first slice small enough for operator approval and rollback.

Use the following context and brief:

--- PATCH CONTEXT ---
{context_path.read_text(encoding='utf-8')}

--- PATCH BRIEF ---
{brief_path.read_text(encoding='utf-8')}
"""


def _operator_decision_payload(operator_id: str, summary_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "beta-fe2-operator-decision-required:v1",
        "created_at": _now(),
        "operator_id": operator_id,
        "source_packet_summary_path": str(summary_path),
        "operator_decision_required": True,
        "allowed_decisions_after_reconciliation": [
            "approve_beta_fe3_apply_gate",
            "request_beta_fe2_revision",
            "reject_beta_fe2_patch_proposal",
        ],
        "patch_slice_id": PATCH_SLICE_ID,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _patch_slice() -> dict[str, Any]:
    return {
        "id": PATCH_SLICE_ID,
        "title": "Extract a typed Task read-model adapter before visual redesign",
        "files_expected_to_add": [
            "src/adapters/taskReadModel.ts",
            "src/adapters/TaskReadAdapter.ts",
            "src/adapters/TaskReadAdapter.test.ts",
        ],
        "files_expected_to_change": ["src/components/TaskPoolPanel.tsx"],
        "backend_api_contract_change_allowed": False,
        "auth_flow_change_allowed": False,
        "visual_redesign_allowed": False,
        "build_tool_migration_allowed": False,
    }


def _parse_participants(specs: list[str]) -> list[dict[str, Any]]:
    rows = specs or [":".join(row) for row in DEFAULT_PARTICIPANTS]
    participants = []
    for spec in rows:
        parts = [part.strip() for part in spec.split(":", 2)]
        if len(parts) != 3 or not all(parts):
            raise ValueError(f"participant must be id:role:focus: {spec}")
        participants.append(
            {
                "participant_id": parts[0],
                "role": parts[1],
                "focus": parts[2],
                "direct_mutation_allowed": False,
            }
        )
    return participants


def _participant_by_id(packet: dict[str, Any], participant_id: str) -> dict[str, Any] | None:
    for item in packet.get("participants", []):
        if isinstance(item, dict) and item.get("participant_id") == participant_id:
            return item
    return None


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _validate_ref(value: Any, failures: list[str], label: str) -> Path | None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an artifact ref object")
        return None
    path_text = _text(value.get("path"))
    digest = _text(value.get("sha256"))
    if not path_text:
        failures.append(f"{label}.path must be non-empty")
        return None
    path = Path(path_text)
    if not path.is_file():
        failures.append(f"{label}.path is not a file: {path}")
        return None
    if digest != _sha256(path):
        failures.append(f"{label}.sha256 does not match file bytes")
    return path


def _validation_report(schema: str, path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": schema,
        "checked_at": _now(),
        "path": str(path.resolve()),
        "passed": not failures,
        "failure_reasons": failures,
        "sha256": _sha256(path) if path.is_file() else None,
        "non_claims": list(NON_CLAIMS),
    }


def _validate_false_boundary(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    for field in _false_boundary_fields():
        if value.get(field) is not False:
            failures.append(f"{label}.{field} must be false")


def _validate_h3_boundary(record: dict[str, Any], failures: list[str]) -> None:
    h3 = record.get("h3_boundary")
    if not isinstance(h3, dict):
        failures.append("h3_boundary must be an object")
        return
    if h3.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if h3.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


def _boundary() -> dict[str, bool]:
    return {field: False for field in _false_boundary_fields()}


def _false_boundary_fields() -> tuple[str, ...]:
    return (
        "direct_mutation_allowed",
        "apply_allowed",
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    )


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    for value in values:
        for token in FORBIDDEN_TEXT:
            if token in value:
                failures.append(f"forbidden token found: {token}")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())


def _excerpt(path: Path, start: int, end: int) -> str:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    selected = lines[max(0, start - 1) : min(len(lines), end)]
    return "\n".join(selected)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(args: list[str], *, cwd: Path) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_passed(report: dict[str, Any]) -> bool:
    return report.get("passed") is True


if __name__ == "__main__":
    raise SystemExit(main())
