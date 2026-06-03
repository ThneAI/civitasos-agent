#!/usr/bin/env python3
"""Create and validate a Beta-FE-1 frontend collaboration packet.

Beta-FE-1 is a non-mutating collaboration gate. It prepares bounded frontend
context for external Agents, records their responses as evidence, and reconciles
those responses before any operator-authorized code change. It does not modify
the frontend repository, commit, merge, deploy, or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKET_SCHEMA = "beta-fe1-frontend-collaboration-packet:v1"
PACKET_VALIDATION_SCHEMA = "beta-fe1-frontend-collaboration-packet-validation:v1"
RESPONSE_SCHEMA = "beta-fe1-agent-response-record:v1"
RESPONSE_VALIDATION_SCHEMA = "beta-fe1-agent-response-record-validation:v1"
RECONCILIATION_SCHEMA = "beta-fe1-multi-agent-reconciliation:v1"
DEFAULT_PARTICIPANTS: tuple[tuple[str, str, str], ...] = (
    ("deepseek-api-agent", "implementation_proposer", "implementation proposal and safe first slice"),
    ("claude-cli-agent", "frontend_architecture_reviewer", "architecture review and risk critique"),
    ("hermes-cli-agent", "ux_product_designer", "UX/product redesign proposal"),
    ("local-gpu-agent", "smoke_check_verifier", "smoke checklist and low-cost verification plan"),
)
RECOMMENDATIONS = ("proceed", "revise", "reject", "inconclusive")
FORBIDDEN_TEXT = ("TODO_REPLACE", "REPLACE_ME", "TEMPLATE_ONLY", "PLACEHOLDER_SECRET")
NON_CLAIMS = (
    "beta_fe1_packet_is_l1_controlled_pilot_evidence_only",
    "beta_fe1_packet_does_not_modify_frontend_repo",
    "beta_fe1_packet_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe1_packet_does_not_claim_h3_production_readiness",
    "beta_fe1_packet_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-packet", help="create a frontend collaboration packet")
    create.add_argument("--frontend-root", required=True)
    create.add_argument("--output-root", required=True)
    create.add_argument(
        "--participant",
        action="append",
        default=[],
        help="participant as id:role:focus; may be repeated",
    )
    create.add_argument("--operator-id", default="local-operator-cc")

    validate_packet = subparsers.add_parser("validate-packet", help="validate a packet summary")
    validate_packet.add_argument("--packet-summary", required=True)
    validate_packet.add_argument("--output")

    record = subparsers.add_parser("record-response", help="record a non-mutating Agent response")
    record.add_argument("--packet-summary", required=True)
    record.add_argument("--participant-id", required=True)
    record.add_argument("--response-file", required=True)
    record.add_argument("--recommendation", choices=RECOMMENDATIONS, required=True)
    record.add_argument("--observer-actor-id", default="external_agent_observer")
    record.add_argument("--output", required=True)

    reconcile = subparsers.add_parser("reconcile", help="reconcile Agent response records")
    reconcile.add_argument("--packet-summary", required=True)
    reconcile.add_argument("--response-record", action="append", required=True)
    reconcile.add_argument("--output", required=True)
    reconcile.add_argument("--min-responses", type=int, default=2)

    args = parser.parse_args(argv)
    if args.command == "create-packet":
        report = create_packet(
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            participant_specs=args.participant,
            operator_id=args.operator_id,
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
    output_root: Path,
    participant_specs: list[str] | None = None,
    operator_id: str = "local-operator-cc",
) -> dict[str, Any]:
    failures: list[str] = []
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    if not frontend_root.is_dir():
        failures.append(f"frontend_root is not a directory: {frontend_root}")
    package_json = frontend_root / "package.json"
    if not package_json.is_file():
        failures.append("frontend_root/package.json is required")
    if failures:
        raise ValueError(f"Beta-FE-1 packet creation blocked: {failures}")

    participants = _parse_participants(participant_specs or [])
    output_root.mkdir(parents=True, exist_ok=True)
    response_dir = output_root / "agent_responses"
    response_dir.mkdir(parents=True, exist_ok=True)

    context_path = output_root / "beta_fe1_frontend_context.md"
    brief_path = output_root / "beta_fe1_task_brief.md"
    response_readme_path = response_dir / "README.md"
    decision_path = output_root / "beta_fe1_operator_decision_required.json"
    summary_path = output_root / "beta_fe1_packet_summary.json"

    snapshot = _frontend_snapshot(frontend_root)
    context_path.write_text(_render_context(frontend_root, snapshot), encoding="utf-8")
    brief_path.write_text(_render_task_brief(participants), encoding="utf-8")
    response_readme_path.write_text(_render_response_readme(participants), encoding="utf-8")
    _write_json(decision_path, _operator_decision_payload(operator_id, summary_path))

    summary = {
        "schema_version": PACKET_SCHEMA,
        "created_at": _now(),
        "passed": True,
        "decision": "beta_fe1_frontend_collaboration_packet_ready",
        "frontend_root": str(frontend_root),
        "frontend_snapshot": snapshot,
        "participants": participants,
        "artifact_refs": {
            "frontend_context": _artifact_ref(context_path),
            "task_brief": _artifact_ref(brief_path),
            "agent_responses_readme": _artifact_ref(response_readme_path),
            "operator_decision_required": _artifact_ref(decision_path),
        },
        "response_dir": str(response_dir),
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(summary_path, summary)
    validation = validate_packet_summary(summary_path)
    if validation["passed"] is not True:
        raise ValueError(f"written Beta-FE-1 packet failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": "beta-fe1-frontend-collaboration-packet-write-report:v1",
        "passed": True,
        "packet_summary_path": str(summary_path),
        "packet_summary_sha256": _sha256(summary_path),
        "output_root": str(output_root),
        "participant_count": len(participants),
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
    if packet.get("decision") != "beta_fe1_frontend_collaboration_packet_ready":
        failures.append("decision must be beta_fe1_frontend_collaboration_packet_ready")
    if packet.get("passed") is not True:
        failures.append("packet passed must be true")
    participants = packet.get("participants")
    if not isinstance(participants, list) or len(participants) < 2:
        failures.append("participants must contain at least 2 entries")
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
    for label in ("frontend_context", "task_brief", "agent_responses_readme", "operator_decision_required"):
        _validate_ref(refs.get(label), failures, label)
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
    participant = _participant_by_id(packet, participant_id)
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
        raise ValueError(f"Beta-FE-1 response record blocked: {failures}")

    response = {
        "schema_version": RESPONSE_SCHEMA,
        "recorded_at": _now(),
        "response_scope": "beta_fe1_frontend_non_mutating_agent_response_only",
        "source_packet": _artifact_ref(packet_summary_path),
        "participant_id": participant_id,
        "role": participant["role"],
        "focus": participant["focus"],
        "response_file": _artifact_ref(response_file),
        "recommendation": recommendation,
        "observer_actor_id": observer_actor_id,
        "external_agent_response_observed": True,
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
    if validation["passed"] is not True:
        raise ValueError(f"written Beta-FE-1 response failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": "beta-fe1-agent-response-record-write-report:v1",
        "passed": True,
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
    if response.get("response_scope") != "beta_fe1_frontend_non_mutating_agent_response_only":
        failures.append("response_scope must be beta_fe1_frontend_non_mutating_agent_response_only")
    for field in ("participant_id", "role", "focus", "observer_actor_id"):
        if not _text(response.get(field)):
            failures.append(f"{field} must be non-empty")
    if response.get("recommendation") not in RECOMMENDATIONS:
        failures.append(f"recommendation must be one of {list(RECOMMENDATIONS)}")
    packet_path = _validate_ref(response.get("source_packet"), failures, "source_packet")
    if packet_path is not None:
        packet_validation = validate_packet_summary(packet_path)
        if packet_validation["passed"] is not True:
            failures.extend(f"source packet invalid: {reason}" for reason in packet_validation["failure_reasons"])
    _validate_ref(response.get("response_file"), failures, "response_file")
    for field in (
        "direct_mutation_allowed",
        "apply_allowed",
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if response.get(field) is not False:
            failures.append(f"{field} must be false")
    _validate_h3_boundary(response, failures)
    return _validation_report(RESPONSE_VALIDATION_SCHEMA, path, failures)


def reconcile_responses(
    *,
    packet_summary_path: Path,
    response_record_paths: list[Path],
    output_path: Path,
    min_responses: int = 2,
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
    participant_ids = [response.get("participant_id") for _, response in responses]
    unique_participants = sorted({str(value) for value in participant_ids if value})
    if len(unique_participants) < min_responses:
        failures.append(f"unique response participant count must be >= {min_responses}")
    recommendation_counts: dict[str, int] = {}
    for _, response in responses:
        recommendation = str(response.get("recommendation") or "unknown")
        recommendation_counts[recommendation] = recommendation_counts.get(recommendation, 0) + 1

    passed = not failures
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe1_operator_decision_ready" if passed else "blocked",
        "failure_reasons": failures,
        "source_packet": packet_ref,
        "frontend_root": packet.get("frontend_root") if isinstance(packet, dict) else None,
        "response_count": len(responses),
        "unique_participant_count": len(unique_participants),
        "unique_participants": unique_participants,
        "recommendation_counts": recommendation_counts,
        "response_records": [_artifact_ref(path) for path, _ in responses if path.is_file()],
        "operator_decision_required": True,
        "safe_next_step": "operator_review_before_any_frontend_code_change" if passed else "collect_or_fix_response_records",
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _frontend_snapshot(frontend_root: Path) -> dict[str, Any]:
    package = _read_json(frontend_root / "package.json", [], "package.json")
    files = _source_files(frontend_root)
    line_counts = sorted(
        ({"path": str(path.relative_to(frontend_root)), "lines": _line_count(path)} for path in files),
        key=lambda item: item["lines"],
        reverse=True,
    )
    components = [item for item in line_counts if item["path"].startswith("src/components/") and item["path"].endswith(".tsx")]
    tests = [item for item in line_counts if item["path"].endswith(".test.tsx") or item["path"].endswith(".test.ts")]
    return {
        "git_commit": _git(["rev-parse", "--short", "HEAD"], cwd=frontend_root),
        "git_dirty": bool(_git(["status", "--short"], cwd=frontend_root).strip()),
        "package_name": package.get("name"),
        "package_version": package.get("version"),
        "scripts": package.get("scripts", {}),
        "dependencies": sorted((package.get("dependencies") or {}).keys()),
        "dev_dependencies": sorted((package.get("devDependencies") or {}).keys()),
        "source_file_count": len(files),
        "component_file_count": len(components),
        "test_file_count": len(tests),
        "total_source_lines": sum(item["lines"] for item in line_counts),
        "largest_files": line_counts[:20],
        "oversized_files": [item for item in line_counts if item["lines"] > 200],
        "entrypoints": [str(path.relative_to(frontend_root)) for path in (frontend_root / "src").glob("*.tsx")],
        "services": [str(path.relative_to(frontend_root)) for path in sorted((frontend_root / "src/services").glob("*"))],
        "contexts": [str(path.relative_to(frontend_root)) for path in sorted((frontend_root / "src/contexts").glob("*"))],
    }


def _render_context(frontend_root: Path, snapshot: dict[str, Any]) -> str:
    largest = "\n".join(f"- `{item['path']}`: {item['lines']} lines" for item in snapshot["largest_files"][:12])
    oversized = "\n".join(f"- `{item['path']}`: {item['lines']} lines" for item in snapshot["oversized_files"][:20]) or "- none"
    scripts = "\n".join(f"- `{name}`: `{cmd}`" for name, cmd in sorted(snapshot["scripts"].items()))
    services = "\n".join(f"- `{path}`" for path in snapshot["services"]) or "- none"
    contexts = "\n".join(f"- `{path}`" for path in snapshot["contexts"]) or "- none"
    deps = ", ".join(snapshot["dependencies"])
    return f"""# Beta-FE-1 Frontend Context

## Scope

This context is generated for non-mutating multi-Agent review. It is a bounded
summary of `civitasos-frontend`; it is not authorization to modify code.

## Repository

- Root: `{frontend_root}`
- Git commit: `{snapshot['git_commit']}`
- Dirty worktree observed: `{str(snapshot['git_dirty']).lower()}`
- Package: `{snapshot['package_name']}@{snapshot['package_version']}`

## Technical Stack

- React / TypeScript / react-scripts CRA
- Dependencies: {deps}

## Package Scripts

{scripts}

## Structure Metrics

- Source files: {snapshot['source_file_count']}
- Component files: {snapshot['component_file_count']}
- Test files: {snapshot['test_file_count']}
- Total source lines: {snapshot['total_source_lines']}

## Largest Files

{largest}

## Files Above 200 Lines

{oversized}

## Services

{services}

## Contexts

{contexts}

## Initial Architectural Signals

- `src/services/apiClient.ts` is very large and should be reviewed as an API/read-model boundary risk.
- `src/App.tsx` owns tab composition, data fetching orchestration, auth-dependent state, and layout concerns.
- Many panel components are self-contained but long, so a full visual rewrite should be delayed until a safe slice is chosen.
- Existing tests are sparse compared with component count, so any refactor should start with smokeable slices.

## Non-Claims

- This file does not authorize apply, commit, push, merge, deploy, production runtime execution, or production receipts.
- This file is not H.3 production evidence.
"""


def _render_task_brief(participants: list[dict[str, Any]]) -> str:
    participant_lines = "\n".join(
        f"- `{item['participant_id']}` ({item['role']}): {item['focus']}" for item in participants
    )
    return f"""# Beta-FE-1 Frontend Refactor Collaboration Brief

## Objective

Design a safe first-stage refactor plan for `civitasos-frontend` so it becomes a
CivitasOS Agent society console rather than a panel-heavy demo/admin surface.

## Participants

{participant_lines}

## Required Response Format

Each Agent response should include:

1. `Role-specific diagnosis`
2. `Target architecture`
3. `First safe slice`
4. `Risks and regressions`
5. `Acceptance checks`
6. `What must not change yet`

## Hard Boundaries

- Read-only review/proposal only.
- Do not apply patches directly.
- Do not commit, push, merge, or deploy.
- Do not request or expose secrets.
- Preserve current backend API behavior unless explicitly proposing a compatibility adapter.
- Keep H.3 blocked and production flags false.

## Preferred First Slice

Prefer a small, reviewable slice such as:

- API/read-model adapter extraction around `apiClient.ts`.
- `App.tsx` tab/data orchestration split without visual redesign.
- One high-value Agent/Task/Observability panel refactor with tests.
- A route/layout shell that preserves current panels while enabling future redesign.

## Operator Decision

After responses are recorded and reconciled, the operator decides whether a
Beta-FE-2 patch proposal may start. Beta-FE-1 itself does not authorize code
changes.
"""


def _render_response_readme(participants: list[dict[str, Any]]) -> str:
    filenames = "\n".join(f"- `{item['participant_id']}.md`" for item in participants)
    return f"""# Beta-FE-1 Agent Responses

Place non-mutating Agent responses here.

Expected response files:

{filenames}

Record each response with:

```bash
./scripts/beta_fe1_frontend_collaboration_packet.py record-response \\
  --packet-summary <run>/beta_fe1_packet_summary.json \\
  --participant-id <participant-id> \\
  --response-file <run>/agent_responses/<participant-id>.md \\
  --recommendation revise \\
  --output <run>/agent_responses/<participant-id>.record.json
```

Responses are evidence only. They do not authorize code mutation.
"""


def _operator_decision_payload(operator_id: str, summary_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "beta-fe1-operator-decision-required:v1",
        "created_at": _now(),
        "operator_id": operator_id,
        "source_packet_summary_path": str(summary_path),
        "operator_decision_required": True,
        "allowed_decisions_after_reconciliation": [
            "start_beta_fe2_patch_proposal",
            "request_more_agent_responses",
            "reject_frontend_refactor_start",
        ],
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


def _source_files(root: Path) -> list[Path]:
    allowed = {".ts", ".tsx", ".js", ".jsx", ".css", ".json", ".html", ".md"}
    blocked_parts = {".git", "node_modules", "build", "dist", ".cache"}
    files = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in allowed:
            continue
        rel = path.relative_to(root)
        if any(part in blocked_parts for part in rel.parts):
            continue
        if not rel.parts or rel.parts[0] not in {"src", "public", "scripts"}:
            continue
        if path.name.startswith(".env"):
            continue
        files.append(path)
    return sorted(files)


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return 0


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
    for field in (
        "direct_mutation_allowed",
        "apply_allowed",
        "commit_allowed",
        "push_allowed",
        "merge_allowed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if value.get(field) is not False:
            failures.append(f"{label}.{field} must be false")


def _validate_h3_boundary(value: dict[str, Any], failures: list[str]) -> None:
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3.get("h3_remains_blocked") is not True:
        failures.append("h3_boundary.h3_remains_blocked must be true")
    if h3.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary.h3_production_readiness_claimed must be false")


def _boundary() -> dict[str, bool]:
    return {
        "direct_mutation_allowed": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _reject_forbidden_text(values: list[str], failures: list[str]) -> None:
    upper = "\n".join(value.upper() for value in values if value)
    for token in FORBIDDEN_TEXT:
        if token in upper:
            failures.append(f"forbidden token present: {token}")


def _git(args: list[str], *, cwd: Path) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_passed(report: dict[str, Any]) -> bool:
    if "passed" in report:
        return report.get("passed") is True
    validation = report.get("validation")
    if isinstance(validation, dict) and "passed" in validation:
        return validation.get("passed") is True
    return True


if __name__ == "__main__":
    raise SystemExit(main())
