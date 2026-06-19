#!/usr/bin/env python3
"""Reusable four-Agent CivitasOS-mediated frontend orchestration gate.

The gate creates a scenario-specific frontend planning packet, posts one
CivitasOS pool task per configured Agent, requires each runner to claim,
generate, and deliver through the pool, then writes a reconciliation artifact.
It does not modify frontend code and does not authorize apply, commit, push,
merge, deploy, production runtime execution, or production receipts.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import beta_fe26_agent_runner_mediation as fe26
except ModuleNotFoundError:
    from scripts import beta_fe26_agent_runner_mediation as fe26

try:
    from beta_fe_four_agent_evidence import (
        REQUIRED_PARTICIPANTS,
        artifact_ref as _artifact_ref,
        boundary as _boundary,
        excerpt as _excerpt,
        extract_verdict as _extract_verdict,
        failure_reasons as _failure_reasons,
        frontend_snapshot as _shared_frontend_snapshot,
        git_text as _git,
        h3_boundary as _h3_boundary,
        line_count as _line_count,
        participant_ids as _participant_ids,
        read_json_object as _read_json,
        response_summaries as _collect_response_summaries,
        write_json as _write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_fe_four_agent_evidence import (
        REQUIRED_PARTICIPANTS,
        artifact_ref as _artifact_ref,
        boundary as _boundary,
        excerpt as _excerpt,
        extract_verdict as _extract_verdict,
        failure_reasons as _failure_reasons,
        frontend_snapshot as _shared_frontend_snapshot,
        git_text as _git,
        h3_boundary as _h3_boundary,
        line_count as _line_count,
        participant_ids as _participant_ids,
        read_json_object as _read_json,
        response_summaries as _collect_response_summaries,
        write_json as _write_json,
    )

PACKET_SCHEMA = "beta-fe2-frontend-patch-proposal-packet:v1"
SUMMARY_SCHEMA = "beta-fe-four-agent-frontend-orchestration-summary:v1"
RECONCILIATION_SCHEMA = "beta-fe-four-agent-frontend-reconciliation:v1"
NON_CLAIMS = (
    "beta_fe_four_agent_orchestrator_posts_civitasos_pool_tasks_before_agent_generation",
    "beta_fe_four_agent_orchestrator_requires_each_agent_to_claim_generate_deliver",
    "beta_fe_four_agent_orchestrator_does_not_modify_frontend_repo",
    "beta_fe_four_agent_orchestrator_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe_four_agent_orchestrator_does_not_claim_h3_production_readiness",
    "beta_fe_four_agent_orchestrator_does_not_write_production_receipts",
)


@dataclass(frozen=True)
class FrontendScenario:
    scenario_id: str
    stage: str
    patch_slice_id: str
    title: str
    goal: str
    current_state: tuple[str, ...]
    allowed_files: tuple[str, ...]
    forbidden_changes: tuple[str, ...]
    focus_files: tuple[str, ...]
    safe_next_step: str
    min_proceed: int = 2
    excerpt_lines: int = 120


SCENARIOS: dict[str, FrontendScenario] = {
    "fe12-task-pool-presentation": FrontendScenario(
        scenario_id="fe12-task-pool-presentation",
        stage="beta_fe12_four_agent_frontend_mediation",
        patch_slice_id="task_pool_presentation_extraction",
        title="Task pool presentation helper extraction",
        goal="Extract pure helper logic from TaskPoolPanel.tsx into taskPoolPresentation.ts with focused tests.",
        current_state=(
            "FE-10 preview passed.",
            "taskPoolApi.ts exists and task pool HTTP calls are no longer embedded directly in apiClient.ts.",
            "TaskReadAdapter exists and TaskPoolPanel.tsx consumes taskReadAdapter.readPool().",
            "TaskPoolPanel.tsx still owns pure presentation/read-model helper functions.",
        ),
        allowed_files=(
            "src/components/TaskPoolPanel.tsx",
            "src/components/taskPoolPresentation.ts",
            "src/components/taskPoolPresentation.test.ts",
        ),
        forbidden_changes=(
            "backend API contract",
            "AuthContext behavior",
            "deploy or production flags",
            "visual redesign beyond helper extraction",
        ),
        focus_files=(
            "src/components/TaskPoolPanel.tsx",
            "src/components/taskPoolPresentation.ts",
            "src/services/taskPoolApi.ts",
            "src/adapters/TaskReadAdapter.ts",
        ),
        safe_next_step="prepare_bounded_fe3_apply_for_task_pool_presentation_extraction",
        excerpt_lines=160,
    ),
    "fe13-app-shell-decomposition": FrontendScenario(
        scenario_id="fe13-app-shell-decomposition",
        stage="beta_fe13_four_agent_frontend_refactor_planning",
        patch_slice_id="app_shell_panel_registry_decomposition",
        title="App shell and panel registry decomposition",
        goal=(
            "Plan a larger but still bounded frontend refactor that extracts App.tsx navigation/panel registry "
            "logic into typed app-shell modules without changing auth, routes, backend contracts, or visual behavior."
        ),
        current_state=(
            "App.tsx is still one of the largest frontend files and owns navigation, panel selection, and layout composition.",
            "Task pool API/read adapter/presentation slices are already separated and covered by focused tests.",
            "This FE-13 gate is planning-only; it must not authorize direct code mutation.",
        ),
        allowed_files=(
            "src/App.tsx",
            "src/app/AppShell.tsx",
            "src/app/panelRegistry.ts",
            "src/app/panelRegistry.test.ts",
        ),
        forbidden_changes=(
            "AuthContext behavior",
            "I18n or Theme context behavior",
            "backend API contract",
            "route semantics",
            "deploy or production flags",
            "large visual redesign",
        ),
        focus_files=(
            "src/App.tsx",
            "src/contexts/AuthContext.tsx",
            "src/contexts/I18nContext.tsx",
            "src/contexts/ThemeContext.tsx",
            "src/components/TaskPoolPanel.tsx",
        ),
        safe_next_step="operator_review_before_bounded_fe3_apply_for_app_shell_panel_registry_decomposition",
        excerpt_lines=90,
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="fe12-task-pool-presentation")
    parser.add_argument("--backend-url", default=fe26.DEFAULT_BACKEND_URL)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument(
        "--runner-spec",
        action="append",
        default=[],
        help="participant=openai-env:/path, participant=ollama-native:model, or participant=command:argv",
    )
    parser.add_argument("--confirm-deliveries", action="store_true")
    parser.add_argument("--demo-login-agent-id", default="beta_fe_four_agent_orchestrator")
    args = parser.parse_args(argv)

    summary = run_orchestrator(
        scenario=SCENARIOS[args.scenario],
        backend_url=args.backend_url,
        frontend_root=Path(args.frontend_root),
        output_root=Path(args.output_root),
        runner_specs=args.runner_spec,
        confirm_deliveries=bool(args.confirm_deliveries),
        demo_login_agent_id=args.demo_login_agent_id,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


def run_orchestrator(
    *,
    scenario: FrontendScenario,
    backend_url: str,
    frontend_root: Path,
    output_root: Path,
    runner_specs: list[str],
    confirm_deliveries: bool,
    demo_login_agent_id: str,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    frontend_root = frontend_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    packet = write_packet(scenario=scenario, frontend_root=frontend_root, output_root=output_root)
    generators = fe26._parse_runner_specs(runner_specs)
    missing = sorted(set(_participant_ids(packet)) - set(generators))
    if missing:
        raise RuntimeError(f"missing runner specs for participant(s): {', '.join(missing)}")
    client = fe26.HttpJsonClient(backend_url, demo_login_agent_id=demo_login_agent_id)
    mediation_root = output_root / "mediation"
    try:
        mediation = fe26.run_mediation(
            client=client,
            fe2_packet_summary_path=output_root / "frontend_four_agent_packet_summary.json",
            output_root=mediation_root,
            generators=generators,
            participant_allowlist=list(_participant_ids(packet)),
            backend_url=backend_url,
            confirm_deliveries=confirm_deliveries,
            expected_patch_slice_id=scenario.patch_slice_id,
        )
    except Exception as exc:
        mediation = {
            "schema_version": fe26.SUMMARY_SCHEMA,
            "checked_at": _now(),
            "passed": False,
            "decision": "blocked",
            "runner_participant_ids": [],
            "task_receipt_count": 0,
            "claim_observed_count": 0,
            "generation_after_claim_observed_count": 0,
            "delivery_observed_count": 0,
            "failure_reasons": [f"mediation runner failed: {exc}"],
            "boundary": _boundary(),
            "h3_boundary": _h3_boundary(),
            "non_claims": list(NON_CLAIMS),
        }
        _write_json(mediation_root / "beta_fe26_agent_runner_mediation_summary.json", mediation)
    reconciliation = write_reconciliation(scenario=scenario, output_root=output_root, mediation_root=mediation_root, mediation=mediation)
    passed = mediation.get("passed") is True and reconciliation.get("passed") is True
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe_four_agent_orchestration_passed" if passed else "blocked",
        "scenario_id": scenario.scenario_id,
        "stage": scenario.stage,
        "patch_slice_id": scenario.patch_slice_id,
        "source_packet": _artifact_ref(output_root / "frontend_four_agent_packet_summary.json"),
        "mediation_summary": _artifact_ref(mediation_root / "beta_fe26_agent_runner_mediation_summary.json"),
        "reconciliation": _artifact_ref(output_root / "frontend_four_agent_reconciliation.json"),
        "participants": list(_participant_ids(packet)),
        "runner_participant_ids": mediation.get("runner_participant_ids"),
        "task_receipt_count": mediation.get("task_receipt_count"),
        "claim_observed_count": mediation.get("claim_observed_count"),
        "generation_after_claim_observed_count": mediation.get("generation_after_claim_observed_count"),
        "delivery_observed_count": mediation.get("delivery_observed_count"),
        "selected_plan": reconciliation.get("selected_plan"),
        "safe_next_step": reconciliation.get("safe_next_step"),
        "failure_reasons": _failure_reasons(mediation, reconciliation),
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "frontend_four_agent_orchestration_summary.json", summary)
    return summary


def write_packet(*, scenario: FrontendScenario, frontend_root: Path, output_root: Path) -> dict[str, Any]:
    snapshot = _frontend_snapshot(frontend_root, scenario)
    context_path = output_root / "frontend_context.md"
    brief_path = output_root / "task_brief.md"
    prompts_dir = output_root / "agent_prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    context = _context_text(frontend_root, scenario, snapshot)
    brief = _brief_text(scenario)
    context_path.write_text(context, encoding="utf-8")
    brief_path.write_text(brief, encoding="utf-8")
    prompt_refs: dict[str, Any] = {}
    for participant_id, role, focus in REQUIRED_PARTICIPANTS:
        prompt_path = prompts_dir / f"{participant_id}.prompt.txt"
        participant_context = _participant_context(participant_id, scenario, context)
        prompt_path.write_text(_prompt_text(participant_id, role, focus, participant_context, brief), encoding="utf-8")
        prompt_refs[participant_id] = _artifact_ref(prompt_path)
    packet = {
        "schema_version": PACKET_SCHEMA,
        "checked_at": _now(),
        "passed": True,
        "decision": "beta_fe2_patch_proposal_packet_ready",
        "compatibility_note": "Reusable FE orchestrator uses the FE-2 packet schema so FE-2.6 task-pool mediation can consume scenario packets.",
        "scenario_id": scenario.scenario_id,
        "stage": scenario.stage,
        "patch_slice_id": scenario.patch_slice_id,
        "frontend_root": str(frontend_root),
        "frontend_snapshot": snapshot,
        "participants": [
            {"participant_id": participant_id, "role": role, "focus": focus, "direct_mutation_allowed": False}
            for participant_id, role, focus in REQUIRED_PARTICIPANTS
        ],
        "context_ref": _artifact_ref(context_path),
        "brief_ref": _artifact_ref(brief_path),
        "agent_prompt_refs": prompt_refs,
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "frontend_four_agent_packet_summary.json", packet)
    return packet


def write_reconciliation(
    *,
    scenario: FrontendScenario,
    output_root: Path,
    mediation_root: Path,
    mediation: dict[str, Any],
) -> dict[str, Any]:
    findings: list[str] = []
    response_summaries = _response_summaries(mediation_root, mediation, findings)
    verdict_counts = {
        verdict: sum(1 for item in response_summaries if item["verdict"] == verdict)
        for verdict in ("proceed", "revise", "reject", "inconclusive")
    }
    required = {participant_id for participant_id, _, _ in REQUIRED_PARTICIPANTS}
    observed = {str(item.get("participant_id")) for item in response_summaries}
    missing = sorted(required - observed)
    if missing:
        findings.append(f"missing participant receipts: {', '.join(missing)}")
    if mediation.get("passed") is not True:
        findings.append("source mediation summary must be passed")
    if verdict_counts["reject"] > 0:
        decision = "blocked"
        safe_next_step = "operator_review_required_before_any_apply"
    elif len(response_summaries) == len(REQUIRED_PARTICIPANTS) and verdict_counts["proceed"] >= scenario.min_proceed and verdict_counts["inconclusive"] == 0 and not findings:
        decision = "beta_fe_four_agent_reconciliation_ready"
        safe_next_step = scenario.safe_next_step
    else:
        decision = "operator_review_required"
        safe_next_step = "operator_review_required_before_any_apply"
    reconciliation = {
        "schema_version": RECONCILIATION_SCHEMA,
        "checked_at": _now(),
        "passed": decision == "beta_fe_four_agent_reconciliation_ready",
        "decision": decision,
        "scenario_id": scenario.scenario_id,
        "patch_slice_id": scenario.patch_slice_id,
        "selected_plan": {
            "slice_id": scenario.patch_slice_id,
            "intent": scenario.goal,
            "allowed_files": list(scenario.allowed_files),
            "forbidden_changes": list(scenario.forbidden_changes),
        },
        "verdict_counts": verdict_counts,
        "response_summaries": response_summaries,
        "failure_reasons": findings,
        "safe_next_step": safe_next_step,
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "frontend_four_agent_reconciliation.json", reconciliation)
    return reconciliation


def _response_summaries(mediation_root: Path, mediation: dict[str, Any], findings: list[str]) -> list[dict[str, Any]]:
    return _collect_response_summaries(mediation_root=mediation_root, mediation=mediation, findings=findings)


def _frontend_snapshot(frontend_root: Path, scenario: FrontendScenario) -> dict[str, Any]:
    return _shared_frontend_snapshot(frontend_root, scenario.focus_files)


def _context_text(frontend_root: Path, scenario: FrontendScenario, snapshot: dict[str, Any]) -> str:
    excerpts = []
    for rel in scenario.focus_files:
        excerpts.append(f"## {rel}\n\n```tsx\n{_excerpt(frontend_root / rel, scenario.excerpt_lines)}\n```")
    state = "\n".join(f"- {item}" for item in scenario.current_state)
    allowed = "\n".join(f"- `{item}`" for item in scenario.allowed_files)
    return f"""# {scenario.title} Context

Repository: `{frontend_root}`
Head: `{snapshot['head_commit']}`
Dirty worktree: `{bool(snapshot['status_short'])}`

Current state:

{state}

Target slice:

`{scenario.patch_slice_id}`

Candidate allowed files:

{allowed}

Relevant excerpts:

{chr(10).join(excerpts)}
"""


def _brief_text(scenario: FrontendScenario) -> str:
    forbidden = "\n".join(f"- {item}" for item in scenario.forbidden_changes)
    return f"""# {scenario.stage} Task Brief

Goal: {scenario.goal}

Your first line must be exactly one of:

```text
Patch proposal verdict: proceed
Patch proposal verdict: revise
Patch proposal verdict: reject
Patch proposal verdict: inconclusive
```

Required response sections:

1. Patch proposal verdict: `proceed`, `revise`, `reject`, or `inconclusive`.
2. Files to add/change.
3. Exact components, functions, or types to move.
4. Tests and smoke checks.
5. Risks and rollback.
6. What must not change.

Hard constraints:

- Do not mutate files.
- Do not recommend direct commit, push, merge, deploy, production runtime, or production receipt.
- Preserve H.3 blocked state.
- Keep the slice small enough for FE-3 bounded apply and rollback.

Forbidden changes:

{forbidden}
"""


def _prompt_text(participant_id: str, role: str, focus: str, context: str, brief: str) -> str:
    return f"""You are `{participant_id}` for a CivitasOS frontend orchestration gate.
Role: {role}
Focus: {focus}

This is a CivitasOS-mediated task. You will only respond after your worker identity has claimed a task from the CivitasOS pool. Produce a fresh, non-mutating proposal/review.

{brief}

--- CONTEXT ---
{context}
"""


def _participant_context(participant_id: str, scenario: FrontendScenario, full_context: str) -> str:
    if participant_id != "local-gpu-agent":
        return full_context
    state = "\n".join(f"- {item}" for item in scenario.current_state)
    allowed = "\n".join(f"- `{item}`" for item in scenario.allowed_files)
    forbidden = "\n".join(f"- {item}" for item in scenario.forbidden_changes)
    return f"""# {scenario.title} Local Verification Context

Target slice:

`{scenario.patch_slice_id}`

Current state:

{state}

Candidate allowed files:

{allowed}

Forbidden changes:

{forbidden}

Verification focus:

- Confirm the proposal is limited to the candidate allowed files.
- Require focused unit tests plus build and rollback checks.
- Reject recommendations that introduce routes, new providers, backend contracts, deploy flags, or visual redesign.
- Do not infer new behavior from unrelated source excerpts; this local reviewer receives no raw implementation excerpts.
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
