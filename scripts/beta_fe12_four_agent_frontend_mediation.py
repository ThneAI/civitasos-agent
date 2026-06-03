#!/usr/bin/env python3
"""Beta-FE-12 four-Agent CivitasOS-mediated frontend planning gate.

This gate creates a fresh frontend patch-planning packet, posts one CivitasOS
pool task per participant, requires each Agent runner to claim/generate/deliver,
and writes a reconciliation artifact. It does not modify frontend code and does
not authorize commit/push/merge/deploy/production actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import beta_fe26_agent_runner_mediation as fe26

PACKET_SCHEMA = "beta-fe2-frontend-patch-proposal-packet:v1"
SUMMARY_SCHEMA = "beta-fe12-four-agent-frontend-mediation-summary:v1"
RECONCILIATION_SCHEMA = "beta-fe12-four-agent-frontend-reconciliation:v1"
PATCH_SLICE_ID = "task_pool_presentation_extraction"
REQUIRED_PARTICIPANTS = (
    ("deepseek-api-agent", "implementation_proposer", "minimal implementation plan and file boundary"),
    ("claude-cli-agent", "architecture_reviewer", "architecture risk and boundary review"),
    ("hermes-cli-agent", "ux_product_reviewer", "operator workflow and UX impact critique"),
    ("local-gpu-agent", "smoke_verifier", "test/build/smoke checklist and rollback risks"),
)
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
    "beta_fe12_posts_civitasos_pool_tasks_before_agent_generation",
    "beta_fe12_requires_each_agent_to_claim_generate_deliver",
    "beta_fe12_does_not_modify_frontend_repo",
    "beta_fe12_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe12_does_not_claim_h3_production_readiness",
    "beta_fe12_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", default=fe26.DEFAULT_BACKEND_URL)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--runner-spec", action="append", default=[], help="participant=openai-env:/path or participant=command:argv")
    parser.add_argument("--confirm-deliveries", action="store_true")
    parser.add_argument("--demo-login-agent-id", default="beta_fe12_four_agent_frontend_mediation")
    args = parser.parse_args(argv)

    output_root = Path(args.output_root).resolve()
    frontend_root = Path(args.frontend_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    packet = write_packet(frontend_root=frontend_root, output_root=output_root)
    generators = fe26._parse_runner_specs(args.runner_spec)
    missing = sorted(set(_participant_ids(packet)) - set(generators))
    if missing:
        raise SystemExit(f"missing runner specs for FE-12 participant(s): {', '.join(missing)}")
    client = fe26.HttpJsonClient(args.backend_url, demo_login_agent_id=args.demo_login_agent_id)
    mediation_root = output_root / "mediation"
    mediation = fe26.run_mediation(
        client=client,
        fe2_packet_summary_path=output_root / "beta_fe12_packet_summary.json",
        output_root=mediation_root,
        generators=generators,
        participant_allowlist=list(_participant_ids(packet)),
        backend_url=args.backend_url,
        confirm_deliveries=bool(args.confirm_deliveries),
        expected_patch_slice_id=PATCH_SLICE_ID,
    )
    reconciliation = write_reconciliation(output_root=output_root, mediation_root=mediation_root, mediation=mediation)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "checked_at": _now(),
        "passed": bool(mediation.get("passed") is True and reconciliation.get("passed") is True),
        "decision": "beta_fe12_four_agent_frontend_mediation_passed" if mediation.get("passed") is True and reconciliation.get("passed") is True else "blocked",
        "patch_slice_id": PATCH_SLICE_ID,
        "source_packet": _artifact_ref(output_root / "beta_fe12_packet_summary.json"),
        "mediation_summary": _artifact_ref(mediation_root / "beta_fe26_agent_runner_mediation_summary.json"),
        "reconciliation": _artifact_ref(output_root / "beta_fe12_four_agent_reconciliation.json"),
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
    _write_json(output_root / "beta_fe12_four_agent_mediation_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def write_packet(*, frontend_root: Path, output_root: Path) -> dict[str, Any]:
    snapshot = _frontend_snapshot(frontend_root)
    context_path = output_root / "beta_fe12_frontend_context.md"
    brief_path = output_root / "beta_fe12_task_brief.md"
    prompts_dir = output_root / "agent_prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    context = _context_text(frontend_root, snapshot)
    brief = _brief_text()
    context_path.write_text(context, encoding="utf-8")
    brief_path.write_text(brief, encoding="utf-8")
    prompt_refs: dict[str, Any] = {}
    for participant_id, role, focus in REQUIRED_PARTICIPANTS:
        prompt_path = prompts_dir / f"{participant_id}.prompt.txt"
        prompt_path.write_text(_prompt_text(participant_id, role, focus, context, brief), encoding="utf-8")
        prompt_refs[participant_id] = _artifact_ref(prompt_path)
    packet = {
        "schema_version": PACKET_SCHEMA,
        "checked_at": _now(),
        "passed": True,
        "decision": "beta_fe2_patch_proposal_packet_ready",
        "compatibility_note": "FE-12 uses the FE-2 packet schema so the verified FE-2.6 task-pool mediation primitive can consume it.",
        "stage": "beta_fe12_four_agent_frontend_mediation",
        "patch_slice_id": PATCH_SLICE_ID,
        "frontend_root": str(frontend_root),
        "frontend_snapshot": snapshot,
        "participants": [
            {
                "participant_id": participant_id,
                "role": role,
                "focus": focus,
                "direct_mutation_allowed": False,
            }
            for participant_id, role, focus in REQUIRED_PARTICIPANTS
        ],
        "context_ref": _artifact_ref(context_path),
        "brief_ref": _artifact_ref(brief_path),
        "agent_prompt_refs": prompt_refs,
        "collaboration_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe12_packet_summary.json", packet)
    return packet


def write_reconciliation(*, output_root: Path, mediation_root: Path, mediation: dict[str, Any]) -> dict[str, Any]:
    findings: list[str] = []
    response_summaries: list[dict[str, Any]] = []
    for participant_id in mediation.get("runner_participant_ids", []):
        receipt_path = mediation_root / f"{participant_id}.task_receipt.json"
        receipt = _read_json(receipt_path)
        generation_ref = receipt.get("generation_response", {}) if isinstance(receipt, dict) else {}
        generation_path = Path(str(generation_ref.get("path") or ""))
        content = generation_path.read_text(encoding="utf-8") if generation_path.is_file() else ""
        verdict = _extract_verdict(content)
        if not content:
            findings.append(f"{participant_id} generation response is missing")
        if verdict == "inconclusive":
            findings.append(f"{participant_id} did not provide a clear proceed/revise/reject verdict")
        response_summaries.append({
            "participant_id": participant_id,
            "task_id": receipt.get("task_id"),
            "runner_kind": receipt.get("runner_kind"),
            "final_status": receipt.get("final_task", {}).get("status"),
            "claim_observed": receipt.get("claim_observed"),
            "generation_observed_after_claim": receipt.get("generation_observed_after_claim"),
            "delivery_observed": receipt.get("delivery_observed"),
            "verdict": verdict,
            "generation_response": generation_ref,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None,
            "content_excerpt": content[:1200],
        })
    verdict_counts = {verdict: sum(1 for item in response_summaries if item["verdict"] == verdict) for verdict in ("proceed", "revise", "reject", "inconclusive")}
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
    elif len(response_summaries) == 4 and verdict_counts["proceed"] >= 2 and verdict_counts["inconclusive"] == 0 and not findings:
        decision = "beta_fe12_reconciliation_ready_for_fe3"
        safe_next_step = "prepare_bounded_fe3_apply_for_task_pool_presentation_extraction"
    else:
        decision = "operator_review_required"
        safe_next_step = "operator_review_required_before_any_apply"
    passed = decision == "beta_fe12_reconciliation_ready_for_fe3"
    reconciliation = {
        "schema_version": RECONCILIATION_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": decision,
        "patch_slice_id": PATCH_SLICE_ID,
        "selected_plan": {
            "slice_id": PATCH_SLICE_ID,
            "intent": "Extract TaskPoolPanel pure presentation/read-model helper logic into a typed module with focused tests.",
            "allowed_files": [
                "src/components/TaskPoolPanel.tsx",
                "src/components/taskPoolPresentation.ts",
                "src/components/taskPoolPresentation.test.ts",
            ],
            "forbidden_changes": [
                "backend API contract",
                "AuthContext behavior",
                "deploy or production flags",
                "visual redesign beyond helper extraction",
            ],
        },
        "verdict_counts": verdict_counts,
        "response_summaries": response_summaries,
        "failure_reasons": findings,
        "safe_next_step": safe_next_step,
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe12_four_agent_reconciliation.json", reconciliation)
    return reconciliation


def _frontend_snapshot(frontend_root: Path) -> dict[str, Any]:
    return {
        "head_commit": _git(frontend_root, "rev-parse", "HEAD"),
        "head_short": _git(frontend_root, "rev-parse", "--short", "HEAD"),
        "status_short": [line for line in _git(frontend_root, "status", "--short").splitlines() if line.strip()],
        "task_pool_panel_lines": _line_count(frontend_root / "src/components/TaskPoolPanel.tsx"),
        "task_pool_api_lines": _line_count(frontend_root / "src/services/taskPoolApi.ts"),
        "task_read_adapter_lines": _line_count(frontend_root / "src/adapters/TaskReadAdapter.ts"),
    }


def _context_text(frontend_root: Path, snapshot: dict[str, Any]) -> str:
    panel = _excerpt(frontend_root / "src/components/TaskPoolPanel.tsx", 220)
    return f"""# Beta-FE-12 Frontend Context

Repository: `{frontend_root}`
Head: `{snapshot['head_commit']}`
Dirty worktree: `{bool(snapshot['status_short'])}`

Current state:

- FE-10 preview passed.
- `taskPoolApi.ts` exists and task pool HTTP calls are no longer embedded directly in `apiClient.ts`.
- `TaskReadAdapter` exists and `TaskPoolPanel.tsx` already consumes `taskReadAdapter.readPool()`.
- `TaskPoolPanel.tsx` still owns many pure presentation/read-model helper functions.

Target slice:

`{PATCH_SLICE_ID}`

Candidate allowed files:

- `src/components/TaskPoolPanel.tsx`
- `src/components/taskPoolPresentation.ts`
- `src/components/taskPoolPresentation.test.ts`

Relevant current `TaskPoolPanel.tsx` excerpt:

```tsx
{panel}
```
"""


def _brief_text() -> str:
    return f"""# Beta-FE-12 Task Brief

Goal: decide whether the next bounded frontend slice should extract pure helper logic from `TaskPoolPanel.tsx` into `taskPoolPresentation.ts` with focused tests.

Required response sections:

1. Patch proposal verdict: `proceed`, `revise`, `reject`, or `inconclusive`.
2. Files to add/change.
3. Exact helper functions or types to move.
4. Tests and smoke checks.
5. Risks and rollback.
6. What must not change.

Hard constraints:

- Do not mutate files.
- Do not recommend direct commit, push, merge, deploy, production runtime, or production receipt.
- Preserve backend API contracts, AuthContext behavior, current visual behavior, and H.3 blocked state.
- Keep the slice small enough for FE-3 bounded apply and rollback.
"""


def _prompt_text(participant_id: str, role: str, focus: str, context: str, brief: str) -> str:
    return f"""You are `{participant_id}` for CivitasOS Beta-FE-12.
Role: {role}
Focus: {focus}

This is a CivitasOS-mediated task. You will only respond after your worker identity has claimed a task from the CivitasOS pool. Produce a fresh, non-mutating proposal/review.

{brief}

--- CONTEXT ---
{context}
"""


def _extract_verdict(content: str) -> str:
    text = content.lower()
    patterns = [
        r"patch proposal verdict\s*[:\-]\s*(proceed|revise|reject|inconclusive)",
        r"verdict\s*[:\-]\s*(proceed|revise|reject|inconclusive)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    for verdict in ("reject", "revise", "proceed"):
        if verdict in text[:1200]:
            return verdict
    return "inconclusive"


def _participant_ids(packet: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(item.get("participant_id")) for item in packet.get("participants", []) if isinstance(item, dict))


def _failure_reasons(mediation: dict[str, Any], reconciliation: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    reasons.extend(str(item) for item in mediation.get("failure_reasons", []) if item)
    reasons.extend(str(item) for item in reconciliation.get("failure_reasons", []) if item)
    return reasons


def _boundary() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARY_FIELDS}


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _artifact_ref(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest()}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.is_file() else 0


def _excerpt(path: Path, max_lines: int) -> str:
    if not path.is_file():
        return ""
    return "\n".join(path.read_text(encoding="utf-8").splitlines()[:max_lines])


if __name__ == "__main__":
    raise SystemExit(main())
