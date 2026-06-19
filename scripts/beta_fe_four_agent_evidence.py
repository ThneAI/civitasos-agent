"""Shared contracts for four-Agent frontend planning gates."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    from beta_evidence import artifact_ref, read_json_object, write_json
except ModuleNotFoundError:
    from scripts.beta_evidence import artifact_ref, read_json_object, write_json


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


def boundary() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARY_FIELDS}


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def participant_ids(packet: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(item.get("participant_id")) for item in packet.get("participants", []) if isinstance(item, dict))


def failure_reasons(mediation: dict[str, Any], reconciliation: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    reasons.extend(str(item) for item in mediation.get("failure_reasons", []) if item)
    reasons.extend(str(item) for item in reconciliation.get("failure_reasons", []) if item)
    return reasons


def response_summaries(
    *,
    mediation_root: Path,
    mediation: dict[str, Any],
    findings: list[str],
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for participant_id in mediation.get("runner_participant_ids", []):
        receipt_path = mediation_root / f"{participant_id}.task_receipt.json"
        receipt = read_json_object(receipt_path)
        generation_ref = receipt.get("generation_response", {}) if isinstance(receipt, dict) else {}
        generation_path = Path(str(generation_ref.get("path") or ""))
        content = generation_path.read_text(encoding="utf-8") if generation_path.is_file() else ""
        verdict = extract_verdict(content)
        if not content:
            findings.append(f"{participant_id} generation response is missing")
        if verdict == "inconclusive":
            findings.append(f"{participant_id} did not provide a clear proceed/revise/reject verdict")
        summaries.append(
            {
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
            }
        )
    return summaries


def extract_verdict(content: str) -> str:
    text = content.lower()
    for pattern in (
        r"patch proposal verdict\s*[:\-]\s*(proceed|revise|reject|inconclusive)",
        r"patchproposalverdict[\"'\s:,\-]*(proceed|revise|reject|inconclusive)",
        r"verdict\s*[:\-]\s*(proceed|revise|reject|inconclusive)",
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    for verdict in ("reject", "revise", "proceed"):
        if verdict in text[:1200]:
            return verdict
    return "inconclusive"


def frontend_snapshot(frontend_root: Path, focus_files: tuple[str, ...]) -> dict[str, Any]:
    return {
        "head_commit": git_text(frontend_root, "rev-parse", "HEAD"),
        "head_short": git_text(frontend_root, "rev-parse", "--short", "HEAD"),
        "status_short": [line for line in git_text(frontend_root, "status", "--short").splitlines() if line.strip()],
        "focus_file_lines": {path: line_count(frontend_root / path) for path in focus_files},
    }


def git_text(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True)
    return result.stdout.strip()


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.is_file() else 0


def excerpt(path: Path, max_lines: int) -> str:
    if not path.is_file():
        return f"// missing: {path}"
    return "\n".join(path.read_text(encoding="utf-8").splitlines()[:max_lines])
