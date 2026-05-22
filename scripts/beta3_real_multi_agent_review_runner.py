#!/usr/bin/env python3
"""Run Beta-3 review/risk verdicts through OpenAI-compatible models.

This runner feeds a bounded post-sandbox evidence context to two role-separated
external model reviewers. Their JSON verdicts are recorded through the Beta-3
packet gate before a multi-Agent packet is built. It never applies a patch to
the source repo, commits, pushes, merges, deploys, executes production runtime
actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta3_multi_agent_review_packet import DECISIONS, NON_CLAIMS, build_review_packet, record_verdict
from beta3_post_sandbox_operator_receipt import validate_post_sandbox_receipt


RUN_SCHEMA = "beta3-real-multi-agent-review-run-summary:v1"
DEFAULT_MAX_EVIDENCE_CHARS = 90_000
DEFAULT_MAX_TOKENS = 1800
DEFAULT_TEMPERATURE = 0.1
ROLES = ("review_agent", "risk_agent")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-receipt", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--model", default=os.getenv("AGENT_LLM", ""))
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", ""))
    parser.add_argument("--api-key-env", default="LLM_API_KEY")
    parser.add_argument("--review-agent-id", default="external-beta3-review-agent")
    parser.add_argument("--risk-agent-id", default="external-beta3-risk-agent")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--max-evidence-chars", type=int, default=DEFAULT_MAX_EVIDENCE_CHARS)
    args = parser.parse_args(argv)

    report = run_real_multi_agent_review(
        operator_receipt_path=Path(args.operator_receipt),
        output_root=Path(args.output_root),
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        review_agent_id=args.review_agent_id,
        risk_agent_id=args.risk_agent_id,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        max_evidence_chars=args.max_evidence_chars,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["packet_validation_passed"] else 1


def run_real_multi_agent_review(
    *,
    operator_receipt_path: Path,
    output_root: Path,
    model: str,
    base_url: str,
    api_key_env: str,
    review_agent_id: str,
    risk_agent_id: str,
    temperature: float,
    max_tokens: int,
    max_evidence_chars: int,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    evidence = build_evidence_context(operator_receipt_path, max_chars=max_evidence_chars)
    evidence_path = output_root / "beta3_review_evidence_context.md"
    evidence_path.write_text(evidence["content"], encoding="utf-8")

    responses: dict[str, dict[str, Any]] = {}
    verdict_paths: dict[str, Path] = {}
    for role, agent_id in (
        ("review_agent", review_agent_id),
        ("risk_agent", risk_agent_id),
    ):
        response = call_openai_compatible_verdict_model(
            model=model,
            base_url=base_url,
            api_key=os.getenv(api_key_env),
            role=role,
            evidence_context=evidence["content"],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        responses[role] = response
        _write_json(output_root / f"{role}_model_response.json", response)
        verdict_payload = parse_verdict_response(response["content"], role=role)
        verdict_path = output_root / f"{role}_verdict.json"
        record_verdict(
            operator_receipt_path=operator_receipt_path,
            role=role,
            agent_id=agent_id,
            decision=verdict_payload["decision"],
            reason=verdict_payload["reason"],
            blocking_findings=verdict_payload["blocking_findings"],
            observations=verdict_payload["observations"],
            output_path=verdict_path,
        )
        verdict_paths[role] = verdict_path

    packet_path = output_root / "beta3_multi_agent_review_packet.json"
    packet_report = build_review_packet(
        operator_receipt_path=operator_receipt_path,
        review_verdict_path=verdict_paths["review_agent"],
        risk_verdict_path=verdict_paths["risk_agent"],
        output_path=packet_path,
    )
    packet_validation = packet_report["validation"]
    report = {
        "schema_version": RUN_SCHEMA,
        "run_root": str(output_root.resolve()),
        "checked_at": _now(),
        "model": responses["review_agent"]["model"],
        "operator_receipt_path": str(operator_receipt_path.resolve()),
        "evidence_context_path": str(evidence_path.resolve()),
        "evidence_context_chars": evidence["chars"],
        "evidence_context_truncated": evidence["truncated"],
        "review_agent": _role_summary(responses, verdict_paths, "review_agent"),
        "risk_agent": _role_summary(responses, verdict_paths, "risk_agent"),
        "packet_path": str(packet_path.resolve()),
        "packet_validation_passed": packet_validation["passed"],
        "packet_status": packet_report["packet_status"],
        "packet_report": packet_report,
        "source_repo_apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta3_real_multi_agent_review_summary.json", report)
    return report


def build_evidence_context(operator_receipt_path: Path, *, max_chars: int) -> dict[str, Any]:
    validation = validate_post_sandbox_receipt(operator_receipt_path)
    if validation.get("passed") is not True:
        raise ValueError(f"operator receipt failed validation: {validation['failure_reasons']}")
    receipt = _read_json_object(operator_receipt_path)
    if receipt.get("decision") != "approved":
        raise ValueError("real multi-Agent review requires approved post-sandbox operator receipt")
    sandbox = _read_ref_json(receipt["source_sandbox_report"], "sandbox report")
    candidate = _read_ref_json(receipt["source_candidate_report"], "candidate report")
    patch = _read_ref_text(sandbox["source_patch"], "patch proposal")
    applied_diff_ref = sandbox.get("sandbox", {}).get("applied_diff")
    applied_diff = _read_ref_text(applied_diff_ref, "sandbox applied diff") if isinstance(applied_diff_ref, dict) else ""
    source_repo = sandbox.get("source_repo", {})
    test_summary = [
        {"command": item.get("command"), "returncode": item.get("returncode")}
        for item in sandbox.get("sandbox", {}).get("tests", [])
        if isinstance(item, dict)
    ]
    content = "\n".join([
        "# CivitasOS Beta-3 Multi-Agent Review Evidence",
        "",
        "Boundary:",
        "- Verdicts decide only whether evidence can enter source-apply authorization review.",
        "- Verdicts never authorize source repo apply, commit, push, merge, deploy, production execution, or production receipts.",
        "- H.3 remains blocked.",
        "",
        "## Post-Sandbox Operator Receipt",
        "```json",
        _json_text(_receipt_prompt_view(receipt)),
        "```",
        "",
        "## Candidate Report",
        "```json",
        _json_text(_candidate_prompt_view(candidate)),
        "```",
        "",
        "## Sandbox Report",
        "```json",
        _json_text({
            "passed": sandbox.get("passed"),
            "sandbox_status": sandbox.get("sandbox_status"),
            "failure_reasons": sandbox.get("failure_reasons"),
            "source_repo": {
                "repo_root": source_repo.get("repo_root"),
                "proposal_head_commit": source_repo.get("proposal_head_commit"),
                "worktree_snapshot_unchanged": source_repo.get("worktree_snapshot_unchanged"),
            },
            "sandbox": {
                "worktree_cleaned": sandbox.get("sandbox", {}).get("worktree_cleaned"),
                "apply_check": _command_prompt_view(sandbox.get("sandbox", {}).get("apply_check")),
                "apply": _command_prompt_view(sandbox.get("sandbox", {}).get("apply")),
                "tests": test_summary,
            },
            "execution_boundary": sandbox.get("execution_boundary"),
            "h3_boundary": sandbox.get("h3_boundary"),
        }),
        "```",
        "",
        "## Patch Proposal",
        "```diff",
        patch,
        "```",
        "",
        "## Sandbox Applied Diff",
        "```diff",
        applied_diff,
        "```",
    ]).strip() + "\n"
    return _truncate_context(content, max_chars=max_chars)


def call_openai_compatible_verdict_model(
    *,
    model: str,
    base_url: str,
    api_key: str | None,
    role: str,
    evidence_context: str,
    temperature: float,
    max_tokens: int,
) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"unknown Beta-3 review role: {role}")
    if not api_key:
        raise RuntimeError("external model API key is missing")
    model_name = normalize_model_name(model)
    prompt = build_prompt(role=role, evidence_context=evidence_context)
    body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": _system_prompt(role)},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    request = urllib.request.Request(
        chat_completions_endpoint(base_url),
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"external model HTTP {exc.code}: {detail}") from exc
    content = payload["choices"][0]["message"]["content"]
    return {
        "schema_version": "beta3-real-multi-agent-review-model-response:v1",
        "role": role,
        "model": model_name,
        "content": content,
        "prompt_chars": len(prompt),
        "non_claims": list(NON_CLAIMS),
    }


def normalize_model_name(model: str) -> str:
    model = (model or "").strip()
    if not model:
        raise RuntimeError("external model name is missing; set AGENT_LLM or --model")
    if ":" in model:
        return model.split(":", 1)[1]
    return model


def chat_completions_endpoint(base_url: str) -> str:
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        raise RuntimeError("external model base URL is missing; set LLM_BASE_URL or --base-url")
    if base_url.endswith("/chat/completions"):
        return base_url
    return base_url + "/chat/completions"


def build_prompt(*, role: str, evidence_context: str) -> str:
    focus = {
        "review_agent": (
            "Review code correctness, patch scope, sandbox diff, and sandbox tests. "
            "Use approved only when the evidence is sufficient for the next authorization review."
        ),
        "risk_agent": (
            "Review boundary preservation, rollback preconditions, H.3/production non-claims, "
            "and source-apply drift risks. Use approved only when the next authorization review "
            "can proceed without treating this verdict as execution authorization."
        ),
    }[role]
    return f"""
You are the {role} in CivitasOS Beta-3.

{focus}

Return only one JSON object with exactly these keys:
{{
  "decision": "approved|rejected|deferred",
  "reason": "one concise non-empty reason",
  "blocking_findings": ["finding when rejected or deferred"],
  "observations": ["evidence observation"]
}}

Rules:
- JSON only. No Markdown fences and no prose outside the object.
- `approved` must use an empty `blocking_findings` list.
- Do not claim source repo apply, commit, push, merge, deploy, production runtime execution, production readiness, or production receipt writes are authorized.
- H.3 remains blocked.

Evidence:
{evidence_context}
""".strip()


def parse_verdict_response(content: str, *, role: str) -> dict[str, Any]:
    payload = _parse_json_object(content)
    decision = payload.get("decision")
    if decision not in DECISIONS:
        raise ValueError(f"{role} verdict decision must be one of {sorted(DECISIONS)}")
    reason = _text(payload.get("reason"))
    if not reason:
        raise ValueError(f"{role} verdict reason must be a non-empty string")
    blocking_findings = _string_list(payload.get("blocking_findings"), label=f"{role} blocking_findings")
    observations = _string_list(payload.get("observations"), label=f"{role} observations")
    if decision == "approved" and blocking_findings:
        raise ValueError(f"{role} approved verdict must not include blocking_findings")
    return {
        "decision": decision,
        "reason": reason,
        "blocking_findings": blocking_findings,
        "observations": observations,
    }


def _parse_json_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model verdict response must be one JSON object: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("model verdict response must be a JSON object")
    return payload


def _receipt_prompt_view(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": receipt.get("request_id"),
        "decision": receipt.get("decision"),
        "reason": receipt.get("reason"),
        "sandbox_summary": receipt.get("sandbox_summary"),
        "next_gate_review_allowed": receipt.get("next_gate_review_allowed"),
        "source_repo_apply_allowed": receipt.get("source_repo_apply_allowed"),
        "h3_boundary": receipt.get("h3_boundary"),
    }


def _candidate_prompt_view(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "passed": candidate.get("passed"),
        "candidate_status": candidate.get("candidate_status"),
        "failure_reasons": candidate.get("failure_reasons"),
        "low_risk_allow_path_prefixes": candidate.get("low_risk_allow_path_prefixes"),
        "source_beta2_outcome": candidate.get("source_beta2_outcome"),
        "execution_boundary": candidate.get("execution_boundary"),
        "h3_boundary": candidate.get("h3_boundary"),
    }


def _command_prompt_view(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {"command": value.get("command"), "returncode": value.get("returncode")}


def _read_ref_json(ref: dict[str, Any], label: str) -> dict[str, Any]:
    path = _read_ref_path(ref, label)
    return _read_json_object(path)


def _read_ref_text(ref: dict[str, Any], label: str) -> str:
    return _read_ref_path(ref, label).read_text(encoding="utf-8")


def _read_ref_path(ref: dict[str, Any], label: str) -> Path:
    if not isinstance(ref, dict):
        raise ValueError(f"{label} ref must be an object")
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        raise FileNotFoundError(f"{label} ref path is not a file: {path}")
    return path


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _truncate_context(content: str, *, max_chars: int) -> dict[str, Any]:
    if max_chars <= 0:
        raise ValueError("max evidence chars must be positive")
    if len(content) <= max_chars:
        return {"content": content, "chars": len(content), "truncated": False}
    suffix = "\n[evidence context truncated]\n"
    truncated = content[: max_chars - len(suffix)] + suffix
    return {"content": truncated, "chars": len(truncated), "truncated": True}


def _role_summary(responses: dict[str, dict[str, Any]], verdict_paths: dict[str, Path], role: str) -> dict[str, Any]:
    verdict = _read_json_object(verdict_paths[role])
    return {
        "agent_id": verdict.get("agent_id"),
        "decision": verdict.get("decision"),
        "model_response_path": str((verdict_paths[role].parent / f"{role}_model_response.json").resolve()),
        "prompt_chars": responses[role]["prompt_chars"],
        "verdict_path": str(verdict_paths[role].resolve()),
    }


def _string_list(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    result: list[str] = []
    for item in value:
        text = _text(item)
        if not text:
            raise ValueError(f"{label} must contain only non-empty strings")
        result.append(text)
    return result


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _json_text(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _system_prompt(role: str) -> str:
    return (
        f"You are a careful CivitasOS {role}. "
        "You return bounded JSON review verdicts and never perform external side effects."
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
