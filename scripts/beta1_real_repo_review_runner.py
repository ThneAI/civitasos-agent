#!/usr/bin/env python3
"""Run a Beta-1 real repo review through an OpenAI-compatible model.

The runner prepares a proposal-only packet, sends a bounded repository diff to
an external model, writes proposal.md, records an operator decision receipt, and
optionally exports an L1 controlled pilot packet. It never merges, pushes,
deploys, executes production runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta1_export_l1_packet import export_beta1_l1_packet
from beta1_repo_review_proposal import NON_CLAIMS, prepare_request, validate_receipt, write_operator_receipt
from beta2_patch_proposal import validate_patch_proposal


RUN_SCHEMA = "beta1-real-repo-review-run-summary:v1"
DEFAULT_MAX_DIFF_CHARS = 90_000
DEFAULT_MAX_TOKENS = 3500
DEFAULT_TEMPERATURE = 0.2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Repository to review.")
    parser.add_argument("--output-root", required=True, help="Run output directory.")
    parser.add_argument("--request-id")
    parser.add_argument("--request-text", required=True)
    parser.add_argument("--base-ref")
    parser.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    parser.add_argument("--target-agent", default="external-model-reviewer")
    parser.add_argument("--model", default=os.getenv("AGENT_LLM", ""))
    parser.add_argument("--base-url", default=os.getenv("LLM_BASE_URL", ""))
    parser.add_argument("--api-key-env", default="LLM_API_KEY")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--max-diff-chars", type=int, default=DEFAULT_MAX_DIFF_CHARS)
    parser.add_argument("--output-kind", choices=["proposal", "patch-proposal"], default="proposal")
    parser.add_argument(
        "--patch-allow-path-prefix",
        action="append",
        default=[],
        help="Allowed patch target prefix when --output-kind=patch-proposal. Repeatable.",
    )
    parser.add_argument(
        "--patch-deny-path-fragment",
        action="append",
        default=[],
        help="Additional denied patch target fragment when --output-kind=patch-proposal. Repeatable.",
    )
    parser.add_argument(
        "--include-untracked-path",
        action="append",
        default=[],
        help="Explicit untracked path to include in review context. Ignored files are rejected.",
    )
    parser.add_argument("--decision", choices=["approved", "rejected", "deferred"], default="deferred")
    parser.add_argument("--decision-reason", default="external model proposal generated; human follow-up required")
    parser.add_argument("--export-packet-root", help="Optional L1 packet output root.")
    parser.add_argument("--audit-actor-id", default="audit-owner-001")
    args = parser.parse_args(argv)

    report = run_beta1_real_repo_review(
        repo=Path(args.repo),
        output_root=Path(args.output_root),
        request_id=args.request_id,
        request_text=args.request_text,
        base_ref=args.base_ref,
        operator_id=args.operator_id,
        target_agent=args.target_agent,
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        max_diff_chars=args.max_diff_chars,
        output_kind=args.output_kind,
        patch_allow_path_prefixes=args.patch_allow_path_prefix,
        patch_deny_path_fragments=args.patch_deny_path_fragment,
        include_untracked_paths=[Path(path) for path in args.include_untracked_path],
        decision=args.decision,
        decision_reason=args.decision_reason,
        export_packet_root=Path(args.export_packet_root) if args.export_packet_root else None,
        audit_actor_id=args.audit_actor_id,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def run_beta1_real_repo_review(
    *,
    repo: Path,
    output_root: Path,
    request_id: str | None,
    request_text: str,
    base_ref: str | None,
    operator_id: str,
    target_agent: str,
    model: str,
    base_url: str,
    api_key_env: str,
    temperature: float,
    max_tokens: int,
    max_diff_chars: int,
    output_kind: str,
    patch_allow_path_prefixes: list[str],
    patch_deny_path_fragments: list[str],
    include_untracked_paths: list[Path],
    decision: str,
    decision_reason: str,
    export_packet_root: Path | None,
    audit_actor_id: str,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    prepare_report = prepare_request(
        repo=repo,
        output_root=output_root,
        request_id=request_id,
        request_text=request_text,
        base_ref=base_ref,
        operator_id=operator_id,
        target_agent=target_agent,
    )
    request_path = Path(prepare_report["request_path"])
    task_path = Path(prepare_report["task_payload_path"])
    diff_context = build_review_context(
        repo=repo,
        base_ref=base_ref,
        include_untracked_paths=include_untracked_paths,
        max_chars=max_diff_chars,
    )
    diff_context_path = output_root / "review_context.md"
    diff_context_path.write_text(diff_context["content"], encoding="utf-8")

    proposal = call_openai_compatible_model(
        model=model,
        base_url=base_url,
        api_key=os.getenv(api_key_env),
        task_payload=_read_json(task_path),
        request_packet=_read_json(request_path),
        review_context=diff_context["content"],
        output_kind=output_kind,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    artifact_path = output_root / ("patch_proposal.patch" if output_kind == "patch-proposal" else "proposal.md")
    artifact_path.write_text(proposal["content"].strip() + "\n", encoding="utf-8")
    patch_validation = None
    if output_kind == "patch-proposal":
        patch_validation = validate_patch_proposal(
            repo=repo,
            patch_path=artifact_path,
            request_path=request_path,
            allow_path_prefixes=patch_allow_path_prefixes,
            deny_path_fragments=patch_deny_path_fragments,
        )
        _write_json(output_root / "beta2_patch_proposal_validation.json", patch_validation)
        if patch_validation["passed"] is not True:
            raise ValueError(f"Beta-2 patch proposal validation failed: {patch_validation['failure_reasons']}")
    external_summary = {
        "schema_version": (
            "beta2-external-model-patch-proposal-run-summary:v1"
            if output_kind == "patch-proposal"
            else "beta1-external-model-proposal-run-summary:v1"
        ),
        "run_root": str(output_root.resolve()),
        "model": proposal["model"],
        "base_url_configured": bool(base_url),
        "output_kind": output_kind,
        "proposal_path": str(artifact_path.resolve()),
        "artifact_path": str(artifact_path.resolve()),
        "prompt_chars": proposal["prompt_chars"],
        "proposal_chars": len(proposal["content"]),
        "review_context_chars": diff_context["chars"],
        "review_context_truncated": diff_context["truncated"],
        "included_untracked_paths": [str(path) for path in include_untracked_paths],
        "boundary": "proposal_only; H.3 remains blocked",
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "external_model_summary.json", external_summary)

    receipt_report = write_operator_receipt(
        request_path=request_path,
        proposal_path=artifact_path,
        output_path=output_root / "operator_decision_receipt.json",
        decision=decision,
        operator_id=operator_id,
        reason=decision_reason,
        audit_output_path=output_root / "sinks" / "audit-events.jsonl",
        audit_actor_id=audit_actor_id,
        append=False,
    )
    validation = validate_receipt(receipt_path=output_root / "operator_decision_receipt.json")
    _write_json(output_root / "operator_decision_receipt_validation.json", validation)

    packet_report = None
    if export_packet_root is not None:
        packet_report = export_beta1_l1_packet(
            run_root=output_root,
            packet_root=export_packet_root,
            operator_id=operator_id,
            observer_actor_id="observer-001",
            registrar_actor_id="agent-registrar-001",
            agent_observer_actor_id="agent-observer-001",
            audit_actor_id=audit_actor_id,
            external_agent_id=target_agent,
            overwrite=True,
        )

    report = {
        "schema_version": RUN_SCHEMA,
        "run_root": str(output_root.resolve()),
        "request_id": prepare_report["request_id"],
        "request_path": str(request_path),
        "task_payload_path": str(task_path),
        "review_context_path": str(diff_context_path.resolve()),
        "output_kind": output_kind,
        "proposal_path": str(artifact_path.resolve()),
        "artifact_path": str(artifact_path.resolve()),
        "patch_validation": patch_validation,
        "receipt_path": receipt_report["receipt_path"],
        "receipt_validation_passed": validation["passed"],
        "decision": decision,
        "model": proposal["model"],
        "packet_report": packet_report,
        "dangerous_flags": _dangerous_flags(output_root / "operator_decision_receipt.json"),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta1_real_repo_review_summary.json", report)
    return report


def build_review_context(
    *,
    repo: Path,
    base_ref: str | None,
    include_untracked_paths: list[Path],
    max_chars: int,
) -> dict[str, Any]:
    repo_root = _repo_root(repo)
    parts = [
        "# Repository Review Context",
        "",
        "## Git Status",
        "```text",
        _git(repo_root, "status", "--short"),
        "```",
        "",
        "## Unstaged Diff",
        "```diff",
        _git_optional(repo_root, "diff") or "",
        "```",
        "",
        "## Staged Diff",
        "```diff",
        _git_optional(repo_root, "diff", "--cached") or "",
        "```",
    ]
    if base_ref:
        parts.extend([
            "",
            f"## Base Diff ({base_ref}..HEAD)",
            "```diff",
            _git_optional(repo_root, "diff", base_ref, "HEAD") or "",
            "```",
        ])
    for path in include_untracked_paths:
        parts.extend(_untracked_file_section(repo_root, path))
    content = "\n".join(parts).strip() + "\n"
    truncated = False
    if len(content) > max_chars:
        content = content[:max_chars] + "\n[review context truncated]\n"
        truncated = True
    return {"content": content, "chars": len(content), "truncated": truncated}


def call_openai_compatible_model(
    *,
    model: str,
    base_url: str,
    api_key: str | None,
    task_payload: dict[str, Any],
    request_packet: dict[str, Any],
    review_context: str,
    output_kind: str,
    temperature: float,
    max_tokens: int,
) -> dict[str, Any]:
    model_name = normalize_model_name(model)
    endpoint = chat_completions_endpoint(base_url)
    if not api_key:
        raise RuntimeError("external model API key is missing")
    prompt = build_prompt(
        task_payload=task_payload,
        request_packet=request_packet,
        review_context=review_context,
        output_kind=output_kind,
    )
    body = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": "You are a careful proposal-only code reviewer. You never perform external side effects.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    request = urllib.request.Request(
        endpoint,
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
    return {"model": model_name, "content": content, "prompt_chars": len(prompt)}


def build_prompt(
    *,
    task_payload: dict[str, Any],
    request_packet: dict[str, Any],
    review_context: str,
    output_kind: str,
) -> str:
    if output_kind == "patch-proposal":
        output_instruction = """
Return only a unified diff patch proposal.
Do not wrap it in Markdown fences.
Do not include prose.
Do not claim the patch has been applied, committed, pushed, merged, or deployed.
The patch must target only repository-relative paths.
""".strip()
    else:
        output_instruction = """
Return Markdown with exactly these sections:
## Scope
## Repository Evidence
## Findings
## Proposal
## Risks
## Operator Decision Required
## H3 Boundary
""".strip()
    return f"""
You are the external model reviewer in CivitasOS Beta-1.

Boundary:
- Proposal only.
- Do not claim merge, push, deploy, production runtime execution, production readiness, or production receipt writes.
- H.3 remains blocked.

Task payload:
{json.dumps(task_payload, ensure_ascii=False, indent=2)}

Proposal request:
{json.dumps(request_packet, ensure_ascii=False, indent=2)}

Repository context:
{review_context}

{output_instruction}
""".strip()


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


def _untracked_file_section(repo_root: Path, raw_path: Path) -> list[str]:
    path = (repo_root / raw_path).resolve() if not raw_path.is_absolute() else raw_path.resolve()
    if not _is_inside(repo_root, path):
        raise ValueError(f"untracked include path escapes repo root: {raw_path}")
    check = subprocess.run(["git", "check-ignore", "-q", str(path)], cwd=repo_root, check=False)
    if check.returncode == 0:
        raise ValueError(f"refusing to include ignored path in model context: {raw_path}")
    if not path.is_file():
        raise FileNotFoundError(f"untracked include path is not a file: {raw_path}")
    rel = path.relative_to(repo_root)
    return [
        "",
        f"## Explicit Untracked File: {rel}",
        "```text",
        path.read_text(encoding="utf-8", errors="replace"),
        "```",
    ]


def _dangerous_flags(receipt_path: Path) -> dict[str, Any]:
    receipt = _read_json(receipt_path)
    return {
        flag: receipt.get(flag)
        for flag in (
            "merge_allowed",
            "push_allowed",
            "deploy_allowed",
            "production_runtime_execution_allowed",
            "production_receipt_write_allowed",
        )
    }


def _repo_root(repo: Path) -> Path:
    return Path(_git(repo, "rev-parse", "--show-toplevel").strip()).resolve()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _git_optional(repo: Path, *args: str) -> str | None:
    result = subprocess.run(["git", *args], cwd=repo, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout if result.returncode == 0 else None


def _is_inside(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
