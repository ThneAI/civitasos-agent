#!/usr/bin/env python3
"""Run a bounded Beta-6 -> Beta-9 real API Agent review chain.

The runner turns the previously manual external API Agent review flow into a
repeatable controlled-pilot artifact generator. It still delegates every gate to
existing validators and never performs merge, deploy, production runtime
execution, or production receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_post_review_merge_authorization import record_post_review_merge_authorization
from beta5_post_review_merge_authorization import validate_post_review_merge_authorization
from beta6_external_agent_onboarding import probe_external_api_from_env
from beta6_external_agent_onboarding import record_invitation
from beta6_external_agent_onboarding import record_registration
from beta6_external_agent_onboarding import record_registration_request
from beta6_external_agent_onboarding import validate_invitation
from beta6_external_agent_onboarding import validate_onboarding_readiness
from beta6_external_agent_onboarding import validate_registration
from beta6_external_agent_onboarding import validate_registration_request
from beta6_external_agent_onboarding import write_agent_card_from_env
from beta7_external_agent_task_invitation import record_task_invitation
from beta7_external_agent_task_invitation import validate_task_invitation
from beta8_external_agent_review_response import record_review_response
from beta8_external_agent_review_response import validate_review_response
from beta9_review_reconciliation import record_reconciliation
from beta9_review_reconciliation import validate_reconciliation


SUMMARY_SCHEMA = "beta6-9-real-api-review-run-summary:v1"
API_CALL_REPORT_SCHEMA = "beta8-external-agent-api-call-report:v1"
DEFAULT_EXTERNAL_AGENT_ID = "external-real-reviewer-002"
DEFAULT_DISPLAY_NAME = "External Real Reviewer 002"
DEFAULT_CONTACT_REF = "external-api:controlled-reviewer-002"
DEFAULT_MAX_TOKENS = 1200
NON_CLAIMS = (
    "beta6_9_real_api_review_runner_is_l1_controlled_pilot_only",
    "beta6_9_real_api_review_runner_does_not_record_api_key",
    "beta6_9_real_api_review_runner_does_not_create_github_approval",
    "beta6_9_real_api_review_runner_does_not_execute_merge_or_deploy",
    "beta6_9_real_api_review_runner_does_not_claim_h3_production_readiness",
    "beta6_9_real_api_review_runner_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--env-file", default=".env.beta6.external.local")
    parser.add_argument("--feedback-index", required=True)
    parser.add_argument("--pr-review-evidence", required=True)
    parser.add_argument("--preview-summary", required=True)
    parser.add_argument("--rollback-evidence-ref", required=True)
    parser.add_argument("--external-agent-id", default=DEFAULT_EXTERNAL_AGENT_ID)
    parser.add_argument("--display-name", default=DEFAULT_DISPLAY_NAME)
    parser.add_argument("--contact-ref", default=DEFAULT_CONTACT_REF)
    parser.add_argument("--model-max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--min-feedback-packets", type=int, default=2)
    parser.add_argument("--min-feedback-accepted-ratio", type=float, default=0.5)
    args = parser.parse_args(argv)

    summary = run_real_api_review_chain(
        output_root=Path(args.output_root),
        env_file=Path(args.env_file),
        feedback_index=Path(args.feedback_index),
        pr_review_evidence=Path(args.pr_review_evidence),
        preview_summary=Path(args.preview_summary),
        rollback_evidence_ref=args.rollback_evidence_ref,
        external_agent_id=args.external_agent_id,
        display_name=args.display_name,
        contact_ref=args.contact_ref,
        model_max_tokens=args.model_max_tokens,
        temperature=args.temperature,
        min_feedback_packets=args.min_feedback_packets,
        min_feedback_accepted_ratio=args.min_feedback_accepted_ratio,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def run_real_api_review_chain(
    *,
    output_root: Path,
    env_file: Path,
    feedback_index: Path,
    pr_review_evidence: Path,
    preview_summary: Path,
    rollback_evidence_ref: str,
    external_agent_id: str = DEFAULT_EXTERNAL_AGENT_ID,
    display_name: str = DEFAULT_DISPLAY_NAME,
    contact_ref: str = DEFAULT_CONTACT_REF,
    model_max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = 0.0,
    min_feedback_packets: int = 2,
    min_feedback_accepted_ratio: float = 0.5,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    _require_file(env_file, "env file")
    _require_file(feedback_index, "Beta-5 owner feedback index")
    _require_file(pr_review_evidence, "Beta-4 PR review evidence")
    _require_file(preview_summary, "Beta-5 repeatable preview summary")

    readiness_path = output_root / "beta6_external_agent_readiness.json"
    readiness = validate_onboarding_readiness(
        feedback_index_path=feedback_index,
        min_packets=min_feedback_packets,
        min_accepted_ratio=min_feedback_accepted_ratio,
    )
    _write_json(readiness_path, readiness)
    if readiness.get("passed") is not True:
        raise ValueError(f"Beta-6 readiness failed: {readiness.get('failure_reasons')}")

    invitation_path = output_root / "beta6_real_api_invitation.json"
    record_invitation(
        external_agent_id=external_agent_id,
        display_name=display_name,
        agent_kind="ai_agent",
        capabilities=["code_review", "boundary_review"],
        allowed_scopes=["review_only", "l1_controlled_message"],
        contact_ref=contact_ref,
        reason="Invite external API-backed Agent for controlled L1 post-review evidence",
        output_path=invitation_path,
        operator_id="external-agent-registrar-001",
        expires_at=None,
        readiness_path=readiness_path,
    )
    _write_json(output_root / "beta6_real_api_invitation_validation.json", validate_invitation(invitation_path))

    registration_request_path = output_root / "beta6_real_api_registration_request.json"
    record_registration_request(
        invitation_path=invitation_path,
        output_path=registration_request_path,
        requester_id="external-agent-registrar-001",
    )
    _write_json(
        output_root / "beta6_real_api_registration_request_validation.json",
        validate_registration_request(registration_request_path),
    )

    agent_card_path = output_root / "beta6_real_api_agent_card.json"
    agent_card_report = write_agent_card_from_env(
        registration_request_path=registration_request_path,
        env_file_path=env_file,
        output_path=agent_card_path,
    )
    _write_json(output_root / "beta6_real_api_agent_card_intake_report.json", agent_card_report)

    api_probe_path = output_root / "beta6_real_api_probe_report.json"
    probe_report = probe_external_api_from_env(
        agent_card_path=agent_card_path,
        env_file_path=env_file,
        output_path=api_probe_path,
    )
    if probe_report.get("passed") is not True:
        raise ValueError(f"external API probe failed: {probe_report.get('failure_reasons')}")

    registration_path = output_root / "beta6_real_api_registration.json"
    record_registration(
        invitation_path=invitation_path,
        agent_card_path=agent_card_path,
        attestation_ref=f"beta6-api-probe:{_sha256(api_probe_path)}",
        observer_actor_id="external-agent-observer-001",
        output_path=registration_path,
    )
    _write_json(output_root / "beta6_real_api_registration_validation.json", validate_registration(registration_path))

    task_brief_path = output_root / "beta7_real_api_pr_review_brief.md"
    task_brief_path.write_text(_task_brief(), encoding="utf-8")
    task_invitation_path = output_root / "beta7_real_api_pr_review_task_invitation.json"
    record_task_invitation(
        registration_path=registration_path,
        task_kind="github_pr_review",
        task_title="Review Beta-4 GitHub approval evidence for Beta-9 reconciliation",
        task_brief_file=task_brief_path,
        expected_output="review_verdict",
        source_artifacts=[preview_summary, api_probe_path, registration_path, pr_review_evidence],
        reason="Request external API-backed Agent verdict before Beta-9 reconciliation",
        output_path=task_invitation_path,
        operator_id="external-agent-task-coordinator-001",
        due_at=None,
    )
    _write_json(
        output_root / "beta7_real_api_pr_review_task_invitation_validation.json",
        validate_task_invitation(task_invitation_path),
    )

    api_call_report_path = output_root / "beta8_real_api_pr_review_external_agent_api_call_report.json"
    response_file_path = output_root / "beta8_real_api_pr_review_external_agent_response.md"
    api_call_report = call_external_review_api(
        env_file=env_file,
        task_invitation_path=task_invitation_path,
        task_brief_path=task_brief_path,
        pr_review_evidence_path=pr_review_evidence,
        preview_summary_path=preview_summary,
        response_file_path=response_file_path,
        report_path=api_call_report_path,
        max_tokens=model_max_tokens,
        temperature=temperature,
    )
    if api_call_report.get("passed") is not True:
        raise ValueError("external Agent API response did not satisfy controlled parser")

    beta8_response_path = output_root / "beta8_real_api_pr_review_response.json"
    record_review_response(
        task_invitation_path=task_invitation_path,
        external_agent_id=external_agent_id,
        response_channel="api_callback",
        review_verdict=api_call_report["review_verdict"],
        response_file=response_file_path,
        attestation_ref=f"beta8-api-call:{_sha256(api_call_report_path)}",
        observer_actor_id="external-agent-observer-001",
        reason="Record external API-backed Agent PR review verdict for Beta-9 reconciliation",
        output_path=beta8_response_path,
    )
    _write_json(
        output_root / "beta8_real_api_pr_review_response_validation.json",
        validate_review_response(beta8_response_path),
    )

    reconciliation_path = output_root / "beta9_real_api_pr_review_reconciliation.json"
    record_reconciliation(
        review_response_path=beta8_response_path,
        pr_review_evidence_path=pr_review_evidence,
        operator_decision="ready_for_beta5_authorization",
        reason=(
            "External Agent verdict and GitHub approval evidence are aligned; "
            "prepare fresh Beta-5 authorization input without merging"
        ),
        output_path=reconciliation_path,
        operator_id="post-review-reconciliation-operator-001",
    )
    _write_json(
        output_root / "beta9_real_api_pr_review_reconciliation_validation.json",
        validate_reconciliation(reconciliation_path),
    )

    authorization_path = output_root / "beta5_real_api_post_review_merge_authorization.json"
    record_post_review_merge_authorization(
        review_evidence_packet_path=pr_review_evidence,
        output_path=authorization_path,
        operator_id="l1-controlled-pilot-operator",
        reason=(
            "Authorize only post-review merge eligibility evidence after Beta-9 reconciliation; "
            "do not execute merge in this step"
        ),
        rollback_evidence_ref=rollback_evidence_ref,
        review_reconciliation_path=reconciliation_path,
    )
    _write_json(
        output_root / "beta5_real_api_post_review_merge_authorization_validation.json",
        validate_post_review_merge_authorization(authorization_path),
    )

    summary = _summary(
        output_root,
        api_call_report,
        reconciliation_path,
        authorization_path,
        agent_card_path,
    )
    _write_json(output_root / "beta6_9_real_api_review_summary.json", summary)
    return summary


def call_external_review_api(
    *,
    env_file: Path,
    task_invitation_path: Path,
    task_brief_path: Path,
    pr_review_evidence_path: Path,
    preview_summary_path: Path,
    response_file_path: Path,
    report_path: Path,
    max_tokens: int,
    temperature: float,
) -> dict[str, Any]:
    env = _read_env_file(env_file)
    base_url = _required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL").rstrip("/")
    model = _required_env(env, "BETA6_EXTERNAL_AGENT_MODEL")
    api_key = _required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY")
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    prompt = _review_prompt(
        task_invitation_path=task_invitation_path,
        task_brief_path=task_brief_path,
        pr_review_evidence_path=pr_review_evidence_path,
        preview_summary_path=preview_summary_path,
    )
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an external L1 controlled pilot review Agent. "
                    "Return only compact JSON. Preserve all safety boundaries."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    status = None
    payload: dict[str, Any] = {}
    error_class = None
    try:
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
        with urllib.request.urlopen(request, timeout=120) as response:
            status = response.status
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status = exc.code
        error_class = "HTTPError"
    except Exception as exc:  # pragma: no cover - exercised by integration failures.
        error_class = exc.__class__.__name__

    message = _first_message(payload)
    content = str(message.get("content") or "").strip()
    response_file_path.parent.mkdir(parents=True, exist_ok=True)
    response_file_path.write_text(content + "\n", encoding="utf-8")
    parsed = _parse_controlled_json(content)
    verdict = str(parsed.get("verdict") or "inconclusive").strip()
    boundary_preserved = parsed.get("boundary_preserved") is True
    h3_remains_blocked = parsed.get("h3_remains_blocked") is True
    production_claim_detected = parsed.get("production_claim_detected") is True
    failures = []
    if status != 200:
        failures.append("external Agent API must return HTTP 200")
    if not content:
        failures.append("external Agent API content must be non-empty")
    if verdict not in {"approved", "changes_requested", "commented", "rejected", "inconclusive"}:
        failures.append("external Agent verdict must be a controlled enum")
    if boundary_preserved is not True:
        failures.append("boundary_preserved must be true")
    if h3_remains_blocked is not True:
        failures.append("h3_remains_blocked must be true")
    if production_claim_detected is not False:
        failures.append("production_claim_detected must be false")
    report = {
        "schema_version": API_CALL_REPORT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "http_status": status,
        "error_class": error_class,
        "endpoint": endpoint,
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "api_key_present": bool(api_key),
        "api_key_recorded": False,
        "request_task_invitation_sha256": _sha256(task_invitation_path),
        "request_pr_review_evidence_sha256": _sha256(pr_review_evidence_path),
        "response_file": str(response_file_path.resolve()),
        "response_file_sha256": _sha256(response_file_path),
        "review_verdict": verdict,
        "boundary_preserved": boundary_preserved,
        "h3_remains_blocked": h3_remains_blocked,
        "production_claim_detected": production_claim_detected,
        "finish_reason": (payload.get("choices") or [{}])[0].get("finish_reason") if isinstance(payload.get("choices"), list) else None,
        "usage": payload.get("usage") if isinstance(payload, dict) else None,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(report_path, report)
    return report


def _summary(
    output_root: Path,
    api_call_report: dict[str, Any],
    reconciliation_path: Path,
    authorization_path: Path,
    agent_card_path: Path,
) -> dict[str, Any]:
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    agent_card = json.loads(agent_card_path.read_text(encoding="utf-8"))
    external_api = agent_card.get("external_api") if isinstance(agent_card.get("external_api"), dict) else {}
    return {
        "schema_version": SUMMARY_SCHEMA,
        "checked_at": _now(),
        "passed": True,
        "run_root": str(output_root.resolve()),
        "external_agent": {
            "agent_id": agent_card.get("agent_id"),
            "display_name": agent_card.get("display_name"),
            "contact_ref": agent_card.get("contact_ref"),
            "provider": external_api.get("provider"),
            "model": external_api.get("model"),
            "api_key_recorded": False,
        },
        "external_review_verdict": api_call_report["review_verdict"],
        "beta5_authorization_input_ready": reconciliation["beta5_authorization_input_ready"],
        "merge_authorized": authorization["merge_authorized"],
        "merge_performed": authorization["merge_performed"],
        "deploy_allowed": authorization["deploy_allowed"],
        "production_runtime_execution_allowed": authorization["production_runtime_execution_allowed"],
        "production_receipt_write_allowed": authorization["production_receipt_write_allowed"],
        "artifacts": _artifact_map(output_root),
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }


def _artifact_map(output_root: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for path in sorted(output_root.glob("*.json")) + sorted(output_root.glob("*.md")):
        result[path.name] = {"path": str(path.resolve()), "sha256": _sha256(path)}
    return result


def _review_prompt(
    *,
    task_invitation_path: Path,
    task_brief_path: Path,
    pr_review_evidence_path: Path,
    preview_summary_path: Path,
) -> str:
    task = _read_json(task_invitation_path)
    pr_review = _read_json(pr_review_evidence_path)
    preview = _read_json(preview_summary_path)
    evidence = {
        "task": {
            "task_title": task.get("task_title"),
            "expected_output": task.get("expected_output"),
            "non_claims": task.get("non_claims"),
        },
        "github_review_packet": {
            "schema_version": pr_review.get("schema_version"),
            "github_review_approval_observed": pr_review.get("github_review_approval_observed"),
            "merge_authorization_required": pr_review.get("merge_authorization_required"),
            "merge_allowed": pr_review.get("merge_allowed"),
            "deploy_allowed": pr_review.get("deploy_allowed"),
            "production_runtime_execution_allowed": pr_review.get("production_runtime_execution_allowed"),
            "production_receipt_write_allowed": pr_review.get("production_receipt_write_allowed"),
            "non_claims": pr_review.get("non_claims"),
        },
        "preview_summary": {
            "schema_version": preview.get("schema_version"),
            "passed": preview.get("passed"),
            "failure_reasons": preview.get("failure_reasons"),
            "external_environment_provider": preview.get("external_environment_provider"),
            "h3_boundary": preview.get("h3_boundary"),
            "non_claims": preview.get("non_claims"),
        },
    }
    return "\n".join(
        [
            "Review this controlled L1 evidence and return only compact JSON.",
            "Required JSON keys: verdict, boundary_preserved, h3_remains_blocked, production_claim_detected, reason.",
            "verdict must be one of: approved, changes_requested, commented, rejected, inconclusive.",
            "Do not authorize merge, deploy, production runtime execution, or production receipt writes.",
            "",
            "Task brief:",
            task_brief_path.read_text(encoding="utf-8"),
            "",
            "Evidence summary JSON:",
            json.dumps(evidence, ensure_ascii=False, separators=(",", ":")),
        ]
    )


def _task_brief() -> str:
    return """# Controlled L1 External Agent PR Review Task

Review the supplied Beta-4 GitHub review-state packet and the Beta-5 repeatable external preview summary.

Return compact JSON using exactly these keys:

```json
{"verdict":"approved|changes_requested|commented|rejected|inconclusive","boundary_preserved":true,"h3_remains_blocked":true,"production_claim_detected":false,"reason":"short reason"}
```

Scope boundaries:
- This is L1 controlled pilot evidence only.
- Do not authorize merge, deploy, production runtime execution, or production receipt writes.
- Treat GitHub approval evidence as an input to reconciliation, not as direct authority.
"""


def _first_message(payload: dict[str, Any]) -> dict[str, Any]:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        return {}
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    return message if isinstance(message, dict) else {}


def _parse_controlled_json(content: str) -> dict[str, Any]:
    if not content.strip():
        return {}
    try:
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", content, re.S)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _read_env_file(path: Path) -> dict[str, str]:
    _require_file(path, "env file")
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _required_env(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise ValueError(f"{key} must be set")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
