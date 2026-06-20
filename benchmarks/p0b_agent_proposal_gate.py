"""Run P0-B Agent proposal gate.

P0-B consumes a passed P0-A task intake summary, asks at least one external
provider Agent to produce a proposal and at least one local GPU/verifier Agent
to review it, then writes operator reconciliation evidence. This gate does not
contact VMs, post pool tasks, start long-running agents, deploy, mutate runtime
state, or write production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.i2_provider_runner import call_openai_compatible, parse_json_object_response

CHAIN_SCHEMA = "p0b-agent-proposal-chain:v1"
AGENT_RESPONSE_SCHEMA = "p0b-agent-proposal-response:v1"
RECONCILIATION_SCHEMA = "p0b-operator-reconciliation:v1"
P0A_SCHEMA = "p0a-task-intake-chain:v1"
P0A_INTAKE_RECEIPT_SCHEMA = "p0a-task-intake-receipt:v1"
P0A_RISK_DECISION_SCHEMA = "p0a-risk-decision:v1"
P0A_ALLOWED_SCOPE_SCHEMA = "p0a-allowed-execution-scope:v1"

ALLOWED_VERDICTS = {"approved", "revise", "rejected"}
ALLOWED_RECOMMENDATIONS = {
    "ready_for_p0c_authorization_request",
    "revise_before_p0c",
    "remain_blocked",
}
FORBIDDEN_AUTHORITY_TARGETS = (
    "production write",
    "production mutation",
    "public ingress",
    "secret access",
    "wallet",
    "payment",
)


def run_gate(
    *,
    p0a_summary_path: Path,
    output_root: Path,
    proposal_providers: list[str],
    review_providers: list[str],
    max_tokens: int = 1800,
    temperature: float = 0.0,
    provider_timeout: int = 120,
    response_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    checks: dict[str, bool] = {}
    p0a = _validate_p0a_summary(p0a_summary_path, checks, failures)
    participants = [
        *[_parse_provider_spec(spec, role="proposal") for spec in proposal_providers],
        *[_parse_provider_spec(spec, role="review") for spec in review_providers],
    ]
    check(checks, failures, "external_proposal_provider_present", bool(proposal_providers))
    check(checks, failures, "local_review_provider_present", bool(review_providers))
    check(checks, failures, "minimum_two_participants", len(participants) >= 2)
    responses: list[dict[str, Any]] = []
    if p0a and not failures:
        for participant in participants:
            response = _run_participant(
                participant=participant,
                p0a_summary_path=p0a_summary_path,
                p0a_summary=p0a,
                output_root=output_root,
                max_tokens=max_tokens,
                temperature=temperature,
                provider_timeout=provider_timeout,
                override=(response_overrides or {}).get(participant["alias"]),
            )
            responses.append(response)
    response_checks = _response_checks(responses)
    checks.update(response_checks)
    failures.extend(name for name, passed in response_checks.items() if not passed)
    failures.extend(
        f"{item.get('alias')}:{reason}"
        for item in responses
        for reason in item.get("failure_reasons", [])
    )
    reconciliation_path = output_root / "p0b_operator_reconciliation.json"
    reconciliation = write_reconciliation(
        p0a_summary_path=p0a_summary_path,
        response_reports=responses,
        output=reconciliation_path,
    )
    passed = _all_checks(checks, failures) and reconciliation.get("passed") is True
    summary_path = output_root / "p0b_agent_proposal_chain_summary.json"
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _collect_failures(failures, reconciliation),
        "checks": checks,
        "source_artifacts": {"p0a_summary": artifact_ref(p0a_summary_path)},
        "artifacts": {
            "agent_responses": [artifact_ref(Path(item["artifact_path"])) for item in responses if item.get("artifact_path")],
            "operator_reconciliation": artifact_ref(reconciliation_path),
        },
        "metrics": {
            "participant_count": len(responses),
            "proposal_count": sum(1 for item in responses if item.get("role") == "proposal"),
            "review_count": sum(1 for item in responses if item.get("role") == "review"),
            "passed_response_count": sum(1 for item in responses if item.get("passed") is True),
            "distinct_provider_host_count": len({item.get("provider_host") for item in responses if item.get("provider_host")}),
        },
        "readiness": {
            "state": "p0b_agent_proposal_gate_passed" if passed else "blocked_p0b_agent_proposal_gate",
            "p0c_authorization_request_ready": object_value(reconciliation.get("operator_reconciliation")).get("decision") == "ready_for_p0c_authorization_request" and passed,
            "p0c_execution_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            provider_api_network_allowed=bool(responses),
            proposal_recording_allowed=bool(responses),
            review_recording_allowed=bool(responses),
            operator_reconciliation_recording_allowed=True,
        ),
        "non_claims": [
            "p0b_does_not_contact_vms",
            "p0b_does_not_post_pool_tasks",
            "p0b_does_not_start_long_running_agents",
            "p0b_does_not_deploy",
            "p0b_does_not_mutate_runtime_state",
            "p0b_does_not_authorize_p0c_execution",
            "p0b_does_not_write_production_receipt",
        ],
    }
    write_json_object(summary_path, summary)
    return summary


def write_reconciliation(*, p0a_summary_path: Path, response_reports: list[dict[str, Any]], output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    passed_responses = [item for item in response_reports if item.get("passed") is True]
    proposals = [item for item in passed_responses if item.get("role") == "proposal"]
    reviews = [item for item in passed_responses if item.get("role") == "review"]
    verdicts = [object_value(item.get("response")).get("verdict") for item in passed_responses]
    recommendations = [object_value(item.get("response")).get("recommendation") for item in passed_responses]
    check(checks, failures, "p0a_summary_bound", Path(p0a_summary_path).is_file())
    check(checks, failures, "proposal_response_present", bool(proposals))
    check(checks, failures, "review_response_present", bool(reviews))
    check(checks, failures, "all_responses_passed", bool(passed_responses) and len(passed_responses) == len(response_reports))
    check(checks, failures, "no_rejected_verdict", "rejected" not in verdicts)
    check(checks, failures, "no_forbidden_authority_requested", all(not item.get("forbidden_authority_observed") for item in passed_responses))
    ready_votes = sum(1 for item in recommendations if item == "ready_for_p0c_authorization_request")
    revise_votes = sum(1 for item in recommendations if item == "revise_before_p0c")
    if ready_votes >= 1 and revise_votes == 0 and "rejected" not in verdicts:
        decision = "ready_for_p0c_authorization_request"
        reason = "External proposal and local review are structured, bounded, and aligned with P0-A scope."
    elif "rejected" in verdicts:
        decision = "remain_blocked"
        reason = "At least one reviewer rejected the proposal."
    else:
        decision = "revise_before_p0c"
        reason = "Structured evidence exists, but at least one reviewer requested revision before P0-C."
    passed = _all_checks(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "p0a_summary": artifact_ref(p0a_summary_path),
            "agent_responses": [artifact_ref(Path(item["artifact_path"])) for item in response_reports if item.get("artifact_path")],
        },
        "operator_reconciliation": {
            "decision": decision if passed else "blocked_p0b_reconciliation",
            "reason": reason if passed else "P0-B evidence failed hard controls.",
            "ready_vote_count": ready_votes,
            "revise_vote_count": revise_votes,
            "verdicts": verdicts,
            "recommendations": recommendations,
        },
        "readiness": {
            "state": decision if passed else "blocked_p0b_reconciliation",
            "p0c_authorization_request_ready": passed and decision == "ready_for_p0c_authorization_request",
            "p0c_execution_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(operator_reconciliation_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def _validate_p0a_summary(path: Path, checks: dict[str, bool], failures: list[str]) -> dict[str, Any]:
    p0a = read_json_object(path)
    artifacts = object_value(p0a.get("artifacts"))
    intake = _read_verified_ref(artifacts.get("task_intake_receipt"), checks, failures, "p0a.task_intake")
    risk = _read_verified_ref(artifacts.get("risk_decision"), checks, failures, "p0a.risk_decision")
    scope = _read_verified_ref(artifacts.get("allowed_execution_scope"), checks, failures, "p0a.allowed_scope")
    readiness = object_value(p0a.get("readiness"))
    boundary = object_value(p0a.get("boundary"))
    check(checks, failures, "p0a_summary_passed", p0a.get("schema_version") == P0A_SCHEMA and p0a.get("passed") is True)
    check(checks, failures, "p0a_ready_for_p0b", readiness.get("p0b_agent_proposal_gate_ready") is True)
    check(checks, failures, "p0a_execution_closed", readiness.get("p0c_execution_allowed") is False)
    check(checks, failures, "p0a_production_closed", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p0a_boundary_closed", boundary.get("vm_contact_allowed") is False and boundary.get("deploy_allowed") is False and boundary.get("production_receipt_write_allowed") is False)
    check(checks, failures, "p0a_intake_receipt_passed", intake.get("schema_version") == P0A_INTAKE_RECEIPT_SCHEMA and intake.get("passed") is True)
    check(checks, failures, "p0a_risk_decision_passed", risk.get("schema_version") == P0A_RISK_DECISION_SCHEMA and risk.get("passed") is True)
    check(checks, failures, "p0a_allowed_scope_passed", scope.get("schema_version") == P0A_ALLOWED_SCOPE_SCHEMA and scope.get("passed") is True)
    return p0a


def _run_participant(
    *,
    participant: dict[str, str],
    p0a_summary_path: Path,
    p0a_summary: dict[str, Any],
    output_root: Path,
    max_tokens: int,
    temperature: float,
    provider_timeout: int,
    override: str | None,
) -> dict[str, Any]:
    alias = participant["alias"]
    role = participant["role"]
    env_file = Path(participant["env_file"]).resolve()
    env = _read_env_file(env_file)
    base_url = _first_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", "LLM_BASE_URL")
    model = _first_env(env, "BETA6_EXTERNAL_AGENT_MODEL", "AGENT_LLM")
    api_key = _first_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", "LLM_API_KEY") or "ollama"
    prompt = _build_prompt(role=role, alias=alias, p0a_summary=p0a_summary)
    failures: list[str] = []
    status = 0
    raw_content = ""
    if override is not None:
        raw_content = override
        status = 200
    else:
        try:
            if _is_local_ollama(base_url):
                raw_content, status = _call_ollama_native_json(
                    base_url=base_url,
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=provider_timeout,
                )
            else:
                raw_content, status = call_openai_compatible(
                    base_url=base_url,
                    api_key=api_key,
                    model=model,
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=provider_timeout,
                )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"provider_call_failed:{exc}")
    response = parse_json_object_response(raw_content, failures) if raw_content else {}
    checks = _validate_response(response=response, role=role, failures=failures)
    forbidden_authority = _forbidden_authority_observed(response)
    check(checks, failures, "forbidden_authority_not_requested", forbidden_authority is False)
    passed = _all_checks(checks, failures)
    report_path = output_root / f"p0b_agent_response_{_safe_name(alias)}.json"
    report = {
        "schema_version": AGENT_RESPONSE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"p0a_summary": artifact_ref(p0a_summary_path)},
        "agent": {
            "alias": alias,
            "role": role,
            "provider_host": urlparse(base_url).hostname or "",
            "model": model,
            "env_file": str(env_file),
            "api_key_recorded": False,
            "http_status": status,
        },
        "response": response,
        "forbidden_authority_observed": forbidden_authority,
        "raw_response_sha256": _sha256_text(raw_content),
        "boundary": _boundary(provider_api_network_allowed=override is None, proposal_recording_allowed=role == "proposal", review_recording_allowed=role == "review"),
    }
    write_json_object(report_path, report)
    return {
        "alias": alias,
        "role": role,
        "passed": passed,
        "artifact_path": str(report_path.resolve()),
        "provider_host": urlparse(base_url).hostname or "",
        "model": model,
        "response": response,
        "forbidden_authority_observed": forbidden_authority,
        "failure_reasons": failures,
    }


def _build_prompt(*, role: str, alias: str, p0a_summary: dict[str, Any]) -> str:
    selected = object_value(p0a_summary.get("selected_task"))
    instruction = (
        "Propose a bounded P0-B plan for the selected task."
        if role == "proposal"
        else "Review the proposal boundary as an independent local verifier."
    )
    return f"""
You are a CivitasOS P0-B {role} Agent named {alias}.
{instruction}

Return exactly one strict JSON object with this schema:
{{
  "schema_version": "{AGENT_RESPONSE_SCHEMA}",
  "role": "{role}",
  "task_id": "{selected.get('task_id')}",
  "verdict": "approved",
  "summary": "one concise sentence",
  "proposal": {{
    "steps": ["3-6 bounded steps"],
    "required_receipts": ["proposal_receipt", "future_execution_receipt", "future_rollback_receipt"],
    "rollback_plan": "one concrete rollback or abort sentence"
  }},
  "risk_controls": ["3-6 concrete controls"],
  "recommendation": "ready_for_p0c_authorization_request",
  "boundary_attestation": {{
    "uses_only_p0a_allowed_scope": true,
    "requests_vm_contact_now": false,
    "requests_task_pool_post_now": false,
    "requests_source_write_now": false,
    "requests_git_write_now": false,
    "requests_deploy_now": false,
    "requests_runtime_mutation_now": false,
    "requests_production_transition_now": false,
    "requests_production_receipt_now": false
  }}
}}

Every key shown above is mandatory for both proposal and review roles.
For review role, put your reviewed/accepted bounded execution shape under
"proposal.steps" and put review controls under "risk_controls"; do not omit
"boundary_attestation" or "recommendation".

Allowed verdicts: approved, revise, rejected.
Allowed recommendations: ready_for_p0c_authorization_request, revise_before_p0c, remain_blocked.
Hard rules:
- Do not ask for production, deploy, git merge, public ingress, secret, payment, wallet, or unbounded authority.
- Do not claim execution has happened.
- Do not contact VMs or run commands.
- Keep P0-C execution blocked until a separate authorization request.

P0-A selected task:
{json.dumps(selected, ensure_ascii=False, indent=2, sort_keys=True)}

P0-A boundary:
{json.dumps(object_value(p0a_summary.get('boundary')), ensure_ascii=False, indent=2, sort_keys=True)}
""".strip()


def _validate_response(*, response: dict[str, Any], role: str, failures: list[str]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    check(checks, failures, "response_schema", response.get("schema_version") == AGENT_RESPONSE_SCHEMA)
    check(checks, failures, "response_role_matches", response.get("role") == role)
    check(checks, failures, "task_id_present", bool(_text(response.get("task_id"))))
    check(checks, failures, "verdict_allowed", response.get("verdict") in ALLOWED_VERDICTS)
    check(checks, failures, "summary_present", bool(_text(response.get("summary"))))
    proposal = object_value(response.get("proposal"))
    check(checks, failures, "proposal_steps_present", bool(_strings(proposal.get("steps"))))
    check(checks, failures, "risk_controls_present", bool(_strings(response.get("risk_controls"))))
    check(checks, failures, "recommendation_allowed", response.get("recommendation") in ALLOWED_RECOMMENDATIONS)
    attestation = object_value(response.get("boundary_attestation"))
    check(checks, failures, "uses_only_p0a_allowed_scope", attestation.get("uses_only_p0a_allowed_scope") is True)
    for key in (
        "requests_vm_contact_now",
        "requests_task_pool_post_now",
        "requests_source_write_now",
        "requests_git_write_now",
        "requests_deploy_now",
        "requests_runtime_mutation_now",
        "requests_production_transition_now",
        "requests_production_receipt_now",
    ):
        check(checks, failures, f"boundary_{key}_false", attestation.get(key) is False)
    return checks


def _response_checks(responses: list[dict[str, Any]]) -> dict[str, bool]:
    proposal_count = sum(1 for item in responses if item.get("role") == "proposal" and item.get("passed") is True)
    review_count = sum(1 for item in responses if item.get("role") == "review" and item.get("passed") is True)
    return {
        "proposal_passed": proposal_count >= 1,
        "review_passed": review_count >= 1,
        "all_agent_responses_passed": bool(responses) and all(item.get("passed") is True for item in responses),
        "no_agent_requested_forbidden_authority": all(not item.get("forbidden_authority_observed") for item in responses),
    }


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_artifact_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_artifact_hash_valid", expected_hash == sha256_file(path) and bool(expected_hash))
    return read_json_object(path)


def _parse_provider_spec(spec: str, *, role: str) -> dict[str, str]:
    if "=" not in spec:
        raise ValueError("provider spec must be alias=env_file")
    alias, env_file = spec.split("=", 1)
    if not alias.strip() or not env_file.strip():
        raise ValueError("provider spec alias and env_file must be non-empty")
    return {"alias": alias.strip(), "env_file": env_file.strip(), "role": role}


def _read_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _is_local_ollama(base_url: str) -> bool:
    parsed = urlparse(base_url)
    return (parsed.hostname or "") in {"127.0.0.1", "localhost", "::1"} and parsed.port == 11434


def _call_ollama_native_json(
    *,
    base_url: str,
    model: str,
    prompt: str,
    max_tokens: int,
    temperature: float,
    timeout: int,
) -> tuple[str, int]:
    parsed = urlparse(base_url)
    endpoint = f"{parsed.scheme or 'http'}://{parsed.netloc}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a strict CivitasOS gate verifier. Return exactly one JSON object and preserve all safety boundaries.",
            },
            {"role": "user", "content": prompt},
        ],
        "think": False,
        "format": "json",
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
        message = data.get("message") if isinstance(data, dict) else {}
        if not isinstance(message, dict):
            raise RuntimeError("Ollama native response missing message")
        return str(message.get("content") or ""), int(response.status)


def _first_env(env: dict[str, str], *keys: str) -> str:
    for key in keys:
        if env.get(key):
            return str(env[key]).strip()
        if os.getenv(key):
            return str(os.getenv(key)).strip()
    return ""


def _forbidden_authority_observed(response: dict[str, Any]) -> bool:
    text = json.dumps(response, ensure_ascii=False, sort_keys=True).lower()
    active_verbs = r"(request|requires?|need|needs|use|uses|using|enable|allow|perform|execute|should)"
    if re.search(r"\bshould\s+deploy\s+now\b|\bdeploy\s+now\b|\bmerge\s+without\b", text):
        return True
    return any(
        re.search(rf"\b{active_verbs}\b.{{0,60}}\b{re.escape(target)}\b", text)
        for target in FORBIDDEN_AUTHORITY_TARGETS
    )


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "provider_api_network_allowed": False,
        "proposal_recording_allowed": False,
        "review_recording_allowed": False,
        "operator_reconciliation_recording_allowed": False,
        "vm_contact_allowed": False,
        "agent_start_allowed": False,
        "task_pool_post_allowed": False,
        "source_tree_write_allowed": False,
        "git_write_allowed": False,
        "deploy_allowed": False,
        "runtime_state_mutation_allowed": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(seed: list[str], *reports: dict[str, Any]) -> list[str]:
    failures = list(seed)
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _all_checks(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()) or "agent"


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-B Agent proposal gate")
    parser.add_argument("--p0a-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--proposal-provider", action="append", required=True, help="alias=env_file")
    parser.add_argument("--review-provider", action="append", required=True, help="alias=env_file")
    parser.add_argument("--max-tokens", type=int, default=1800)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--provider-timeout", type=int, default=120)
    args = parser.parse_args()
    summary = run_gate(
        p0a_summary_path=Path(args.p0a_summary),
        output_root=Path(args.output_root),
        proposal_providers=args.proposal_provider,
        review_providers=args.review_provider,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        provider_timeout=args.provider_timeout,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
