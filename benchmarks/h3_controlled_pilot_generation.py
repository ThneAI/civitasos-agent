"""H.3 controlled-pilot Agent generation runner."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from benchmarks.h3_evidence import object_value, objects_value, write_json_object

AGENT_ROLES = (
    "relation_evidence_analyst",
    "counterexample_challenger",
    "audit_verifier",
)
REQUIRED_RESPONSE_FIELDS = {
    "verdict",
    "supported_conditions",
    "counterexamples",
    "unresolved_assumptions",
    "evidence_refs",
    "boundary_attestation",
}
RESPONSE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string"},
        "supported_conditions": {"type": "array", "items": {"type": "string"}},
        "counterexamples": {"type": "array", "items": {"type": "string"}},
        "unresolved_assumptions": {"type": "array", "items": {"type": "string"}},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "boundary_attestation": {"type": "boolean"},
    },
    "required": sorted(REQUIRED_RESPONSE_FIELDS),
    "additionalProperties": True,
}
AgentCall = Callable[[str, str], tuple[dict[str, Any], dict[str, Any]]]


def run_agent_generations(
    *,
    call: AgentCall,
    task: dict[str, Any],
    generation_dir: Path,
    kill_switch_file: Path | None,
    profile: str,
) -> list[dict[str, Any]]:
    prompt = _task_prompt(task)
    reports: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(AGENT_ROLES)) as pool:
        futures = {
            pool.submit(call, role, _role_bound_prompt(role, prompt, profile)): role
            for role in AGENT_ROLES
        }
        for future in concurrent.futures.as_completed(futures):
            role = futures[future]
            if kill_switch_file is not None and kill_switch_file.exists():
                raise RuntimeError("operator kill switch triggered during Agent execution")
            payload, raw = future.result()
            raw_reports = [raw]
            valid = valid_agent_payload(
                payload,
                task,
                strict_evidence_refs=profile == "qualification",
            )
            if not valid:
                payload, repair_raw = call(
                    role,
                    _repair_prompt(
                        task=task,
                        previous_payload=payload,
                        profile=profile,
                    ),
                )
                raw_reports.append(repair_raw)
                valid = valid_agent_payload(
                    payload,
                    task,
                    strict_evidence_refs=profile == "qualification",
                )
            report = {
                "schema_version": "h3-controlled-pilot-agent-generation:v1",
                "passed": valid,
                "agent_role": role,
                "task_id": task["task_id"],
                "response": payload,
                "raw_provider_report": raw_reports[-1],
                "raw_provider_reports": raw_reports,
                "generation_attempt_count": len(raw_reports),
                "repair_attempted": len(raw_reports) > 1,
                "boundary": {
                    "read_only_analysis": True,
                    "state_mutation_allowed": False,
                    "operator_review_required": True,
                },
            }
            report_path = generation_dir / f"{role}.json"
            write_json_object(report_path, report)
            report["report_path"] = str(report_path.resolve())
            reports.append(report)
    return sorted(reports, key=lambda item: str(item["agent_role"]))


def ollama_agent_call(
    *,
    model: str,
    ollama_url: str,
    timeout_seconds: int,
) -> AgentCall:
    endpoint = f"{ollama_url.rstrip('/')}/api/chat"

    def call(role: str, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        body = {
            "model": model,
            "stream": False,
            "think": False,
            "format": RESPONSE_JSON_SCHEMA,
            "messages": [
                {
                    "role": "system",
                    "content": _role_instruction(role),
                },
                {"role": "user", "content": prompt},
            ],
            "options": {
                "temperature": 0.2,
                "num_ctx": 8192,
                "num_predict": 1200,
            },
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                provider = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {exc.code}: {detail}") from exc
        content = str(object_value(provider.get("message")).get("content") or "")
        if not content.strip():
            raise RuntimeError(
                "Ollama returned an empty response "
                f"(done_reason={provider.get('done_reason')!r}, "
                f"prompt_eval_count={provider.get('prompt_eval_count')!r}, "
                f"eval_count={provider.get('eval_count')!r})"
            )
        payload = parse_json_response(content)
        return payload, {
            "provider": "ollama",
            "model": model,
            "duration_seconds": time.monotonic() - started,
            "prompt_eval_count": provider.get("prompt_eval_count"),
            "eval_count": provider.get("eval_count"),
            "done_reason": provider.get("done_reason"),
            "raw_content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "raw_content_chars": len(content),
        }

    return call


def parse_json_response(content: str) -> dict[str, Any]:
    cleaned = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as original:
        normalized = _normalize_escaped_json_whitespace(cleaned)
        if normalized != cleaned:
            try:
                value = json.loads(normalized)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(value, dict):
                    return value
        decoder = json.JSONDecoder()
        for index, character in enumerate(cleaned):
            if character != "{":
                continue
            try:
                candidate, _ = decoder.raw_decode(cleaned[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict):
                return candidate
        excerpt = cleaned[:200].replace("\n", "\\n")
        raise ValueError(
            f"Agent response did not contain a JSON object; excerpt={excerpt!r}"
        ) from original
    if not isinstance(value, dict):
        raise ValueError("Agent response must be a JSON object")
    return value


def valid_agent_payload(
    payload: dict[str, Any],
    task: dict[str, Any],
    *,
    strict_evidence_refs: bool = False,
) -> bool:
    if not REQUIRED_RESPONSE_FIELDS.issubset(payload):
        return False
    boundary = payload.get("boundary_attestation")
    evidence_ids = {
        str(item.get("record_id") or "")
        for item in objects_value(task.get("evidence_refs"))
    }
    claimed_refs = _normalize_evidence_refs(
        payload.get("evidence_refs"),
        evidence_ids=evidence_ids,
        reject_unknown=strict_evidence_refs,
    )
    return (
        isinstance(payload.get("supported_conditions"), list)
        and isinstance(payload.get("counterexamples"), list)
        and isinstance(payload.get("unresolved_assumptions"), list)
        and bool(str(payload.get("verdict") or "").strip())
        and bool(claimed_refs)
        and claimed_refs.issubset(evidence_ids)
        and _boundary_attested(boundary)
    )


def _role_instruction(role: str) -> str:
    instructions = {
        "relation_evidence_analyst": (
            "Audit whether the supplied relation evidence supports the claimed delta. "
            "Trace before, after, raw, bounded, and applied values to source events."
        ),
        "counterexample_challenger": (
            "Challenge the relation-learning claims. Find template fallback, identity bias, "
            "replay, cap bypass, hidden state, confounders, and unsafe generalizations."
        ),
        "audit_verifier": (
            "Audit traceability, falsifiability, rollback boundaries, and whether any claim "
            "would improperly change trust, authorization, or normative state."
        ),
    }
    return (
        "You are the CivitasOS controlled-pilot Agent role "
        f"{role}. {instructions[role]} Return JSON only with keys: "
        "verdict, supported_conditions, counterexamples, unresolved_assumptions, "
        "evidence_refs, boundary_attestation. evidence_refs must be a non-empty list "
        "containing only exact record_id strings from task.evidence_refs. Set "
        "boundary_attestation to boolean true to attest that no trust, authorization, "
        "relation, IEM, or normative mutation is requested."
    )


def _role_bound_prompt(role: str, prompt: str, profile: str) -> str:
    return (
        f"Execution profile: {profile}. "
        "This is read-only analysis and the result requires operator review.\n\n"
        + prompt
    )


def _task_prompt(task: dict[str, Any]) -> str:
    return (
        "Analyze this single bounded task. Do not invent evidence and do not propose direct "
        "state changes.\n\n"
        + json.dumps(
            task,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _repair_prompt(
    *,
    task: dict[str, Any],
    previous_payload: dict[str, Any],
    profile: str,
) -> str:
    evidence_ids = sorted(
        str(item.get("record_id") or "")
        for item in objects_value(task.get("evidence_refs"))
        if str(item.get("record_id") or "")
    )
    return (
        f"Repair this {profile} controlled-pilot response to satisfy the exact JSON "
        "contract. Preserve the substantive analysis, but return only these required "
        "fields: verdict as string; supported_conditions, counterexamples, and "
        "unresolved_assumptions as arrays of strings; evidence_refs as a non-empty "
        f"array containing only exact values from {json.dumps(evidence_ids)}; and "
        "boundary_attestation as the literal JSON boolean true only because this "
        "analysis requests no trust, relation, IEM, authorization, normative, or "
        "production mutation. Do not describe historical observed changes as changes "
        "requested by this analysis. The authorized task remains hash-bound by the "
        f"runner; task_id={task.get('task_id')}.\n\nPrevious response:\n"
        + json.dumps(previous_payload, ensure_ascii=False, indent=2, sort_keys=True)
    )


def _normalize_escaped_json_whitespace(content: str) -> str:
    """Decode provider-emitted structural whitespace without altering strings."""
    normalized: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(content):
        character = content[index]
        if in_string:
            normalized.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            normalized.append(character)
            index += 1
            continue
        if character == "\\" and index + 1 < len(content):
            replacement = {"n": "\n", "r": "\r", "t": "\t"}.get(
                content[index + 1]
            )
            if replacement is not None:
                normalized.append(replacement)
                index += 2
                continue
        normalized.append(character)
        index += 1
    return "".join(normalized)


def _normalize_evidence_refs(
    value: Any,
    *,
    evidence_ids: set[str],
    reject_unknown: bool = False,
) -> set[str]:
    if not isinstance(value, list):
        return set()
    normalized: set[str] = set()
    for item in value:
        text = str(item)
        matches = {evidence_id for evidence_id in evidence_ids if evidence_id in text}
        if len(matches) > 1:
            return set()
        if reject_unknown and len(matches) != 1:
            return set()
        normalized.update(matches)
    return normalized


def _boundary_attested(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        lowered = value.lower()
        return "no" in lowered and (
            "mutation" in lowered
            or all(
                token in lowered
                for token in ("trust", "authorization", "normative")
            )
        )
    if not isinstance(value, dict):
        return False
    if value.get("attested") is True:
        return True
    if (
        value.get("state_unchanged") is True
        and value.get("no_auto_modification") is True
    ):
        return True
    text = json.dumps(value, ensure_ascii=False).lower()
    return "no " in text and (
        "mutation" in text
        or all(token in text for token in ("trust", "authorization", "normative"))
    )
