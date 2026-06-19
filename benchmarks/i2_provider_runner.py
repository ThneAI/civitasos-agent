"""Provider runner helpers for I.2 read-only commands."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def call_openai_compatible(
    *,
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    temperature: float,
) -> tuple[str, int]:
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an external CivitasOS Agent. Return exactly one strict JSON object and no prose."},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if (urllib.parse.urlparse(base_url).hostname or "") in {"127.0.0.1", "localhost", "::1"}:
        payload["response_format"] = {"type": "json_object"}
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            choices = data.get("choices") if isinstance(data, dict) else []
            if not choices:
                raise RuntimeError("provider returned no choices")
            content = choices[0].get("message", {}).get("content", "")
            return str(content), int(response.status)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"external provider HTTP {exc.code}: {detail}") from exc


def build_readonly_command_prompt(*, response_schema: str, command: dict[str, Any], i2a_excerpt: str) -> str:
    return f"""
You are executing a single I.2-B read-only external Agent command.

Return strict JSON matching this schema:
{{
  "schema_version": "{response_schema}",
  "command_id": "{command.get('command_id')}",
  "accepted": true,
  "verdict": "accepted_scope_executed_read_only",
  "summary": "one concise sentence",
  "observations": ["2-4 concrete observations"],
  "recommendation": "remain_blocked_for_real_task_commanding",
  "boundary_attestation": {{
    "network_used_only_for_provider_api": true,
    "source_tree_modified": false,
    "git_used": false,
    "runtime_state_mutated": false,
    "production_touched": false
  }}
}}

Hard rules:
- Do not ask for more context.
- Do not claim source, Git, runtime, deploy, or production authority.
- Do not recommend real task commanding without a separate operator gate.
- Keep recommendation exactly one of: remain_blocked_for_real_task_commanding, operator_review_before_next_gate.

Command envelope:
{json.dumps(command, ensure_ascii=False, indent=2, sort_keys=True)}

I.2-A summary excerpt:
{i2a_excerpt}
""".strip()


def parse_json_object_response(content: str, failures: list[str]) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            failures.append("external response was not JSON")
            return {}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            failures.append("external response JSON parse failed")
            return {}
    if not isinstance(value, dict):
        failures.append("external response JSON must be object")
        return {}
    return value
