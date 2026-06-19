"""Provider execution runner for I.2-B read-only commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from benchmarks.i_gate_evidence import sha256_text
from benchmarks.i2_provider_runner import (
    build_readonly_command_prompt,
    call_openai_compatible,
    parse_json_object_response,
)

ProviderCall = Callable[..., tuple[str, int]]


def execute_provider_readonly_command(
    *,
    response_schema: str,
    command: dict[str, Any],
    i2a_excerpt: str,
    base_url: str,
    api_key: str,
    model: str,
    max_tokens: int,
    temperature: float,
    api_response_override: str | None = None,
    provider_call: ProviderCall = call_openai_compatible,
) -> dict[str, Any]:
    prompt = build_readonly_command_prompt(
        response_schema=response_schema,
        command=command,
        i2a_excerpt=i2a_excerpt,
    )
    failures: list[str] = []
    content = ""
    http_status: int | None = None
    if api_response_override is not None:
        content = api_response_override.replace("__COMMAND_ID__", str(command.get("command_id") or ""))
        http_status = 200
    else:
        try:
            content, http_status = provider_call(
                base_url=base_url,
                api_key=api_key,
                model=model,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        except RuntimeError as exc:
            failures.append(f"external provider call failed: {exc}")

    parsed = parse_json_object_response(content, failures) if content else {}
    return {
        "content": content,
        "http_status": http_status,
        "parsed": parsed,
        "failures": failures,
        "prompt_sha256": sha256_text(prompt),
        "response_content_sha256": sha256_text(content) if content else None,
    }
