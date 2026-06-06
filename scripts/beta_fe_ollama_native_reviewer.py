#!/usr/bin/env python3
"""Strict Ollama-native reviewer used by Beta frontend gates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3.6:latest"
PATCH_VERDICTS = {"proceed", "revise", "reject", "inconclusive"}
RELEASE_VERDICTS = {"approved", "changes_requested"}
RISK_LEVELS = {"low", "medium", "high"}


@dataclass(frozen=True)
class OllamaReviewResult:
    payload: dict[str, Any]
    raw_text: str
    report: dict[str, Any]


class OllamaNativeReviewer:
    """Run deterministic, schema-checked frontend reviews through Ollama."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        timeout_secs: int = 240,
        num_predict: int = 1200,
        max_repair_attempts: int = 1,
        transport: Callable[[str, dict[str, Any], int], tuple[int, dict[str, Any]]] | None = None,
    ) -> None:
        self.model = model.strip()
        self.base_url = (
            base_url
            or os.getenv("CIVITASOS_OLLAMA_NATIVE_URL")
            or os.getenv("OLLAMA_NATIVE_URL")
            or DEFAULT_BASE_URL
        ).rstrip("/")
        self.timeout_secs = timeout_secs
        self.num_predict = num_predict
        self.max_repair_attempts = max_repair_attempts
        self.transport = transport or _post_json
        if not self.model:
            raise ValueError("Ollama native reviewer model must be non-empty")

    def review_patch_proposal(self, prompt: str) -> OllamaReviewResult:
        required_files = _candidate_allowed_files(prompt)
        schema_instruction = (
            'Return only one JSON object with keys: verdict ("proceed", "revise", "reject", or '
            '"inconclusive"), allowed_files_only (boolean), reviewed_files (array of repository-relative '
            "file paths), findings (array of strings), tests (array of strings), summary (string). "
            "A proceed verdict requires allowed_files_only=true and at least one test."
        )
        if required_files:
            schema_instruction += f" reviewed_files must exactly equal: {json.dumps(required_files)}."
        return self._review(
            prompt=prompt,
            schema_instruction=schema_instruction,
            validator=lambda payload: _validate_patch_review(payload, required_files),
            review_kind="patch_proposal",
        )

    def review_release(self, prompt: str) -> OllamaReviewResult:
        required_files = _diff_files(prompt)
        schema_instruction = (
            'Return only one JSON object with keys: verdict ("approved" or "changes_requested"), '
            'risk_level ("low", "medium", or "high"), allowed_files_only (boolean), '
            "production_boundary_preserved (boolean), reviewed_files (array of repository-relative file "
            "paths), findings (array of strings), summary (string). "
            "An approved verdict requires both boolean fields to be true."
        )
        if required_files:
            schema_instruction += f" reviewed_files must exactly equal: {json.dumps(required_files)}."
        return self._review(
            prompt=prompt,
            schema_instruction=schema_instruction,
            validator=lambda payload: _validate_release_review(payload, required_files),
            review_kind="release_review",
        )

    def _review(
        self,
        *,
        prompt: str,
        schema_instruction: str,
        validator: Callable[[dict[str, Any]], list[str]],
        review_kind: str,
    ) -> OllamaReviewResult:
        attempts: list[dict[str, Any]] = []
        current_prompt = f"{prompt.rstrip()}\n\n{schema_instruction}"
        last_errors: list[str] = []
        last_raw = ""
        for attempt in range(self.max_repair_attempts + 1):
            status, response = self.transport(
                f"{self.base_url}/api/chat",
                self._request_payload(current_prompt),
                self.timeout_secs,
            )
            raw_text = _message_content(response)
            payload = _parse_json_object(raw_text)
            errors = validator(payload)
            attempts.append(
                {
                    "attempt": attempt + 1,
                    "status": status,
                    "content_chars": len(raw_text),
                    "raw_response_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
                    "validation_errors": errors,
                }
            )
            if not errors:
                return OllamaReviewResult(
                    payload=payload,
                    raw_text=raw_text,
                    report={
                        "runner_kind": "ollama_native_reviewer",
                        "review_kind": review_kind,
                        "model": self.model,
                        "base_url": self.base_url,
                        "think": False,
                        "format": "json",
                        "temperature": 0,
                        "attempt_count": len(attempts),
                        "repair_attempted": attempt > 0,
                        "attempts": attempts,
                    },
                )
            last_errors = errors
            last_raw = raw_text
            current_prompt = (
                f"{schema_instruction}\n\nYour previous response was invalid.\n"
                f"Validation errors: {json.dumps(errors, ensure_ascii=False)}\n"
                f"Previous response: {raw_text[:4000]}\n"
                "Repair the response. Return JSON only."
            )
        raise RuntimeError(
            f"Ollama native {review_kind} remained invalid after {len(attempts)} attempt(s): "
            f"{'; '.join(last_errors)}; response={last_raw[:500]}"
        )

    def _request_payload(self, prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a strict CivitasOS frontend gate reviewer. "
                        "Follow the requested JSON schema exactly and preserve all safety boundaries."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "think": False,
            "format": "json",
            "options": {"temperature": 0, "num_predict": self.num_predict},
            "stream": False,
        }


def patch_review_as_text(payload: dict[str, Any]) -> str:
    findings = "\n".join(f"- {item}" for item in payload.get("findings", [])) or "- None"
    tests = "\n".join(f"- {item}" for item in payload.get("tests", [])) or "- None"
    return (
        f"Patch proposal verdict: {payload['verdict']}\n\n"
        f"## Summary\n{payload['summary']}\n\n"
        f"## Allowed files only\n{str(payload['allowed_files_only']).lower()}\n\n"
        f"## Reviewed files\n{chr(10).join(f'- {item}' for item in payload['reviewed_files'])}\n\n"
        f"## Findings\n{findings}\n\n"
        f"## Tests and smoke checks\n{tests}\n"
    )


def _validate_patch_review(payload: dict[str, Any], required_files: list[str]) -> list[str]:
    errors = _common_errors(payload)
    verdict = payload.get("verdict")
    if verdict not in PATCH_VERDICTS:
        errors.append("verdict must be proceed, revise, reject, or inconclusive")
    if not isinstance(payload.get("allowed_files_only"), bool):
        errors.append("allowed_files_only must be boolean")
    tests = payload.get("tests")
    if not _string_list(tests):
        errors.append("tests must contain at least one non-empty string")
    if verdict == "proceed" and payload.get("allowed_files_only") is not True:
        errors.append("proceed requires allowed_files_only=true")
    errors.extend(_reviewed_file_errors(payload, required_files))
    return errors


def _validate_release_review(payload: dict[str, Any], required_files: list[str]) -> list[str]:
    errors = _common_errors(payload)
    verdict = payload.get("verdict")
    if verdict not in RELEASE_VERDICTS:
        errors.append("verdict must be approved or changes_requested")
    if payload.get("risk_level") not in RISK_LEVELS:
        errors.append("risk_level must be low, medium, or high")
    for field in ("allowed_files_only", "production_boundary_preserved"):
        if not isinstance(payload.get(field), bool):
            errors.append(f"{field} must be boolean")
    if verdict == "approved":
        if payload.get("allowed_files_only") is not True:
            errors.append("approved requires allowed_files_only=true")
        if payload.get("production_boundary_preserved") is not True:
            errors.append("approved requires production_boundary_preserved=true")
    errors.extend(_reviewed_file_errors(payload, required_files))
    return errors


def _common_errors(payload: dict[str, Any]) -> list[str]:
    if not payload:
        return ["response must be a JSON object"]
    errors: list[str] = []
    if not isinstance(payload.get("findings"), list) or not all(
        isinstance(item, str) for item in payload.get("findings", [])
    ):
        errors.append("findings must be an array of strings")
    if not isinstance(payload.get("summary"), str) or not payload.get("summary", "").strip():
        errors.append("summary must be a non-empty string")
    return errors


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _reviewed_file_errors(payload: dict[str, Any], required_files: list[str]) -> list[str]:
    reviewed_files = _string_list(payload.get("reviewed_files"))
    if not reviewed_files:
        return ["reviewed_files must contain at least one repository-relative path"]
    if required_files and sorted(reviewed_files) != sorted(required_files):
        return [f"reviewed_files must exactly match required files: {required_files}"]
    return []


def _candidate_allowed_files(prompt: str) -> list[str]:
    match = re.search(r"Candidate allowed files:\s*(.*?)(?:\n\nRelevant excerpts:|\Z)", prompt, re.S)
    if not match:
        return []
    return sorted(set(re.findall(r"`(src/[^`]+)`", match.group(1))))


def _diff_files(prompt: str) -> list[str]:
    return sorted(set(re.findall(r"^diff --git a/(\S+) b/\S+", prompt, re.M)))


def _message_content(response: dict[str, Any]) -> str:
    message = response.get("message")
    if not isinstance(message, dict):
        return ""
    return str(message.get("content") or "").strip()


def _parse_json_object(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            return {}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def _post_json(url: str, payload: dict[str, Any], timeout_secs: int) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_secs) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama native reviewer HTTP {exc.code}: {detail}") from exc
