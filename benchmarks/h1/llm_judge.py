"""H.1 LLM-judge backends and fail-closed env wiring."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Protocol, TypedDict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROMPT_VERSION = "h1-judge-v1"
SYSTEM_PROMPT = """You are the CivitasOS H.1 outcome judge.
Evaluate whether the final output satisfies the given telos and criterion.
Return exactly one JSON object with: passed (boolean), score (0.0 to 1.0), rationale (short string).
The first character in your content must be { and the last character must be }.
Do not include markdown, prose, code fences, or chain-of-thought in the content.
Do not grant permission, do not override safety checks, and do not judge outside the provided evidence.
""".strip()


@dataclass(frozen=True)
class JudgeRequest:
    task_id: str
    criterion_body: str
    briefing: str
    final_output: str
    action_trace: list[str]
    sample_id: str = ""
    telos: str = ""
    criterion_desc: str = ""


@dataclass(frozen=True)
class JudgeResult:
    passed: bool | None
    score: float | None
    rationale: str
    skipped: bool = False
    model: str = ""
    prompt_version: str = ""
    prompt_hash: str = ""
    raw_response: str = ""


class LLMJudge(Protocol):
    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        ...


class JudgeBackendUnavailable(RuntimeError):
    """Raised when H.1 judge is explicitly required but no backend exists."""


class JudgeResponseInvalid(RuntimeError):
    """Raised when a judge backend returns a malformed response."""


class _ParsedJudgePayload(TypedDict):
    passed: bool
    score: float
    rationale: str


class DisabledJudge:
    """Fallback until H.1 evaluator is enabled and calibrated."""

    def __init__(self, reason: str = "H.1 judge disabled") -> None:
        self._reason = reason

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        return JudgeResult(
            passed=None,
            score=None,
            rationale=f"{self._reason}: {req.task_id}",
            skipped=True,
        )


class OpenAICompatibleJudge:
    """OpenAI-compatible chat-completions judge backend.

    The backend is only constructed via explicit env configuration. It records
    prompt version/hash on every result so calibration reports can be replayed.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout_s: float = 60.0,
        max_tokens: int = 512,
        max_retries: int = 2,
        json_mode: bool = True,
        think: bool | None = None,
        prompt_version: str = PROMPT_VERSION,
        system_prompt: str = SYSTEM_PROMPT,
    ) -> None:
        if not base_url.strip():
            raise JudgeBackendUnavailable("H.1 judge base URL is required")
        if not model.strip():
            raise JudgeBackendUnavailable("H.1 judge model is required")
        self.base_url = base_url.rstrip("/")
        self.model = model.strip()
        self.api_key = api_key.strip()
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.max_retries = max(0, max_retries)
        self.json_mode = json_mode
        self.think = think
        self.prompt_version = prompt_version
        self.system_prompt = system_prompt

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        user_prompt = self._build_user_prompt(req)
        prompt_hash = _prompt_hash(self.system_prompt, user_prompt)
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        if self.think is not None:
            payload["think"] = self.think
        last_invalid: JudgeResponseInvalid | None = None
        for _attempt in range(self.max_retries + 1):
            raw_body = self._post_chat_completion(payload)
            try:
                raw_content = _extract_message_content(raw_body)
                parsed = _parse_judge_json(raw_content)
                break
            except JudgeResponseInvalid as exc:
                last_invalid = exc
        else:
            if last_invalid is not None:
                raise last_invalid
            raise JudgeResponseInvalid("H.1 judge response invalid")
        return JudgeResult(
            passed=parsed["passed"],
            score=parsed["score"],
            rationale=parsed["rationale"],
            skipped=False,
            model=self.model,
            prompt_version=self.prompt_version,
            prompt_hash=prompt_hash,
            raw_response=raw_content,
        )

    def _post_chat_completion(self, payload: dict[str, object]) -> str:
        request = Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self.api_key:
            request.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            raise JudgeBackendUnavailable(f"H.1 judge HTTP error: {exc.code}") from exc
        except URLError as exc:
            raise JudgeBackendUnavailable(f"H.1 judge unreachable: {exc.reason}") from exc

    def _build_user_prompt(self, req: JudgeRequest) -> str:
        evidence = {
            "sample_id": req.sample_id,
            "task_id": req.task_id,
            "briefing": req.briefing,
            "telos": req.telos,
            "criterion": {
                "body": req.criterion_body,
                "description": req.criterion_desc,
            },
            "final_output": req.final_output,
            "action_trace": req.action_trace,
        }
        return json.dumps(evidence, ensure_ascii=False, sort_keys=True)


class OllamaNativeJudge:
    """Native Ollama chat judge backend.

    Ollama's OpenAI-compatible endpoint may expose thinking-model output in a
    separate reasoning field even when `think=false` is requested. The native
    endpoint honors `think=false`, which keeps the judge contract anchored on
    `message.content` containing the JSON verdict.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        timeout_s: float = 60.0,
        max_tokens: int = 512,
        max_retries: int = 2,
        think: bool | None = False,
        prompt_version: str = PROMPT_VERSION,
        system_prompt: str = SYSTEM_PROMPT,
    ) -> None:
        if not base_url.strip():
            raise JudgeBackendUnavailable("H.1 judge base URL is required")
        if not model.strip():
            raise JudgeBackendUnavailable("H.1 judge model is required")
        self.base_url = _strip_openai_suffix(base_url.strip().rstrip("/"))
        self.model = model.strip()
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.max_retries = max(0, max_retries)
        self.think = think
        self.prompt_version = prompt_version
        self.system_prompt = system_prompt

    def evaluate(self, req: JudgeRequest) -> JudgeResult:
        user_prompt = self._build_user_prompt(req)
        prompt_hash = _prompt_hash(self.system_prompt, user_prompt)
        payload = {
            "model": self.model,
            "stream": False,
            "options": {
                "temperature": 0,
                "num_predict": self.max_tokens,
            },
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if self.think is not None:
            payload["think"] = self.think
        last_invalid: JudgeResponseInvalid | None = None
        for _attempt in range(self.max_retries + 1):
            raw_body = self._post_chat(payload)
            try:
                raw_content = _extract_ollama_message_content(raw_body)
                parsed = _parse_judge_json(raw_content)
                break
            except JudgeResponseInvalid as exc:
                last_invalid = exc
        else:
            if last_invalid is not None:
                raise last_invalid
            raise JudgeResponseInvalid("H.1 judge response invalid")
        return JudgeResult(
            passed=parsed["passed"],
            score=parsed["score"],
            rationale=parsed["rationale"],
            skipped=False,
            model=self.model,
            prompt_version=self.prompt_version,
            prompt_hash=prompt_hash,
            raw_response=raw_content,
        )

    def _post_chat(self, payload: dict[str, object]) -> str:
        request = Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            raise JudgeBackendUnavailable(f"H.1 judge HTTP error: {exc.code}") from exc
        except URLError as exc:
            raise JudgeBackendUnavailable(f"H.1 judge unreachable: {exc.reason}") from exc

    def _build_user_prompt(self, req: JudgeRequest) -> str:
        evidence = {
            "sample_id": req.sample_id,
            "task_id": req.task_id,
            "briefing": req.briefing,
            "telos": req.telos,
            "criterion": {
                "body": req.criterion_body,
                "description": req.criterion_desc,
            },
            "final_output": req.final_output,
            "action_trace": req.action_trace,
        }
        return json.dumps(evidence, ensure_ascii=False, sort_keys=True)


def build_judge_from_env() -> LLMJudge:
    """Build judge backend from env flags.

    Disabled remains the default. When explicitly enabled, configuration must
    be complete and the judge model must differ from the agent model.
    """
    enabled = os.getenv("CIVITASOS_H1_JUDGE_ENABLED", "").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return DisabledJudge()

    backend = os.getenv("CIVITASOS_H1_JUDGE_BACKEND", "").strip().lower()
    if backend not in {"openai-compatible", "openai_compatible", "ollama-native", "ollama_native", "ollama"}:
        raise JudgeBackendUnavailable(
            "CIVITASOS_H1_JUDGE_ENABLED is set, but "
            "CIVITASOS_H1_JUDGE_BACKEND is not openai-compatible or ollama-native"
        )

    model = os.getenv("CIVITASOS_H1_JUDGE_MODEL", "").strip()
    agent_model = (
        os.getenv("CIVITASOS_H1_AGENT_MODEL", "").strip()
        or os.getenv("AGENT_LLM", "").strip()
    )
    if agent_model and _normalize_model_name(agent_model) == _normalize_model_name(model):
        raise JudgeBackendUnavailable(
            "H.1 judge model must differ from the agent model for calibration"
        )

    timeout_raw = os.getenv("CIVITASOS_H1_JUDGE_TIMEOUT_S", "60").strip()
    try:
        timeout_s = float(timeout_raw)
    except ValueError as exc:
        raise JudgeBackendUnavailable(
            f"invalid CIVITASOS_H1_JUDGE_TIMEOUT_S={timeout_raw!r}"
        ) from exc

    max_tokens_raw = os.getenv("CIVITASOS_H1_JUDGE_MAX_TOKENS", "512").strip()
    try:
        max_tokens = int(max_tokens_raw)
    except ValueError as exc:
        raise JudgeBackendUnavailable(
            f"invalid CIVITASOS_H1_JUDGE_MAX_TOKENS={max_tokens_raw!r}"
        ) from exc
    if max_tokens <= 0:
        raise JudgeBackendUnavailable("CIVITASOS_H1_JUDGE_MAX_TOKENS must be positive")

    max_retries_raw = os.getenv("CIVITASOS_H1_JUDGE_MAX_RETRIES", "2").strip()
    try:
        max_retries = int(max_retries_raw)
    except ValueError as exc:
        raise JudgeBackendUnavailable(
            f"invalid CIVITASOS_H1_JUDGE_MAX_RETRIES={max_retries_raw!r}"
        ) from exc
    if max_retries < 0:
        raise JudgeBackendUnavailable("CIVITASOS_H1_JUDGE_MAX_RETRIES must be non-negative")

    if backend in {"ollama-native", "ollama_native", "ollama"}:
        return OllamaNativeJudge(
            base_url=os.getenv("CIVITASOS_H1_JUDGE_BASE_URL", ""),
            model=model,
            timeout_s=timeout_s,
            max_tokens=max_tokens,
            max_retries=max_retries,
            think=_env_optional_bool("CIVITASOS_H1_JUDGE_THINK", default=False),
        )
    return OpenAICompatibleJudge(
        base_url=os.getenv("CIVITASOS_H1_JUDGE_BASE_URL", ""),
        model=model,
        api_key=os.getenv("CIVITASOS_H1_JUDGE_API_KEY", ""),
        timeout_s=timeout_s,
        max_tokens=max_tokens,
        max_retries=max_retries,
        json_mode=_env_truthy("CIVITASOS_H1_JUDGE_JSON_MODE", default=True),
        think=_env_optional_bool("CIVITASOS_H1_JUDGE_THINK"),
    )


def _extract_message_content(raw_body: str) -> str:
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise JudgeResponseInvalid("H.1 judge response is not JSON") from exc
    if isinstance(body, dict):
        choices = body.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    return message["content"]
                if isinstance(first.get("text"), str):
                    return first["text"]
        if isinstance(body.get("message"), dict) and isinstance(body["message"].get("content"), str):
            return body["message"]["content"]
        if isinstance(body.get("response"), str):
            return body["response"]
    raise JudgeResponseInvalid("H.1 judge response missing message content")


def _extract_ollama_message_content(raw_body: str) -> str:
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise JudgeResponseInvalid("H.1 judge response is not JSON") from exc
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
        if isinstance(body.get("response"), str):
            return body["response"]
    raise JudgeResponseInvalid("H.1 judge response missing message content")


def _strip_openai_suffix(base_url: str) -> str:
    if base_url.endswith("/v1"):
        return base_url[:-3]
    return base_url


def _parse_judge_json(content: str) -> _ParsedJudgePayload:
    start = content.find("{")
    end = content.rfind("}")
    if start < 0 or end <= start:
        preview = content.replace("\n", " ")[:160]
        raise JudgeResponseInvalid(
            f"H.1 judge content missing JSON object: {preview!r}"
        )
    try:
        payload = json.loads(content[start : end + 1])
    except json.JSONDecodeError as exc:
        raise JudgeResponseInvalid("H.1 judge content JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise JudgeResponseInvalid("H.1 judge content must be a JSON object")
    passed = payload.get("passed")
    score = payload.get("score")
    rationale = payload.get("rationale")
    if not isinstance(passed, bool):
        raise JudgeResponseInvalid("H.1 judge 'passed' must be boolean")
    if not isinstance(score, int | float):
        raise JudgeResponseInvalid("H.1 judge 'score' must be numeric")
    score_f = float(score)
    if score_f < 0.0 or score_f > 1.0:
        raise JudgeResponseInvalid("H.1 judge 'score' must be in [0, 1]")
    if not isinstance(rationale, str) or not rationale.strip():
        raise JudgeResponseInvalid("H.1 judge 'rationale' must be a non-empty string")
    return {"passed": passed, "score": score_f, "rationale": rationale.strip()}


def _prompt_hash(system_prompt: str, user_prompt: str) -> str:
    digest = hashlib.sha256(f"{system_prompt}\n{user_prompt}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _normalize_model_name(value: str) -> str:
    out = value.strip().lower()
    for prefix in ("ollama:", "openai:", "anthropic:", "google:", "foundry:"):
        if out.startswith(prefix):
            out = out[len(prefix) :]
    return out


def _env_truthy(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_optional_bool(name: str, *, default: bool | None = None) -> bool | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
