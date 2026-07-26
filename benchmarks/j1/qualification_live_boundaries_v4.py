"""Host-only Provider and PKCS#11 boundaries for live J1-D execution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from benchmarks.j1_qualification_provider_admission_probe import _https_post_once

from .qualification_provider_broker import (
    QualificationBudgetStore,
    execute_provider_call,
    sanitized_provider_failure,
)


class Pkcs11ParticipantSigner:
    def __init__(self, *, session: Any, profiles: dict[str, dict[str, Any]]) -> None:
        self.session = session
        self.profiles = profiles

    def sign(self, *, participant_id: str, payload: bytes) -> bytes:
        profile = self._profile(participant_id)
        private_key = self.session.get_key(
            object_class=pkcs11.ObjectClass.PRIVATE_KEY,
            label=profile["pkcs11_key"]["key_label"],
            id=bytes.fromhex(profile["pkcs11_key"]["key_id_hex"]),
        )
        return bytes(private_key.sign(payload, mechanism=pkcs11.Mechanism.EDDSA))

    def verify(self, *, participant_id: str, payload: bytes, signature: bytes) -> bool:
        profile = self._profile(participant_id)
        try:
            VerifyKey(bytes.fromhex(profile["participant"]["public_key_hex"])).verify(
                payload, signature
            )
            return True
        except (BadSignatureError, ValueError):
            return False

    def _profile(self, participant_id: str) -> dict[str, Any]:
        profile = self.profiles.get(participant_id)
        if profile is None:
            raise ValueError("participant PKCS#11 profile is not bound")
        return profile


class OpenAICompatibleQualificationProvider:
    def __init__(
        self,
        *,
        run_id: str,
        api_key: str,
        authorization_sha256: str,
        amended_design: dict[str, Any],
        budget_path: Path,
    ) -> None:
        if not api_key:
            raise ValueError("provider API key is required")
        self.run_id = run_id
        self.api_key = api_key
        self.authorization_sha256 = authorization_sha256
        self.design = _normalized_design(amended_design)
        self.budget = QualificationBudgetStore(budget_path)

    def call(self, *, task: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        prompt = json.dumps(
            {"system": request["system"], "user": request["user"]},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        result = execute_provider_call(
            call_id=task["call_id"],
            run_id=self.run_id,
            participant_id=task["participant_id"],
            task_id=task["task"]["task_id"],
            prompt=prompt,
            api_key=self.api_key,
            execution_authorization_sha256=self.authorization_sha256,
            reviewed_design=self.design,
            budget_store=self.budget,
            provider_call=self._post_once,
        )
        receipt = result["receipt"]
        return {
            "decision": result["decision"],
            "receipt": receipt,
            "usage": {
                **receipt["usage"],
                "cost_microunits": receipt["actual"]["microunits"],
            },
        }

    @staticmethod
    def _post_once(
        *,
        base_url: str,
        api_key: str,
        model: str,
        prompt: str,
        max_tokens: int,
        temperature: int,
    ) -> dict[str, Any]:
        try:
            messages = json.loads(prompt)
        except json.JSONDecodeError as error:
            raise sanitized_provider_failure(
                category="parse",
                stage="request_parse",
                error=error,
            ) from None
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": messages["system"]},
                {"role": "user", "content": messages["user"]},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        try:
            status, raw = _https_post_once(
                f"{base_url.rstrip('/')}/chat/completions", api_key, body
            )
        except Exception as error:
            raise sanitized_provider_failure(
                category="http",
                stage="http_transport",
                error=error,
            ) from None
        if status != 200:
            raise sanitized_provider_failure(
                category="http",
                stage="http_status",
                source_exception_type="ProviderHttpStatusError",
            )
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise sanitized_provider_failure(
                category="parse",
                stage="response_json_parse",
                error=error,
            ) from None
        if not isinstance(response, dict):
            raise sanitized_provider_failure(
                category="schema",
                stage="response_shape",
                source_exception_type="ProviderResponseShapeError",
            )
        if response.get("model") != model:
            raise sanitized_provider_failure(
                category="schema",
                stage="response_model",
                source_exception_type="ProviderModelMismatchError",
            )
        choices = response.get("choices")
        if not (
            isinstance(choices, list)
            and choices
            and isinstance(choices[0], dict)
            and isinstance(choices[0].get("message"), dict)
            and isinstance(choices[0]["message"].get("content"), str)
            and choices[0]["message"]["content"]
        ):
            raise sanitized_provider_failure(
                category="schema",
                stage="response_decision",
                source_exception_type="ProviderDecisionShapeError",
            )
        try:
            usage = _normalize_wire_usage(response.get("usage"))
        except ValueError as error:
            raise sanitized_provider_failure(
                category="usage",
                stage="response_usage",
                error=error,
            ) from None
        return {
            "content": choices[0]["message"]["content"],
            "usage": usage,
        }


def load_participant_profiles(root: Path) -> dict[str, dict[str, Any]]:
    result = {}
    for path in sorted(root.glob("*.json")):
        value = json.loads(path.read_bytes())
        participant_id = value.get("participant", {}).get("participant_id")
        if not participant_id or participant_id in result:
            raise ValueError("participant profile inventory invalid")
        result[participant_id] = value
    if len(result) != 40:
        raise ValueError("exactly 40 participant profiles are required")
    return result


def _normalized_design(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider_call": value.get("provider_call") or value["preserved_provider_call"],
        "budget_reservation": value.get("budget_reservation")
        or value["preserved_budget_reservation"],
        "pricing": value.get("pricing") or value["preserved_pricing"],
    }


def _normalize_wire_usage(value: Any) -> dict[str, int]:
    usage = value if isinstance(value, dict) else {}
    prompt = usage.get("prompt_tokens")
    output = usage.get("completion_tokens")
    hit = usage.get("prompt_cache_hit_tokens", 0)
    miss = usage.get("prompt_cache_miss_tokens", prompt)
    if (
        type(prompt) is not int
        or type(output) is not int
        or type(hit) is not int
        or type(miss) is not int
        or min(prompt, output, hit, miss) < 0
        or hit + miss != prompt
    ):
        raise ValueError("provider usage counters invalid")
    return {
        "input_cache_hit": hit,
        "input_cache_miss": miss,
        "output": output,
    }
