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
    SanitizedProviderFailure,
    execute_provider_call,
    sanitized_provider_failure,
)
from .qualification_http_transport import PreparedHTTPSPost

DECISION_SYSTEM_SUFFIX = (
    'Return exactly one JSON object with the form {"decision":"<participant '
    'decision>"} and no other fields. The decision must be a non-empty string. '
    "Do not return markdown or explanatory text outside the JSON object."
)
DECISION_RESPONSE_FORMAT = {"type": "json_object"}
DECISION_THINKING = {"type": "disabled"}
MAX_DECISION_BYTES = 65_536


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
        transport_factory: Any | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("provider API key is required")
        self.run_id = run_id
        self.api_key = api_key
        self.authorization_sha256 = authorization_sha256
        self.design = _normalized_design(amended_design)
        self.budget = QualificationBudgetStore(budget_path)
        self._transport_factory = transport_factory or PreparedHTTPSPost
        self._prepared: dict[str, PreparedHTTPSPost] = {}

    def prepare(self, *, task: dict[str, Any]) -> None:
        call_id = task["call_id"]
        if call_id in self._prepared:
            return
        provider = self.design["provider_call"]
        transport = self._transport_factory(
            f"{provider['base_url'].rstrip('/')}/chat/completions"
        )
        transport.prepare()
        self._prepared[call_id] = transport

    def discard(self, *, task: dict[str, Any]) -> None:
        transport = self._prepared.pop(task["call_id"], None)
        if transport is not None:
            transport.close()

    def call(self, *, task: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        transport = self._prepared.pop(task["call_id"], None)
        if transport is None:
            raise sanitized_provider_failure(
                category="internal",
                stage="pre_dispatch_unclassified",
                source_exception_type="ProviderTransportNotPreparedError",
            )
        prompt = _decision_prompt(
            system=request["system"],
            user=request["user"],
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
            provider_call=lambda **kwargs: self._post_prepared_once(
                transport=transport,
                **kwargs,
            ),
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
    def _post_prepared_once(
        *,
        transport: PreparedHTTPSPost,
        base_url: str,
        api_key: str,
        model: str,
        prompt: str,
        max_tokens: int,
        temperature: int,
    ) -> dict[str, Any]:
        expected_url = f"{base_url.rstrip('/')}/chat/completions"
        if transport.url.geturl() != expected_url:
            transport.close()
            raise sanitized_provider_failure(
                category="schema",
                stage="request_decision_contract",
                source_exception_type="ProviderTransportBindingError",
            )
        try:
            return OpenAICompatibleQualificationProvider._post_with_sender(
                sender=lambda _url, key, body: transport.post_json_once(
                    api_key=key,
                    body=body,
                    user_agent="civitasos-j1d-live-execution/1",
                ),
                base_url=base_url,
                api_key=api_key,
                model=model,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        except Exception:
            transport.close()
            raise

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
        return OpenAICompatibleQualificationProvider._post_with_sender(
            sender=_https_post_once,
            base_url=base_url,
            api_key=api_key,
            model=model,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    @staticmethod
    def _post_with_sender(
        *,
        sender: Any,
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
        if not (
            isinstance(messages, dict)
            and set(messages) == {"system", "user"}
            and isinstance(messages.get("system"), str)
            and messages["system"].endswith(DECISION_SYSTEM_SUFFIX)
            and isinstance(messages.get("user"), str)
            and messages["user"]
        ):
            raise sanitized_provider_failure(
                category="schema",
                stage="request_decision_contract",
                source_exception_type="ProviderDecisionContractError",
            )
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": messages["system"]},
                {"role": "user", "content": messages["user"]},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "thinking": DECISION_THINKING,
            "response_format": DECISION_RESPONSE_FORMAT,
            "stream": False,
        }
        try:
            status, raw = sender(
                f"{base_url.rstrip('/')}/chat/completions", api_key, body
            )
        except SanitizedProviderFailure:
            raise
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
        if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
            raise sanitized_provider_failure(
                category="schema",
                stage="response_shape",
                source_exception_type="ProviderChoiceShapeError",
            )
        choice = choices[0]
        if choice.get("finish_reason") != "stop":
            raise sanitized_provider_failure(
                category="schema",
                stage="response_finish_reason",
                source_exception_type="ProviderFinishReasonError",
            )
        message = choice.get("message")
        if not isinstance(message, dict):
            raise sanitized_provider_failure(
                category="schema",
                stage="response_shape",
                source_exception_type="ProviderMessageShapeError",
            )
        content = message.get("content")
        if not isinstance(content, str) or not content:
            raise sanitized_provider_failure(
                category="schema",
                stage="response_decision",
                source_exception_type="ProviderDecisionShapeError",
            )
        try:
            decision_object = json.loads(content)
        except json.JSONDecodeError as error:
            raise sanitized_provider_failure(
                category="parse",
                stage="response_decision_json_parse",
                error=error,
            ) from None
        decision = (
            decision_object.get("decision")
            if isinstance(decision_object, dict)
            and set(decision_object) == {"decision"}
            else None
        )
        if not (
            isinstance(decision, str)
            and 0 < len(decision.encode("utf-8")) <= MAX_DECISION_BYTES
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
            "content": decision,
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


def _decision_prompt(*, system: str, user: str) -> str:
    if not system or not user:
        raise ValueError("provider decision prompt fields are required")
    return json.dumps(
        {
            "system": f"{system.rstrip()}\n\n{DECISION_SYSTEM_SUFFIX}",
            "user": user,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


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
