"""Host-only J1-D provider broker with atomic budget reservation."""

from __future__ import annotations

import hashlib
import math
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256


RECEIPT_SCHEMA = "j1-qualification-provider-receipt:v1"
ProviderCall = Callable[..., dict[str, Any]]

PROVIDER_FAILURE_STAGES = {
    "http": {"http_transport", "http_status"},
    "parse": {
        "request_parse",
        "response_json_parse",
        "response_decision_json_parse",
    },
    "schema": {
        "request_decision_contract",
        "response_shape",
        "response_model",
        "response_finish_reason",
        "response_decision",
        "broker_result_shape",
        "receipt_validation",
    },
    "usage": {"response_usage", "broker_usage", "budget_reconciliation"},
    "internal": {
        "pre_dispatch_unclassified",
        "post_dispatch_unclassified",
        "legacy_unclassified_post_dispatch",
        "recovery_after_dispatch_intent",
    },
}


class SanitizedProviderFailure(ValueError):
    """Provider failure carrying only reviewed, non-content diagnostics."""

    def __init__(
        self,
        *,
        category: str,
        stage: str,
        source_exception_type: str,
    ) -> None:
        if stage not in PROVIDER_FAILURE_STAGES.get(category, set()):
            raise ValueError("provider failure category or stage is not reviewed")
        self.failure_category = category
        self.failure_stage = stage
        self.source_exception_type = source_exception_type
        super().__init__(f"sanitized provider failure at {category}/{stage}")


def sanitized_provider_failure(
    *,
    category: str,
    stage: str,
    error: BaseException | None = None,
    source_exception_type: str | None = None,
) -> SanitizedProviderFailure:
    return SanitizedProviderFailure(
        category=category,
        stage=stage,
        source_exception_type=source_exception_type
        or (type(error).__name__ if error is not None else "ProviderBoundaryError"),
    )


class QualificationBudgetStore:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    call_id TEXT PRIMARY KEY,
                    participant_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    reserved_tokens INTEGER NOT NULL,
                    reserved_microunits INTEGER NOT NULL,
                    actual_tokens INTEGER,
                    actual_microunits INTEGER,
                    status TEXT NOT NULL
                )
                """
            )
        self.path.chmod(0o600)

    def reserve(
        self,
        *,
        call_id: str,
        participant_id: str,
        task_id: str,
        reserved_tokens: int,
        reserved_microunits: int,
        participant_token_ceiling: int,
        participant_cost_ceiling: int,
        aggregate_token_ceiling: int,
        aggregate_cost_ceiling: int,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM reservations WHERE call_id = ?", (call_id,)
            ).fetchone():
                raise ValueError("provider call ID already reserved")
            participant = connection.execute(
                """
                SELECT COALESCE(SUM(CASE WHEN status = 'reconciled' THEN actual_tokens ELSE reserved_tokens END), 0),
                       COALESCE(SUM(CASE WHEN status = 'reconciled' THEN actual_microunits ELSE reserved_microunits END), 0)
                FROM reservations WHERE participant_id = ?
                """,
                (participant_id,),
            ).fetchone()
            aggregate = connection.execute(
                """
                SELECT COALESCE(SUM(CASE WHEN status = 'reconciled' THEN actual_tokens ELSE reserved_tokens END), 0),
                       COALESCE(SUM(CASE WHEN status = 'reconciled' THEN actual_microunits ELSE reserved_microunits END), 0)
                FROM reservations
                """
            ).fetchone()
            if (
                participant[0] + reserved_tokens > participant_token_ceiling
                or participant[1] + reserved_microunits > participant_cost_ceiling
                or aggregate[0] + reserved_tokens > aggregate_token_ceiling
                or aggregate[1] + reserved_microunits > aggregate_cost_ceiling
            ):
                raise ValueError("provider budget reservation ceiling exceeded")
            connection.execute(
                "INSERT INTO reservations VALUES (?, ?, ?, ?, ?, NULL, NULL, 'reserved')",
                (
                    call_id,
                    participant_id,
                    task_id,
                    reserved_tokens,
                    reserved_microunits,
                ),
            )

    def reconcile(
        self, *, call_id: str, actual_tokens: int, actual_microunits: int
    ) -> None:
        overrun = False
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT reserved_tokens, reserved_microunits, status FROM reservations WHERE call_id = ?",
                (call_id,),
            ).fetchone()
            if row is None or row[2] != "reserved":
                raise ValueError(
                    "provider reservation is missing or already reconciled"
                )
            if actual_tokens > row[0] or actual_microunits > row[1]:
                connection.execute(
                    "UPDATE reservations SET actual_tokens = ?, actual_microunits = ?, status = 'overrun' WHERE call_id = ?",
                    (actual_tokens, actual_microunits, call_id),
                )
                overrun = True
            else:
                connection.execute(
                    "UPDATE reservations SET actual_tokens = ?, actual_microunits = ?, status = 'reconciled' WHERE call_id = ?",
                    (actual_tokens, actual_microunits, call_id),
                )
        if overrun:
            raise ValueError("provider usage exceeded per-call reservation")

    def fail(self, *, call_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE reservations SET status = 'provider_outcome_unknown' "
                "WHERE call_id = ? AND status = 'reserved'",
                (call_id,),
            ).rowcount
            if changed != 1:
                raise ValueError(
                    "provider reservation cannot transition to outcome unknown"
                )

    def status(self, call_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM reservations WHERE call_id = ?", (call_id,)
            ).fetchone()
        return str(row[0]) if row else None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection


def execute_provider_call(
    *,
    call_id: str,
    run_id: str,
    participant_id: str,
    task_id: str,
    prompt: str,
    api_key: str,
    execution_authorization_sha256: str,
    reviewed_design: dict[str, Any],
    budget_store: QualificationBudgetStore,
    provider_call: ProviderCall,
) -> dict[str, Any]:
    for name, value in {
        "call_id": call_id,
        "run_id": run_id,
        "participant_id": participant_id,
        "task_id": task_id,
    }.items():
        if not _text(value):
            raise ValueError(f"provider {name} is required")
    if not _sha256(execution_authorization_sha256):
        raise ValueError("provider execution authorization hash is invalid")
    if not api_key:
        raise ValueError("provider API key is required")
    provider = reviewed_design["provider_call"]
    budget = reviewed_design["budget_reservation"]
    if len(prompt.encode()) > provider["max_input_utf8_bytes"]:
        raise ValueError("provider prompt exceeds reviewed UTF-8 byte limit")
    reservation = {
        "tokens": provider["reserved_total_tokens_per_call"],
        "microunits": budget["per_call_max_microunits"],
    }
    budget_store.reserve(
        call_id=call_id,
        participant_id=participant_id,
        task_id=task_id,
        reserved_tokens=reservation["tokens"],
        reserved_microunits=reservation["microunits"],
        participant_token_ceiling=budget["per_participant_reserved_tokens"],
        participant_cost_ceiling=budget["per_participant_reserved_microunits"],
        aggregate_token_ceiling=budget["aggregate_reserved_tokens"],
        aggregate_cost_ceiling=budget["aggregate_reserved_microunits"],
    )
    request = {
        "model": provider["model_id"],
        "temperature": provider["temperature"],
        "max_tokens": provider["max_output_tokens"],
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
    }
    try:
        try:
            response = provider_call(
                base_url=provider["base_url"],
                api_key=api_key,
                model=provider["model_id"],
                prompt=prompt,
                max_tokens=provider["max_output_tokens"],
                temperature=provider["temperature"],
            )
        except SanitizedProviderFailure:
            raise
        except Exception as error:
            raise sanitized_provider_failure(
                category="http",
                stage="http_transport",
                error=error,
            ) from None
        if not (
            isinstance(response, dict)
            and isinstance(response.get("content"), str)
            and bool(response["content"])
        ):
            raise sanitized_provider_failure(
                category="schema",
                stage="broker_result_shape",
                source_exception_type="ProviderResultShapeError",
            )
        content = response["content"]
        try:
            usage = normalize_usage(response.get("usage"))
            actual_tokens = sum(usage.values())
            actual_cost = calculate_cost_microunits(
                usage=usage, pricing=reviewed_design["pricing"]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise sanitized_provider_failure(
                category="usage",
                stage="broker_usage",
                error=error,
            ) from None
    except Exception:
        if budget_store.status(call_id) == "reserved":
            budget_store.fail(call_id=call_id)
        raise
    if actual_tokens > reservation["tokens"] or actual_cost > reservation["microunits"]:
        try:
            budget_store.reconcile(
                call_id=call_id,
                actual_tokens=actual_tokens,
                actual_microunits=actual_cost,
            )
        except ValueError as error:
            raise sanitized_provider_failure(
                category="usage",
                stage="budget_reconciliation",
                error=error,
            ) from None
        raise AssertionError("provider overrun must fail reconciliation")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "call_id": call_id,
        "run_id": run_id,
        "participant_id": participant_id,
        "task_id": task_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "execution_authorization_sha256": execution_authorization_sha256,
        "provider": {
            "provider_id": provider["provider_id"],
            "base_url_sha256": hashlib.sha256(
                provider["base_url"].encode()
            ).hexdigest(),
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
            "api_key_recorded": False,
        },
        "request": request,
        "response": {
            "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "content_utf8_bytes": len(content.encode()),
            "raw_content_recorded": False,
        },
        "usage": usage,
        "reservation": reservation,
        "actual": {"tokens": actual_tokens, "microunits": actual_cost},
        "budget_store": {
            "path_sha256": hashlib.sha256(str(budget_store.path).encode()).hexdigest(),
            "status": "reconciled",
        },
        "execution_boundary": {
            "host_broker_only": True,
            "api_key_recorded": False,
            "api_key_forwarded_to_container": False,
            "raw_prompt_recorded": False,
            "raw_response_recorded": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    failures = validate_provider_receipt(receipt, reviewed_design=reviewed_design)
    if failures:
        if budget_store.status(call_id) == "reserved":
            budget_store.fail(call_id=call_id)
        raise sanitized_provider_failure(
            category="schema",
            stage="receipt_validation",
            source_exception_type="ProviderReceiptValidationError",
        )
    try:
        budget_store.reconcile(
            call_id=call_id,
            actual_tokens=actual_tokens,
            actual_microunits=actual_cost,
        )
    except ValueError as error:
        if budget_store.status(call_id) == "reserved":
            budget_store.fail(call_id=call_id)
        raise sanitized_provider_failure(
            category="usage",
            stage="budget_reconciliation",
            error=error,
        ) from None
    return {"decision": content, "receipt": receipt}


def normalize_usage(value: Any) -> dict[str, int]:
    usage = value if isinstance(value, dict) else {}
    cache_hit = usage.get("input_cache_hit", 0)
    cache_miss = usage.get("input_cache_miss")
    output = usage.get("output")
    if cache_miss is None:
        cache_miss = usage.get("input", 0)
        cache_hit = 0
    result = {
        "input_cache_hit": cache_hit,
        "input_cache_miss": cache_miss,
        "output": output,
    }
    if any(type(item) is not int or item < 0 for item in result.values()):
        raise ValueError("provider usage counters are invalid")
    return result


def calculate_cost_microunits(*, usage: dict[str, int], pricing: dict[str, Any]) -> int:
    rates = pricing["rates_microunits"]
    numerator = sum(usage[name] * rates[name] for name in usage)
    return math.ceil(numerator / pricing["rate_basis_tokens"])


def validate_provider_receipt(
    value: Any, *, reviewed_design: dict[str, Any]
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    provider = reviewed_design["provider_call"]
    budget = reviewed_design["budget_reservation"]
    _require(
        set(receipt)
        == {
            "schema_version",
            "call_id",
            "run_id",
            "participant_id",
            "task_id",
            "completed_at",
            "execution_authorization_sha256",
            "provider",
            "request",
            "response",
            "usage",
            "reservation",
            "actual",
            "budget_store",
            "execution_boundary",
            "receipt_sha256",
        },
        "provider_receipt_fields_invalid",
        failures,
    )
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA,
        "provider_receipt_schema_invalid",
        failures,
    )
    for field in ("call_id", "run_id", "participant_id", "task_id"):
        _require(
            _text(receipt.get(field)), f"provider_receipt_{field}_invalid", failures
        )
    _require(
        _rfc3339(receipt.get("completed_at")), "provider_receipt_time_invalid", failures
    )
    _require(
        _sha256(receipt.get("execution_authorization_sha256")),
        "provider_receipt_authorization_invalid",
        failures,
    )
    _require(
        receipt.get("provider")
        == {
            "provider_id": provider["provider_id"],
            "base_url_sha256": hashlib.sha256(
                provider["base_url"].encode()
            ).hexdigest(),
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
            "api_key_recorded": False,
        },
        "provider_receipt_provider_invalid",
        failures,
    )
    request = receipt.get("request")
    _require(
        request
        == {
            "model": provider["model_id"],
            "temperature": provider["temperature"],
            "max_tokens": provider["max_output_tokens"],
            "prompt_sha256": request.get("prompt_sha256")
            if isinstance(request, dict)
            else None,
        }
        and _sha256(request.get("prompt_sha256")),
        "provider_receipt_request_invalid",
        failures,
    )
    response = receipt.get("response")
    _require(
        isinstance(response, dict)
        and set(response)
        == {"content_sha256", "content_utf8_bytes", "raw_content_recorded"}
        and _sha256(response.get("content_sha256"))
        and type(response.get("content_utf8_bytes")) is int
        and response["content_utf8_bytes"] >= 0
        and response.get("raw_content_recorded") is False,
        "provider_receipt_response_invalid",
        failures,
    )
    usage = receipt.get("usage") if isinstance(receipt.get("usage"), dict) else {}
    try:
        normalized = normalize_usage(usage)
        cost = calculate_cost_microunits(
            usage=normalized, pricing=reviewed_design["pricing"]
        )
    except (KeyError, TypeError, ValueError):
        normalized, cost = {}, -1
        failures.append("provider_receipt_usage_invalid")
    actual = receipt.get("actual", {})
    _require(
        actual == {"tokens": sum(normalized.values()), "microunits": cost}
        and actual.get("tokens", 0) <= provider["reserved_total_tokens_per_call"]
        and actual.get("microunits", 0) <= budget["per_call_max_microunits"],
        "provider_receipt_reconciliation_invalid",
        failures,
    )
    _require(
        receipt.get("reservation")
        == {
            "tokens": provider["reserved_total_tokens_per_call"],
            "microunits": budget["per_call_max_microunits"],
        },
        "provider_receipt_reservation_invalid",
        failures,
    )
    _require(
        isinstance(receipt.get("budget_store"), dict)
        and set(receipt["budget_store"]) == {"path_sha256", "status"}
        and _sha256(receipt["budget_store"].get("path_sha256"))
        and receipt["budget_store"].get("status") == "reconciled",
        "provider_receipt_budget_status_invalid",
        failures,
    )
    boundary = receipt.get("execution_boundary")
    _require(
        boundary
        == {
            "host_broker_only": True,
            "api_key_recorded": False,
            "api_key_forwarded_to_container": False,
            "raw_prompt_recorded": False,
            "raw_response_recorded": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
        "provider_receipt_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    _require(
        receipt.get("receipt_sha256") == canonical_sha256(body),
        "provider_receipt_hash_invalid",
        failures,
    )
    _require(
        not _contains_secret(receipt), "provider_receipt_secret_field_present", failures
    )
    return list(dict.fromkeys(failures))


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {"api_key", "token", "secret", "password", "pin"}:
                return True
            if _contains_secret(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
