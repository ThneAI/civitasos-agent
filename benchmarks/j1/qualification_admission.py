"""Fail-closed provider admission for the J1-D qualification freeze."""

from __future__ import annotations

import ast
import stat
import urllib.parse
from pathlib import Path
from typing import Any

from .controlled_comparison import canonical_sha256


REQUEST_SCHEMA = "j1-qualification-admission-request:v1"
REPORT_SCHEMA = "j1-qualification-admission-report:v1"
FALSE_BOUNDARIES = {
    "provider_api_call_allowed",
    "agent_execution_allowed",
    "backend_fact_append_allowed",
    "runtime_advice_injection_allowed",
    "ledger_append_allowed",
    "effectiveness_claim_allowed",
    "maturity_upgrade_allowed",
}


def evaluate_admission(request: dict[str, Any], *, env_file: Path) -> dict[str, Any]:
    failures = validate_request(request)
    env_failures: list[str] = []
    env = _load_private_env(env_file, env_failures)
    failures.extend(env_failures)
    provider = (
        request.get("provider") if isinstance(request.get("provider"), dict) else {}
    )
    configured = {
        "kind": env.get("BETA6_EXTERNAL_AGENT_PROVIDER", ""),
        "base_url": env.get("BETA6_EXTERNAL_AGENT_API_BASE_URL", "").rstrip("/"),
        "model": env.get("BETA6_EXTERNAL_AGENT_MODEL", ""),
    }
    for field in ("kind", "base_url", "model"):
        if configured[field] != provider.get(field):
            failures.append(f"configured_provider_{field}_mismatch")
    if not env.get("BETA6_EXTERNAL_AGENT_API_KEY"):
        failures.append("provider_api_key_missing")
    passed = not failures
    parsed = urllib.parse.urlparse(configured["base_url"])
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "request_sha256": canonical_sha256(request),
        "provider_admission": {
            "kind": configured["kind"],
            "host": parsed.hostname or "",
            "model": configured["model"],
            "api_key_present": bool(env.get("BETA6_EXTERNAL_AGENT_API_KEY")),
            "api_key_recorded": False,
            "network_probe_performed": False,
            "model_invocation_performed": False,
        },
        "readiness": {
            "state": (
                "j1d_qualification_provider_admission_passed_roster_required"
                if passed
                else "blocked_j1d_qualification_provider_admission"
            ),
            "provider_configuration_admitted": passed,
            "qualification_protocol_frozen": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": request.get("execution_boundary", {}),
        "non_claims": [
            "provider_admission_does_not_probe_or_invoke_the_model",
            "provider_admission_does_not_bind_a_real_roster",
            "provider_admission_does_not_issue_execution_authorization",
            "provider_admission_does_not_verify_mentorship_effectiveness",
        ],
    }


def validate_request(value: Any) -> list[str]:
    failures: list[str] = []
    request = value if isinstance(value, dict) else {}
    _require(
        request.get("schema_version") == REQUEST_SCHEMA,
        "request_schema_invalid",
        failures,
    )
    _require(bool(_text(request.get("request_id"))), "request_id_missing", failures)
    _require(request.get("status") == "proposed", "request_status_invalid", failures)
    _require(
        _sha256(request.get("source_development_protocol_sha256")),
        "source_protocol_hash_invalid",
        failures,
    )
    _validate_provider(_object(request.get("provider")), failures)
    _validate_budget(_object(request.get("qualification_budget_ceiling")), failures)
    _validate_roster(_object(request.get("roster_contract")), failures)
    _validate_authorization(_object(request.get("authorization_contract")), failures)
    boundary = _object(request.get("execution_boundary"))
    _require(
        boundary.get("admission_validation_only") is True,
        "admission_only_boundary_required",
        failures,
    )
    for field in FALSE_BOUNDARIES:
        _require(boundary.get(field) is False, f"{field}_must_be_false", failures)
    return failures


def _validate_provider(provider: dict[str, Any], failures: list[str]) -> None:
    _require(
        provider.get("kind") == "openai_compatible", "provider_kind_invalid", failures
    )
    url = urllib.parse.urlparse(_text(provider.get("base_url")))
    _require(
        url.scheme == "https"
        and bool(url.hostname)
        and not url.username
        and not url.password
        and not url.query
        and not url.fragment,
        "provider_base_url_invalid",
        failures,
    )
    model = _text(provider.get("model"))
    _require(
        bool(model) and "synthetic" not in model.lower(),
        "provider_model_invalid",
        failures,
    )
    _require(provider.get("temperature") == 0, "provider_temperature_invalid", failures)


def _validate_budget(budget: dict[str, Any], failures: list[str]) -> None:
    expected = {
        "max_pairs": 20,
        "max_tasks_per_participant": 12,
        "max_tokens_per_participant": 20000,
        "max_cost_microunits_per_participant": 100000,
    }
    _require(budget == expected, "qualification_budget_invalid", failures)


def _validate_roster(roster: dict[str, Any], failures: list[str]) -> None:
    expected = {
        "real_identity_snapshots_required": True,
        "minimum_completed_pairs": 20,
        "exact_strata_required": True,
        "operator_review_required": True,
        "synthetic_participants_allowed": False,
    }
    _require(roster == expected, "roster_contract_invalid", failures)


def _validate_authorization(value: dict[str, Any], failures: list[str]) -> None:
    expected = {
        "single_use_required": True,
        "maximum_ttl_seconds": 1800,
        "explicit_cost_acknowledgement_required": True,
        "consumption_receipt_required": True,
    }
    _require(value == expected, "authorization_contract_invalid", failures)


def _load_private_env(path: Path, failures: list[str]) -> dict[str, str]:
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink() or not path.is_file():
            failures.append("provider_env_must_be_regular_file")
            return {}
        if mode & 0o077:
            failures.append("provider_env_permissions_not_private")
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        failures.append("provider_env_unreadable")
        return {}
    values: dict[str, str] = {}
    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            failures.append(f"provider_env_line_{line_number}_invalid")
            continue
        key, raw_value = line.split("=", 1)
        values[key.strip()] = _unquote(raw_value.strip(), line_number, failures)
    return values


def _unquote(value: str, line_number: int, failures: list[str]) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        try:
            return str(ast.literal_eval(value))
        except (SyntaxError, ValueError):
            failures.append(f"provider_env_line_{line_number}_quote_invalid")
            return ""
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
