#!/usr/bin/env python3
"""Validate Beta external Agent provider env files before running a preview chain.

The preflight is intentionally read-only. It validates env-file shape, transport
safety, optional model visibility, and provider diversity without recording API
keys or authorizing any task execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import beta6_external_agent_onboarding as beta6

REPORT_SCHEMA = "beta-external-provider-env-preflight:v1"
NON_CLAIMS = (
    "beta_external_provider_env_preflight_is_read_only",
    "beta_external_provider_env_preflight_does_not_store_api_keys",
    "beta_external_provider_env_preflight_does_not_assign_tasks",
    "beta_external_provider_env_preflight_does_not_call_chat_completion",
    "beta_external_provider_env_preflight_does_not_authorize_merge_or_deploy",
    "beta_external_provider_env_preflight_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-providers", type=int, default=1)
    parser.add_argument("--require-distinct-providers", action="store_true")
    parser.add_argument("--skip-model-probe", action="store_true")
    args = parser.parse_args(argv)

    report = inspect_provider_envs(
        env_files=[Path(path) for path in args.env_file],
        output_path=Path(args.output),
        min_providers=args.min_providers,
        require_distinct_providers=bool(args.require_distinct_providers),
        probe_models=not args.skip_model_probe,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def inspect_provider_envs(
    *,
    env_files: list[Path],
    output_path: Path,
    min_providers: int = 1,
    require_distinct_providers: bool = False,
    probe_models: bool = True,
) -> dict[str, Any]:
    failures: list[str] = []
    if min_providers < 1:
        failures.append("min_providers must be >= 1")
    if len(env_files) < min_providers:
        failures.append(f"env file count must be >= {min_providers}")

    records = [_inspect_one(path, probe_models=probe_models, failures=failures) for path in env_files]
    identities = sorted({record["provider_identity"] for record in records if record.get("provider_identity")})
    agent_models = sorted({record["model"] for record in records if record.get("model")})
    if require_distinct_providers and len(identities) < min_providers:
        failures.append(f"distinct provider identity count must be >= {min_providers}")

    report = {
        "schema_version": REPORT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "provider_env_ready" if not failures else "blocked",
        "failure_reasons": failures,
        "env_file_count": len(env_files),
        "min_providers": min_providers,
        "require_distinct_providers": require_distinct_providers,
        "probe_models": probe_models,
        "unique_provider_identity_count": len(identities),
        "unique_provider_identities": identities,
        "unique_model_count": len(agent_models),
        "unique_models": agent_models,
        "providers": records,
        "api_key_recorded": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _inspect_one(path: Path, *, probe_models: bool, failures: list[str]) -> dict[str, Any]:
    local_failures: list[str] = []
    env = beta6._read_env_file(path, local_failures)
    base_url = beta6._required_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", local_failures).rstrip("/")
    model = beta6._required_env(env, "BETA6_EXTERNAL_AGENT_MODEL", local_failures)
    api_key = beta6._required_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", local_failures)
    provider = beta6._text(env.get("BETA6_EXTERNAL_AGENT_PROVIDER")) or "openai_compatible"
    beta6._reject_forbidden_text([base_url, model, api_key, provider], local_failures)
    beta6._validate_api_base_url(base_url, env, local_failures)
    parsed = urllib.parse.urlparse(base_url)
    local_http_allowed = beta6._env_flag(env, "BETA6_EXTERNAL_AGENT_ALLOW_LOCAL_HTTP")
    model_probe = None
    if probe_models and not local_failures:
        model_probe = beta6._probe_models_endpoint(base_url=base_url, api_key=api_key, model=model)
        if model_probe.get("reachable") is not True:
            local_failures.append("provider models endpoint must be reachable")
        if model_probe.get("http_status") != 200:
            local_failures.append("provider models endpoint must return HTTP 200")
        if model_probe.get("requested_model_visible") is not True:
            local_failures.append("requested model must be visible in provider models response")

    failures.extend(f"{path}: {reason}" for reason in local_failures)
    return {
        "env_file": str(path.resolve()),
        "env_file_sha256": _sha256(path) if path.is_file() else None,
        "passed": not local_failures,
        "failure_reasons": local_failures,
        "provider": provider,
        "provider_identity": _provider_identity(provider, base_url),
        "base_url": base_url,
        "base_url_scheme": parsed.scheme,
        "base_url_host": parsed.hostname,
        "model": model,
        "api_key_present": bool(api_key),
        "api_key_recorded": False,
        "local_http_allowed": local_http_allowed,
        "transport_security": "https" if parsed.scheme == "https" else "local_http_opt_in",
        "model_probe": model_probe,
    }


def _provider_identity(provider: str, base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.netloc or parsed.path
    return f"{provider}@{host}"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
