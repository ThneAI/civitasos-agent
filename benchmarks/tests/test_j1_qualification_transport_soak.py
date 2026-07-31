from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_provider_broker import sanitized_provider_failure
from benchmarks.j1.qualification_transport_reliability import (
    FAULT_SCENARIOS,
    build_fault_matrix_report,
    build_soak_plan,
    build_transport_contract,
)
from benchmarks.j1.qualification_transport_soak import (
    PLANNING_BOUNDARY,
    authorization_statement,
    build_authorization_preflight,
    build_execution_plan,
    normalize_response,
    validate_execution_plan,
)
from benchmarks.j1_qualification_transport_soak_execute import execute_soak


IMPLEMENTATION = {
    "source_revision": "1" * 40,
    "domain_source_sha256": "2" * 64,
    "preflight_source_sha256": "3" * 64,
    "execution_source_sha256": "4" * 64,
}
PRICING = {
    "billing_currency": "USD",
    "cost_unit": "usd_microunit",
    "microunits_per_usd": 1_000_000,
    "missing_cache_usage": "charge_all_input_as_cache_miss",
    "observed_at": "2026-07-22T11:37:04+00:00",
    "price_drift_requires_new_reviewed_design": True,
    "rate_basis_tokens": 1_000_000,
    "rates_microunits": {
        "input_cache_hit": 3625,
        "input_cache_miss": 435000,
        "output": 870000,
    },
    "rounding": "ceil_each_provider_call_to_integer_microunit",
    "source_url": "https://api-docs.deepseek.com/quick_start/pricing/",
}


def _ref(name: str, canonical: str = "a" * 64) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": canonical_sha256([name, "raw"]),
        "canonical_sha256": canonical,
    }


def _reviewed_plan() -> dict:
    candidate_implementation = {
        "source_revision": "5" * 40,
        "domain_source_sha256": "6" * 64,
        "operation_source_sha256": "7" * 64,
        "transport_source_sha256": "8" * 64,
    }
    contract = build_transport_contract(
        contract_id="transport-r1",
        created_at="2026-07-31T13:00:00+00:00",
        source_binding={
            "r2_terminal_gate": _ref("r2"),
            "r3_terminal_gate": _ref("r3"),
        },
        implementation=candidate_implementation,
    )
    contract_ref = _ref("contract", contract["contract_sha256"])
    scenarios = [
        {
            "scenario": name,
            "expected": "bounded",
            "observed": "bounded",
            "observed_connect_attempt_count": 1,
            "observed_http_request_count": (
                0 if "before_dispatch" in name else 1
            ),
            "observed_post_dispatch_retry_count": 0,
            "passed": True,
        }
        for name in FAULT_SCENARIOS
    ]
    fault = build_fault_matrix_report(
        checked_at="2026-07-31T13:01:00+00:00",
        contract_ref=contract_ref,
        scenarios=scenarios,
        implementation=candidate_implementation,
    )
    return build_soak_plan(
        plan_id="reviewed-soak-r1",
        created_at="2026-07-31T13:02:00+00:00",
        contract_ref=contract_ref,
        fault_matrix_ref=_ref("fault", fault["report_sha256"]),
        provider_design_ref=_ref("provider"),
        provider={
            "provider_id": "openai_compatible",
            "base_url": "https://api.deepseek.com",
            "endpoint": "/chat/completions",
            "model": "deepseek-v4-pro",
        },
        implementation=candidate_implementation,
    )


def _plan() -> dict:
    return build_execution_plan(
        soak_id="transport-soak-live-r1",
        created_at="2026-07-31T14:00:00+00:00",
        source_artifacts={
            "promotion_gate": _ref("gate"),
            "frozen_review": _ref("frozen"),
            "reviewed_soak_plan": _ref("reviewed-plan"),
        },
        reviewed_plan=_reviewed_plan(),
        pricing=PRICING,
        implementation=IMPLEMENTATION,
    )


def _response() -> bytes:
    return json.dumps(
        {
            "id": "response-1",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": '{"status":"ok"}'}}],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 5,
                "total_tokens": 25,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 20,
            },
        }
    ).encode()


class _SuccessfulTransport:
    def __init__(self, _: str) -> None:
        self.connect_attempt_count = 1
        self.http_request_count = 0

    def prepare(self) -> None:
        return None

    def post_json_once(self, **_: object) -> tuple[int, bytes]:
        self.http_request_count = 1
        return 200, _response()

    def close(self) -> None:
        return None


class _AmbiguousTransport(_SuccessfulTransport):
    def post_json_once(self, **_: object) -> tuple[int, bytes]:
        self.http_request_count = 1
        raise sanitized_provider_failure(
            category="http",
            stage="http_dispatch_ambiguous",
            source_exception_type="TimeoutError",
        )


class _ConnectExhaustedTransport(_SuccessfulTransport):
    def prepare(self) -> None:
        self.connect_attempt_count = 3
        raise sanitized_provider_failure(
            category="http",
            stage="http_pre_dispatch_connect",
            source_exception_type="TimeoutError",
        )


def test_transport_soak_plan_and_preflight_freeze_single_use_boundary() -> None:
    plan = _plan()
    assert validate_execution_plan(plan) == []
    plan_ref = _ref("plan", plan["plan_sha256"])
    preflight = build_authorization_preflight(
        plan_ref=plan_ref,
        plan=plan,
        created_at="2026-07-31T14:01:00+00:00",
    )
    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert "at most 64 sequential HTTPS POSTs" in statement
    assert "any failure after dispatch is ambiguous" in statement
    assert preflight["execution_boundary"] == PLANNING_BOUNDARY


def test_transport_soak_normalizes_without_persisting_content() -> None:
    result = normalize_response(status=200, body=_response(), plan=_plan())
    assert result["http_status"] == 200
    assert result["usage"]["total"] == 25
    assert result["actual_cost_microunits"] <= 926
    assert result["response_content_persisted"] is False
    assert "content" not in result


def _write_sources(tmp_path: Path) -> tuple[Path, Path, str]:
    plan = _plan()
    plan_path = tmp_path / "plan.json"
    write_private_json(plan_path, plan)
    plan_ref = {
        "path": str(plan_path.resolve()),
        "sha256": __import__("hashlib").sha256(plan_path.read_bytes()).hexdigest(),
        "canonical_sha256": plan["plan_sha256"],
    }
    preflight = build_authorization_preflight(
        plan_ref=plan_ref,
        plan=plan,
        created_at="2026-07-31T14:01:00+00:00",
    )
    preflight_path = tmp_path / "preflight.json"
    write_private_json(preflight_path, preflight)
    statement = authorization_statement(
        plan_raw_sha256=plan_ref["sha256"],
        plan=plan,
    )
    return plan_path, preflight_path, statement


def _patch_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "benchmarks.j1_qualification_transport_soak_execute."
        "_clean_pushed_implementation",
        lambda _: IMPLEMENTATION,
    )
    monkeypatch.setattr(
        "benchmarks.j1_qualification_transport_soak_execute._replay_sources",
        lambda _: None,
    )
    monkeypatch.setattr(
        "benchmarks.j1_qualification_transport_soak_execute._read_provider_env",
        lambda *_: "test-key",
    )


def test_transport_soak_executes_64_single_use_calls_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_offline(monkeypatch)
    plan_path, preflight_path, statement = _write_sources(tmp_path)
    gate = execute_soak(
        claimed_at="2026-07-31T14:02:00+00:00",
        authorization_statement_value=statement,
        plan_path=plan_path,
        preflight_path=preflight_path,
        provider_env_path=tmp_path / "provider.env",
        claim_root=tmp_path / "claims",
        output_root=tmp_path / "output",
        repository_root=tmp_path,
        transport_factory=_SuccessfulTransport,
    )
    assert gate["passed"] is True
    report = json.loads(
        (tmp_path / "output" / "transport-admission-soak-report.json").read_bytes()
    )
    assert report["scope"]["provider_dispatch_count"] == 64
    assert report["scope"]["completed_call_count"] == 64
    assert report["scope"]["post_dispatch_retry_count"] == 0
    assert len(report["call_receipts"]) == 64
    assert report["credential"]["value_persisted"] is False


def test_transport_soak_ambiguous_dispatch_stops_and_cannot_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_offline(monkeypatch)
    plan_path, preflight_path, statement = _write_sources(tmp_path)
    kwargs = {
        "claimed_at": "2026-07-31T14:02:00+00:00",
        "authorization_statement_value": statement,
        "plan_path": plan_path,
        "preflight_path": preflight_path,
        "provider_env_path": tmp_path / "provider.env",
        "claim_root": tmp_path / "claims",
        "output_root": tmp_path / "failed-output",
        "repository_root": tmp_path,
        "transport_factory": _AmbiguousTransport,
    }
    gate = execute_soak(**kwargs)
    assert gate["passed"] is False
    report = json.loads(
        (
            tmp_path
            / "failed-output"
            / "transport-admission-soak-report.json"
        ).read_bytes()
    )
    assert report["scope"]["provider_dispatch_count"] == 1
    assert report["scope"]["completed_call_count"] == 0
    assert report["scope"]["provider_outcome_unknown_count"] == 1
    assert report["scope"]["post_dispatch_retry_count"] == 0
    assert report["sanitized_failure"]["retry_performed"] is False

    kwargs["output_root"] = tmp_path / "replay-output"
    with pytest.raises(ValueError, match="already claimed"):
        execute_soak(**kwargs)


def test_transport_soak_connect_exhaustion_stays_pre_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_offline(monkeypatch)
    plan_path, preflight_path, statement = _write_sources(tmp_path)
    gate = execute_soak(
        claimed_at="2026-07-31T14:02:00+00:00",
        authorization_statement_value=statement,
        plan_path=plan_path,
        preflight_path=preflight_path,
        provider_env_path=tmp_path / "provider.env",
        claim_root=tmp_path / "claims",
        output_root=tmp_path / "connect-failed-output",
        repository_root=tmp_path,
        transport_factory=_ConnectExhaustedTransport,
    )
    assert gate["passed"] is False
    report = json.loads(
        (
            tmp_path
            / "connect-failed-output"
            / "transport-admission-soak-report.json"
        ).read_bytes()
    )
    assert report["scope"]["provider_dispatch_count"] == 0
    assert report["scope"]["provider_outcome_unknown_count"] == 0
    assert report["connect_attempt_histogram"] == {"3": 1}
    assert report["sanitized_failure"]["connect_attempt_count"] == 3
    assert report["sanitized_failure"]["dispatch_performed"] is False
