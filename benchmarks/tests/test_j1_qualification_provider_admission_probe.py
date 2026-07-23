from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import benchmarks.j1_qualification_provider_admission_probe as probe_operation
from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_provider_admission_probe import (
    PROBE_BOUNDARY,
    build_claim,
    build_probe_receipt,
    normalize_probe_response,
    validate_probe_receipt,
    validate_probe_sources,
)
from benchmarks.j1.qualification_provider_admission_refresh import (
    PREFLIGHT_SCHEMA,
    probe_authorization_statement,
)
from benchmarks.tests.test_j1_qualification_provider_admission_refresh import (
    _plan,
)


NOW = "2026-07-23T22:00:00+08:00"
API_KEY = "private-test-provider-key"


def _artifacts(tmp_path: Path) -> tuple[dict, Path, dict, Path, str]:
    plan = _plan()
    plan_path = tmp_path / "plan.json"
    write_private_json(plan_path, plan)
    plan_raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    statement = probe_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan_canonical_sha256=plan["plan_sha256"],
        provider_id=plan["frozen_stack"]["provider_id"],
        base_url=plan["frozen_stack"]["base_url"],
        model_id=plan["frozen_stack"]["model_id"],
        request_body_sha256=plan["probe_contract"]["request_body_sha256"],
        maximum_cost_microunits=plan["pricing_and_budget"]["maximum_cost_microunits"],
        max_input_tokens=plan["probe_contract"]["max_input_tokens"],
        max_output_tokens=plan["probe_contract"]["max_output_tokens"],
    )
    preflight = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "provider_admission_refresh_candidate_ready_owner_authorization_required"
        ),
        "plan": {
            "path": str(plan_path),
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        },
        "owner_authorization": {
            "required": True,
            "statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "offline_preflight_complete": True,
            "owner_probe_authorization_required": True,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
    }
    preflight["preflight_sha256"] = canonical_sha256(preflight)
    preflight_path = tmp_path / "preflight.json"
    write_private_json(preflight_path, preflight)
    return plan, plan_path, preflight, preflight_path, statement


def _provider_body(*, model: str = "deepseek-v4-pro", output: int = 2) -> bytes:
    return json.dumps(
        {
            "id": "provider-response-1",
            "model": model,
            "choices": [{"message": {"content": "ADMITTED"}}],
            "usage": {
                "prompt_tokens": 7,
                "completion_tokens": output,
                "total_tokens": 7 + output,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 7,
            },
        }
    ).encode()


def _inventory() -> dict:
    return {
        "participant_count": 40,
        "container_count": 40,
        "created_count": 40,
        "running_count": 0,
        "container_set_sha256": "a" * 64,
        "container_details_persisted": False,
    }


def test_probe_source_requires_exact_generated_authorization(tmp_path: Path) -> None:
    plan, plan_path, preflight, _, statement = _artifacts(tmp_path)
    raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()

    assert (
        validate_probe_sources(
            plan=plan,
            plan_raw_sha256=raw_sha256,
            preflight=preflight,
            authorization_statement=statement,
        )
        == []
    )
    assert "probe_owner_authorization_mismatch" in validate_probe_sources(
        plan=plan,
        plan_raw_sha256=raw_sha256,
        preflight=preflight,
        authorization_statement=f"{statement} expanded",
    )


def test_probe_response_enforces_model_usage_and_cost_ceiling() -> None:
    plan = _plan()

    result = normalize_probe_response(
        status=200,
        body=_provider_body(),
        plan=plan,
    )

    assert result["response_model"] == "deepseek-v4-pro"
    assert result["usage"]["total"] == 9
    assert result["actual_cost_microunits"] == 5
    assert result["content_sha256"] == hashlib.sha256(b"ADMITTED").hexdigest()
    assert "ADMITTED" not in str(result)

    with pytest.raises(ValueError, match="model mismatch"):
        normalize_probe_response(
            status=200,
            body=_provider_body(model="other-model"),
            plan=plan,
        )
    with pytest.raises(ValueError, match="token reservation"):
        normalize_probe_response(
            status=200,
            body=_provider_body(output=1001),
            plan=plan,
        )


def test_failed_transport_diagnostics_hash_null_content_without_persisting_body() -> (
    None
):
    body = json.dumps(
        {
            "id": "provider-response-1",
            "model": "deepseek-v4-pro",
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": None, "reasoning_content": "private"},
                }
            ],
            "usage": {
                "prompt_tokens": 7,
                "completion_tokens": 8,
                "total_tokens": 15,
            },
        }
    ).encode()

    evidence = probe_operation._sanitized_transport_evidence(status=200, body=body)

    assert evidence["content_kind"] == "null"
    assert evidence["content_sha256"] == hashlib.sha256(b"null").hexdigest()
    assert evidence["usage"]["completion_tokens"] == 8
    assert "private" not in str(evidence)


def test_probe_receipt_rejects_inventory_or_boundary_expansion() -> None:
    plan = _plan()
    authorization_sha256 = "b" * 64
    result = normalize_probe_response(status=200, body=_provider_body(), plan=plan)
    receipt = build_probe_receipt(
        probe_id="probe-r1",
        completed_at=NOW,
        authorization_statement_sha256=authorization_sha256,
        claim_raw_sha256="c" * 64,
        claim_canonical_sha256="d" * 64,
        plan=plan,
        plan_raw_sha256="e" * 64,
        preflight_raw_sha256="f" * 64,
        provider_result=result,
        inventory_before=_inventory(),
        inventory_after=_inventory(),
        implementation={"source_revision": "1" * 40},
        credential_basename=".private.env",
    )

    assert (
        validate_probe_receipt(
            receipt,
            plan=plan,
            expected_authorization_sha256=authorization_sha256,
        )
        == []
    )
    tampered = copy.deepcopy(receipt)
    tampered["inventory"]["after"]["running_count"] = 1
    tampered["inventory"]["unchanged"] = False
    tampered["execution_boundary"]["participant_container_started"] = True
    tampered["receipt_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "receipt_sha256"}
    )
    failures = validate_probe_receipt(
        tampered,
        plan=plan,
        expected_authorization_sha256=authorization_sha256,
    )
    assert "probe_receipt_inventory_invalid" in failures
    assert "probe_receipt_boundary_invalid" in failures


def test_probe_claim_binds_reservation_and_output() -> None:
    plan = _plan()
    claim = build_claim(
        probe_id="probe-r1",
        claimed_at=NOW,
        authorization_statement_sha256="1" * 64,
        plan_raw_sha256="2" * 64,
        plan_canonical_sha256=plan["plan_sha256"],
        preflight_raw_sha256="3" * 64,
        preflight_canonical_sha256="4" * 64,
        output_root_sha256="5" * 64,
        plan=plan,
    )

    assert claim["single_use"] is True
    assert claim["claim_must_survive_probe_failure"] is True
    assert claim["reservation"] == {
        "call_count": 1,
        "max_input_tokens": 128,
        "max_output_tokens": 1000,
        "max_total_tokens": 1128,
        "max_cost_microunits": 926,
    }
    assert claim["claim_sha256"] == canonical_sha256(
        {key: item for key, item in claim.items() if key != "claim_sha256"}
    )


def test_complete_probe_claims_once_and_never_persists_content_or_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _, plan_path, _, preflight_path, statement = _artifacts(tmp_path)
    env_path = tmp_path / ".provider.env"
    env_path.write_text(
        "\n".join(
            [
                "BETA6_EXTERNAL_AGENT_PROVIDER=openai_compatible",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://api.deepseek.com",
                "BETA6_EXTERNAL_AGENT_MODEL=deepseek-v4-pro",
                f"BETA6_EXTERNAL_AGENT_API_KEY={API_KEY}",
            ]
        )
        + "\n"
    )
    env_path.chmod(0o600)
    monkeypatch.setattr(
        probe_operation,
        "_replay_plan_sources",
        lambda _plan: {"infrastructure": {}, "activation": {}},
    )
    monkeypatch.setattr(
        probe_operation,
        "_inspect_current_inventory",
        lambda **_kwargs: (_inventory(), []),
    )
    monkeypatch.setattr(
        probe_operation,
        "_implementation",
        lambda *_args, **_kwargs: {
            "source_revision": "1" * 40,
            "plan_source_revision": "2" * 40,
            "domain_source_sha256": "3" * 64,
            "operation_source_sha256": "4" * 64,
        },
    )
    calls = []

    def transport(url: str, api_key: str, body: dict) -> tuple[int, bytes]:
        calls.append((url, api_key, body))
        return 200, _provider_body()

    claim_root = tmp_path / "claims"
    output_root = tmp_path / "output"
    report = probe_operation.execute_probe(
        probe_id="probe-r1",
        claimed_at=NOW,
        authorization_statement=statement,
        plan_path=plan_path,
        preflight_path=preflight_path,
        provider_env_path=env_path,
        claim_root=claim_root,
        output_root=output_root,
        repository_root=tmp_path,
        transport=transport,
    )

    assert report["passed"] is True
    assert report["execution_boundary"] == PROBE_BOUNDARY
    assert len(calls) == 1
    persisted = "\n".join(
        path.read_text() for path in [*claim_root.iterdir(), *output_root.iterdir()]
    )
    assert API_KEY not in persisted
    assert "ADMITTED" not in persisted

    with pytest.raises(ValueError, match="already claimed"):
        probe_operation.execute_probe(
            probe_id="probe-r2",
            claimed_at=NOW,
            authorization_statement=statement,
            plan_path=plan_path,
            preflight_path=preflight_path,
            provider_env_path=env_path,
            claim_root=claim_root,
            output_root=tmp_path / "second-output",
            repository_root=tmp_path,
            transport=transport,
        )
    assert len(calls) == 1
