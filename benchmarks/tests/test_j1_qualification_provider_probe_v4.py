from __future__ import annotations

import copy
import json

from benchmarks.j1.qualification_provider_probe_v4 import (
    PROBE_BOUNDARY,
    build_claim,
    build_receipt,
    normalize_response,
    validate_receipt,
)
from benchmarks.tests.test_j1_qualification_provider_admission_v4 import _plan


def _ref(name: str) -> dict[str, str]:
    return {
        "path": f"/private/{name}.json",
        "sha256": name[0] * 64,
        "canonical_sha256": name[-1] * 64,
    }


def _response() -> bytes:
    return json.dumps(
        {
            "id": "response-1",
            "model": "deepseek-v4-pro",
            "choices": [{"message": {"content": "ADMITTED."}}],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 2,
                "total_tokens": 14,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 12,
            },
        }
    ).encode()


def test_r4_probe_normalizes_usage_cost_and_builds_receipt() -> None:
    plan = _plan()
    result = normalize_response(status=200, body=_response(), plan=plan)
    inventory = {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }
    receipt = build_receipt(
        probe_id="probe-r1",
        completed_at="2026-07-25T12:00:00+08:00",
        authorization_statement_sha256="a" * 64,
        claim_ref=_ref("claim"),
        plan_ref=_ref("plan"),
        preflight_ref=_ref("preflight"),
        plan=plan,
        provider_result=result,
        inventory_before=inventory,
        inventory_after=inventory,
        credential_basename=".env.test",
        implementation={"source_revision": "b" * 40},
    )

    assert (
        validate_receipt(
            receipt, plan=plan, expected_authorization_sha256="a" * 64
        )
        == []
    )
    assert receipt["budget"]["actual_cost_microunits"] <= 926
    assert receipt["execution_boundary"] == PROBE_BOUNDARY


def test_r4_probe_claim_is_single_use_and_stack_bound() -> None:
    plan = _plan()
    claim = build_claim(
        probe_id="probe-r1",
        claimed_at="2026-07-25T12:00:00+08:00",
        authorization_statement_sha256="a" * 64,
        plan_ref=_ref("plan"),
        preflight_ref=_ref("preflight"),
        output_root_sha256="b" * 64,
        plan=plan,
    )

    assert claim["single_use"] is True
    assert claim["claim_must_survive_probe_failure"] is True
    assert claim["frozen_r4_stack_sha256"] == plan["frozen_r4_stack_sha256"]


def test_r4_probe_receipt_rejects_inventory_or_boundary_tamper() -> None:
    plan = _plan()
    result = normalize_response(status=200, body=_response(), plan=plan)
    inventory = {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }
    receipt = build_receipt(
        probe_id="probe-r1",
        completed_at="2026-07-25T12:00:00+08:00",
        authorization_statement_sha256="a" * 64,
        claim_ref=_ref("claim"),
        plan_ref=_ref("plan"),
        preflight_ref=_ref("preflight"),
        plan=plan,
        provider_result=result,
        inventory_before=inventory,
        inventory_after=inventory,
        credential_basename=".env.test",
        implementation={"source_revision": "b" * 40},
    )
    tampered = copy.deepcopy(receipt)
    tampered["inventory"]["after"]["running_count"] = 1
    tampered["execution_boundary"]["participant_container_started"] = True

    failures = validate_receipt(
        tampered, plan=plan, expected_authorization_sha256="a" * 64
    )
    assert "r4_probe_receipt_inventory_invalid" in failures
    assert "r4_probe_receipt_secret_or_boundary_invalid" in failures
