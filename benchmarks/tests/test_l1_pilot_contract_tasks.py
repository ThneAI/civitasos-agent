from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l1_pilot_001_contract_tasks.py"
spec = importlib.util.spec_from_file_location("l1_pilot_001_contract_tasks", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_alpha_payload_has_h3_delivery_contract() -> None:
    payload = module.build_alpha_payload(requester="did:req", alpha_did="did:alpha")

    assert payload["requester"] == "did:req"
    assert payload["allowed_agents"] == ["did:alpha"]
    contract = payload["input"]["delivery_contract"]
    assert contract["h3_must_remain_blocked"] is True
    assert "任务边界" in contract["required_sections"]
    assert "H.3 remains blocked" in payload["input"]["boundary"]


def test_beta_payload_carries_alpha_output_and_replay_guard() -> None:
    payload = module.build_beta_payload(
        requester="did:alpha",
        beta_did="did:beta",
        alpha_task_id="task-alpha",
        alpha_output={"result": "alpha plan"},
    )

    assert payload["requester"] == "did:alpha"
    assert payload["required_capability"] == "implementation"
    assert payload["allowed_agents"] == ["did:beta"]
    assert payload["input"]["upstream_task_id"] == "task-alpha"
    assert payload["input"]["alpha_output"] == '{"result": "alpha plan"}'
    assert payload["input"]["delivery_contract"]["forbid_upstream_replay"] is True
    assert "与上游不同之处" in payload["input"]["delivery_contract"]["required_sections"]


def test_gamma_payload_requires_review_issue_list_and_h3_boundary() -> None:
    payload = module.build_gamma_payload(
        requester="did:beta",
        gamma_did="did:gamma",
        alpha_task_id="task-alpha",
        beta_task_id="task-beta",
        alpha_output="alpha",
        beta_output="beta",
    )

    assert payload["requester"] == "did:beta"
    assert payload["required_capability"] == "review"
    assert payload["allowed_agents"] == ["did:gamma"]
    assert payload["input"]["delivery_contract"]["review_must_have_issue_list"] is True
    assert payload["input"]["delivery_contract"]["h3_must_remain_blocked"] is True
    assert "通过/不通过" in payload["input"]["delivery_contract"]["required_sections"]
