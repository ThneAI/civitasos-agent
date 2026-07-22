from __future__ import annotations

import copy

from benchmarks.j1.qualification_cohort_amendment import (
    build_amendment_bundle,
    build_design_amendment,
    build_protocol_amendment,
    validate_amendment_bundle,
    validate_design_amendment,
    validate_protocol_amendment,
)
from benchmarks.tests.test_j1_qualification_cohort_migration import _plan, _sources


NOW = "2026-07-23T06:10:00+08:00"
SOURCE_BINDING = {"reviewed_migration_plan_artifact_sha256": "a" * 64}
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}


def _inputs() -> tuple[dict, dict, dict, dict, dict]:
    _, design, _, advice, verifier = _sources()
    plan, _ = _plan()
    plan["status"] = "operator_reviewed"
    plan["reviewed_plan_sha256"] = "d" * 64
    protocol = {
        "experiment_id": "j1d-experiment",
        "hypothesis": "mentor advice improves verified outcomes",
        "analysis": {"paired_analysis": True},
        "minimum_completed_pairs": 20,
        "metric_definitions_sha256": "e" * 64,
        "task_corpus": {
            "corpus_id": "j1q-heldout-corpus-20260719-v1",
            "tasks_sha256": "f" * 64,
            "task_count": 8,
        },
        "frozen_stack": {
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
            "verifier_id": "j1q-deterministic-verifier:v1",
            "verifier_manifest_sha256": "1" * 64,
        },
    }
    corpus = {
        "corpus_id": "j1q-heldout-corpus-20260719-v1",
        "tasks_sha256": "f" * 64,
    }
    design["reviewed_design_sha256"] = "2" * 64
    advice["manifest_sha256"] = "3" * 64
    return protocol, design, corpus, verifier, {**advice, "status": "signed"}


def _materials() -> tuple[dict, dict, dict, dict]:
    protocol, design, corpus, verifier, advice = _inputs()
    plan, _ = _plan()
    plan["status"] = "operator_reviewed"
    plan["reviewed_plan_sha256"] = "d" * 64
    protocol_inputs = {
        "created_at": NOW,
        "source_binding": SOURCE_BINDING,
        "base_protocol": protocol,
        "reviewed_corpus_v2": corpus,
        "reviewed_verifier_v2": verifier,
        "reviewed_migration_plan": plan,
    }
    design_inputs = {
        "created_at": NOW,
        "source_binding": SOURCE_BINDING,
        "base_reviewed_design": design,
        "signed_advice_manifest": advice,
        "reviewed_migration_plan": plan,
    }
    protocol_amendment = build_protocol_amendment(**protocol_inputs)
    design_amendment = build_design_amendment(**design_inputs)
    return protocol_amendment, design_amendment, protocol_inputs, design_inputs


def test_amendment_materials_preserve_base_and_require_new_consent() -> None:
    protocol, design, protocol_inputs, design_inputs = _materials()

    assert validate_protocol_amendment(protocol, **protocol_inputs) == []
    assert validate_design_amendment(design, **design_inputs) == []
    assert protocol["amended_frozen_stack"]["verifier_id"].endswith(":v2")
    assert protocol["consent_contract"]["prior_consent_inherited"] is False
    assert all(
        task["control"]["advice_projection"] == []
        and task["mentor"]["base_event_script_unchanged"] is True
        for task in design["task_contracts"]
    )
    plan = protocol_inputs["reviewed_migration_plan"]
    bundle_inputs = {
        "created_at": NOW,
        "source_binding": SOURCE_BINDING,
        "protocol_amendment_artifact": {"path": "/private/protocol", "sha256": "4" * 64},
        "protocol_amendment": protocol,
        "design_amendment_artifact": {"path": "/private/design", "sha256": "5" * 64},
        "design_amendment": design,
        "reviewed_migration_plan": plan,
        "implementation": IMPLEMENTATION,
    }
    bundle = build_amendment_bundle(**bundle_inputs)
    assert validate_amendment_bundle(bundle, **bundle_inputs) == []
    assert bundle["blockers"] == [
        "participant_consent_extension_required",
        "roster_assignment_infrastructure_rebind_required",
    ]


def test_design_amendment_rejects_control_advice_injection() -> None:
    _, design, _, design_inputs = _materials()
    tampered = copy.deepcopy(design)
    tampered["task_contracts"][0]["control"]["advice_projection"] = ["forbidden"]

    failures = validate_design_amendment(tampered, **design_inputs)

    assert "design_amendment_cohort_contract_invalid" in failures
    assert "design_amendment_copy_on_write_binding_invalid" in failures
