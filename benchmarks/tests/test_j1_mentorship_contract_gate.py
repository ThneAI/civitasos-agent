from __future__ import annotations

import copy
import json
from pathlib import Path

from benchmarks.j1.contracts import canonical_sha256, validate_bundle
from benchmarks.j1_mentorship_contract_gate import DEFAULT_BUNDLE, REPORT_SCHEMA, run_gate


def _bundle() -> dict:
    return json.loads(DEFAULT_BUNDLE.read_text(encoding="utf-8"))


def test_fixture_contract_is_valid_and_hash_is_canonical() -> None:
    bundle = _bundle()

    assert validate_bundle(bundle) == []
    reordered = dict(reversed(list(bundle.items())))
    assert canonical_sha256(bundle) == canonical_sha256(reordered)


def test_contract_rejects_raw_memory_and_direct_execution() -> None:
    bundle = _bundle()
    bundle["relation"]["memory_projection"]["raw_memory_access_allowed"] = True
    bundle["advice"]["boundary"]["direct_execution_allowed"] = True

    failures = validate_bundle(bundle)

    assert "raw_memory_access_must_be_false" in failures
    assert "advice_direct_execution_allowed_must_be_false" in failures


def test_contract_rejects_mentor_decision_and_causal_claim() -> None:
    bundle = _bundle()
    bundle["decision"]["decided_by"] = bundle["relation"]["mentor_did"]
    bundle["outcome"]["attribution"] = {
        "mode": "causal",
        "causal_claim_allowed": True,
    }

    failures = validate_bundle(bundle)

    assert "decision_actor_must_be_apprentice" in failures
    assert "outcome_causal_claim_must_be_false" in failures
    assert "outcome_attribution_mode_invalid" in failures


def test_contract_rejects_reference_drift() -> None:
    bundle = _bundle()
    bundle["advice"]["observation_id"] = "mentor-observation:other"
    bundle["outcome"]["decision_id"] = "advice-decision:other"

    failures = validate_bundle(bundle)

    assert "advice_observation_mismatch" in failures
    assert "outcome_decision_mismatch" in failures


def test_gate_passes_all_negative_controls_without_execution(tmp_path: Path) -> None:
    output = tmp_path / "j1a_contract_gate_report.json"

    report = run_gate(bundle_path=DEFAULT_BUNDLE, output_path=output)

    assert report["schema_version"] == REPORT_SCHEMA
    assert report["passed"] is True
    assert report["failure_reasons"] == []
    assert len(report["negative_controls"]) == 8
    assert all(item["rejected"] is True for item in report["negative_controls"])
    assert report["readiness"] == {
        "j1_contracts_complete": True,
        "state": "j1_contracts_validated_not_started",
        "ready_for_j1_backend_fact_implementation": True,
        "mentorship_runtime_ready": False,
        "j1_controlled_experiment_ready": False,
    }
    assert all(
        value is False
        for key, value in report["execution_boundary"].items()
        if key != "contract_fixture_only"
    )
    assert output.stat().st_mode & 0o777 == 0o600


def test_gate_fails_closed_on_invalid_bundle(tmp_path: Path) -> None:
    bundle = copy.deepcopy(_bundle())
    bundle["execution_boundary"]["fact_append_allowed"] = True
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps(bundle), encoding="utf-8")

    report = run_gate(
        bundle_path=source,
        output_path=tmp_path / "invalid-report.json",
    )

    assert report["passed"] is False
    assert "fact_append_allowed_must_be_false" in report["failure_reasons"]


def test_gate_fails_closed_when_bundle_is_missing(tmp_path: Path) -> None:
    report = run_gate(
        bundle_path=tmp_path / "missing.json",
        output_path=tmp_path / "missing-report.json",
    )

    assert report["passed"] is False
    assert "contract_bundle_missing" in report["failure_reasons"]
    assert "bundle_must_not_be_empty" in report["failure_reasons"]
    assert report["negative_controls"] == []
