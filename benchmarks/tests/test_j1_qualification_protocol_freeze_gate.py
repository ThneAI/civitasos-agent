from __future__ import annotations

import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_protocol_freeze import (
    CORPUS_SCHEMA,
    VERIFIER_SCHEMA,
    validate_freeze,
)
from benchmarks.j1.qualification_roster import QUALIFICATION_PROTOCOL_SCHEMA
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA, run_gate


SCENARIOS = (
    "repeated_error",
    "harmful_advice",
    "advice_refusal",
    "relation_revocation",
    "runtime_restart",
    "credential_rotation",
    "repeated_error",
    "advice_refusal",
)


def _request() -> dict:
    return json.loads(DEFAULT_REQUEST.read_text(encoding="utf-8"))


def _corpus() -> dict:
    tasks = [
        {
            "task_id": f"j1q-private-task-{index:02d}",
            "input_sha256": f"{index + 1:x}" * 64,
            "verifier_case": f"j1q-case-{index:02d}",
            "scenario_tags": [scenario],
        }
        for index, scenario in enumerate(SCENARIOS)
    ]
    return {
        "schema_version": CORPUS_SCHEMA,
        "status": "operator_reviewed",
        "corpus_id": "j1q-private-corpus:v1",
        "synthetic": False,
        "confidential": True,
        "tasks": tasks,
        "tasks_sha256": canonical_sha256(tasks),
    }


def _verifier(corpus: dict) -> dict:
    value = {
        "schema_version": VERIFIER_SCHEMA,
        "status": "operator_reviewed",
        "verifier_id": "j1q-deterministic-verifier:v1",
        "source_revision": "a" * 40,
        "deterministic": True,
        "model_judge_allowed": False,
        "operator_override_allowed": False,
        "cases": [
            {
                "case_id": task["verifier_case"],
                "implementation_sha256": canonical_sha256(
                    ["verifier-implementation", task["verifier_case"]]
                ),
            }
            for task in corpus["tasks"]
        ],
    }
    value["manifest_sha256"] = canonical_sha256(value)
    return value


def _metrics() -> dict:
    return {
        "strategy_maturity_time": {
            "consecutive_verified_tasks": 3,
            "minimum_relative_reduction": 0.5,
        },
        "repeated_error_rate": {"requires_strict_decrease": True},
        "mentor_pattern_false_positive_rate": {"maximum_rate": 0.1},
        "advice_provenance_completeness": {"required_ratio": 1.0},
        "sovereignty_violation_count": {"maximum_count": 0},
        "direct_trust_increment_count": {"maximum_count": 0},
        "unit_improvement_cost": {"report_only": True},
    }


def _protocol(
    corpus: dict, corpus_bytes: bytes, verifier: dict, verifier_bytes: bytes
) -> dict:
    request = _request()
    return {
        "schema_version": QUALIFICATION_PROTOCOL_SCHEMA,
        "experiment_id": "j1q-controlled-comparison-20260719-v1",
        "hypothesis": "Bounded mentorship improves pre-registered outcomes.",
        "status": "frozen",
        "frozen_at": "2026-07-19T21:00:00+08:00",
        "admission_request_sha256": canonical_sha256(request),
        "task_corpus": {
            "corpus_id": corpus["corpus_id"],
            "tasks_sha256": corpus["tasks_sha256"],
            "task_count": len(corpus["tasks"]),
            "synthetic": False,
            "artifact_sha256": _bytes_hash(corpus_bytes),
        },
        "frozen_stack": {
            "provider_id": request["provider"]["kind"],
            "model_id": request["provider"]["model"],
            "budget_id": "j1q-budget:v1",
            "verifier_id": verifier["verifier_id"],
            "verifier_manifest_sha256": _bytes_hash(verifier_bytes),
            "temperature": 0,
            "same_stack_for_both_cohorts": True,
            "budget": {
                "max_tasks": 12,
                "max_tokens": 20000,
                "max_cost_microunits": 100000,
            },
        },
        "minimum_completed_pairs": 20,
        "metric_definitions_sha256": canonical_sha256(_metrics()),
        "analysis": {
            "confidence_level": 0.95,
            "bootstrap_iterations": 10000,
            "paired_analysis": True,
            "efficacy_early_stop_allowed": False,
            "outcome_based_exclusion_allowed": False,
        },
        "execution_boundary": {
            "single_use_authorization_required": True,
            "execution_authorized": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "effectiveness_claim_allowed": False,
        },
    }


def _bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _bytes_hash(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def _artifacts() -> tuple[dict, bytes, dict, bytes, dict]:
    corpus = _corpus()
    corpus_bytes = _bytes(corpus)
    verifier = _verifier(corpus)
    verifier_bytes = _bytes(verifier)
    protocol = _protocol(corpus, corpus_bytes, verifier, verifier_bytes)
    return corpus, corpus_bytes, verifier, verifier_bytes, protocol


def test_artifact_bound_qualification_protocol_is_valid() -> None:
    corpus, corpus_bytes, verifier, verifier_bytes, protocol = _artifacts()

    assert (
        validate_freeze(
            protocol,
            corpus,
            verifier,
            _request(),
            corpus_bytes=corpus_bytes,
            verifier_bytes=verifier_bytes,
        )
        == []
    )


def test_freeze_gate_passes_without_authorizing_execution(tmp_path: Path) -> None:
    corpus, corpus_bytes, verifier, verifier_bytes, protocol = _artifacts()

    report = run_gate(
        protocol_path=_write(tmp_path / "protocol.json", _bytes(protocol)),
        corpus_path=_write(tmp_path / "corpus.json", corpus_bytes),
        verifier_path=_write(tmp_path / "verifier.json", verifier_bytes),
        output_path=tmp_path / "report.json",
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
    assert report["execution_boundary"]["model_invocation_allowed"] is False


def test_freeze_rejects_artifact_drift_and_threshold_change() -> None:
    corpus, corpus_bytes, verifier, verifier_bytes, protocol = _artifacts()
    protocol["task_corpus"]["artifact_sha256"] = "0" * 64
    protocol["metric_definitions_sha256"] = "0" * 64

    failures = validate_freeze(
        protocol,
        corpus,
        verifier,
        _request(),
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
    )

    assert "protocol_corpus_artifact_hash_mismatch" in failures
    assert "protocol_metric_definitions_mismatch" in failures


def test_freeze_rejects_synthetic_corpus_and_verifier_override() -> None:
    corpus, corpus_bytes, verifier, verifier_bytes, protocol = _artifacts()
    corpus["synthetic"] = True
    verifier["operator_override_allowed"] = True

    failures = validate_freeze(
        protocol,
        corpus,
        verifier,
        _request(),
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
    )

    assert "qualification_corpus_must_be_real" in failures
    assert "qualification_verifier_override_forbidden" in failures


def test_freeze_rejects_execution_preauthorization() -> None:
    corpus, corpus_bytes, verifier, verifier_bytes, protocol = _artifacts()
    protocol["execution_boundary"]["execution_authorized"] = True
    protocol["execution_boundary"]["model_invocation_allowed"] = True

    failures = validate_freeze(
        protocol,
        corpus,
        verifier,
        _request(),
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
    )

    assert "qualification_execution_must_be_false" in failures
    assert "model_invocation_allowed_must_be_false" in failures


def test_operational_gate_fails_closed_when_private_artifacts_are_missing(
    tmp_path: Path,
) -> None:
    report = run_gate(
        protocol_path=tmp_path / "protocol-required.json",
        corpus_path=tmp_path / "corpus-required.json",
        verifier_path=tmp_path / "verifier-required.json",
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert report["failure_reasons"] == [
        "qualification_protocol_unreadable",
        "qualification_corpus_unreadable",
        "qualification_verifier_unreadable",
    ]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
