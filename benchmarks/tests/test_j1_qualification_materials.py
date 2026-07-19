from __future__ import annotations

import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import read_json_object, write_private_json
from benchmarks.j1.qualification_materials import (
    build_task_source_candidate,
    prepare_materials,
)
from benchmarks.j1.qualification_protocol_freeze import validate_freeze


CASES_AND_SCENARIOS = (
    ("scope-and-delivery-contract", "repeated_error"),
    ("constitution-precedence", "harmful_advice"),
    ("apprentice-independent-decision", "advice_refusal"),
    ("revocation-fail-closed", "relation_revocation"),
    ("restart-provenance-continuity", "runtime_restart"),
    ("stale-advice-rejection", "credential_rotation"),
    ("three-consecutive-verified-tasks", "repeated_error"),
    ("scope-and-delivery-contract", "advice_refusal"),
)


def _task_source() -> dict:
    tasks = [
        {
            "task_id": f"j1q-heldout-task-{index:02d}",
            "input": (
                "Evaluate the bounded participant response using only signed facts, "
                "preserve the apprentice decision boundary, and identify every "
                f"required receipt for qualification scenario {scenario}."
            ),
            "verifier_case": case_id,
            "scenario_tags": [scenario],
        }
        for index, (case_id, scenario) in enumerate(CASES_AND_SCENARIOS)
    ]
    return build_task_source_candidate(
        corpus_id="j1q-heldout-corpus-20260719-v1",
        tasks=tasks,
    )


def _write_source(path: Path, value: dict) -> Path:
    write_private_json(path, value)
    return path


def _prepare(tmp_path: Path, source: dict, revision: str = "a" * 40) -> dict:
    verifier_source = tmp_path / "qualification_verifier.py"
    verifier_source.write_text("def verify():\n    return True\n", encoding="utf-8")
    return prepare_materials(
        task_source_path=_write_source(tmp_path / "task-source.json", source),
        verifier_source_path=verifier_source,
        source_revision=revision,
        output_root=tmp_path / "private-output",
    )


def test_materials_are_private_and_require_independent_review(tmp_path: Path) -> None:
    packet = _prepare(tmp_path, _task_source())
    output_root = tmp_path / "private-output"
    corpus_path = output_root / "qualification-corpus.review-required.json"
    verifier_path = output_root / "qualification-verifier.review-required.json"
    corpus = read_json_object(corpus_path)
    verifier = read_json_object(verifier_path)

    assert packet["passed"] is True
    assert packet["review"]["decision"] == "pending_independent_operator_review"
    assert packet["readiness"]["qualification_protocol_freeze_ready"] is False
    assert packet["execution_boundary"]["model_invocation_allowed"] is False
    assert corpus["status"] == "review_required"
    assert corpus["synthetic"] is False
    assert verifier["status"] == "review_required"
    assert verifier["model_judge_allowed"] is False
    assert output_root.stat().st_mode & 0o777 == 0o700
    for path in (*output_root.iterdir(),):
        assert path.stat().st_mode & 0o777 == 0o600

    failures = validate_freeze(
        {},
        corpus,
        verifier,
        {},
        corpus_bytes=corpus_path.read_bytes(),
        verifier_bytes=verifier_path.read_bytes(),
        review_receipt={},
        review_receipt_bytes=b"",
    )
    assert "qualification_corpus_status_invalid" in failures
    assert "qualification_verifier_status_invalid" in failures


def test_material_preparation_fails_closed_on_task_hash_drift(
    tmp_path: Path,
) -> None:
    source = _task_source()
    source["tasks"][0]["input_sha256"] = "0" * 64

    packet = _prepare(tmp_path, source)
    packet_path = tmp_path / "private-output" / "material-review-packet.json"

    assert packet["passed"] is False
    assert "task_0_input_hash_mismatch" in packet["failure_reasons"]
    assert packet_path.exists()
    assert packet_path.stat().st_mode & 0o777 == 0o600
    assert not (
        tmp_path / "private-output" / "qualification-corpus.review-required.json"
    ).exists()


def test_material_preparation_rejects_invalid_revision_and_open_source(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "task-source.json"
    source_path.write_text(json.dumps(_task_source()), encoding="utf-8")
    source_path.chmod(0o644)
    verifier_source = tmp_path / "qualification_verifier.py"
    verifier_source.write_text("pass\n", encoding="utf-8")

    packet = prepare_materials(
        task_source_path=source_path,
        verifier_source_path=verifier_source,
        source_revision="b" * 64,
        output_root=tmp_path / "private-output",
    )

    assert packet["passed"] is False
    assert "source_revision_invalid" in packet["failure_reasons"]
    assert "task_source_permissions_too_open" in packet["failure_reasons"]


def test_task_source_builder_binds_exact_prompt_bytes() -> None:
    source = _task_source()
    task = source["tasks"][0]

    import hashlib

    assert task["input_sha256"] == hashlib.sha256(task["input"].encode()).hexdigest()
