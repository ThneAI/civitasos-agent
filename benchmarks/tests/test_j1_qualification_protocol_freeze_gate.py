from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_material_review import promote_reviewed_materials
from benchmarks.j1.qualification_protocol_freeze import (
    CORPUS_SCHEMA,
    LEGACY_VERIFIER_SCHEMA,
    build_qualification_protocol,
    validate_freeze,
)
from benchmarks.j1.qualification_review_receipt import (
    FALSE_BOUNDARIES,
    REQUIRED_CHECKS,
    REVIEW_RECEIPT_SCHEMA,
    review_signature_payload,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA, run_gate
from benchmarks.j1_qualification_protocol import prepare_qualification_protocol


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
IMPLEMENTATION_SHA256 = "b" * 64
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


def _candidate_corpus() -> dict:
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
        "status": "review_required",
        "corpus_id": "j1q-private-corpus:v1",
        "synthetic": False,
        "confidential": True,
        "tasks": tasks,
        "tasks_sha256": canonical_sha256(tasks),
    }


def _candidate_verifier(corpus: dict) -> dict:
    value = {
        "schema_version": LEGACY_VERIFIER_SCHEMA,
        "status": "review_required",
        "verifier_id": "j1q-deterministic-verifier:v1",
        "source_revision": "a" * 40,
        "deterministic": True,
        "model_judge_allowed": False,
        "operator_override_allowed": False,
        "cases": [
            {
                "case_id": task["verifier_case"],
                "implementation_sha256": IMPLEMENTATION_SHA256,
            }
            for task in corpus["tasks"]
        ],
    }
    value["manifest_sha256"] = canonical_sha256(value)
    return value


def _review_receipt(
    corpus: dict,
    corpus_bytes: bytes,
    verifier: dict,
    verifier_bytes: bytes,
) -> dict:
    signing_key = SigningKey.generate()
    public_key_hex = signing_key.verify_key.encode().hex()
    receipt = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": "j1q-material-review-20260719-alpha",
        "review_request_sha256": "e" * 64,
        "reviewer": {
            "did": _did(public_key_hex),
            "public_key_hex": public_key_hex,
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "custody_provenance_sha256": "c" * 64,
            "signer_attestation_sha256": "d" * 64,
        },
        "decision": "approve_qualification_materials",
        "reviewed_at": "2026-07-19T21:00:00+08:00",
        "independence": {
            "independent_from_authoring": True,
            "conflicts_disclosed": True,
            "ai_assisted_authoring_disclosed": True,
        },
        "review_scope": {
            "corpus_artifact_sha256": _bytes_hash(corpus_bytes),
            "corpus_id": corpus["corpus_id"],
            "corpus_tasks_sha256": corpus["tasks_sha256"],
            "verifier_artifact_sha256": _bytes_hash(verifier_bytes),
            "verifier_id": verifier["verifier_id"],
            "verifier_implementation_sha256": IMPLEMENTATION_SHA256,
            "verifier_manifest_sha256": verifier["manifest_sha256"],
            "verifier_source_revision": verifier["source_revision"],
        },
        "checklist": {name: True for name in sorted(REQUIRED_CHECKS)},
        "execution_boundary": {name: False for name in sorted(FALSE_BOUNDARIES)},
    }
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": _bytes_hash(payload),
        "signature_hex": signing_key.sign(payload).signature.hex(),
    }
    return receipt


def _protocol(
    corpus: dict,
    corpus_bytes: bytes,
    verifier: dict,
    verifier_bytes: bytes,
    receipt: dict,
    receipt_bytes: bytes,
) -> dict:
    request = _request()
    return build_qualification_protocol(
        experiment_id="j1q-controlled-comparison-20260719-v1",
        hypothesis="Bounded mentorship improves pre-registered outcomes.",
        budget_id="j1q-budget:v1",
        frozen_at="2026-07-19T21:00:00+08:00",
        corpus=corpus,
        verifier=verifier,
        admission_request=request,
        review_receipt=receipt,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        review_receipt_bytes=receipt_bytes,
    )


def _bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _bytes_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _artifacts() -> dict:
    candidate_corpus = _candidate_corpus()
    candidate_corpus_bytes = _bytes(candidate_corpus)
    candidate_verifier = _candidate_verifier(candidate_corpus)
    candidate_verifier_bytes = _bytes(candidate_verifier)
    receipt = _review_receipt(
        candidate_corpus,
        candidate_corpus_bytes,
        candidate_verifier,
        candidate_verifier_bytes,
    )
    receipt_bytes = _bytes(receipt)
    corpus, verifier = promote_reviewed_materials(
        corpus=candidate_corpus,
        verifier=candidate_verifier,
        review_receipt_bytes=receipt_bytes,
    )
    corpus_bytes = _bytes(corpus)
    verifier_bytes = _bytes(verifier)
    protocol = _protocol(
        corpus,
        corpus_bytes,
        verifier,
        verifier_bytes,
        receipt,
        receipt_bytes,
    )
    return {
        "corpus": corpus,
        "corpus_bytes": corpus_bytes,
        "verifier": verifier,
        "verifier_bytes": verifier_bytes,
        "receipt": receipt,
        "receipt_bytes": receipt_bytes,
        "protocol": protocol,
    }


def _validate(artifacts: dict) -> list[str]:
    return validate_freeze(
        artifacts["protocol"],
        artifacts["corpus"],
        artifacts["verifier"],
        _request(),
        corpus_bytes=artifacts["corpus_bytes"],
        verifier_bytes=artifacts["verifier_bytes"],
        review_receipt=artifacts["receipt"],
        review_receipt_bytes=artifacts["receipt_bytes"],
    )


def test_artifact_bound_qualification_protocol_is_valid() -> None:
    assert _validate(_artifacts()) == []


def test_prepares_private_protocol_from_reviewed_artifacts(tmp_path: Path) -> None:
    artifacts = _artifacts()
    output_path = tmp_path / "private" / "qualification-protocol.json"
    report_path = tmp_path / "private" / "preparation-report.json"

    report = prepare_qualification_protocol(
        experiment_id="j1q-controlled-comparison-20260720-r1",
        hypothesis="Bounded mentorship improves pre-registered outcomes.",
        budget_id="j1q-budget-20260720-r1",
        frozen_at="2026-07-20T22:00:00+08:00",
        admission_request_path=_write(
            tmp_path / "admission-request.json", _bytes(_request())
        ),
        corpus_path=_write(tmp_path / "corpus.json", artifacts["corpus_bytes"]),
        verifier_path=_write(tmp_path / "verifier.json", artifacts["verifier_bytes"]),
        review_receipt_path=_write(
            tmp_path / "review-receipt.json", artifacts["receipt_bytes"]
        ),
        output_path=output_path,
        report_path=report_path,
    )

    assert report["passed"] is True
    assert report["qualification_protocol"]["canonical_sha256"]
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert output_path.parent.stat().st_mode & 0o777 == 0o700


def test_protocol_preparation_rejects_open_reviewed_artifact(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts()
    corpus_path = _write(tmp_path / "corpus.json", artifacts["corpus_bytes"])
    corpus_path.chmod(0o644)
    output_path = tmp_path / "private" / "qualification-protocol.json"

    report = prepare_qualification_protocol(
        experiment_id="j1q-controlled-comparison-20260720-r1",
        hypothesis="Bounded mentorship improves pre-registered outcomes.",
        budget_id="j1q-budget-20260720-r1",
        frozen_at="2026-07-20T22:00:00+08:00",
        admission_request_path=_write(
            tmp_path / "admission-request.json", _bytes(_request())
        ),
        corpus_path=corpus_path,
        verifier_path=_write(tmp_path / "verifier.json", artifacts["verifier_bytes"]),
        review_receipt_path=_write(
            tmp_path / "review-receipt.json", artifacts["receipt_bytes"]
        ),
        output_path=output_path,
        report_path=tmp_path / "private" / "preparation-report.json",
    )

    assert report["passed"] is False
    assert "qualification_corpus_permissions_too_open" in report["failure_reasons"]
    assert not output_path.exists()


def test_freeze_gate_passes_without_authorizing_execution(tmp_path: Path) -> None:
    artifacts = _artifacts()
    report = run_gate(
        protocol_path=_write(tmp_path / "protocol.json", _bytes(artifacts["protocol"])),
        corpus_path=_write(tmp_path / "corpus.json", artifacts["corpus_bytes"]),
        verifier_path=_write(tmp_path / "verifier.json", artifacts["verifier_bytes"]),
        review_receipt_path=_write(
            tmp_path / "review-receipt.json", artifacts["receipt_bytes"]
        ),
        output_path=tmp_path / "report.json",
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
    assert report["execution_boundary"]["model_invocation_allowed"] is False


def test_freeze_rejects_artifact_drift_and_threshold_change() -> None:
    artifacts = _artifacts()
    artifacts["protocol"]["task_corpus"]["artifact_sha256"] = "0" * 64
    artifacts["protocol"]["metric_definitions_sha256"] = "0" * 64

    failures = _validate(artifacts)

    assert "protocol_corpus_artifact_hash_mismatch" in failures
    assert "protocol_metric_definitions_mismatch" in failures


def test_freeze_rejects_forged_review_status_without_receipt_binding() -> None:
    artifacts = _artifacts()
    artifacts["protocol"]["material_review"]["review_receipt_sha256"] = "0" * 64
    artifacts["corpus"]["operator_review"]["review_receipt_sha256"] = "0" * 64

    failures = _validate(artifacts)

    assert "protocol_material_review_binding_mismatch" in failures
    assert "qualification_corpus_review_binding_mismatch" in failures


def test_freeze_rejects_synthetic_corpus_and_verifier_override() -> None:
    artifacts = _artifacts()
    artifacts["corpus"]["synthetic"] = True
    artifacts["verifier"]["operator_override_allowed"] = True

    failures = _validate(artifacts)

    assert "qualification_corpus_must_be_real" in failures
    assert "qualification_verifier_override_forbidden" in failures


def test_freeze_rejects_execution_preauthorization() -> None:
    artifacts = _artifacts()
    artifacts["protocol"]["execution_boundary"]["execution_authorized"] = True
    artifacts["protocol"]["execution_boundary"]["model_invocation_allowed"] = True

    failures = _validate(artifacts)

    assert "qualification_execution_must_be_false" in failures
    assert "model_invocation_allowed_must_be_false" in failures


def test_freeze_gate_rejects_open_review_receipt_permissions(tmp_path: Path) -> None:
    artifacts = _artifacts()
    review_receipt_path = _write(
        tmp_path / "review-receipt.json", artifacts["receipt_bytes"]
    )
    review_receipt_path.chmod(0o644)

    report = run_gate(
        protocol_path=_write(tmp_path / "protocol.json", _bytes(artifacts["protocol"])),
        corpus_path=_write(tmp_path / "corpus.json", artifacts["corpus_bytes"]),
        verifier_path=_write(tmp_path / "verifier.json", artifacts["verifier_bytes"]),
        review_receipt_path=review_receipt_path,
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert (
        "qualification_material_review_receipt_permissions_too_open"
        in report["failure_reasons"]
    )
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def test_operational_gate_fails_closed_when_private_artifacts_are_missing(
    tmp_path: Path,
) -> None:
    report = run_gate(
        protocol_path=tmp_path / "protocol-required.json",
        corpus_path=tmp_path / "corpus-required.json",
        verifier_path=tmp_path / "verifier-required.json",
        review_receipt_path=tmp_path / "review-receipt-required.json",
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert report["failure_reasons"] == [
        "qualification_protocol_unreadable",
        "qualification_corpus_unreadable",
        "qualification_verifier_unreadable",
        "qualification_material_review_receipt_unreadable",
    ]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def _did(public_key_hex: str) -> str:
    number = int.from_bytes(b"\xed\x01" + bytes.fromhex(public_key_hex), "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:testnet:z{encoded}"
