from __future__ import annotations

import hashlib
from pathlib import Path

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_review_receipt import (
    FALSE_BOUNDARIES,
    REQUIRED_CHECKS,
    REVIEW_RECEIPT_SCHEMA,
    review_signature_payload,
)
from benchmarks.j1.qualification_materials import (
    build_task_source_candidate,
    prepare_materials,
)
from benchmarks.j1.qualification_protocol_freeze import validate_freeze
from benchmarks.j1_qualification_material_review_gate import run_gate


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
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


def _prepare_candidates(tmp_path: Path) -> tuple[Path, Path, Path]:
    tasks = [
        {
            "task_id": f"j1q-heldout-review-{index:02d}",
            "input": (
                "Evaluate this confidential qualification scenario using signed "
                "source artifacts, preserve the apprentice decision boundary, and "
                f"record deterministic evidence for scenario {scenario}."
            ),
            "verifier_case": case_id,
            "scenario_tags": [scenario],
        }
        for index, (case_id, scenario) in enumerate(CASES_AND_SCENARIOS)
    ]
    source = build_task_source_candidate(
        corpus_id="j1q-heldout-review-corpus-20260719-v1",
        tasks=tasks,
    )
    source_path = tmp_path / "task-source.json"
    write_private_json(source_path, source)
    verifier_source = tmp_path / "qualification_verifier.py"
    verifier_source.write_text("def verify():\n    return True\n", encoding="utf-8")
    candidate_root = tmp_path / "candidate"
    packet = prepare_materials(
        task_source_path=source_path,
        verifier_source_path=verifier_source,
        source_revision="a" * 40,
        output_root=candidate_root,
    )
    assert packet["passed"] is True
    return (
        candidate_root / "qualification-corpus.review-required.json",
        candidate_root / "qualification-verifier.review-required.json",
        verifier_source,
    )


def _receipt(
    corpus_path: Path,
    verifier_path: Path,
    verifier_source_path: Path,
    *,
    decision: str = "approve_qualification_materials",
) -> tuple[dict, SigningKey]:
    corpus = read_json_object(corpus_path)
    verifier = read_json_object(verifier_path)
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
        "decision": decision,
        "reviewed_at": "2026-07-19T22:00:00+08:00",
        "independence": {
            "independent_from_authoring": True,
            "conflicts_disclosed": True,
            "ai_assisted_authoring_disclosed": True,
        },
        "review_scope": {
            "corpus_artifact_sha256": hashlib.sha256(
                corpus_path.read_bytes()
            ).hexdigest(),
            "corpus_id": corpus["corpus_id"],
            "corpus_tasks_sha256": corpus["tasks_sha256"],
            "verifier_artifact_sha256": hashlib.sha256(
                verifier_path.read_bytes()
            ).hexdigest(),
            "verifier_id": verifier["verifier_id"],
            "verifier_implementation_sha256": hashlib.sha256(
                verifier_source_path.read_bytes()
            ).hexdigest(),
            "verifier_manifest_sha256": verifier["manifest_sha256"],
            "verifier_source_revision": verifier["source_revision"],
        },
        "checklist": {name: True for name in sorted(REQUIRED_CHECKS)},
        "execution_boundary": {name: False for name in sorted(FALSE_BOUNDARIES)},
    }
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signing_key.sign(payload).signature.hex(),
    }
    return receipt, signing_key


def _run(
    tmp_path: Path,
    corpus_path: Path,
    verifier_path: Path,
    verifier_source_path: Path,
    receipt: dict,
) -> dict:
    receipt_path = tmp_path / "review-receipt.json"
    write_private_json(receipt_path, receipt)
    return run_gate(
        corpus_path=corpus_path,
        verifier_path=verifier_path,
        verifier_source_path=verifier_source_path,
        review_receipt_path=receipt_path,
        output_root=tmp_path / "review-gate",
    )


def test_signed_approval_promotes_private_materials(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    receipt, _ = _receipt(corpus_path, verifier_path, source_path)

    report = _run(tmp_path, corpus_path, verifier_path, source_path, receipt)
    output_root = tmp_path / "review-gate"
    reviewed_corpus_path = output_root / "qualification-corpus.operator-reviewed.json"
    reviewed_verifier_path = (
        output_root / "qualification-verifier.operator-reviewed.json"
    )
    reviewed_corpus = read_json_object(reviewed_corpus_path)
    reviewed_verifier = read_json_object(reviewed_verifier_path)

    assert report["passed"] is True
    assert report["review_receipt_signature_valid"] is True
    assert report["readiness"]["qualification_protocol_freeze_ready"] is True
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
    assert reviewed_corpus["status"] == "operator_reviewed"
    assert reviewed_verifier["status"] == "operator_reviewed"
    assert reviewed_verifier["manifest_sha256"] == canonical_sha256(
        {
            key: value
            for key, value in reviewed_verifier.items()
            if key != "manifest_sha256"
        }
    )
    assert corpus_path.read_bytes() != reviewed_corpus_path.read_bytes()
    assert output_root.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output_root.iterdir())

    failures = validate_freeze(
        {},
        reviewed_corpus,
        reviewed_verifier,
        {},
        corpus_bytes=reviewed_corpus_path.read_bytes(),
        verifier_bytes=reviewed_verifier_path.read_bytes(),
        review_receipt=receipt,
        review_receipt_bytes=(tmp_path / "review-receipt.json").read_bytes(),
    )
    assert "qualification_corpus_status_invalid" not in failures
    assert "qualification_verifier_status_invalid" not in failures
    assert "qualification_verifier_manifest_hash_mismatch" not in failures


def test_review_rejects_candidate_artifact_drift(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    receipt, _ = _receipt(corpus_path, verifier_path, source_path)
    corpus = read_json_object(corpus_path)
    corpus["authoring_provenance"] = "changed_after_operator_review"
    write_private_json(corpus_path, corpus)

    report = _run(tmp_path, corpus_path, verifier_path, source_path, receipt)

    assert report["passed"] is False
    assert "review_scope_mismatch" in report["failure_reasons"]
    assert report["promoted_artifacts"] is None


def test_review_rejects_invalid_signature(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    receipt, _ = _receipt(corpus_path, verifier_path, source_path)
    receipt["signature"]["signature_hex"] = "00" * 64

    report = _run(tmp_path, corpus_path, verifier_path, source_path, receipt)

    assert report["passed"] is False
    assert "review_signature_invalid" in report["failure_reasons"]
    assert report["review_receipt_signature_valid"] is False


def test_valid_rejection_does_not_promote_materials(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    receipt, _ = _receipt(
        corpus_path,
        verifier_path,
        source_path,
        decision="reject_qualification_materials",
    )

    report = _run(tmp_path, corpus_path, verifier_path, source_path, receipt)

    assert report["passed"] is False
    assert report["review_receipt_signature_valid"] is True
    assert "review_decision_does_not_approve" in report["failure_reasons"]
    assert report["promoted_artifacts"] is None


def test_review_rejects_software_signer_and_secret_field(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    receipt, signing_key = _receipt(corpus_path, verifier_path, source_path)
    receipt["reviewer"]["signer_kind"] = "software_seed"
    receipt["seed_backup"] = "forbidden"
    receipt.pop("signature")
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signing_key.sign(payload).signature.hex(),
    }

    report = _run(tmp_path, corpus_path, verifier_path, source_path, receipt)

    assert report["passed"] is False
    assert "reviewer_signer_kind_invalid" in report["failure_reasons"]
    assert "review_receipt_contains_secret_field" in report["failure_reasons"]


def test_review_gate_fails_closed_without_receipt(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path = _prepare_candidates(tmp_path)
    output_root = tmp_path / "review-gate"

    report = run_gate(
        corpus_path=corpus_path,
        verifier_path=verifier_path,
        verifier_source_path=source_path,
        review_receipt_path=tmp_path / "independent-review-receipt.required.json",
        output_root=output_root,
    )

    assert report["passed"] is False
    assert report["failure_reasons"] == ["review_receipt_unreadable"]
    assert report["review_receipt_signature_valid"] is False
    assert report["readiness"]["qualification_protocol_freeze_ready"] is False
    assert report["execution_boundary"]["model_invocation_allowed"] is False
    assert (
        output_root / "material-review-gate-report.json"
    ).stat().st_mode & 0o777 == 0o600
    assert not (output_root / "qualification-corpus.operator-reviewed.json").exists()


def _did(public_key_hex: str) -> str:
    payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:testnet:z{encoded}"
