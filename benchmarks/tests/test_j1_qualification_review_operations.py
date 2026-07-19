from __future__ import annotations

from pathlib import Path

import pytest
from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import read_json_object, write_private_json
from benchmarks.j1.qualification_materials import (
    build_task_source_candidate,
    prepare_materials,
)
from benchmarks.j1.qualification_review_operations import (
    REVIEW_DECISION_SCHEMA,
    sign_review_decision,
)
from benchmarks.j1.qualification_review_receipt import REQUIRED_CHECKS
from benchmarks.j1_qualification_material_review_gate import run_gate
from benchmarks.j1_qualification_review_operations import (
    assemble_detached_signature,
    prepare_request,
    prepare_signature_payload,
)


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


class _Signer:
    def __init__(self, key: SigningKey) -> None:
        self.key = key
        self.calls = 0

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        return self.key.sign(message).signature


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    tasks = [
        {
            "task_id": f"j1q-heldout-operations-{index:02d}",
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
    task_source_path = tmp_path / "task-source.json"
    write_private_json(
        task_source_path,
        build_task_source_candidate(
            corpus_id="j1q-heldout-operations-corpus-20260719-v1",
            tasks=tasks,
        ),
    )
    verifier_source_path = tmp_path / "qualification_verifier.py"
    verifier_source_path.write_text(
        "def verify():\n    return True\n", encoding="utf-8"
    )
    candidate_root = tmp_path / "candidate"
    packet = prepare_materials(
        task_source_path=task_source_path,
        verifier_source_path=verifier_source_path,
        source_revision="a" * 40,
        output_root=candidate_root,
    )
    assert packet["passed"] is True
    review_root = tmp_path / "independent-review"
    report = prepare_request(
        corpus_path=candidate_root / "qualification-corpus.review-required.json",
        verifier_path=candidate_root / "qualification-verifier.review-required.json",
        verifier_source_path=verifier_source_path,
        output_root=review_root,
        request_id="j1q-review-request-20260719-alpha",
        created_at="2026-07-19T23:00:00+08:00",
    )
    assert report["passed"] is True
    return (
        candidate_root / "qualification-corpus.review-required.json",
        candidate_root / "qualification-verifier.review-required.json",
        verifier_source_path,
        review_root / "review-request.json",
    )


def _decision(
    request_path: Path,
    key: SigningKey,
    *,
    signer_kind: str = "pkcs11_ed25519",
) -> dict:
    request = read_json_object(request_path)
    public_key_hex = key.verify_key.encode().hex()
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "j1q-material-review-20260719-alpha",
        "review_request_sha256": request["request_sha256"],
        "decision": "approve_qualification_materials",
        "reviewed_at": "2026-07-19T23:30:00+08:00",
        "reviewer": {
            "did": _did(public_key_hex),
            "public_key_hex": public_key_hex,
            "credential_version": 1,
            "signer_kind": signer_kind,
            "custody_provenance_sha256": "c" * 64,
            "signer_attestation_sha256": "d" * 64,
        },
        "independence": {
            "independent_from_authoring": True,
            "conflicts_disclosed": True,
            "ai_assisted_authoring_disclosed": True,
        },
        "checklist": {name: True for name in sorted(REQUIRED_CHECKS)},
    }


def _sign_inputs(
    corpus_path: Path, verifier_path: Path, verifier_source_path: Path
) -> dict:
    return {
        "corpus": read_json_object(corpus_path),
        "verifier": read_json_object(verifier_path),
        "corpus_bytes": corpus_path.read_bytes(),
        "verifier_bytes": verifier_path.read_bytes(),
        "verifier_source_bytes": verifier_source_path.read_bytes(),
    }


def test_prepare_request_is_deterministic_private_and_non_executing(
    tmp_path: Path,
) -> None:
    corpus_path, verifier_path, source_path, request_path = _prepare(tmp_path)
    first = request_path.read_bytes()

    report = prepare_request(
        corpus_path=corpus_path,
        verifier_path=verifier_path,
        verifier_source_path=source_path,
        output_root=request_path.parent,
        request_id="j1q-review-request-20260719-alpha",
        created_at="2026-07-19T23:00:00+08:00",
    )

    assert request_path.read_bytes() == first
    assert report["state"] == "awaiting_independent_operator_decision"
    assert all(value is False for value in report["execution_boundary"].values())
    assert request_path.parent.stat().st_mode & 0o777 == 0o700
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in request_path.parent.iterdir()
    )


def test_valid_explicit_decision_creates_gate_accepted_receipt(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    signer = _Signer(key)
    receipt = sign_review_decision(
        request=read_json_object(request_path),
        decision=_decision(request_path, key),
        signer=signer,
        **_sign_inputs(corpus_path, verifier_path, source_path),
    )
    receipt_path = tmp_path / "review-receipt.json"
    write_private_json(receipt_path, receipt)

    report = run_gate(
        corpus_path=corpus_path,
        verifier_path=verifier_path,
        verifier_source_path=source_path,
        review_receipt_path=receipt_path,
        output_root=tmp_path / "gate",
    )

    assert signer.calls == 1
    assert report["passed"] is True
    assert (
        receipt["review_request_sha256"]
        == read_json_object(request_path)["request_sha256"]
    )


def test_invalid_decision_is_rejected_before_signer_call(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    signer = _Signer(key)
    decision = _decision(request_path, key)
    decision["checklist"]["verifier_logic_reviewed"] = False

    with pytest.raises(ValueError, match="review_checklist_incomplete"):
        sign_review_decision(
            request=read_json_object(request_path),
            decision=decision,
            signer=signer,
            **_sign_inputs(corpus_path, verifier_path, source_path),
        )

    assert signer.calls == 0


def test_candidate_drift_is_rejected_before_signer_call(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    signer = _Signer(key)
    corpus = read_json_object(corpus_path)
    corpus["authoring_provenance"] = "changed_after_request"
    write_private_json(corpus_path, corpus)

    with pytest.raises(ValueError, match="review_request_scope_mismatch"):
        sign_review_decision(
            request=read_json_object(request_path),
            decision=_decision(request_path, key),
            signer=signer,
            **_sign_inputs(corpus_path, verifier_path, source_path),
        )

    assert signer.calls == 0


def test_signer_key_mismatch_is_rejected_before_signing(tmp_path: Path) -> None:
    corpus_path, verifier_path, source_path, request_path = _prepare(tmp_path)
    decision_key = SigningKey.generate()
    signer = _Signer(SigningKey.generate())

    with pytest.raises(ValueError, match="signer public key does not match"):
        sign_review_decision(
            request=read_json_object(request_path),
            decision=_decision(request_path, decision_key),
            signer=signer,
            **_sign_inputs(corpus_path, verifier_path, source_path),
        )

    assert signer.calls == 0


def test_callback_payload_and_detached_signature_are_verified(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    decision_path = tmp_path / "review-decision.json"
    write_private_json(
        decision_path,
        _decision(
            request_path,
            key,
            signer_kind="non_exportable_ed25519_callback",
        ),
    )
    payload_path = tmp_path / "review-signature-payload.bin"
    payload_report = prepare_signature_payload(
        request_path=request_path,
        decision_path=decision_path,
        output_path=payload_path,
    )
    signature_path = tmp_path / "review-signature.hex"
    signature_path.write_text(
        key.sign(payload_path.read_bytes()).signature.hex() + "\n", encoding="ascii"
    )
    receipt_path = tmp_path / "review-receipt.json"

    report = assemble_detached_signature(
        request_path=request_path,
        decision_path=decision_path,
        signature_path=signature_path,
        output_path=receipt_path,
    )

    assert payload_report["state"] == "awaiting_non_exportable_signature"
    assert report["passed"] is True
    assert report["private_key_exported"] is False
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    assert receipt_path.with_suffix(".json.report.json").stat().st_mode & 0o777 == 0o600


def test_tampered_detached_signature_is_rejected(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    decision_path = tmp_path / "review-decision.json"
    write_private_json(
        decision_path,
        _decision(
            request_path,
            key,
            signer_kind="non_exportable_ed25519_callback",
        ),
    )
    signature_path = tmp_path / "review-signature.bin"
    signature_path.write_bytes(b"\x00" * 64)

    with pytest.raises(ValueError, match="review_signature_invalid"):
        assemble_detached_signature(
            request_path=request_path,
            decision_path=decision_path,
            signature_path=signature_path,
            output_path=tmp_path / "review-receipt.json",
        )


def test_open_decision_permissions_fail_closed(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    decision_path = tmp_path / "review-decision.json"
    write_private_json(decision_path, _decision(request_path, SigningKey.generate()))
    decision_path.chmod(0o644)

    with pytest.raises(ValueError, match="permissions are too open"):
        prepare_signature_payload(
            request_path=request_path,
            decision_path=decision_path,
            output_path=tmp_path / "payload.bin",
        )


def _did(public_key_hex: str) -> str:
    payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:testnet:z{encoded}"
