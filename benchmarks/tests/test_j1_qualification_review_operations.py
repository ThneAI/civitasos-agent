from __future__ import annotations

import hashlib
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
from benchmarks.j1.qualification_reviewer_identity import (
    build_reviewer_identity_profile,
)
from benchmarks.j1_qualification_material_review_gate import run_gate
from benchmarks.j1_qualification_review_operations import (
    assemble_detached_signature,
    bind_reviewer_identity,
    prepare_request,
    prepare_signature_payload,
    run_review_preflight,
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
    identity_sha256: str | None = None,
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
            "custody_provenance_sha256": identity_sha256 or "c" * 64,
            "signer_attestation_sha256": identity_sha256 or "d" * 64,
        },
        "independence": {
            "independent_from_authoring": True,
            "conflicts_disclosed": True,
            "ai_assisted_authoring_disclosed": True,
        },
        "checklist": {name: True for name in sorted(REQUIRED_CHECKS)},
    }


def _identity_profile(
    tmp_path: Path,
    key: SigningKey,
    module_path: Path,
) -> tuple[Path, str]:
    challenge = b"j1-reviewer-identity-proof-v1!!!"
    assert len(challenge) == 32
    public_key_hex = key.verify_key.encode().hex()
    profile = build_reviewer_identity_profile(
        created_at="2026-07-20T10:00:00+08:00",
        public_key_hex=public_key_hex,
        credential_version=1,
        module_path=str(module_path.resolve()),
        module_bytes=module_path.read_bytes(),
        token_label="reviewer-token",
        token_serial="reviewer-token-serial",
        token_model="SoftHSM v2",
        token_manufacturer="SoftHSM project",
        key_label="reviewer-key",
        key_id_hex="01",
        key_reference="pkcs11:reviewer-token:reviewer-key:01",
        challenge=challenge,
        signature=key.sign(challenge).signature,
        private_key_sensitive=True,
        private_key_extractable=False,
    )
    path = tmp_path / "reviewer-identity.json"
    write_private_json(path, profile)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


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


def test_preflight_reports_incomplete_operator_template(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    output_path = tmp_path / "review-handoff-preflight.json"

    report = run_review_preflight(
        request_path=request_path,
        decision_path=request_path.parent / "review-decision.template.json",
        output_path=output_path,
    )

    assert report["passed"] is False
    assert report["state"] == "blocked_independent_operator_review_handoff"
    assert report["request_validated"] is True
    assert report["decision_validated"] is False
    assert "review_id_invalid" in report["failure_reasons"]
    assert "reviewed_at_invalid" in report["failure_reasons"]
    assert "reviewer_signer_kind_invalid" in report["failure_reasons"]
    assert "review_checklist_incomplete" in report["failure_reasons"]
    assert report["execution_boundary"]["hardware_contact_performed"] is False
    assert report["execution_boundary"]["pin_read"] is False
    assert report["execution_boundary"]["signature_performed"] is False
    assert output_path.stat().st_mode & 0o777 == 0o600


def test_pkcs11_preflight_passes_only_with_complete_structural_config(
    tmp_path: Path,
) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    module_path = tmp_path / "pkcs11-module.so"
    module_path.write_bytes(b"module-placeholder")
    profile_path, profile_sha256 = _identity_profile(tmp_path, key, module_path)
    decision_path = tmp_path / "review-decision.json"
    write_private_json(
        decision_path,
        _decision(request_path, key, identity_sha256=profile_sha256),
    )

    report = run_review_preflight(
        request_path=request_path,
        decision_path=decision_path,
        output_path=tmp_path / "preflight.json",
        module_path=str(module_path),
        token_label="reviewer-token",
        key_label="reviewer-key",
        key_id="01",
        reviewer_identity_profile_path=profile_path,
    )

    assert report["passed"] is True
    assert report["decision_validated"] is True
    assert report["signer_preflight"]["configuration_complete"] is True
    assert report["reviewer_identity_profile"]["validated"] is True
    assert report["readiness"]["signature_payload_ready"] is True
    assert report["readiness"]["hardware_identity_probe_required"] is True
    assert report["readiness"]["signed_receipt_present"] is False


def test_pkcs11_preflight_rejects_missing_signer_configuration(
    tmp_path: Path,
) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    decision_path = tmp_path / "review-decision.json"
    write_private_json(decision_path, _decision(request_path, SigningKey.generate()))

    report = run_review_preflight(
        request_path=request_path,
        decision_path=decision_path,
        output_path=tmp_path / "preflight.json",
        module_path=str(tmp_path / "missing-pkcs11-module.so"),
    )

    assert report["passed"] is False
    assert report["failure_reasons"] == [
        "pkcs11_module_unreadable",
        "pkcs11_token_label_missing",
        "pkcs11_key_label_missing",
        "pkcs11_key_id_invalid",
        "reviewer_identity_profile_required",
    ]
    assert report["readiness"]["signature_payload_ready"] is False
    assert report["execution_boundary"]["hardware_contact_performed"] is False


def test_pkcs11_preflight_rejects_identity_profile_binding_drift(
    tmp_path: Path,
) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    module_path = tmp_path / "pkcs11-module.so"
    module_path.write_bytes(b"module-placeholder")
    profile_path, profile_sha256 = _identity_profile(tmp_path, key, module_path)
    decision = _decision(request_path, key, identity_sha256=profile_sha256)
    decision["reviewer"]["signer_attestation_sha256"] = "0" * 64
    decision_path = tmp_path / "review-decision.json"
    write_private_json(decision_path, decision)

    report = run_review_preflight(
        request_path=request_path,
        decision_path=decision_path,
        output_path=tmp_path / "preflight.json",
        module_path=str(module_path),
        token_label="reviewer-token",
        key_label="reviewer-key",
        key_id="01",
        reviewer_identity_profile_path=profile_path,
    )

    assert report["passed"] is False
    assert (
        "reviewer_identity_profile_signer_attestation_sha256_mismatch"
        in report["failure_reasons"]
    )
    assert report["reviewer_identity_profile"]["validated"] is False


def test_callback_preflight_requires_no_pkcs11_configuration(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    decision_path = tmp_path / "review-decision.json"
    write_private_json(
        decision_path,
        _decision(
            request_path,
            SigningKey.generate(),
            signer_kind="non_exportable_ed25519_callback",
        ),
    )

    report = run_review_preflight(
        request_path=request_path,
        decision_path=decision_path,
        output_path=tmp_path / "preflight.json",
    )

    assert report["passed"] is True
    assert report["readiness"]["external_signature_required"] is True
    assert report["readiness"]["hardware_identity_probe_required"] is False


def test_bind_reviewer_populates_identity_but_not_operator_decision(
    tmp_path: Path,
) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    module_path = tmp_path / "pkcs11-module.so"
    module_path.write_bytes(b"module-placeholder")
    profile_path, profile_sha256 = _identity_profile(tmp_path, key, module_path)
    output_path = tmp_path / "review-decision.identity-bound.json"

    report = bind_reviewer_identity(
        request_path=request_path,
        reviewer_identity_profile_path=profile_path,
        output_path=output_path,
    )
    decision = read_json_object(output_path)

    assert report["passed"] is True
    assert report["readiness"]["reviewer_identity_bound"] is True
    assert all(
        value is False
        for key_name, value in report["readiness"].items()
        if key_name != "reviewer_identity_bound"
    )
    assert decision["reviewer"]["public_key_hex"] == key.verify_key.encode().hex()
    assert decision["reviewer"]["custody_provenance_sha256"] == profile_sha256
    assert decision["reviewer"]["signer_attestation_sha256"] == profile_sha256
    assert decision["decision"] == "REQUIRED_ALLOWED_DECISION"
    assert all(value is False for value in decision["independence"].values())
    assert all(value is False for value in decision["checklist"].values())
    assert output_path.stat().st_mode & 0o777 == 0o600


def test_bind_reviewer_rejects_tampered_identity_profile(tmp_path: Path) -> None:
    _, _, _, request_path = _prepare(tmp_path)
    key = SigningKey.generate()
    module_path = tmp_path / "pkcs11-module.so"
    module_path.write_bytes(b"module-placeholder")
    profile_path, _ = _identity_profile(tmp_path, key, module_path)
    profile = read_json_object(profile_path)
    profile["possession_proof"]["signature_hex"] = "00" * 64
    write_private_json(profile_path, profile)

    with pytest.raises(ValueError, match="signature_verification_failed"):
        bind_reviewer_identity(
            request_path=request_path,
            reviewer_identity_profile_path=profile_path,
            output_path=tmp_path / "review-decision.identity-bound.json",
        )


def _did(public_key_hex: str) -> str:
    payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    number = int.from_bytes(payload, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return f"did:civ:testnet:z{encoded}"
