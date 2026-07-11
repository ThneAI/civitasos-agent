import importlib.util
import json
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey, VerifyKey

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "credential_ops.py"
SPEC = importlib.util.spec_from_file_location("credential_ops", MODULE_PATH)
credential_ops = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(credential_ops)


def _identity(path: Path, agent_id: str = "did:civitas:test") -> SigningKey:
    key = SigningKey.generate()
    path.write_text(json.dumps({"seed_hex": bytes(key).hex(), "public_key_hex": key.verify_key.encode().hex(), "agent_id": agent_id}))
    return key


def test_rotate_dual_signs_and_stages_without_replacing_current(tmp_path, monkeypatch):
    current = tmp_path / "current.json"
    staged = tmp_path / "staged.json"
    old_key = _identity(current)
    original = current.read_bytes()
    monkeypatch.setenv("TOKEN", "secret-token")
    calls = []

    def fake_request(base_url, path, body, token=None):
        calls.append((path, body, token))
        if path.endswith("challenge"):
            return {"challenge_id": "challenge-1", "message": b"proof".hex()}
        VerifyKey(bytes.fromhex(body["new_public_key"])).verify(b"proof", bytes.fromhex(body["new_signature"]))
        old_key.verify_key.verify(b"proof", bytes.fromhex(body["current_signature"]))
        return {"rotated": True, "fact_id": "fact:rotation"}

    monkeypatch.setattr(credential_ops, "_request", fake_request)
    result = credential_ops.rotate("https://backend.example", current, staged, "TOKEN")

    assert current.read_bytes() == original
    assert os.stat(staged).st_mode & 0o777 == 0o600
    assert result["active_identity_replaced"] is False
    assert calls[1][2] == "secret-token"


def test_revoke_and_emergency_require_fact_evidence(tmp_path, monkeypatch):
    identity = tmp_path / "identity.json"
    _identity(identity)
    monkeypatch.setenv("AGENT_TOKEN", "agent-token")
    monkeypatch.setenv("OPERATOR_TOKEN", "operator-token")

    def fake_request(base_url, path, body, token=None):
        if path.endswith("challenge"):
            return {"challenge_id": "challenge-1", "message": b"proof".hex()}
        if path.endswith("emergency-revoke"):
            assert token == "operator-token"
            return {"emergency_revoked": True, "fact_id": "fact:emergency"}
        return {"revoked": True, "fact_id": "fact:revoke"}

    monkeypatch.setattr(credential_ops, "_request", fake_request)
    assert credential_ops.revoke("https://backend.example", identity, "AGENT_TOKEN")["revoked"]
    assert credential_ops.emergency_revoke("https://backend.example", "did:civitas:test", "key compromised", "OPERATOR_TOKEN")["emergency_revoked"]


def test_rejects_insecure_remote_url_and_missing_token(monkeypatch):
    with pytest.raises(ValueError, match="require HTTPS"):
        credential_ops._base_url("http://backend.example")
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    with pytest.raises(ValueError, match="environment variable"):
        credential_ops._token("MISSING_TOKEN")
