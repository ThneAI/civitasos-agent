import importlib.util
import json
import os
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "identity_ops.py"
SPEC = importlib.util.spec_from_file_location("identity_ops", MODULE_PATH)
identity_ops = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(identity_ops)


def test_create_backup_restore_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("CIVITASOS_IDENTITY_PASSPHRASE", "correct horse battery staple")
    identity = tmp_path / "identity.json"
    encrypted = tmp_path / "identity.backup.json"
    restored = tmp_path / "restored.json"

    created = identity_ops.create(identity, "did:civitas:test")
    identity_ops.backup(identity, encrypted)
    verification = identity_ops.verify_backup(encrypted)
    result = identity_ops.restore(encrypted, restored)

    assert created["public_key_hex"] == result["public_key_hex"]
    assert identity.read_bytes() == restored.read_bytes()
    assert os.stat(identity).st_mode & 0o777 == 0o600
    assert os.stat(encrypted).st_mode & 0o777 == 0o600
    assert "seed_hex" not in encrypted.read_text()
    assert verification["plaintext_written"] is False


def test_restore_rejects_wrong_passphrase(tmp_path, monkeypatch):
    identity = tmp_path / "identity.json"
    encrypted = tmp_path / "identity.backup.json"
    identity_ops.create(identity, None)
    monkeypatch.setenv("CIVITASOS_IDENTITY_PASSPHRASE", "correct horse battery staple")
    identity_ops.backup(identity, encrypted)
    monkeypatch.setenv("CIVITASOS_IDENTITY_PASSPHRASE", "incorrect horse battery staple")

    with pytest.raises(Exception):
        identity_ops.restore(encrypted, tmp_path / "restored.json")


def test_verify_backup_rejects_tampered_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("CIVITASOS_IDENTITY_PASSPHRASE", "correct horse battery staple")
    identity = tmp_path / "identity.json"
    encrypted = tmp_path / "identity.backup.json"
    identity_ops.create(identity, "did:civitas:test")
    identity_ops.backup(identity, encrypted)
    envelope = json.loads(encrypted.read_text())
    envelope["agent_id"] = "did:civitas:other"
    encrypted.write_text(json.dumps(envelope))

    with pytest.raises(ValueError, match="metadata does not match"):
        identity_ops.verify_backup(encrypted)
