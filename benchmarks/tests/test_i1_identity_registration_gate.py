from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.i1.identity_preparation import did_from_public_key
from benchmarks.i1_identity_registration_gate import run_gate
from nacl.signing import SigningKey, VerifyKey


class FakeAgent:
    registry: dict[str, str] = {}

    def __init__(self, *_: Any, **__: Any) -> None:
        self._key: SigningKey | None = None
        self._public_key = ""
        self.agent_id: str | None = None
        self.jwt_auth_context: dict[str, Any] = {}

    def load_identity(self, path: str) -> str:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._key = SigningKey(bytes.fromhex(data["seed_hex"]))
        self._public_key = self._key.verify_key.encode().hex()
        self.agent_id = data.get("agent_id")
        return self._public_key

    def save_identity(self, path: str) -> None:
        assert self._key is not None
        Path(path).write_text(
            json.dumps(
                {
                    "seed_hex": bytes(self._key._seed).hex(),  # noqa: SLF001
                    "public_key_hex": self._public_key,
                    "agent_id": self.agent_id,
                }
            ),
            encoding="utf-8",
        )
        Path(path).chmod(0o600)

    def a2a_quickstart(self, **_: Any) -> dict[str, Any]:
        self.agent_id = did_from_public_key(self._public_key)
        self.registry[self.agent_id] = self._public_key
        return {"agent": {"did": self.agent_id}}

    def authenticate_service_token(self, **_: Any) -> str:
        self.jwt_auth_context = {
            "auth_method": "service_token",
            "scopes": ["agents:write"],
            "evidence_allowed": False,
        }
        return "bootstrap-token"

    def authenticate(self, **_: Any) -> str:
        self.jwt_auth_context = {
            "auth_method": "did_signature_challenge",
            "evidence_allowed": True,
            "production_allowed": False,
        }
        return "test-token"

    def sign(self, message: bytes) -> str:
        assert self._key is not None
        return self._key.sign(message).signature.hex()

    def _a2a_request(
        self,
        _method: str,
        _path: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        public_key = self.registry[body["agent_id"]]
        VerifyKey(bytes.fromhex(public_key)).verify(
            body["message"].encode("utf-8"),
            bytes.fromhex(body["signature_hex"]),
        )
        return {"agent_id": body["agent_id"], "verified": True}


def test_registration_gate_registers_five_and_proves_control(
    tmp_path: Path,
) -> None:
    preparation = _write_preparation(tmp_path)
    h3 = _write_h3(tmp_path)

    report = run_gate(
        preparation_report_path=preparation,
        h3_qualification_path=h3,
        backend_url="http://test.invalid",
        output=tmp_path / "registration.json",
        service_token_secret="test-secret",
        agent_factory=FakeAgent,
    )

    assert report["passed"] is True
    assert report["metrics"]["registered_identity_count"] == 5
    assert report["metrics"]["signature_control_verified_count"] == 5
    assert report["metrics"]["did_challenge_auth_count"] == 5
    assert report["readiness"]["i1_execution_preflight_input_ready"] is True
    assert report["readiness"]["i1_execution_allowed"] is False


def test_registration_gate_rejects_unqualified_h3(tmp_path: Path) -> None:
    preparation = _write_preparation(tmp_path)
    h3 = _write_h3(tmp_path)
    value = json.loads(h3.read_text(encoding="utf-8"))
    value["valid_for_qualification"] = False
    h3.write_text(json.dumps(value), encoding="utf-8")

    report = run_gate(
        preparation_report_path=preparation,
        h3_qualification_path=h3,
        backend_url="http://test.invalid",
        output=tmp_path / "registration.json",
        service_token_secret="test-secret",
        agent_factory=FakeAgent,
    )

    assert report["passed"] is False
    assert report["metrics"]["registered_identity_count"] == 0


def _write_preparation(tmp_path: Path) -> Path:
    identities = []
    for index in range(5):
        key = SigningKey.generate()
        public_key = key.verify_key.encode().hex()
        key_path = tmp_path / f"identity-{index}.key"
        key_path.write_text(
            json.dumps(
                {
                    "seed_hex": bytes(key._seed).hex(),  # noqa: SLF001
                    "public_key_hex": public_key,
                    "agent_id": None,
                }
            ),
            encoding="utf-8",
        )
        key_path.chmod(0o600)
        identities.append(
            {
                "identity_alias": f"agent-{index}",
                "display_name": f"Agent {index}",
                "provider_family": f"provider-{index}",
                "runtime_family": "test",
                "roles": ["verifier"],
                "identity_key_path": str(key_path),
                "identity_key_mode": "0600",
                "public_key_hex": public_key,
                "did": did_from_public_key(public_key),
            }
        )
    path = tmp_path / "preparation.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i1-verifier-preparation-report:v1",
                "passed": True,
                "identity_manifest": {
                    "identity_count": 5,
                    "identities": identities,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_h3(tmp_path: Path) -> Path:
    path = tmp_path / "h3.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": (
                    "h3-relation-learning-semantic-qualification:v1"
                ),
                "passed": True,
                "valid_for_qualification": True,
                "readiness": {"i1_entry_inputs_ready": True},
            }
        ),
        encoding="utf-8",
    )
    return path
