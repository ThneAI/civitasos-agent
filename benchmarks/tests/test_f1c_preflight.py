from __future__ import annotations

import json
import sys
import types
from pathlib import Path

from benchmarks import f1c_preflight


class _Response:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_register_agent_bootstraps_sdk_auth_before_quickstart(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class FakeCivitasAgent:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url
            self._jwt_token = None
            self._jwt_expires_at = 0.0
            self._agent_id = None
            self._public_key_hex = "pub"

        def generate_keys(self) -> str:
            return self._public_key_hex

        def save_identity(self, path: str) -> None:
            Path(path).write_text(
                json.dumps({"seed_hex": "0" * 64, "public_key_hex": self._public_key_hex}),
                encoding="utf-8",
            )

        def a2a_quickstart(self, **_kwargs: object) -> dict:
            assert self._jwt_token == "demo-token"
            self._agent_id = "did:civ:devnet:alpha"
            return {"agent": {"did": self._agent_id}}

        def register(self, **_kwargs: object) -> None:
            raise AssertionError("register fallback should not be used after demo-login")

    def fake_urlopen(req, timeout: int):
        assert timeout == 20
        assert req.full_url == "http://backend/api/v1/auth/demo-login"
        assert json.loads(req.data.decode("utf-8"))["agent_id"] == "alphatrader"
        return _Response({"data": {"token": "demo-token", "expires_in": 120}})

    monkeypatch.setattr(f1c_preflight.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setitem(
        sys.modules,
        "civitasos",
        types.SimpleNamespace(CivitasAgent=FakeCivitasAgent),
    )
    monkeypatch.delenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", raising=False)

    record = f1c_preflight.register_agent(
        backend_url="http://backend",
        cfg=f1c_preflight.AgentConfig("alpha", "AlphaTrader", ("trading",)),
        identity_dir=tmp_path,
    )

    assert record["did"] == "did:civ:devnet:alpha"