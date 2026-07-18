#!/usr/bin/env python3
"""Remote checkpoint operations for the isolated P5-B4 multi-VM Gate."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import ssl
import urllib.error
import urllib.parse
import urllib.request
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

from nacl.signing import SigningKey

from civitasos_runtime.atomic_checkpoint import AtomicCheckpointStore
from civitasos_runtime.checkpoint_capture import (
    AtomicCheckpointCapture,
    BackendCheckpointClient,
)
from civitasos_runtime.checkpoint_files import read_private_json, write_private_json
from civitasos_runtime.checkpoint_restore import AtomicCheckpointRestore
from civitasos_runtime.llm import LLMAdapter
from civitasos_runtime.memory import LocalMemory
from civitasos_runtime.models import LLMResponse
from civitasos_runtime.runner import AgentRunner


FIXTURE_SCHEMA = "civitasos-p5b4-remote-checkpoint-fixture:v1"
RUNNER_RESULT_SCHEMA = "civitasos-p5b4-real-agent-runner-result:v1"
PROJECTION_SCHEMA = "civitasos-p5b4-checkpoint-projection:v1"


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class PersistentSigner:
    def __init__(self, seed_hex: str) -> None:
        self.key = SigningKey(bytes.fromhex(seed_hex))

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


class NoNetworkLLM(LLMAdapter):
    """Deterministic Gate adapter that never opens an LLM connection."""

    def __init__(self) -> None:
        super().__init__(max_retries=1, timeout=1, base_delay=0)
        self.calls = 0

    async def _do_chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.3,
    ) -> LLMResponse:
        del messages, tools, temperature
        self.calls += 1
        return LLMResponse(content="wait", tool_calls=[], usage={"gate_local": 1})


class GateAgent:
    """Minimal SDK-compatible identity anchored to the captured checkpoint."""

    def __init__(
        self,
        *,
        identity_id: str,
        signer: PersistentSigner,
        base_url: str,
        token: str,
    ) -> None:
        self.agent_id = identity_id
        self.public_key_hex = signer.public_key_hex
        self.base_url = base_url
        self._jwt_token = token
        self._signer = signer

    def generate_keys(self) -> str:
        return self.public_key_hex

    def sign(self, message: bytes) -> str:
        return self._signer.sign(message).hex()

    def briefing(self) -> dict[str, Any]:
        return {
            "active_tasks": [],
            "available_tasks": [],
            "balance": 100,
            "staked": 0,
            "reputation": 0.5,
        }

    def heartbeat(self) -> None:
        return None

    def remember(self, key: str, value: Any) -> None:
        del key, value

    def recall(self, key: str) -> None:
        del key
        return None

    def recall_similar(self, query: str, top_k: int = 3) -> list[Any]:
        del query, top_k
        return []


class OneTickGateRunner(AgentRunner):
    """Use the production start path and stop after one post-activation tick."""

    def __init__(self, agent: GateAgent, **kwargs: Any) -> None:
        self._gate_agent = agent
        self.tick_evidence: dict[str, Any] | None = None
        super().__init__(**kwargs)

    def _create_agent(self) -> GateAgent:
        return self._gate_agent

    async def _register(self) -> None:
        return None

    async def _cognitive_loop(self) -> None:
        if self._loop is None:
            raise RuntimeError("P5-B4 AgentRunner did not construct CognitiveLoop")
        self._checkpoint_latch.require_tick_allowed()
        context = await self._loop.tick()
        self.tick_evidence = {
            "tick_count": self._loop.tick_count,
            "action": context.decision.action if context.decision else None,
            "phase": context.phase.value,
        }
        self.request_shutdown("p5b4-one-post-activation-tick")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


def _opener(ca: Path, certificate: Path, private_key: Path) -> urllib.request.OpenerDirector:
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(str(certificate), str(private_key))
    return urllib.request.build_opener(
        _NoRedirect,
        urllib.request.HTTPSHandler(context=context),
        urllib.request.ProxyHandler({}),
    )


def _request_json(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with opener.open(request, timeout=10) as response:
            value = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:1000]
        raise RuntimeError(f"P5-B4 Backend HTTP {error.code}: {detail}") from error
    if not isinstance(value, dict):
        raise RuntimeError("P5-B4 Backend response must be a JSON object")
    return value


def _checkpoint_transport(
    opener: urllib.request.OpenerDirector,
    *,
    fault_point: str | None = None,
    backend_pid_path: Path | None = None,
    after_preflight: Callable[[], None] | None = None,
):
    preflight_callback_pending = True

    def transport(request: urllib.request.Request, timeout: float) -> dict[str, Any]:
        nonlocal preflight_callback_pending
        try:
            with opener.open(request, timeout=timeout) as response:
                value = json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:1000]
            raise RuntimeError(
                f"P5-B4 checkpoint HTTP {error.code}: {detail}"
            ) from error
        if not isinstance(value, dict):
            raise RuntimeError("P5-B4 checkpoint response must be an object")
        if fault_point == "backend_sigkill_before_activation_ack" and request.full_url.endswith(
            "/restore/activate"
        ):
            if backend_pid_path is None:
                raise RuntimeError("P5-B4 Backend fault requires a PID path")
            marker = backend_pid_path.parent / "backend-fault-triggered.json"
            marker.unlink(missing_ok=True)
            write_private_json(
                marker,
                {
                    "schema_version": "civitasos-p5b4-backend-fault-trigger:v1",
                    "fault_point": fault_point,
                    "activation_response_received": True,
                    "runtime_ack_delivered": False,
                },
            )
            os.kill(int(backend_pid_path.read_text().strip()), signal.SIGKILL)
            raise RuntimeError(
                "injected Backend SIGKILL after durable activation before Runtime ack"
            )
        if (
            after_preflight is not None
            and preflight_callback_pending
            and request.full_url.endswith("/restore/preflight")
        ):
            preflight_callback_pending = False
            after_preflight()
        return value

    return transport


def _service_token(
    opener: urllib.request.OpenerDirector, base_url: str, service_secret: str
) -> str:
    scopes = [
        "agents:read",
        "agents:write",
        "audit:read",
        "checkpoints:read",
        "checkpoints:write",
        "pool:read",
    ]
    response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/service-token",
        body={
            "service_id": "p5b4-remote-worker",
            "secret": service_secret,
            "scopes": scopes,
        },
    )
    data = response.get("data") or response
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("P5-B4 service-token response is missing token")
    return token


def _did_token(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    identity_id: str,
    signer: PersistentSigner,
) -> str:
    challenge_response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/challenge",
        body={"agent_id": identity_id},
    )
    challenge = challenge_response.get("data") or challenge_response
    challenge_id = challenge.get("challenge_id")
    message = challenge.get("message")
    if not isinstance(challenge_id, str) or not isinstance(message, str):
        raise RuntimeError("P5-B4 DID challenge response is incomplete")
    token_response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/token",
        body={
            "agent_id": identity_id,
            "challenge_id": challenge_id,
            "message": message,
            "signature": signer.sign(bytes.fromhex(message)).hex(),
        },
    )
    data = token_response.get("data") or token_response
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("P5-B4 DID token response is missing token")
    return token


def _rotate_credential(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    identity_id: str,
    signer: PersistentSigner,
) -> str:
    did_token = _did_token(opener, base_url, identity_id, signer)
    challenge_response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/challenge",
        body={"agent_id": identity_id},
    )
    challenge = challenge_response.get("data") or challenge_response
    challenge_id = challenge["challenge_id"]
    message_hex = challenge["message"]
    message = bytes.fromhex(message_hex)
    replacement = PersistentSigner(SigningKey.generate().encode().hex())
    _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/credential/rotate",
        token=did_token,
        body={
            "challenge_id": challenge_id,
            "message": message_hex,
            "current_signature": signer.sign(message).hex(),
            "new_public_key": replacement.public_key_hex,
            "new_signature": replacement.sign(message).hex(),
        },
    )
    return replacement.public_key_hex


def _load_or_create_signer(root: Path) -> PersistentSigner:
    path = root / "identity.seed"
    if path.exists():
        seed = path.read_text().strip()
    else:
        seed = SigningKey.generate().encode().hex()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(seed + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    return PersistentSigner(seed)


def capture(
    *,
    root: Path,
    base_url: str,
    opener: urllib.request.OpenerDirector,
    token: str,
    force_next: bool = False,
) -> dict[str, Any]:
    fixture_path = root / "fixture.json"
    if fixture_path.exists() and not force_next:
        fixture = read_private_json(fixture_path)
        if fixture.get("schema_version") != FIXTURE_SCHEMA:
            raise ValueError("unsupported P5-B4 fixture schema")
        return fixture
    signer = _load_or_create_signer(root)
    prior = read_private_json(fixture_path) if fixture_path.exists() else None
    if prior is None:
        response = _request_json(
            opener,
            base_url,
            "POST",
            "/api/v1/a2a/quickstart",
            token=token,
            body={
                "public_key": signer.public_key_hex,
                "name": "P5-B4 Real AgentRunner",
                "alias": f"p5b4-{os.getpid()}",
                "endpoint": "",
            },
        )
        identity_id = (response.get("agent") or {}).get("did")
    else:
        identity_id = prior.get("identity_id")
    if not isinstance(identity_id, str) or not identity_id.startswith("did:civ:"):
        raise RuntimeError("P5-B4 quickstart response is missing DID")
    memory = LocalMemory(root / "runtime-memory")
    expected = {
        "identity_iem_state": {
            "identity_id": identity_id,
            "phase": "captured",
            "capture_generation": 1 if prior is None else int(prior["sequence"]) + 1,
        },
        "identity_iem_anchor": {
            "version_id": f"iem:v1:p5b4:{1 if prior is None else int(prior['sequence']) + 1}"
        },
        "expectation_update_log": [],
        "lessons": ["retain-multivm-checkpoint"],
    }
    try:
        memory.restore_snapshot(expected)
        store = AtomicCheckpointStore(root / "checkpoints")
        client = BackendCheckpointClient(
            base_url,
            token,
            timeout=10,
            transport=_checkpoint_transport(opener),
        )
        manifest = AtomicCheckpointCapture(store, client, nullcontext).prepare(
            identity_id=identity_id,
            memory=memory,
            signer=signer,
            signer_ref="p5b4-isolated-file-signer",
        )
        store.commit(manifest["checkpoint_id"])
        memory.put("lessons", ["mutated-before-real-agent-runner"])
        memory.put("temporary", True)
    finally:
        memory.close()
    fixture = {
        "schema_version": FIXTURE_SCHEMA,
        "identity_id": identity_id,
        "checkpoint_id": manifest["checkpoint_id"],
        "manifest_hash": manifest["manifest_hash"],
        "sequence": manifest["sequence"],
        "public_key_hex": signer.public_key_hex,
        "expected_memory_sha256": _canonical_hash(expected),
        "private_material_exported": False,
        "production_identity": False,
    }
    fixture_path.unlink(missing_ok=True)
    write_private_json(fixture_path, fixture)
    return fixture


async def run_agent(
    *,
    root: Path,
    base_url: str,
    opener: urllib.request.OpenerDirector,
    token: str,
    fault_point: str | None = None,
) -> dict[str, Any]:
    fixture = read_private_json(root / "fixture.json")
    if fixture.get("schema_version") != FIXTURE_SCHEMA:
        raise ValueError("unsupported P5-B4 fixture schema")
    signer = _load_or_create_signer(root)
    if signer.public_key_hex != fixture.get("public_key_hex"):
        raise ValueError("P5-B4 signer continuity check failed")
    after_preflight = None
    if fault_point == "credential_rotation_after_preflight":
        def rotate_after_preflight() -> None:
            replacement = _rotate_credential(
                opener, base_url, fixture["identity_id"], signer
            )
            marker = root.parent / "credential-rotation-triggered.json"
            marker.unlink(missing_ok=True)
            write_private_json(
                marker,
                {
                    "schema_version": "civitasos-p5b4-credential-rotation-trigger:v1",
                    "fault_point": fault_point,
                    "checkpoint_id": fixture["checkpoint_id"],
                    "sequence": fixture["sequence"],
                    "old_public_key_hex": signer.public_key_hex,
                    "new_public_key_hex": replacement,
                    "backend_preflight_completed": True,
                    "backend_activation_attempted": False,
                },
            )

        after_preflight = rotate_after_preflight
    client = BackendCheckpointClient(
        base_url,
        token,
        timeout=10,
        transport=_checkpoint_transport(
            opener,
            fault_point=fault_point,
            backend_pid_path=root.parent / "backend.pid",
            after_preflight=after_preflight,
        ),
    )
    agent = GateAgent(
        identity_id=fixture["identity_id"],
        signer=signer,
        base_url=base_url,
        token=token,
    )
    llm = NoNetworkLLM()
    milestones: list[dict[str, Any]] = []
    latch_memory_hash: str | None = None
    runner_holder: dict[str, OneTickGateRunner] = {}

    def observe(milestone: str, event: dict[str, Any]) -> None:
        nonlocal latch_memory_hash
        milestones.append({"milestone": milestone, "event": event})
        if (
            fault_point == "agent_runner_sigkill_after_runtime_sqlite_commit"
            and milestone == "runtime_sqlite_committed"
        ):
            marker = root.parent / "runner-fault-triggered.json"
            marker.unlink(missing_ok=True)
            write_private_json(
                marker,
                {
                    "schema_version": "civitasos-p5b4-runner-fault-trigger:v1",
                    "fault_point": fault_point,
                    "checkpoint_id": fixture["checkpoint_id"],
                    "sequence": fixture["sequence"],
                    "runtime_sqlite_committed": True,
                    "backend_activation_attempted": False,
                },
            )
            os.kill(os.getpid(), signal.SIGKILL)
        if milestone == "runtime_tick_latch_released":
            runner = runner_holder["runner"]
            if runner._memory is None:
                raise RuntimeError("P5-B4 Runtime memory is missing at latch release")
            latch_memory_hash = _canonical_hash(runner._memory.local_snapshot())

    runner = OneTickGateRunner(
        agent,
        base_url=base_url,
        name="P5-B4 Real AgentRunner",
        capabilities=["checkpoint-gate"],
        llm=llm,
        heartbeat_interval=1,
        data_dir=str(root / "runtime-memory"),
        checkpoint_root=str(root / "checkpoints"),
        restore_checkpoint_on_start=True,
        checkpoint_backend_client=client,
        checkpoint_signer=signer,
        checkpoint_restore_observer=observe,
    )
    runner_holder["runner"] = runner
    await runner.start()
    if latch_memory_hash != fixture["expected_memory_sha256"]:
        raise RuntimeError("P5-B4 Runtime SQLite did not match checkpoint before tick")
    result = {
        "schema_version": RUNNER_RESULT_SCHEMA,
        "agent_runner_started": True,
        "agent_runner_class": f"{AgentRunner.__module__}.{AgentRunner.__name__}",
        "tick_evidence": runner.tick_evidence,
        "pre_activation_tick_count": 0,
        "post_activation_tick_count": (runner.tick_evidence or {}).get("tick_count"),
        "checkpoint_latch_released": True,
        "memory_sha256_at_latch_release": latch_memory_hash,
        "expected_memory_sha256": fixture["expected_memory_sha256"],
        "restore_milestones": milestones,
        "llm_mode": "deterministic_local_wait",
        "external_llm_calls": 0,
        "local_llm_calls": llm.calls,
        "production_evidence": False,
    }
    output = root / "agent-runner-result.json"
    if output.exists():
        output.unlink()
    write_private_json(output, result)
    return result


def projection(
    *,
    root: Path,
    base_url: str,
    opener: urllib.request.OpenerDirector,
    token: str,
) -> dict[str, Any]:
    fixture = read_private_json(root / "fixture.json")
    identity = urllib.parse.quote(fixture["identity_id"], safe="")
    checkpoint = urllib.parse.quote(fixture["checkpoint_id"], safe="")
    receipt_response = _request_json(
        opener,
        base_url,
        "GET",
        f"/api/v1/checkpoints/identity/{identity}/restores/{checkpoint}/receipt",
        token=token,
    )
    evidence_response = _request_json(
        opener,
        base_url,
        "GET",
        f"/api/v1/checkpoints/identity/{identity}/restores/{checkpoint}/evidence-manifest",
        token=token,
    )
    integrity_response = _request_json(
        opener,
        base_url,
        "GET",
        "/api/v1/a2a/facts/integrity",
        token=token,
    )
    receipt = receipt_response.get("data") or {}
    evidence = evidence_response.get("data") or {}
    integrity = integrity_response.get("data") or {}
    result = {
        "schema_version": PROJECTION_SCHEMA,
        "node_base_url": base_url,
        "identity_id": fixture["identity_id"],
        "checkpoint_id": fixture["checkpoint_id"],
        "receipt": receipt,
        "evidence_manifest": evidence,
        "fact_integrity": integrity,
        "passed": (
            receipt.get("fact_count") == 1
            and evidence.get("receipt_hash") == receipt.get("receipt_hash")
            and integrity.get("valid") is True
        ),
        "production_evidence": False,
    }
    return result


def stale_replay(
    *,
    root: Path,
    base_url: str,
    opener: urllib.request.OpenerDirector,
    token: str,
) -> dict[str, Any]:
    fixture = read_private_json(root / "fixture.json")
    store = AtomicCheckpointStore(root / "checkpoints")
    manifest = store.load_latest()
    if manifest is None or int(manifest["sequence"]) < 2:
        raise RuntimeError("P5-B4 stale replay requires checkpoint sequence >= 2")
    client = BackendCheckpointClient(
        base_url,
        token,
        timeout=10,
        transport=_checkpoint_transport(opener),
    )
    memory = LocalMemory(root / "runtime-memory")
    try:
        before_hash = _canonical_hash(memory.snapshot())
    finally:
        memory.close()
    request = AtomicCheckpointRestore(store, client, nullcontext)._backend_request(
        manifest, store.snapshots(manifest)
    )
    request.update(
        {
            "checkpoint_id": "aic:v1:p5b4-stale-replay",
            "manifest_hash": f"sha256:{'1' * 64}",
            "sequence": int(fixture["sequence"]) - 1,
        }
    )
    failure = ""
    try:
        client.restore_preflight(fixture["identity_id"], request)
    except Exception as error:
        failure = str(error)
    if "sequence is stale" not in failure:
        raise RuntimeError(f"P5-B4 stale replay was not rejected: {failure}")
    memory = LocalMemory(root / "runtime-memory")
    try:
        after_hash = _canonical_hash(memory.snapshot())
    finally:
        memory.close()
    if before_hash != after_hash:
        raise RuntimeError("P5-B4 stale replay mutated Runtime SQLite")
    return {
        "schema_version": "civitasos-p5b4-stale-replay-result:v1",
        "passed": True,
        "stale_sequence": request["sequence"],
        "authoritative_sequence": fixture["sequence"],
        "failure": failure,
        "runtime_memory_unchanged": True,
    }


def assert_no_projection(
    *,
    root: Path,
    base_url: str,
    opener: urllib.request.OpenerDirector,
    token: str,
    require_rotation_marker: bool = False,
) -> dict[str, Any]:
    fixture = read_private_json(root / "fixture.json")
    identity = urllib.parse.quote(fixture["identity_id"], safe="")
    checkpoint = urllib.parse.quote(fixture["checkpoint_id"], safe="")
    path = f"/api/v1/checkpoints/identity/{identity}/restores/{checkpoint}/receipt"
    try:
        _request_json(opener, base_url, "GET", path, token=token)
    except RuntimeError as error:
        if "HTTP 404" in str(error):
            rotation = None
            if require_rotation_marker:
                rotation = read_private_json(
                    root.parent / "credential-rotation-triggered.json"
                )
                if (
                    rotation.get("checkpoint_id") != fixture["checkpoint_id"]
                    or rotation.get("sequence") != fixture["sequence"]
                    or rotation.get("backend_preflight_completed") is not True
                ):
                    raise RuntimeError(
                        "P5-B4 credential rotation marker binding is invalid"
                    )
            return {
                "schema_version": "civitasos-p5b4-no-projection-result:v1",
                "passed": True,
                "checkpoint_id": fixture["checkpoint_id"],
                "receipt_status": 404,
                "credential_rotation": rotation,
            }
        raise
    raise RuntimeError("P5-B4 rejected checkpoint unexpectedly has a Receipt")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument(
        "action",
        choices=(
            "capture",
            "capture-next",
            "run-agent",
            "projection",
            "stale-replay",
            "assert-no-projection",
        ),
    )
    root.add_argument("--require-rotation-marker", action="store_true")
    root.add_argument("--root", type=Path, required=True)
    root.add_argument("--base-url", required=True)
    root.add_argument("--ca", type=Path, required=True)
    root.add_argument("--cert", type=Path, required=True)
    root.add_argument("--key", type=Path, required=True)
    root.add_argument("--service-secret-file", type=Path, required=True)
    root.add_argument(
        "--fault-point",
        choices=(
            "backend_sigkill_before_activation_ack",
            "agent_runner_sigkill_after_runtime_sqlite_commit",
            "credential_rotation_after_preflight",
        ),
    )
    return root


def main() -> int:
    args = parser().parse_args()
    root = args.root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    opener = _opener(args.ca, args.cert, args.key)
    service_secret = args.service_secret_file.read_text().strip()
    token = _service_token(opener, args.base_url, service_secret)
    if args.action in {"capture", "capture-next"}:
        result = capture(
            root=root,
            base_url=args.base_url,
            opener=opener,
            token=token,
            force_next=args.action == "capture-next",
        )
    elif args.action == "run-agent":
        result = asyncio.run(
            run_agent(
                root=root,
                base_url=args.base_url,
                opener=opener,
                token=token,
                fault_point=args.fault_point,
            )
        )
    elif args.action == "projection":
        result = projection(root=root, base_url=args.base_url, opener=opener, token=token)
    elif args.action == "stale-replay":
        result = stale_replay(
            root=root, base_url=args.base_url, opener=opener, token=token
        )
    else:
        result = assert_no_projection(
            root=root,
            base_url=args.base_url,
            opener=opener,
            token=token,
            require_rotation_marker=args.require_rotation_marker,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
