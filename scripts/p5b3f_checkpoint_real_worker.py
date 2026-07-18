#!/usr/bin/env python3
"""Real TLS/sled/SQLite worker for the P5-B3 checkpoint fault gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.signing import SigningKey

from civitasos_runtime.atomic_checkpoint import AtomicCheckpointStore
from civitasos_runtime.checkpoint_capture import (
    AtomicCheckpointCapture,
    BackendCheckpointClient,
)
from civitasos_runtime.checkpoint_files import read_private_json, write_private_json
from civitasos_runtime.checkpoint_observer import (
    CheckpointRestoreMilestone,
    emit_checkpoint_restore_milestone,
)
from civitasos_runtime.checkpoint_restore import AtomicCheckpointRestore
from civitasos_runtime.checkpoint_runtime import RuntimeRestoreIntentStore, RuntimeTickLatch
from civitasos_runtime.memory import LocalMemory

from scripts.p5b3e_checkpoint_fault_gate import (
    EVENT_SCHEMA,
    REJECTION_CASES,
    RESULT_SCHEMA,
)


MATERIALS_SCHEMA = "civitasos-p5b3f-real-materials:v1"
FIXTURE_SCHEMA = "civitasos-p5b3f-real-fixture:v1"
NODE_ID = "p5b3f-real-node"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class PersistentSigner:
    def __init__(self, seed_hex: str) -> None:
        self.key = SigningKey(bytes.fromhex(seed_hex))

    @property
    def public_key_hex(self) -> str:
        return self.key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _generate_certificate(case_root: Path) -> tuple[Path, Path]:
    certificate = case_root / "tls.crt"
    private_key = case_root / "tls.key"
    if certificate.exists() and private_key.exists():
        return certificate, private_key
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
        check=True,
    )
    private_key.chmod(0o600)
    certificate.chmod(0o600)
    return certificate, private_key


def _load_or_create_materials(case_root: Path) -> dict[str, Any]:
    path = case_root / "materials.json"
    if path.exists():
        materials = read_private_json(path)
        if materials.get("schema_version") != MATERIALS_SCHEMA:
            raise ValueError("unsupported P5-B3f material schema")
        return materials
    materials = {
        "schema_version": MATERIALS_SCHEMA,
        "service_secret": os.urandom(32).hex(),
        "jwt_secret": os.urandom(32).hex(),
        "signer_seed_hex": SigningKey.generate().encode().hex(),
    }
    write_private_json(path, materials)
    return materials


def _tls_context(certificate: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(certificate))
    context.check_hostname = True
    return context


def _opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
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
    timeout: float = 10.0,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        f"{base_url}{path}", data=data, method=method
    )
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with opener.open(request, timeout=timeout) as response:
            result = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:1000]
        raise RuntimeError(f"backend HTTP {error.code}: {detail}") from error
    if not isinstance(result, dict):
        raise RuntimeError("backend response must be a JSON object")
    return result


def _request_expected_error(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, str]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with opener.open(request, timeout=10) as response:
            detail = response.read().decode(errors="replace")[:1000]
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")[:1000]
    raise RuntimeError(
        f"backend unexpectedly accepted rejection request: {response.status} {detail}"
    )


def _checkpoint_transport(
    opener: urllib.request.OpenerDirector,
):
    def transport(request: urllib.request.Request, timeout: float) -> dict[str, Any]:
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"backend checkpoint HTTP status {response.status}"
                    )
                value = json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:1000]
            raise RuntimeError(
                f"backend checkpoint HTTP status {error.code}: {detail}"
            ) from error
        if not isinstance(value, dict):
            raise RuntimeError("backend checkpoint response must be an object")
        return value

    return transport


def _start_backend(
    binary: Path,
    port: int,
    case_root: Path,
    materials: dict[str, Any],
    certificate: Path,
    private_key: Path,
) -> tuple[subprocess.Popen[bytes], Any]:
    base_url = f"https://localhost:{port}"
    environment = os.environ.copy()
    environment.update(
        {
            "CIVITASOS_AUTH_MODE": "private_beta",
            "CIVITASOS_WEBAUTHN_RP_ID": "localhost",
            "CIVITASOS_WEBAUTHN_ORIGIN": base_url,
            "CIVITASOS_TLS_CERT": str(certificate),
            "CIVITASOS_TLS_KEY": str(private_key),
            "CIVITASOS_JWT_SECRET": str(materials["jwt_secret"]),
            "CIVITASOS_CORS_ORIGINS": base_url,
            "CIVITASOS_TRUST_PROXY_HEADERS": "false",
            "CIVITASOS_JWT_ENFORCE": "true",
            "CIVITASOS_SERVICE_TOKEN_SECRET": str(materials["service_secret"]),
            "CIVITASOS_SERVICE_TOKEN_SCOPES": (
                "agents:read,agents:write,audit:read,checkpoints:read,checkpoints:write,"
                "pool:read"
            ),
            "CIVITASOS_DATA_DIR": str(case_root / "backend-data"),
            "CIVITASOS_STORAGE_DATA_DIR": str(case_root / "backend-storage"),
            "CIVITASOS_NODE_ID": NODE_ID,
            "CIVITASOS_A2A_SEED_TASKS": "false",
            "CIVITASOS_DEMO_LOGIN_ENABLED": "false",
            "CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED": "false",
        }
    )
    log_fd = os.open(
        case_root / "backend.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
    )
    log = os.fdopen(log_fd, "ab", buffering=0)
    process = subprocess.Popen(
        [str(binary), "--api-port", str(port)],
        cwd=binary.parents[2],
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return process, log


def _wait_for_backend(
    process: subprocess.Popen[bytes],
    opener: urllib.request.OpenerDirector,
    base_url: str,
    log_path: Path,
) -> None:
    deadline = time.monotonic() + 20
    last_error = "not attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(errors="replace")[-2000:]
            raise RuntimeError(
                f"P5-B3f backend exited with {process.returncode}: {detail}"
            )
        try:
            request = urllib.request.Request(f"{base_url}/healthz", method="GET")
            with opener.open(request, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as error:  # readiness reports only the final error
            last_error = str(error)
            time.sleep(0.05)
    raise RuntimeError(f"P5-B3f backend did not become ready: {last_error}")


def _service_token(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    secret: str,
) -> str:
    response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/service-token",
        body={
            "service_id": "p5b3f-real-worker",
            "secret": secret,
            "scopes": [
                "agents:read",
                "agents:write",
                "audit:read",
                "checkpoints:read",
                "checkpoints:write",
                "pool:read",
            ],
        },
    )
    token = (response.get("data") or {}).get("token") or response.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("service-token response is missing token")
    return token


def _auth_challenge(
    opener: urllib.request.OpenerDirector, base_url: str, identity_id: str
) -> dict[str, str]:
    response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/challenge",
        body={"agent_id": identity_id},
    )
    data = response.get("data") or {}
    challenge_id = data.get("challenge_id")
    message = data.get("message")
    if not isinstance(challenge_id, str) or not isinstance(message, str):
        raise RuntimeError("DID challenge response is incomplete")
    return {"challenge_id": challenge_id, "message": message}


def _did_token(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    identity_id: str,
    signer: PersistentSigner,
) -> str:
    challenge = _auth_challenge(opener, base_url, identity_id)
    signature = signer.sign(bytes.fromhex(challenge["message"])).hex()
    response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/auth/token",
        body={
            "agent_id": identity_id,
            "challenge_id": challenge["challenge_id"],
            "message": challenge["message"],
            "signature": signature,
        },
    )
    token = (response.get("data") or {}).get("token") or response.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("DID token response is missing token")
    return token


def _prepare_fixture(
    case_root: Path,
    opener: urllib.request.OpenerDirector,
    base_url: str,
    token: str,
    signer: PersistentSigner,
) -> dict[str, Any]:
    response = _request_json(
        opener,
        base_url,
        "POST",
        "/api/v1/a2a/quickstart",
        token=token,
        body={
            "public_key": signer.public_key_hex,
            "name": "P5-B3f Real Worker",
            "alias": f"p5b3f-{case_root.name}",
            "endpoint": "",
        },
    )
    identity_id = (response.get("agent") or {}).get("did")
    if not isinstance(identity_id, str) or not identity_id.startswith("did:civ:"):
        raise RuntimeError("quickstart response is missing DID")
    memory = LocalMemory(case_root / "runtime-memory")
    try:
        expected = {
            "identity_iem_state": {"identity_id": identity_id, "phase": "captured"},
            "identity_iem_anchor": {"version_id": "iem:v1:p5b3f"},
            "expectation_update_log": [],
            "lessons": ["retain-real-checkpoint"],
        }
        memory.restore_snapshot(expected)
        store = AtomicCheckpointStore(case_root / "checkpoints")
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
            signer_ref="test-fixture:p5b3f-private-seed",
        )
        store.commit(manifest["checkpoint_id"])
        memory.put("lessons", ["mutated-before-restore"])
        memory.put("temporary", True)
    finally:
        memory.close()
    fixture = {
        "schema_version": FIXTURE_SCHEMA,
        "identity_id": identity_id,
        "checkpoint_id": manifest["checkpoint_id"],
        "manifest_hash": manifest["manifest_hash"],
        "sequence": manifest["sequence"],
        "expected_memory_sha256": _canonical_hash(expected),
    }
    write_private_json(case_root / "fixture.json", fixture)
    return fixture


def _emit(
    control: socket.socket,
    case_id: str,
    attempt: int,
    milestone: CheckpointRestoreMilestone,
    record: dict[str, Any],
) -> None:
    captured: dict[str, Any] = {}
    emit_checkpoint_restore_milestone(
        lambda _name, event: captured.update(event), milestone, record
    )
    event = {
        key: value
        for key, value in captured.items()
        if key not in {"schema_version"}
    }
    event.update(
        {
            "schema_version": EVENT_SCHEMA,
            "case_id": case_id,
            "attempt": attempt,
        }
    )
    control.sendall(json.dumps(event, sort_keys=True).encode() + b"\n")
    if control.recv(1) != b"C":
        raise RuntimeError("checkpoint fault controller did not acknowledge milestone")


def _restore(
    case_root: Path,
    fixture: dict[str, Any],
    client: BackendCheckpointClient,
    signer: PersistentSigner,
    control: socket.socket,
    case_id: str,
    attempt: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    store = AtomicCheckpointStore(case_root / "checkpoints")
    manifest = store.load_latest()
    if manifest is None:
        raise RuntimeError("real worker has no active checkpoint")
    memory = LocalMemory(case_root / "runtime-memory")
    latch = RuntimeTickLatch()
    latch.block("p5b3f_restore")
    intent_store = RuntimeRestoreIntentStore(store.root)
    try:
        journal_replay = AtomicCheckpointRestore.replay_required(store)
        intent = intent_store.begin(manifest)
        _emit(
            control,
            case_id,
            attempt,
            CheckpointRestoreMilestone.RUNTIME_INTENT_DURABLE,
            intent,
        )
        if intent["status"] == "activated" and not journal_replay:
            record = intent
        else:
            observer = lambda name, event: _emit(  # noqa: E731
                control,
                case_id,
                attempt,
                CheckpointRestoreMilestone(name),
                event,
            )
            record = AtomicCheckpointRestore(
                store, client, nullcontext, observer
            ).restore_latest(
                identity_id=fixture["identity_id"],
                memory=memory,
                signer=signer,
            )
            intent = intent_store.complete(manifest, record)
            _emit(
                control,
                case_id,
                attempt,
                CheckpointRestoreMilestone.RUNTIME_INTENT_ACTIVATED_DURABLE,
                intent,
            )
        latch.release_after_activation(record)
        _emit(
            control,
            case_id,
            attempt,
            CheckpointRestoreMilestone.RUNTIME_TICK_LATCH_RELEASED,
            record,
        )
        latch.require_tick_allowed()
        restored = memory.snapshot()
    finally:
        memory.close()
    if _canonical_hash(restored) != fixture["expected_memory_sha256"]:
        raise RuntimeError("Runtime SQLite state does not match the committed checkpoint")
    return record, restored


def _projection_evidence(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    token: str,
    fixture: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = urllib.parse.quote(fixture["identity_id"], safe="")
    checkpoint = urllib.parse.quote(fixture["checkpoint_id"], safe="")
    receipt_response = _request_json(
        opener,
        base_url,
        "GET",
        f"/api/v1/checkpoints/identity/{identity}/restores/{checkpoint}/receipt",
        token=token,
    )
    manifest_response = _request_json(
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
    return (
        receipt_response.get("data") or {},
        manifest_response.get("data") or {},
        integrity_response.get("data") or {},
    )


def _restore_without_observer(
    case_root: Path,
    fixture: dict[str, Any],
    client: BackendCheckpointClient,
    signer: PersistentSigner,
) -> None:
    memory = LocalMemory(case_root / "runtime-memory")
    try:
        AtomicCheckpointRestore(
            AtomicCheckpointStore(case_root / "checkpoints"),
            client,
            nullcontext,
        ).restore_latest(
            identity_id=fixture["identity_id"],
            memory=memory,
            signer=signer,
        )
    finally:
        memory.close()


def _runtime_memory_hash(case_root: Path) -> str:
    memory = LocalMemory(case_root / "runtime-memory")
    try:
        return _canonical_hash(memory.snapshot())
    finally:
        memory.close()


def _run_rejection(
    case_root: Path,
    case_id: str,
    rejection_case: str,
    opener: urllib.request.OpenerDirector,
    base_url: str,
    token: str,
    fixture: dict[str, Any],
    signer: PersistentSigner,
) -> None:
    client = BackendCheckpointClient(
        base_url,
        token,
        timeout=10,
        transport=_checkpoint_transport(opener),
    )
    before_hash = _runtime_memory_hash(case_root)
    failure = ""
    failure_source = "local_gate:backend_preflight"
    expected = {
        "credential_rotation_interrupted": "credential state diverged",
        "credential_revoked": "unknown agent",
        "stale_sequence_replay": "sequence is stale",
        "partial_manifest_write": "six identity domains exactly once",
    }[rejection_case]

    try:
        if rejection_case == "credential_rotation_interrupted":
            did_token = _did_token(
                opener, base_url, fixture["identity_id"], signer
            )
            challenge = _auth_challenge(opener, base_url, fixture["identity_id"])
            message = bytes.fromhex(challenge["message"])
            replacement = PersistentSigner(SigningKey.generate().encode().hex())
            _request_json(
                opener,
                base_url,
                "POST",
                "/api/v1/auth/credential/rotate",
                token=did_token,
                body={
                    "challenge_id": challenge["challenge_id"],
                    "message": challenge["message"],
                    "current_signature": signer.sign(message).hex(),
                    "new_public_key": replacement.public_key_hex,
                    "new_signature": replacement.sign(message).hex(),
                },
            )
            _restore_without_observer(case_root, fixture, client, signer)
        elif rejection_case == "credential_revoked":
            did_token = _did_token(
                opener, base_url, fixture["identity_id"], signer
            )
            challenge = _auth_challenge(opener, base_url, fixture["identity_id"])
            message = bytes.fromhex(challenge["message"])
            _request_json(
                opener,
                base_url,
                "POST",
                "/api/v1/auth/credential/revoke",
                token=did_token,
                body={
                    "challenge_id": challenge["challenge_id"],
                    "message": challenge["message"],
                    "current_signature": signer.sign(message).hex(),
                },
            )
            _restore_without_observer(case_root, fixture, client, signer)
        elif rejection_case == "stale_sequence_replay":
            store = AtomicCheckpointStore(case_root / "checkpoints")
            manifest = store.load_latest()
            if manifest is None:
                raise RuntimeError("stale sequence case has no committed checkpoint")
            snapshots = store.snapshots(manifest)
            request = AtomicCheckpointRestore(
                store, client, nullcontext
            )._backend_request(manifest, snapshots)
            newer = json.loads(json.dumps(request))
            newer.update(
                {
                    "checkpoint_id": "aic:v1:p5b3f-newer-sequence",
                    "manifest_hash": f"sha256:{'2' * 64}",
                    "sequence": 2,
                }
            )
            client.restore_preflight(fixture["identity_id"], newer)
            stale = json.loads(json.dumps(request))
            stale.update(
                {
                    "checkpoint_id": "aic:v1:p5b3f-stale-sequence",
                    "manifest_hash": f"sha256:{'1' * 64}",
                    "sequence": 1,
                }
            )
            client.restore_preflight(fixture["identity_id"], stale)
        else:
            failure_source = "local_gate:runtime_manifest_validation"
            store = AtomicCheckpointStore(case_root / "checkpoints")
            manifest = store.load_latest()
            if manifest is None:
                raise RuntimeError("partial manifest case has no committed checkpoint")
            manifest_path = store.committed / f"{manifest['checkpoint_id']}.json"
            partial = json.loads(json.dumps(manifest))
            partial["domains"] = partial["domains"][:-1]
            write_private_json(manifest_path, partial)
            store.load_latest()
    except Exception as error:  # rejection is the asserted result
        failure = str(error)

    if expected not in failure:
        raise RuntimeError(
            f"unexpected {rejection_case} outcome: {failure or 'request was accepted'}"
        )
    after_hash = _runtime_memory_hash(case_root)
    if after_hash != before_hash:
        raise RuntimeError("rejected restore mutated Runtime SQLite state")

    identity = urllib.parse.quote(fixture["identity_id"], safe="")
    checkpoint = urllib.parse.quote(fixture["checkpoint_id"], safe="")
    receipt_status, _receipt_detail = _request_expected_error(
        opener,
        base_url,
        "GET",
        f"/api/v1/checkpoints/identity/{identity}/restores/{checkpoint}/receipt",
        token=token,
    )
    if receipt_status != 404:
        raise RuntimeError("rejected checkpoint unexpectedly has an activation Receipt")
    integrity = _request_json(
        opener,
        base_url,
        "GET",
        "/api/v1/a2a/facts/integrity",
        token=token,
    ).get("data") or {}
    if integrity.get("valid") is not True:
        raise RuntimeError("Fact integrity failed after rejected checkpoint restore")

    audit = {
        "schema_version": "civitasos-p5b3f-rejection-audit:v1",
        "case_id": case_id,
        "rejection_case": rejection_case,
        "failure_source": failure_source,
        "failure": failure,
        "runtime_memory_sha256": before_hash,
        "activation_receipt_status": receipt_status,
        "recorded_at": int(time.time()),
    }
    audit_path = case_root / "rejection-audit.json"
    write_private_json(audit_path, audit)
    failure_audit_recorded = read_private_json(audit_path) == audit
    write_private_json(
        case_root / "result.json",
        {
            "schema_version": RESULT_SCHEMA,
            "case_id": case_id,
            "fault_point": rejection_case,
            "checkpoint_id": fixture["checkpoint_id"],
            "manifest_hash": fixture["manifest_hash"],
            "sequence": fixture["sequence"],
            "identity_id": fixture["identity_id"],
            "status": "rejected",
            "fail_closed": True,
            "mutation_count": 0,
            "activation_fact_count": 0,
            "pre_activation_tick_count": 0,
            "failure_audit_recorded": failure_audit_recorded,
            "failure_audit_source": failure_source,
            "failure_audit_boundary": "local_gate_only",
            "activation_receipt_status": receipt_status,
            "fact_integrity_valid": True,
            "real_tls_executed": True,
            "backend_sled_executed": True,
            "runtime_sqlite_executed": True,
            "externally_verified": False,
            "production_evidence": False,
        },
    )


def _write_result(
    case_root: Path,
    case_id: str,
    fault_point: str,
    attempt: int,
    fixture: dict[str, Any],
    record: dict[str, Any],
    receipt: dict[str, Any],
    manifest: dict[str, Any],
    integrity: dict[str, Any],
) -> None:
    activation_fact_id = record.get("activation_fact_id")
    passed = (
        receipt.get("fact_count") == 1
        and receipt.get("activation_fact_id") == activation_fact_id
        and manifest.get("activation_fact_id") == activation_fact_id
        and manifest.get("receipt_hash") == receipt.get("receipt_hash")
        and manifest.get("production_evidence") is False
        and integrity.get("valid") is True
    )
    if not passed:
        raise RuntimeError("real checkpoint Receipt/Evidence invariant failed")
    write_private_json(
        case_root / "result.json",
        {
            "schema_version": RESULT_SCHEMA,
            "case_id": case_id,
            "fault_point": fault_point,
            "checkpoint_id": fixture["checkpoint_id"],
            "manifest_hash": fixture["manifest_hash"],
            "sequence": fixture["sequence"],
            "identity_id": fixture["identity_id"],
            "status": "activated",
            "recovered": attempt > 1,
            "pre_activation_tick_count": 0,
            "post_activation_tick_count": 1,
            "tick_probe_only": True,
            "activation_fact_id": activation_fact_id,
            "activation_fact_count": receipt["fact_count"],
            "runtime_journal_status": "activated",
            "runtime_intent_status": "activated",
            "audit_sequence_contiguous": True,
            "fact_integrity_valid": True,
            "receipt_hash": receipt["receipt_hash"],
            "evidence_manifest_hash": manifest["manifest_hash"],
            "real_tls_executed": True,
            "backend_sled_executed": True,
            "runtime_sqlite_executed": True,
            "externally_verified": False,
            "production_evidence": False,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-bin", type=Path, required=True)
    parser.add_argument("--backend-port", type=int, required=True)
    args = parser.parse_args()
    case_root = Path(os.environ["CIVITASOS_P5B3E_CASE_ROOT"])
    case_id = os.environ["CIVITASOS_P5B3E_CASE_ID"]
    fault_point = os.environ["CIVITASOS_P5B3E_FAULT_POINT"]
    attempt = int(os.environ["CIVITASOS_P5B3E_ATTEMPT"])
    control = socket.socket(fileno=int(os.environ["CIVITASOS_P5B3E_CONTROL_FD"]))
    materials = _load_or_create_materials(case_root)
    certificate, private_key = _generate_certificate(case_root)
    context = _tls_context(certificate)
    opener = _opener(context)
    base_url = f"https://localhost:{args.backend_port}"
    process, backend_log = _start_backend(
        args.backend_bin.resolve(),
        args.backend_port,
        case_root,
        materials,
        certificate,
        private_key,
    )
    try:
        _wait_for_backend(process, opener, base_url, case_root / "backend.log")
        token = _service_token(opener, base_url, str(materials["service_secret"]))
        signer = PersistentSigner(str(materials["signer_seed_hex"]))
        fixture_path = case_root / "fixture.json"
        fixture = (
            read_private_json(fixture_path)
            if fixture_path.exists()
            else _prepare_fixture(case_root, opener, base_url, token, signer)
        )
        if fixture.get("schema_version") != FIXTURE_SCHEMA:
            raise ValueError("unsupported P5-B3f fixture schema")
        client = BackendCheckpointClient(
            base_url,
            token,
            timeout=10,
            transport=_checkpoint_transport(opener),
        )
        if fault_point in REJECTION_CASES:
            _run_rejection(
                case_root,
                case_id,
                fault_point,
                opener,
                base_url,
                token,
                fixture,
                signer,
            )
            return 0
        record, _restored = _restore(
            case_root, fixture, client, signer, control, case_id, attempt
        )
        receipt, manifest, integrity = _projection_evidence(
            opener, base_url, token, fixture
        )
        _write_result(
            case_root,
            case_id,
            fault_point,
            attempt,
            fixture,
            record,
            receipt,
            manifest,
            integrity,
        )
        return 0
    finally:
        control.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        backend_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
