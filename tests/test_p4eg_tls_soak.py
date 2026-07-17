import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.p4ef_multivm_tls_drill as p4ef
import scripts.p4eg_tls_soak as p4eg
from scripts.p4ef_multivm_tls_drill import prepare_materials, sha256
from scripts.p4eg_tls_soak import (
    PersistentSoakIdentityStore,
    ROUND_SCHEMA,
    SUMMARY_SCHEMA,
    append_jsonl,
    authorize,
    journal_payload_sha256,
    load_rounds,
)


def assets(tmp_path: Path) -> tuple[Path, Path, Path]:
    candidate = tmp_path / "candidate"
    frontend = tmp_path / "frontend"
    materials = tmp_path / "materials"
    candidate.write_bytes(b"candidate")
    frontend.mkdir()
    (frontend / "index.html").write_text("ready")
    prepare_materials(
        argparse.Namespace(output_dir=str(materials), node=[], valid_days=7)
    )
    return candidate, frontend, materials


def auth_args(
    candidate: Path,
    frontend: Path,
    materials: Path,
    output: Path,
    *,
    hours: int = 1,
    previous_summary: Path | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        hours=hours,
        candidate_bin=str(candidate),
        frontend_build_dir=str(frontend),
        materials_dir=str(materials),
        previous_summary=str(previous_summary) if previous_summary else None,
        output=str(output),
        operator_id="test-operator",
        remote_root="/tmp/civitasos-p4eg-test",
        backend_port=18444,
        frontend_port=18443,
        round_interval_seconds=60.0,
        browser_every_rounds=15,
        restart_every_rounds=15,
        authorization_grace_seconds=3600,
        ack_private_beta_soak=True,
    )


def passed_summary(path: Path, hours: int) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": SUMMARY_SCHEMA,
                "passed": True,
                "status": "passed",
                "tier_hours": hours,
                "requested_duration_seconds": hours * 3600,
                "elapsed_seconds": hours * 3600,
                "cleanup": {"passed": True},
            }
        )
    )


def test_stage_authorization_binds_previous_passed_summary(tmp_path: Path) -> None:
    candidate, frontend, materials = assets(tmp_path)
    first = tmp_path / "1h-auth.json"
    assert authorize(auth_args(candidate, frontend, materials, first)) == 0
    assert json.loads(first.read_text())["previous_summary_sha256"] is None

    previous = tmp_path / "1h-summary.json"
    passed_summary(previous, 1)
    second = tmp_path / "8h-auth.json"
    assert authorize(
        auth_args(
            candidate,
            frontend,
            materials,
            second,
            hours=8,
            previous_summary=previous,
        )
    ) == 0
    assert json.loads(second.read_text())["previous_summary_sha256"] == sha256(previous)


def test_stage_authorization_rejects_missing_dependency_and_tampering(tmp_path: Path) -> None:
    candidate, frontend, materials = assets(tmp_path)
    with pytest.raises(SystemExit, match="requires a passed 1h summary"):
        authorize(auth_args(candidate, frontend, materials, tmp_path / "auth.json", hours=8))

    output = tmp_path / "1h-auth.json"
    authorize(auth_args(candidate, frontend, materials, output))
    (materials / "vm1.service").write_text("tampered\n")
    with pytest.raises(SystemExit, match="material hash mismatch"):
        authorize(auth_args(candidate, frontend, materials, tmp_path / "other.json"))


def test_round_journal_detects_payload_and_evidence_tampering(tmp_path: Path) -> None:
    evidence = tmp_path / "round-1.json"
    evidence.write_text('{"passed":true}\n')
    record = {
        "schema_version": ROUND_SCHEMA,
        "round": 1,
        "passed": True,
        "evidence": str(evidence),
        "evidence_sha256": sha256(evidence),
    }
    record["journal_payload_sha256"] = journal_payload_sha256(record)
    journal = tmp_path / "rounds.jsonl"
    append_jsonl(journal, record)
    assert load_rounds(journal) == [record]

    evidence.write_text('{"passed":false}\n')
    with pytest.raises(RuntimeError, match="evidence hash mismatch"):
        load_rounds(journal)

    evidence.write_text('{"passed":true}\n')
    tampered = json.loads(journal.read_text())
    tampered["passed"] = False
    journal.write_text(json.dumps(tampered) + "\n")
    with pytest.raises(RuntimeError, match="payload hash mismatch"):
        load_rounds(journal)


def test_persistent_identity_store_registers_once_and_reauthenticates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def fake_identity_token(
        node,
        frontend_port,
        service_token,
        alias,
        *,
        signing_key,
        agent_id,
    ):
        calls.append(
            {
                "node": node.node_id,
                "agent_id": agent_id,
                "public_key": signing_key.verify_key.encode().hex(),
                "alias": alias,
            }
        )
        return agent_id or "did:civ:fixed-requester", "jwt"

    monkeypatch.setattr(p4eg, "identity_token", fake_identity_token)
    store = PersistentSoakIdentityStore(tmp_path, "p4eg-test:authorization")
    node = SimpleNamespace(node_id="vm1")

    first = store.token_for(node, 18443, "service-token", "requester")
    second = store.token_for(node, 18443, "service-token", "requester")

    assert first == second == ("did:civ:fixed-requester", "jwt")
    assert [call["agent_id"] for call in calls] == [None, "did:civ:fixed-requester"]
    assert calls[0]["public_key"] == calls[1]["public_key"]
    identity_path = tmp_path / "private" / "identities" / "vm1-requester.json"
    assert identity_path.stat().st_mode & 0o777 == 0o600
    assert len(store.inventory()) == 1


def test_persistent_identity_store_rejects_binding_and_permission_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        p4eg,
        "identity_token",
        lambda *args, agent_id=None, **kwargs: (agent_id or "did:civ:fixed", "jwt"),
    )
    node = SimpleNamespace(node_id="vm1")
    store = PersistentSoakIdentityStore(tmp_path, "authorization-1")
    store.token_for(node, 18443, "service-token", "worker")

    identity_path = tmp_path / "private" / "identities" / "vm1-worker.json"
    with pytest.raises(RuntimeError, match="binding mismatch"):
        PersistentSoakIdentityStore(tmp_path, "authorization-2").token_for(
            node, 18443, "service-token", "worker"
        )

    os.chmod(identity_path, 0o644)
    with pytest.raises(RuntimeError, match="permissions are too broad"):
        store.token_for(node, 18443, "service-token", "worker")


def test_candidate_task_smoke_uses_persistent_identity_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materials = tmp_path / "materials"
    materials.mkdir()
    nodes = [
        SimpleNamespace(node_id=f"vm{index}", node_ip=f"192.0.2.{index}")
        for index in range(1, 4)
    ]
    for node in nodes:
        (materials / f"{node.node_id}.service").write_text("service-secret\n")
    roles = []

    def provider(node, frontend_port, service_token, role):
        roles.append(role)
        return f"did:civ:{role}", f"{role}-token"

    def fake_api_request(node, frontend_port, path, payload=None, token=None):
        if path == "/api/v1/auth/service-token":
            return 200, {"data": {"token": "service-token"}}
        if path == "/api/v1/a2a/pool/post":
            return 201, {"task_id": "task-1", "auto_claimed_by": None}
        if path in {"/api/v1/a2a/pool/claim", "/api/v1/a2a/task/execute"}:
            return 200, {}
        raise AssertionError(path)

    monkeypatch.setattr(p4ef, "api_request", fake_api_request)
    monkeypatch.setattr(
        p4ef,
        "wait_for_settled_receipt",
        lambda *args, **kwargs: ({"fact_count": 5, "receipt_hash": "hash"}, 1, 0.1),
    )
    monkeypatch.setattr(
        p4ef,
        "api_text_request",
        lambda *args, **kwargs: (200, "civitasos_evidence_export_pending 0"),
    )

    first = p4ef.candidate_task_smoke(
        nodes,
        materials,
        18443,
        tmp_path / "task-report-1.json",
        identity_provider=provider,
    )
    second = p4ef.candidate_task_smoke(
        nodes,
        materials,
        18443,
        tmp_path / "task-report-2.json",
        identity_provider=provider,
    )

    assert roles == ["requester", "worker"] * 6
    assert first["identity_mode"] == second["identity_mode"] == "stage_persistent"
    assert first["passed"] is second["passed"] is True
    assert [item["requester_id"] for item in first["observations"]] == [
        item["requester_id"] for item in second["observations"]
    ]
    assert [item["worker_id"] for item in first["observations"]] == [
        item["worker_id"] for item in second["observations"]
    ]
