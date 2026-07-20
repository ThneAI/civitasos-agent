"""Provision 40 controlled-beta J1-D participant identities and isolation slots."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pkcs11
from nacl.signing import VerifyKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_collection import COLLECTION_SCHEMA
from benchmarks.j1.qualification_participant_provisioning import (
    build_pairing_proposal,
    build_participant_profile,
    participant_id,
)
from benchmarks.j1.qualification_roster import validate_qualification_protocol
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


PROVISIONING_SCHEMA = "j1-qualification-participant-provisioning:v1"
PARTICIPANT_COUNT = 40


def provision_participants(
    *,
    provisioning_id: str,
    proposal_id: str,
    created_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    qualification_protocol_path: Path,
    collection_manifest_path: Path,
    module_path: str,
    token_label: str,
    pin: str,
    container_image: str,
    agent_revision: str,
    runtime_revision: str,
    output_root: Path,
    limitations_acknowledged: bool,
) -> dict[str, Any]:
    if not limitations_acknowledged:
        raise ValueError("SoftHSM limitations must be explicitly acknowledged")
    if output_root.exists():
        raise ValueError(f"output already exists: {output_root}")
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    protocol = _read_private_object(qualification_protocol_path)
    request = _read_private_object(DEFAULT_REQUEST, enforce_private=False)
    protocol_hash = canonical_sha256(protocol)
    failures = validate_qualification_protocol(
        protocol, admission_request_sha256=canonical_sha256(request)
    )
    collection = _read_private_object(collection_manifest_path)
    failures.extend(_collection_failures(collection, protocol_hash))
    failures.extend(
        _metadata_failures(
            provisioning_id,
            proposal_id,
            created_at,
            authorization_id,
            authorization_statement_sha256,
            agent_revision,
            runtime_revision,
        )
    )
    if failures:
        raise ValueError(f"participant provisioning preflight failed: {failures}")
    module = Path(module_path).resolve()
    module_sha256 = hashlib.sha256(module.read_bytes()).hexdigest()
    image_id = _docker_image_id(container_image)
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    if _decode(token.model) != "SoftHSM v2":
        raise ValueError(f"token is not SoftHSM v2: {_decode(token.model)}")
    pin_state = inspect_token_pin_state(
        module_path=str(module), token_label=token_label
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    profiles_root = output_root / "profiles"
    states_root = output_root / "states"
    profiles_root.mkdir(mode=0o700)
    states_root.mkdir(mode=0o700)
    created_containers: list[str] = []
    created_keys: list[Any] = []
    profiles: list[dict[str, Any]] = []
    try:
        with token.open(user_pin=pin, rw=True) as session:
            key_specs = _key_specs(provisioning_id)
            _preflight_key_inventory(session, key_specs)
            _preflight_container_inventory(key_specs, provisioning_id)
            try:
                for index, key_label, key_id in key_specs:
                    public_key, private_key = session.generate_keypair(
                        pkcs11.KeyType.EC_EDWARDS,
                        public_template={
                            pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570"),
                            pkcs11.Attribute.VERIFY: True,
                        },
                        private_template={
                            pkcs11.Attribute.SIGN: True,
                            pkcs11.Attribute.SENSITIVE: True,
                            pkcs11.Attribute.EXTRACTABLE: False,
                        },
                        label=key_label,
                        id=key_id,
                        store=True,
                    )
                    created_keys.extend((public_key, private_key))
                    encoded_point = bytes(public_key[pkcs11.Attribute.EC_POINT])
                    if encoded_point[:2] != b"\x04\x20" or len(encoded_point) != 34:
                        raise RuntimeError("SoftHSM returned unsupported Ed25519 point")
                    public_key_hex = encoded_point[2:].hex()
                    challenge = secrets.token_bytes(32)
                    signature = bytes(
                        private_key.sign(challenge, mechanism=pkcs11.Mechanism.EDDSA)
                    )
                    VerifyKey(bytes.fromhex(public_key_hex)).verify(
                        challenge, signature
                    )
                    profile = _build_live_profile(
                        index=index,
                        provisioning_id=provisioning_id,
                        created_at=created_at,
                        protocol_hash=protocol_hash,
                        authorization_id=authorization_id,
                        authorization_statement_sha256=authorization_statement_sha256,
                        public_key_hex=public_key_hex,
                        module=module,
                        module_sha256=module_sha256,
                        token=token,
                        key_label=key_label,
                        key_id=key_id,
                        challenge=challenge,
                        signature=signature,
                        private_key=private_key,
                        container_image=container_image,
                        image_id=image_id,
                        agent_revision=agent_revision,
                        runtime_revision=runtime_revision,
                        states_root=states_root,
                        created_containers=created_containers,
                    )
                    profiles.append(profile)
                    write_private_json(
                        profiles_root
                        / f"{profile['participant']['participant_id']}.json",
                        profile,
                    )
            except Exception:
                _destroy_keys(created_keys)
                created_keys.clear()
                raise
        proposal = build_pairing_proposal(
            proposal_id=proposal_id,
            created_at=created_at,
            qualification_protocol_sha256=protocol_hash,
            profiles=profiles,
            assignment_nonce=secrets.token_bytes(32),
        )
        proposal_path = output_root / "pairing-proposal.review-required.json"
        write_private_json(proposal_path, proposal)
        report = _provisioning_report(
            provisioning_id=provisioning_id,
            created_at=created_at,
            protocol_hash=protocol_hash,
            collection_manifest_path=collection_manifest_path,
            profiles_root=profiles_root,
            profiles=profiles,
            proposal_path=proposal_path,
            token=token,
            module=module,
            module_sha256=module_sha256,
            image_id=image_id,
        )
        write_private_json(output_root / "provisioning-report.json", report)
        return report
    except Exception:
        _rollback(created_containers, created_keys, output_root)
        raise


def _build_live_profile(
    *,
    index: int,
    provisioning_id: str,
    created_at: str,
    protocol_hash: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    public_key_hex: str,
    module: Path,
    module_sha256: str,
    token: Any,
    key_label: str,
    key_id: bytes,
    challenge: bytes,
    signature: bytes,
    private_key: Any,
    container_image: str,
    image_id: str,
    agent_revision: str,
    runtime_revision: str,
    states_root: Path,
    created_containers: list[str],
) -> dict[str, Any]:
    participant = participant_id(public_key_hex)
    state_root = states_root / participant
    state_root.mkdir(mode=0o700)
    initial_state = {
        "schema_version": "j1-qualification-initial-state:v1",
        "participant_id": participant,
        "qualification_protocol_sha256": protocol_hash,
        "agent_revision": agent_revision,
        "runtime_revision": runtime_revision,
        "prior_mentorship_exposure": False,
        "memory_entry_count": 0,
        "relation_count": 0,
        "model_invocation_count": 0,
        "tick_count": 0,
        "execution_authorized": False,
    }
    initial_state["initial_state_sha256"] = canonical_sha256(initial_state)
    state_path = state_root / "initial-state.json"
    write_private_json(state_path, initial_state)
    container_name = _container_name(index, provisioning_id)
    container_id = _create_container(
        name=container_name,
        participant=participant,
        provisioning_id=provisioning_id,
        image=container_image,
        state_root=state_root,
    )
    created_containers.append(container_id)
    inspect = _docker_inspect(container_id)
    host_config = inspect["HostConfig"]
    isolation = {
        "isolation_id": container_id,
        "container_name": container_name,
        "container_image": container_image,
        "container_image_id": image_id,
        "container_config_sha256": canonical_sha256(
            {"Config": inspect["Config"], "HostConfig": host_config}
        ),
        "state_root": str(state_root.resolve()),
        "initial_state_artifact_sha256": hashlib.sha256(
            state_path.read_bytes()
        ).hexdigest(),
        "network_mode": host_config["NetworkMode"],
        "read_only_rootfs": host_config["ReadonlyRootfs"],
        "cap_drop_all": host_config["CapDrop"] == ["ALL"],
        "no_new_privileges": "no-new-privileges:true" in host_config["SecurityOpt"],
        "pids_limit": host_config["PidsLimit"],
        "memory_limit_bytes": host_config["Memory"],
        "nano_cpus": host_config["NanoCpus"],
        "exclusive_assignment": True,
        "container_started": inspect["State"]["Running"],
    }
    key_reference = {
        "provider": "pkcs11",
        "module_path": str(module),
        "token_label": _decode(token.label),
        "key_label": key_label,
        "key_id_hex": key_id.hex(),
    }
    return build_participant_profile(
        created_at=created_at,
        qualification_protocol_sha256=protocol_hash,
        authorization_id=authorization_id,
        authorization_statement_sha256=authorization_statement_sha256,
        public_key_hex=public_key_hex,
        credential_version=1,
        module_path=str(module),
        module_sha256=module_sha256,
        token_label=_decode(token.label),
        token_serial=_decode(token.serial),
        key_label=key_label,
        key_id_hex=key_id.hex(),
        key_reference_sha256=canonical_sha256(key_reference),
        challenge=challenge,
        signature=signature,
        private_key_sensitive=bool(private_key[pkcs11.Attribute.SENSITIVE]),
        private_key_extractable=bool(private_key[pkcs11.Attribute.EXTRACTABLE]),
        initial_state=initial_state,
        isolation=isolation,
    )


def _create_container(
    *, name: str, participant: str, provisioning_id: str, image: str, state_root: Path
) -> str:
    command = [
        "docker",
        "create",
        "--name",
        name,
        "--label",
        f"civitasos.j1q.provisioning={provisioning_id}",
        "--label",
        f"civitasos.j1q.participant={participant}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "0.25",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16777216",
        "--mount",
        f"type=bind,src={state_root.resolve()},dst=/app/data",
        image,
        "python",
        "-c",
        "raise SystemExit('J1-D execution authorization required')",
    ]
    return _run(command).strip()


def _docker_inspect(container_id: str) -> dict[str, Any]:
    value = json.loads(_run(["docker", "inspect", container_id]))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeError("unexpected Docker inspect response")
    return value[0]


def _docker_image_id(image: str) -> str:
    value = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    image_id = value.strip()
    if not image_id.startswith("sha256:"):
        raise ValueError(f"Docker image is not content-addressed: {image}")
    return image_id


def _preflight_container_inventory(
    specs: list[tuple[int, str, bytes]], provisioning_id: str
) -> None:
    conflicts = []
    for index, _, _ in specs:
        name = _container_name(index, provisioning_id)
        result = subprocess.run(
            ["docker", "container", "inspect", name],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            conflicts.append(name)
    if conflicts:
        raise ValueError(f"participant Docker containers already exist: {conflicts}")


def _preflight_key_inventory(session: Any, specs: list[tuple[int, str, bytes]]) -> None:
    for _, label, key_id in specs:
        if list(session.get_objects({pkcs11.Attribute.LABEL: label})):
            raise ValueError(f"participant PKCS#11 key label already exists: {label}")
        if list(session.get_objects({pkcs11.Attribute.ID: key_id})):
            raise ValueError(
                f"participant PKCS#11 key ID already exists: {key_id.hex()}"
            )


def _key_specs(provisioning_id: str) -> list[tuple[int, str, bytes]]:
    return [
        (
            index,
            f"{provisioning_id}-participant-{index:02d}",
            hashlib.sha256(f"{provisioning_id}:{index}".encode()).digest()[:16],
        )
        for index in range(1, PARTICIPANT_COUNT + 1)
    ]


def _container_name(index: int, provisioning_id: str) -> str:
    digest = hashlib.sha256(provisioning_id.encode()).hexdigest()[:8]
    return f"civitas-j1q-{digest}-{index:02d}"


def _provisioning_report(
    *,
    provisioning_id: str,
    created_at: str,
    protocol_hash: str,
    collection_manifest_path: Path,
    profiles_root: Path,
    profiles: list[dict[str, Any]],
    proposal_path: Path,
    token: Any,
    module: Path,
    module_sha256: str,
    image_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": PROVISIONING_SCHEMA,
        "passed": True,
        "state": "participant_identities_provisioned_pairing_review_required",
        "provisioning_id": provisioning_id,
        "created_at": created_at,
        "qualification_protocol_sha256": protocol_hash,
        "collection_manifest": _artifact(collection_manifest_path),
        "participant_count": len(profiles),
        "participant_profile_sha256": sorted(
            profile["profile_sha256"] for profile in profiles
        ),
        "profiles_root": str(profiles_root.resolve()),
        "pairing_proposal": _artifact(proposal_path),
        "pkcs11_boundary": {
            "module_path": str(module),
            "module_sha256": module_sha256,
            "token_label": _decode(token.label),
            "token_serial": _decode(token.serial),
            "unique_key_count": len(profiles),
            "private_keys_sensitive": True,
            "private_keys_extractable": False,
            "token_store_copyable": True,
            "physical_hsm_claimed": False,
            "production_custody_claimed": False,
            "pin_recorded": False,
        },
        "isolation_boundary": {
            "provider": "docker",
            "container_count": len(profiles),
            "container_image_id": image_id,
            "all_containers_started": False,
            "network_mode": "none",
            "read_only_rootfs": True,
            "cap_drop_all": True,
            "no_new_privileges": True,
        },
        "readiness": {
            "participant_identities_provisioned": len(profiles) == PARTICIPANT_COUNT,
            "pairing_operator_reviewed": False,
            "participant_evidence_complete": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "identity_and_isolation_provisioning_only": True,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "operator_pairing_review_automated": False,
        },
    }


def _collection_failures(collection: dict[str, Any], protocol_hash: str) -> list[str]:
    failures = []
    if collection.get("schema_version") != COLLECTION_SCHEMA:
        failures.append("collection_manifest_schema_invalid")
    if collection.get("passed") is not True:
        failures.append("collection_manifest_not_passed")
    if collection.get("status") != "collection_open_real_participant_evidence_required":
        failures.append("collection_manifest_status_invalid")
    if collection.get("qualification_protocol_sha256") != protocol_hash:
        failures.append("collection_manifest_protocol_hash_mismatch")
    declared = collection.get("manifest_sha256")
    body = {key: item for key, item in collection.items() if key != "manifest_sha256"}
    if declared != canonical_sha256(body):
        failures.append("collection_manifest_hash_mismatch")
    readiness = collection.get("readiness")
    if not isinstance(readiness, dict):
        failures.append("collection_manifest_readiness_invalid")
    else:
        if readiness.get("qualification_protocol_frozen") is not True:
            failures.append("collection_manifest_protocol_not_frozen")
        for field in (
            "participant_evidence_complete",
            "independent_roster_review_required",
            "real_participant_roster_bound",
            "single_use_authorization_issued",
            "controlled_experiment_execution_ready",
        ):
            if readiness.get(field) is not False:
                failures.append(f"collection_manifest_{field}_must_be_false")
    return failures


def _metadata_failures(*values: str) -> list[str]:
    failures = []
    for index, value in enumerate(values):
        if not str(value).strip():
            failures.append(f"provisioning_metadata_{index}_missing")
    try:
        parsed = datetime.fromisoformat(values[2].replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        failures.append("provisioning_created_at_invalid")
    if len(values[4]) != 64 or any(
        char not in "0123456789abcdef" for char in values[4]
    ):
        failures.append("authorization_statement_hash_invalid")
    return failures


def _read_private_object(path: Path, *, enforce_private: bool = True) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"JSON artifact unreadable: {path}")
    if enforce_private and path.stat().st_mode & 0o077:
        raise ValueError(f"JSON artifact permissions too open: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no command output"
        raise RuntimeError(
            f"{command[0]} failed with exit code {result.returncode}: {detail}"
        )
    return result.stdout


def _rollback(containers: list[str], keys: list[Any], output_root: Path) -> None:
    for container in reversed(containers):
        subprocess.run(
            ["docker", "rm", "-f", container],
            check=False,
            capture_output=True,
            text=True,
        )
    _destroy_keys(keys)
    shutil.rmtree(output_root, ignore_errors=True)


def _destroy_keys(keys: list[Any]) -> None:
    for key in reversed(keys):
        try:
            key.destroy()
        except pkcs11.PKCS11Error:
            pass


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii").strip()
    return str(value).strip()


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provisioning-id", required=True)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument("--created-at", default=_timestamp())
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--collection-manifest", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--container-image", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--runtime-revision", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--acknowledge-soft-token-limitations", action="store_true")
    args = parser.parse_args()
    if not args.acknowledge_soft_token_limitations:
        parser.error("--acknowledge-soft-token-limitations is required")
    state = inspect_token_pin_state(
        module_path=args.module, token_label=args.token_label
    )
    if not state["safe_to_attempt_user_login"]:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "blocked_user_pin_retry_risk",
                    "token_pin_state": state,
                },
                indent=2,
            )
        )
        return 1
    pin = read_pin(args.pin_file)
    try:
        try:
            report = provision_participants(
                provisioning_id=args.provisioning_id,
                proposal_id=args.proposal_id,
                created_at=args.created_at,
                authorization_id=args.authorization_id,
                authorization_statement_sha256=args.authorization_statement_sha256,
                qualification_protocol_path=args.qualification_protocol,
                collection_manifest_path=args.collection_manifest,
                module_path=args.module,
                token_label=args.token_label,
                pin=pin,
                container_image=args.container_image,
                agent_revision=args.agent_revision,
                runtime_revision=args.runtime_revision,
                output_root=args.output_root,
                limitations_acknowledged=True,
            )
        except pkcs11.exceptions.PinIncorrect:
            report = {
                "schema_version": PROVISIONING_SCHEMA,
                "passed": False,
                "state": "blocked_user_pin_incorrect_stop_retrying",
                "pin_recorded": False,
                "participant_keys_created": False,
            }
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
