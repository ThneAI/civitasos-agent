"""Create signed J1-D cognitive baselines and participant consent Evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import canonical_sha256, read_json_object, write_private_json
from benchmarks.j1.qualification_baseline_consent import (
    build_cognitive_baseline,
    build_participant_consent,
)
from benchmarks.j1.qualification_pairing_review import validate_reviewed_pairing
from benchmarks.j1.qualification_participant_evidence import (
    PACKET_SCHEMA,
    validate_evidence_artifact,
    validate_packet_evidence_bindings,
    validate_participant_packet,
)
from benchmarks.j1.qualification_participant_provisioning import validate_participant_profile
from benchmarks.j1.qualification_reviewer_identity import validate_reviewer_identity_profile
from benchmarks.j1.qualification_roster import validate_qualification_protocol
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-baseline-consent-operation:v1"
MANIFEST_SCHEMA = "j1-qualification-baseline-consent-manifest:v1"
SOURCE_EVIDENCE_SUFFIX = {
    "identity_snapshot": "identity",
    "custody_provenance": "custody",
    "isolation_root": "isolation",
}


class _SessionSigner:
    def __init__(self, private_key: Any, public_key_hex: str) -> None:
        self._private_key = private_key
        self._public_key_hex = public_key_hex

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign(self, message: bytes) -> bytes:
        return bytes(self._private_key.sign(message, mechanism=pkcs11.Mechanism.EDDSA))


def preflight_baseline_consent(
    *,
    operation_id: str,
    attested_at: str,
    owner_authorization_id: str,
    owner_authorization_statement: str,
    owner_authorization_statement_sha256: str,
    qualification_protocol_path: Path,
    reviewed_pairing_path: Path,
    profiles_root: Path,
    states_root: Path,
    reviewer_profile_path: Path,
    source_evidence_root: Path,
    module_path: str,
    token_label: str,
    output_root: Path,
) -> dict[str, Any]:
    context = _load_context(
        operation_id=operation_id,
        attested_at=attested_at,
        owner_authorization_id=owner_authorization_id,
        owner_authorization_statement=owner_authorization_statement,
        owner_authorization_statement_sha256=owner_authorization_statement_sha256,
        qualification_protocol_path=qualification_protocol_path,
        reviewed_pairing_path=reviewed_pairing_path,
        profiles_root=profiles_root,
        states_root=states_root,
        reviewer_profile_path=reviewer_profile_path,
        source_evidence_root=source_evidence_root,
        module_path=module_path,
        token_label=token_label,
        output_root=output_root,
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": True,
        "state": "baseline_consent_preflight_passed_pin_not_read",
        "operation_id": operation_id,
        "qualification_protocol_sha256": context["protocol_hash"],
        "reviewed_pairing_sha256": context["reviewed_pairing"]["reviewed_pairing_sha256"],
        "counts": {"pairs": 20, "participants": 40, "source_evidence": 120},
        "pin_read": False,
        "hardware_contact_performed": False,
        "signature_performed": False,
    }


def create_baselines_and_consents(
    *,
    operation_id: str,
    attested_at: str,
    owner_authorization_id: str,
    owner_authorization_statement: str,
    owner_authorization_statement_sha256: str,
    qualification_protocol_path: Path,
    reviewed_pairing_path: Path,
    profiles_root: Path,
    states_root: Path,
    reviewer_profile_path: Path,
    source_evidence_root: Path,
    module_path: str,
    token_label: str,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    context = _load_context(
        operation_id=operation_id,
        attested_at=attested_at,
        owner_authorization_id=owner_authorization_id,
        owner_authorization_statement=owner_authorization_statement,
        owner_authorization_statement_sha256=owner_authorization_statement_sha256,
        qualification_protocol_path=qualification_protocol_path,
        reviewed_pairing_path=reviewed_pairing_path,
        profiles_root=profiles_root,
        states_root=states_root,
        reviewer_profile_path=reviewer_profile_path,
        source_evidence_root=source_evidence_root,
        module_path=module_path,
        token_label=token_label,
        output_root=output_root,
    )
    module = Path(module_path).resolve()
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    pin_state = inspect_token_pin_state(module_path=str(module), token_label=token_label)
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}")

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    evidence_root = output_root / "evidence"
    evidence_root.mkdir(mode=0o700)
    try:
        with token.open(user_pin=pin) as session:
            baselines, consents = _sign_evidence(session, context)
        packets = _write_and_validate_evidence(evidence_root, context, baselines, consents)
        manifest = _build_manifest(evidence_root, context, baselines, consents, packets)
        manifest_path = output_root / "baseline-consent-manifest.json"
        write_private_json(manifest_path, manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "signed_baselines_and_participant_consents_ready_roster_intake_required",
            "operation_id": operation_id,
            "attested_at": attested_at,
            "qualification_protocol_sha256": context["protocol_hash"],
            "reviewed_pairing_sha256": context["reviewed_pairing"]["reviewed_pairing_sha256"],
            "owner_authorization": {
                "authorization_id": owner_authorization_id,
                "statement": owner_authorization_statement,
                "authorization_statement_sha256": owner_authorization_statement_sha256,
                "source": "interactive_owner_authorization",
            },
            "manifest": _artifact(manifest_path),
            "evidence_root": str(evidence_root.resolve()),
            "counts": {
                "cognitive_baselines": len(baselines),
                "participant_consents": len(consents),
                "participant_packets": len(packets),
                "copied_public_state_evidence": 120,
            },
            "pkcs11_boundary": {
                "module_path": str(module),
                "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                "token_label": token_label,
                "single_session_login": True,
                "distinct_participant_signatures": len(consents),
                "pin_recorded": False,
            },
            "execution_boundary": {
                "cognitive_state_baseline_created": True,
                "performance_measurement_performed": False,
                "participant_consent_created": True,
                "model_execution_authorized": False,
                "model_invocation_performed": False,
                "agent_execution_performed": False,
                "containers_started": False,
                "backend_fact_append_performed": False,
                "ledger_append_performed": False,
                "roster_approved": False,
                "single_use_authorization_issued": False,
            },
        }
        write_private_json(output_root / "baseline-consent-operation-report.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _load_context(**values: Any) -> dict[str, Any]:
    output_root = Path(values["output_root"])
    if output_root.exists():
        raise ValueError(f"baseline/consent output already exists: {output_root}")
    _validate_metadata(values)
    protocol = _read_private(Path(values["qualification_protocol_path"]))
    protocol_hash = canonical_sha256(protocol)
    request_hash = canonical_sha256(read_json_object(DEFAULT_REQUEST))
    failures = validate_qualification_protocol(protocol, admission_request_sha256=request_hash)
    if failures:
        raise ValueError(f"qualification protocol invalid: {failures}")
    reviewed = _read_private(Path(values["reviewed_pairing_path"]))
    failures = validate_reviewed_pairing(reviewed)
    if failures or reviewed.get("qualification_protocol_sha256") != protocol_hash:
        raise ValueError(f"reviewed pairing invalid: {failures or ['protocol_hash_mismatch']}")
    profiles = _load_profiles(Path(values["profiles_root"]), reviewed)
    states = _load_states(Path(values["states_root"]), profiles, protocol_hash)
    reviewer_profile = _read_private(Path(values["reviewer_profile_path"]))
    failures = validate_reviewer_identity_profile(reviewer_profile)
    if failures:
        raise ValueError(f"reviewer profile invalid: {failures}")
    _validate_pkcs11_configuration(
        profiles, reviewer_profile, str(Path(values["module_path"]).resolve()), values["token_label"]
    )
    _validate_stopped_containers(profiles)
    source_artifacts = _load_source_evidence(
        Path(values["source_evidence_root"]), profiles, reviewed, protocol
    )
    return {
        **values,
        "protocol": protocol,
        "protocol_hash": protocol_hash,
        "reviewed_pairing": reviewed,
        "profiles": profiles,
        "states": states,
        "reviewer_profile": reviewer_profile,
        "source_artifacts": source_artifacts,
    }


def _sign_evidence(session: Any, context: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    profiles = context["profiles"]
    reviewer_profile = context["reviewer_profile"]
    reviewer_key = _session_key(session, reviewer_profile["pkcs11_key"])
    reviewer = reviewer_profile["reviewer"]
    reviewer_signer = _SessionSigner(reviewer_key, reviewer["public_key_hex"])
    pairing_hash = context["reviewed_pairing"]["reviewed_pairing_sha256"]
    baselines: dict[str, dict[str, Any]] = {}
    consents: dict[str, dict[str, Any]] = {}
    for pair in context["reviewed_pairing"]["pairs"]:
        pair_profiles = [profiles[participant_id] for participant_id in pair["participant_ids"]]
        records = [
            {
                "participant_id": profile["participant"]["participant_id"],
                "participant_profile_sha256": profile["profile_sha256"],
                "initial_state_artifact_sha256": profile["isolation"]["initial_state_artifact_sha256"],
                "initial_state": context["states"][profile["participant"]["participant_id"]],
            }
            for profile in pair_profiles
        ]
        baselines[pair["pair_id"]] = build_cognitive_baseline(
            pair_id=pair["pair_id"],
            reviewed_pairing_sha256=pairing_hash,
            qualification_protocol_sha256=context["protocol_hash"],
            owner_authorization_id=context["owner_authorization_id"],
            owner_authorization_statement_sha256=context["owner_authorization_statement_sha256"],
            attested_at=context["attested_at"],
            participants=records,
            reviewer=reviewer,
            signer=reviewer_signer,
        )
        for profile in pair_profiles:
            participant = profile["participant"]
            participant_key = _session_key(session, profile["pkcs11_key"])
            consents[participant["participant_id"]] = build_participant_consent(
                participant=participant,
                pair_id=pair["pair_id"],
                participant_profile_sha256=profile["profile_sha256"],
                reviewed_pairing_sha256=pairing_hash,
                qualification_protocol_sha256=context["protocol_hash"],
                owner_authorization_id=context["owner_authorization_id"],
                owner_authorization_statement_sha256=context["owner_authorization_statement_sha256"],
                attested_at=context["attested_at"],
                consent_nonce=secrets.token_bytes(32),
                signer=_SessionSigner(participant_key, participant["public_key_hex"]),
            )
    return baselines, consents


def _write_and_validate_evidence(
    evidence_root: Path,
    context: dict[str, Any],
    baselines: dict[str, dict[str, Any]],
    consents: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    for pair_id, baseline in baselines.items():
        write_private_json(evidence_root / f"{pair_id}.baseline.json", baseline)
    packets: dict[str, dict[str, Any]] = {}
    stack = _packet_stack(context["protocol"])
    pair_by_participant = {
        participant_id: pair["pair_id"]
        for pair in context["reviewed_pairing"]["pairs"]
        for participant_id in pair["participant_ids"]
    }
    for participant_id, profile in context["profiles"].items():
        pair_id = pair_by_participant[participant_id]
        paths = {"cognitive_baseline": evidence_root / f"{pair_id}.baseline.json"}
        for kind, suffix in SOURCE_EVIDENCE_SUFFIX.items():
            paths[kind] = evidence_root / f"{participant_id}.{suffix}.json"
            write_private_json(paths[kind], context["source_artifacts"][participant_id][kind])
        paths["consent_receipt"] = evidence_root / f"{participant_id}.consent.json"
        write_private_json(paths["consent_receipt"], consents[participant_id])
        participant = profile["participant"]
        packet = {
            "schema_version": PACKET_SCHEMA,
            "participant_id": participant_id,
            "pair_id": pair_id,
            "execution_did": participant["execution_did"],
            "credential_version": participant["credential_version"],
            "signer_kind": participant["signer_kind"],
            "prior_mentorship_exposure": participant["prior_mentorship_exposure"],
            "random_assignment_consented": True,
            "model_execution_authorized": False,
            "stack": stack,
            "evidence": {kind: {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for kind, path in paths.items()},
        }
        packet["packet_sha256"] = canonical_sha256(packet)
        artifacts = {kind: read_json_object(path) for kind, path in paths.items()}
        failures = validate_participant_packet(packet, expected_stack=stack, qualification_protocol_sha256=context["protocol_hash"])
        for kind, artifact in artifacts.items():
            failures.extend(validate_evidence_artifact(kind, artifact, packet=packet, qualification_protocol_sha256=context["protocol_hash"], reviewed_pairing_sha256=context["reviewed_pairing"]["reviewed_pairing_sha256"]))
        failures.extend(validate_packet_evidence_bindings(artifacts, packet=packet))
        if failures:
            raise ValueError(f"participant packet invalid ({participant_id}): {list(dict.fromkeys(failures))}")
        write_private_json(evidence_root / f"{participant_id}.participant.json", packet)
        packets[participant_id] = packet
    return packets


def _load_profiles(root: Path, reviewed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        profile = _read_private(path)
        failures = validate_participant_profile(profile)
        if failures:
            raise ValueError(f"participant profile invalid ({path.name}): {failures}")
        profiles[profile["participant"]["participant_id"]] = profile
    if len(profiles) != 40 or {item["profile_sha256"] for item in profiles.values()} != set(reviewed["participant_profile_sha256"]):
        raise ValueError("participant profiles do not match reviewed pairing")
    return profiles


def _load_states(root: Path, profiles: dict[str, dict[str, Any]], protocol_hash: str) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    for participant_id, profile in profiles.items():
        path = root / participant_id / "initial-state.json"
        state = _read_private(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != profile["isolation"]["initial_state_artifact_sha256"]:
            raise ValueError(f"initial state artifact hash mismatch: {participant_id}")
        if state != profile["initial_state"] or state.get("qualification_protocol_sha256") != protocol_hash:
            raise ValueError(f"initial state/profile mismatch: {participant_id}")
        states[participant_id] = state
    return states


def _load_source_evidence(root: Path, profiles: dict[str, dict[str, Any]], reviewed: dict[str, Any], protocol: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    pair_by_participant = {participant_id: pair["pair_id"] for pair in reviewed["pairs"] for participant_id in pair["participant_ids"]}
    stack = _packet_stack(protocol)
    for participant_id, profile in profiles.items():
        participant = profile["participant"]
        packet = {"participant_id": participant_id, "pair_id": pair_by_participant[participant_id], "execution_did": participant["execution_did"], "credential_version": participant["credential_version"], "signer_kind": participant["signer_kind"], "stack": stack}
        result[participant_id] = {}
        for kind, suffix in SOURCE_EVIDENCE_SUFFIX.items():
            artifact = _read_private(root / f"{participant_id}.{suffix}.json")
            failures = validate_evidence_artifact(kind, artifact, packet=packet, qualification_protocol_sha256=reviewed["qualification_protocol_sha256"])
            if failures:
                raise ValueError(f"source Evidence invalid ({participant_id}, {kind}): {failures}")
            result[participant_id][kind] = artifact
    return result


def _validate_stopped_containers(profiles: dict[str, dict[str, Any]]) -> None:
    ids = [profile["isolation"]["isolation_id"] for profile in profiles.values()]
    result = subprocess.run(["docker", "inspect", *ids], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"participant isolation inspect failed: {result.stderr.strip()}")
    inspected = json.loads(result.stdout)
    if len(inspected) != 40 or any(item["State"]["Running"] for item in inspected):
        raise ValueError("all 40 participant containers must exist and remain stopped")


def _validate_pkcs11_configuration(profiles: dict[str, dict[str, Any]], reviewer: dict[str, Any], module_path: str, token_label: str) -> None:
    records = [profile["pkcs11_key"] for profile in profiles.values()] + [reviewer["pkcs11_key"]]
    for record in records:
        if str(Path(record["module_path"]).resolve()) != module_path or record["token_label"] != token_label:
            raise ValueError("PKCS#11 configuration does not match identity profiles")


def _session_key(session: Any, reference: dict[str, Any]) -> Any:
    selector = {"label": reference["key_label"], "id": bytes.fromhex(reference["key_id_hex"])}
    private_key = session.get_key(object_class=pkcs11.ObjectClass.PRIVATE_KEY, **selector)
    public_key = session.get_key(object_class=pkcs11.ObjectClass.PUBLIC_KEY, **selector)
    point = bytes(public_key[pkcs11.Attribute.EC_POINT])
    if len(point) != 34 or point[:2] != b"\x04\x20":
        raise ValueError(f"unsupported Ed25519 point: {reference['key_label']}")
    return private_key


def _packet_stack(protocol: dict[str, Any]) -> dict[str, str]:
    frozen = protocol["frozen_stack"]
    return {"provider_id": frozen["provider_id"], "model_id": frozen["model_id"], "budget_id": frozen["budget_id"], "corpus_id": protocol["task_corpus"]["corpus_id"], "verifier_id": frozen["verifier_id"]}


def _build_manifest(evidence_root: Path, context: dict[str, Any], baselines: dict[str, dict[str, Any]], consents: dict[str, dict[str, Any]], packets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    artifacts = [_artifact(path) for path in sorted(evidence_root.glob("*.json"))]
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "created_at": context["attested_at"],
        "qualification_protocol_sha256": context["protocol_hash"],
        "reviewed_pairing_sha256": context["reviewed_pairing"]["reviewed_pairing_sha256"],
        "evidence_root": str(evidence_root.resolve()),
        "counts": {"cognitive_baselines": len(baselines), "participant_consents": len(consents), "participant_packets": len(packets), "total_json_artifacts": len(artifacts)},
        "artifacts": artifacts,
        "public_only": True,
        "secret_material_included": False,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def _validate_metadata(values: dict[str, Any]) -> None:
    for field in ("operation_id", "owner_authorization_id"):
        if not str(values[field]).strip():
            raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(str(values["attested_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("attested_at must be RFC3339") from error
    if parsed.tzinfo is None:
        raise ValueError("attested_at must include timezone")
    if not _sha256(values["owner_authorization_statement_sha256"]):
        raise ValueError("owner authorization statement hash invalid")
    statement = str(values["owner_authorization_statement"])
    if (
        not statement.strip()
        or hashlib.sha256(statement.encode("utf-8")).hexdigest()
        != values["owner_authorization_statement_sha256"]
    ):
        raise ValueError("owner authorization statement/hash mismatch")


def _read_private(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact unreadable or permissions too open: {path}")
    return read_json_object(path)


def _artifact(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and text == text.lower() and all(char in "0123456789abcdef" for char in text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--attested-at", default=datetime.now().astimezone().isoformat(timespec="seconds"))
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-authorization-statement", required=True)
    parser.add_argument("--owner-authorization-statement-sha256", required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--reviewed-pairing", type=Path, required=True)
    parser.add_argument("--profiles-root", type=Path, required=True)
    parser.add_argument("--states-root", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--source-evidence-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    values = {
        "operation_id": args.operation_id,
        "attested_at": args.attested_at,
        "owner_authorization_id": args.owner_authorization_id,
        "owner_authorization_statement": args.owner_authorization_statement,
        "owner_authorization_statement_sha256": args.owner_authorization_statement_sha256,
        "qualification_protocol_path": args.qualification_protocol,
        "reviewed_pairing_path": args.reviewed_pairing,
        "profiles_root": args.profiles_root,
        "states_root": args.states_root,
        "reviewer_profile_path": args.reviewer_profile,
        "source_evidence_root": args.source_evidence_root,
        "module_path": args.module,
        "token_label": args.token_label,
        "output_root": args.output_root,
    }
    try:
        report = preflight_baseline_consent(**values)
        if not args.preflight_only:
            report = create_baselines_and_consents(**values, pin=read_pin(args.pin_file))
    except (ValueError, RuntimeError, OSError, pkcs11.PKCS11Error) as error:
        print(json.dumps({"schema_version": REPORT_SCHEMA, "passed": False, "error": str(error)}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
