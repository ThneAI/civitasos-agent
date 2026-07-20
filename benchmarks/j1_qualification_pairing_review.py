"""Sign an exact J1-D pairing review and export public state Evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_pairing_review import (
    build_pairing_review_receipt,
    build_public_state_evidence,
    build_reviewed_pairing,
    validate_pairing_review_receipt,
    validate_reviewed_pairing,
)
from benchmarks.j1.qualification_participant_provisioning import (
    validate_pairing_proposal,
    validate_participant_profile,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-pairing-review-operation:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_pairing_review.py"
OPERATION_SOURCE = Path(__file__)


def preflight_pairing_review(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    proposal_path: Path,
    profiles_root: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    output_root: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"pairing review output already exists: {output_root}")
    proposal, _ = _read_private(proposal_path)
    proposal_failures = validate_pairing_proposal(proposal)
    if proposal_failures:
        raise ValueError(f"pairing proposal invalid: {proposal_failures}")
    reviewer_profile, _ = _read_private(reviewer_profile_path)
    reviewer_failures = validate_reviewer_identity_profile(reviewer_profile)
    if reviewer_failures:
        raise ValueError(f"reviewer identity profile invalid: {reviewer_failures}")
    _validate_reviewer_configuration(
        reviewer_profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    profiles = _load_profiles(profiles_root, proposal)
    _validate_live_isolation(profiles)
    _preflight_evidence_root(evidence_root, profiles)
    _validate_metadata(
        review_id,
        reviewed_at,
        authorization_id,
        authorization_statement_sha256,
        agent_revision,
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": True,
        "state": "pairing_review_preflight_passed_pin_not_read",
        "proposal_sha256": proposal["proposal_sha256"],
        "participant_count": len(profiles),
        "pair_count": len(proposal["pairs"]),
        "pin_read": False,
        "hardware_contact_performed": False,
        "signature_performed": False,
    }


def approve_pairing(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    proposal_path: Path,
    profiles_root: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    pin: str,
    output_root: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"pairing review output already exists: {output_root}")
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    proposal, proposal_bytes = _read_private(proposal_path)
    proposal_failures = validate_pairing_proposal(proposal)
    if proposal_failures:
        raise ValueError(f"pairing proposal invalid: {proposal_failures}")
    reviewer_profile, reviewer_profile_bytes = _read_private(reviewer_profile_path)
    reviewer_failures = validate_reviewer_identity_profile(reviewer_profile)
    if reviewer_failures:
        raise ValueError(f"reviewer identity profile invalid: {reviewer_failures}")
    _validate_reviewer_configuration(
        reviewer_profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    profiles = _load_profiles(profiles_root, proposal)
    _validate_live_isolation(profiles)
    _preflight_evidence_root(evidence_root, profiles)
    _validate_metadata(
        review_id,
        reviewed_at,
        authorization_id,
        authorization_statement_sha256,
        agent_revision,
    )
    proposal_artifact_sha256 = hashlib.sha256(proposal_bytes).hexdigest()
    reviewer_profile_sha256 = hashlib.sha256(reviewer_profile_bytes).hexdigest()
    review_implementation = {
        "agent_revision": agent_revision,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }
    created_evidence: list[Path] = []
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            reviewer_profile["reviewer"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            receipt = build_pairing_review_receipt(
                review_id=review_id,
                reviewed_at=reviewed_at,
                authorization_id=authorization_id,
                authorization_statement_sha256=authorization_statement_sha256,
                proposal=proposal,
                proposal_artifact_sha256=proposal_artifact_sha256,
                reviewer_profile=reviewer_profile,
                reviewer_profile_sha256=reviewer_profile_sha256,
                review_implementation=review_implementation,
                signer=signer,
            )
        receipt_path = output_root / "pairing-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        reviewed = build_reviewed_pairing(
            proposal=proposal,
            receipt=receipt,
            receipt_sha256=receipt_sha256,
        )
        reviewed_path = output_root / "pairing-proposal.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        pair_by_participant = {
            participant_id: pair["pair_id"]
            for pair in reviewed["pairs"]
            for participant_id in pair["participant_ids"]
        }
        evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        evidence_root.chmod(0o700)
        evidence_manifest = []
        for profile in profiles:
            participant_id = profile["participant"]["participant_id"]
            artifacts = build_public_state_evidence(
                profile=profile,
                pair_id=pair_by_participant[participant_id],
                attested_at=reviewed_at,
                operator_attestation_sha256=receipt_sha256,
            )
            for kind, artifact in artifacts.items():
                suffix = {
                    "identity_snapshot": "identity",
                    "custody_provenance": "custody",
                    "isolation_root": "isolation",
                }[kind]
                path = evidence_root / f"{participant_id}.{suffix}.json"
                write_private_json(path, artifact)
                created_evidence.append(path)
                evidence_manifest.append(
                    {
                        "participant_id": participant_id,
                        "pair_id": pair_by_participant[participant_id],
                        "kind": kind,
                        **_artifact(path),
                    }
                )
        manifest = {
            "schema_version": "j1-qualification-public-state-evidence-manifest:v1",
            "created_at": reviewed_at,
            "qualification_protocol_sha256": reviewed["qualification_protocol_sha256"],
            "reviewed_pairing_sha256": reviewed["reviewed_pairing_sha256"],
            "pairing_review_receipt_sha256": receipt_sha256,
            "participant_count": len(profiles),
            "artifact_count": len(evidence_manifest),
            "artifacts": sorted(
                evidence_manifest,
                key=lambda item: (item["participant_id"], item["kind"]),
            ),
            "missing_evidence": {
                "cognitive_baseline": 20,
                "participant_consent": 40,
                "participant_packet": 40,
            },
            "readiness": {
                "pairing_operator_reviewed": True,
                "public_identity_custody_isolation_evidence_complete": True,
                "participant_evidence_complete": False,
                "real_participant_roster_bound": False,
                "single_use_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
        }
        manifest["manifest_sha256"] = canonical_sha256(manifest)
        manifest_path = output_root / "public-state-evidence-manifest.json"
        write_private_json(manifest_path, manifest)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "exact_pairing_reviewed_public_state_evidence_ready_participant_consent_and_baseline_required",
            "review_id": review_id,
            "proposal": _artifact(proposal_path),
            "pairing_review_receipt": _artifact(receipt_path),
            "reviewed_pairing": _artifact(reviewed_path),
            "public_state_evidence_manifest": _artifact(manifest_path),
            "counts": {
                "participants": len(profiles),
                "pairs": len(reviewed["pairs"]),
                "public_state_evidence_artifacts": len(evidence_manifest),
                "cognitive_baselines": 0,
                "participant_consents": 0,
                "participant_packets": 0,
            },
            "execution_boundary": {
                "pairing_operator_reviewed": True,
                "public_state_evidence_exported": True,
                "cognitive_baseline_created": False,
                "participant_consent_created": False,
                "participant_packet_created": False,
                "model_invocation_performed": False,
                "agent_execution_performed": False,
                "backend_fact_append_performed": False,
                "ledger_append_performed": False,
                "roster_approved": False,
                "single_use_authorization_issued": False,
            },
        }
        write_private_json(output_root / "pairing-review-operation-report.json", report)
        return report
    except Exception:
        for path in reversed(created_evidence):
            path.unlink(missing_ok=True)
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def verify_pairing_review_outputs(
    *,
    proposal_path: Path,
    reviewer_profile_path: Path,
    output_root: Path,
    agent_revision: str,
) -> list[str]:
    failures: list[str] = []
    proposal, proposal_bytes = _read_private(proposal_path)
    reviewer, reviewer_bytes = _read_private(reviewer_profile_path)
    receipt, _ = _read_private(output_root / "pairing-review-receipt.json")
    reviewed, _ = _read_private(output_root / "pairing-proposal.operator-reviewed.json")
    failures.extend(
        validate_pairing_review_receipt(
            receipt,
            proposal=proposal,
            proposal_artifact_sha256=hashlib.sha256(proposal_bytes).hexdigest(),
            reviewer_profile=reviewer,
            reviewer_profile_sha256=hashlib.sha256(reviewer_bytes).hexdigest(),
            review_implementation={
                "agent_revision": agent_revision,
                "contract_source_sha256": hashlib.sha256(
                    CONTRACT_SOURCE.read_bytes()
                ).hexdigest(),
                "operation_source_sha256": hashlib.sha256(
                    OPERATION_SOURCE.read_bytes()
                ).hexdigest(),
            },
        )
    )
    failures.extend(validate_reviewed_pairing(reviewed))
    return list(dict.fromkeys(failures))


def _load_profiles(
    profiles_root: Path, proposal: dict[str, Any]
) -> list[dict[str, Any]]:
    if profiles_root.is_symlink() or not profiles_root.is_dir():
        raise ValueError(f"participant profiles root unreadable: {profiles_root}")
    paths = sorted(profiles_root.glob("*.json"))
    if len(paths) != 40:
        raise ValueError(
            f"participant profiles must contain exactly 40 files: {len(paths)}"
        )
    profiles = []
    for path in paths:
        profile, _ = _read_private(path)
        failures = validate_participant_profile(profile)
        if failures:
            raise ValueError(f"participant profile invalid ({path.name}): {failures}")
        profiles.append(profile)
    profile_hashes = sorted(profile["profile_sha256"] for profile in profiles)
    if profile_hashes != proposal["participant_profile_sha256"]:
        raise ValueError("participant profiles do not match exact pairing proposal")
    return profiles


def _validate_live_isolation(profiles: list[dict[str, Any]]) -> None:
    ids = [profile["isolation"]["isolation_id"] for profile in profiles]
    result = subprocess.run(
        ["docker", "inspect", *ids],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(
            f"participant isolation inspect failed: {result.stderr.strip()}"
        )
    values = json.loads(result.stdout)
    by_id = {value["Id"]: value for value in values}
    failures = []
    for profile in profiles:
        isolation = profile["isolation"]
        value = by_id.get(isolation["isolation_id"], {})
        host = value.get("HostConfig", {})
        if value.get("State", {}).get("Running") is not False:
            failures.append(f"{isolation['container_name']}:container_not_stopped")
        if host.get("NetworkMode") != "none":
            failures.append(f"{isolation['container_name']}:network_not_none")
        if host.get("ReadonlyRootfs") is not True:
            failures.append(f"{isolation['container_name']}:rootfs_not_readonly")
        if host.get("CapDrop") != ["ALL"]:
            failures.append(f"{isolation['container_name']}:cap_drop_invalid")
        if "no-new-privileges:true" not in host.get("SecurityOpt", []):
            failures.append(f"{isolation['container_name']}:security_opt_invalid")
        state_path = Path(isolation["state_root"]) / "initial-state.json"
        state, _ = _read_private(state_path)
        if state.get("execution_authorized") is not False:
            failures.append(f"{isolation['container_name']}:execution_authorized")
        for field in (
            "memory_entry_count",
            "relation_count",
            "model_invocation_count",
            "tick_count",
        ):
            if state.get(field) != 0:
                failures.append(f"{isolation['container_name']}:{field}_not_zero")
    if failures:
        raise ValueError(f"participant live isolation invalid: {failures}")


def _preflight_evidence_root(
    evidence_root: Path, profiles: list[dict[str, Any]]
) -> None:
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise ValueError(f"participant Evidence root unreadable: {evidence_root}")
    if evidence_root.stat().st_mode & 0o077:
        raise ValueError(
            f"participant Evidence root permissions too open: {evidence_root}"
        )
    conflicts = []
    for profile in profiles:
        participant_id = profile["participant"]["participant_id"]
        for suffix in ("identity", "custody", "isolation"):
            path = evidence_root / f"{participant_id}.{suffix}.json"
            if path.exists() or path.is_symlink():
                conflicts.append(path.name)
    if conflicts:
        raise ValueError(f"participant public Evidence already exists: {conflicts}")


def _validate_reviewer_configuration(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    key = profile["pkcs11_key"]
    expected = {
        "module_path": str(Path(module_path).resolve()),
        "token_label": token_label,
        "key_label": key_label,
        "key_id_hex": key_id_hex.lower(),
    }
    failures = [field for field, value in expected.items() if key.get(field) != value]
    if failures:
        raise ValueError(f"reviewer PKCS#11 configuration mismatch: {failures}")
    module_hash = hashlib.sha256(Path(module_path).resolve().read_bytes()).hexdigest()
    if key.get("module_sha256") != module_hash:
        raise ValueError("reviewer PKCS#11 module hash mismatch")


def _validate_metadata(*values: str) -> None:
    review_id, reviewed_at, authorization_id, authorization_hash, agent_revision = (
        values
    )
    if not review_id.strip() or not authorization_id.strip():
        raise ValueError("pairing review metadata is incomplete")
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise ValueError("pairing review timestamp must be RFC3339 with timezone")
    if len(authorization_hash) != 64 or any(
        char not in "0123456789abcdef" for char in authorization_hash
    ):
        raise ValueError("pairing review authorization hash is invalid")
    if not 7 <= len(agent_revision) <= 64 or any(
        char not in "0123456789abcdef" for char in agent_revision.lower()
    ):
        raise ValueError("pairing review Agent revision is invalid")


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"private JSON artifact unreadable: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact permissions too open: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"private JSON artifact must be an object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--reviewed-at", default=_timestamp())
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--profiles-root", type=Path, required=True)
    parser.add_argument("--reviewer-identity-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        preflight_pairing_review(
            review_id=args.review_id,
            reviewed_at=args.reviewed_at,
            authorization_id=args.authorization_id,
            authorization_statement_sha256=args.authorization_statement_sha256,
            proposal_path=args.proposal,
            profiles_root=args.profiles_root,
            reviewer_profile_path=args.reviewer_identity_profile,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            agent_revision=args.agent_revision,
            output_root=args.output_root,
            evidence_root=args.evidence_root,
        )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_SCHEMA,
                    "passed": False,
                    "state": "blocked_pairing_review_preflight",
                    "error_class": type(error).__name__,
                    "error": str(error),
                    "pin_read": False,
                    "hardware_contact_performed": False,
                    "signature_performed": False,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    state = inspect_token_pin_state(
        module_path=args.module, token_label=args.token_label
    )
    if not state["safe_to_attempt_user_login"]:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_SCHEMA,
                    "passed": False,
                    "state": "blocked_user_pin_retry_risk",
                    "token_pin_state": state,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    pin = read_pin(args.pin_file)
    try:
        try:
            report = approve_pairing(
                review_id=args.review_id,
                reviewed_at=args.reviewed_at,
                authorization_id=args.authorization_id,
                authorization_statement_sha256=args.authorization_statement_sha256,
                proposal_path=args.proposal,
                profiles_root=args.profiles_root,
                reviewer_profile_path=args.reviewer_identity_profile,
                module_path=args.module,
                token_label=args.token_label,
                key_label=args.key_label,
                key_id_hex=args.key_id,
                agent_revision=args.agent_revision,
                pin=pin,
                output_root=args.output_root,
                evidence_root=args.evidence_root,
            )
        except pkcs11.exceptions.PinIncorrect:
            report = {
                "schema_version": REPORT_SCHEMA,
                "passed": False,
                "state": "blocked_user_pin_incorrect_stop_retrying",
                "pin_recorded": False,
            }
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            json.JSONDecodeError,
        ) as error:
            report = {
                "schema_version": REPORT_SCHEMA,
                "passed": False,
                "state": "blocked_pairing_review_operation",
                "error_class": type(error).__name__,
                "error": str(error),
                "pin_recorded": False,
            }
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
