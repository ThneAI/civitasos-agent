"""Register prepared I.1 identities and prove Ed25519 key control."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.i1.identity_preparation import did_from_public_key

SCHEMA_VERSION = "i1-identity-registration-gate:v1"


def run_gate(
    *,
    preparation_report_path: Path,
    h3_qualification_path: Path,
    backend_url: str,
    output: Path,
    service_token_secret: str | None = None,
    agent_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    from civitasos import CivitasAgent

    factory = agent_factory or CivitasAgent
    failures: list[str] = []
    checks: dict[str, bool] = {}
    preparation = _read_json(preparation_report_path)
    h3 = _read_json(h3_qualification_path)

    _check(
        checks,
        failures,
        "h3_semantic_qualification_passed",
        h3.get("schema_version")
        == "h3-relation-learning-semantic-qualification:v1"
        and h3.get("passed") is True
        and h3.get("valid_for_qualification") is True
        and _object(h3.get("readiness")).get("i1_entry_inputs_ready") is True,
    )
    identities = [
        item
        for item in _object(preparation.get("identity_manifest")).get(
            "identities", []
        )
        if isinstance(item, dict)
    ]
    _check(
        checks,
        failures,
        "preparation_report_passed",
        preparation.get("schema_version")
        == "i1-verifier-preparation-report:v1"
        and preparation.get("passed") is True,
    )
    _check(
        checks,
        failures,
        "five_prepared_identities_present",
        len(identities) == 5,
    )
    aliases = [str(item.get("identity_alias") or "") for item in identities]
    _check(
        checks,
        failures,
        "prepared_aliases_unique",
        all(aliases) and len(aliases) == len(set(aliases)),
    )
    _check(
        checks,
        failures,
        "service_token_bootstrap_configured",
        bool(service_token_secret),
    )

    receipts: list[dict[str, Any]] = []
    if not failures:
        for identity in identities:
            try:
                receipts.append(
                    _register_identity(
                        identity=identity,
                        backend_url=backend_url,
                        service_token_secret=str(service_token_secret),
                        agent_factory=factory,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                failures.append(
                    f"identity_registration_failed:"
                    f"{identity.get('identity_alias')}:{type(exc).__name__}:{exc}"
                )
                break

    _check(
        checks,
        failures,
        "all_five_identities_registered",
        len(receipts) == 5
        and all(item.get("registration_verified") is True for item in receipts),
    )
    _check(
        checks,
        failures,
        "all_five_signature_controls_verified",
        len(receipts) == 5
        and all(
            item.get("signature_control_verified") is True for item in receipts
        ),
    )
    _check(
        checks,
        failures,
        "all_five_did_challenge_auth_proven",
        len(receipts) == 5
        and all(item.get("did_challenge_auth_proven") is True for item in receipts),
    )
    _check(
        checks,
        failures,
        "registered_dids_unique",
        len(receipts) == 5
        and len({str(item.get("did") or "") for item in receipts}) == 5,
    )

    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "backend_url": backend_url,
        "source_artifacts": {
            "preparation_report": _artifact_ref(preparation_report_path),
            "h3_semantic_qualification": _artifact_ref(h3_qualification_path),
        },
        "identity_receipts": receipts,
        "metrics": {
            "prepared_identity_count": len(identities),
            "registered_identity_count": sum(
                item.get("registration_verified") is True for item in receipts
            ),
            "signature_control_verified_count": sum(
                item.get("signature_control_verified") is True
                for item in receipts
            ),
            "did_challenge_auth_count": sum(
                item.get("did_challenge_auth_proven") is True for item in receipts
            ),
        },
        "readiness": {
            "state": (
                "i1_identity_prerequisites_complete"
                if passed
                else "blocked_i1_identity_registration"
            ),
            "h3_qualification_complete": (
                checks.get("h3_semantic_qualification_passed") is True
            ),
            "identity_registration_complete": passed,
            "signature_control_proof_complete": passed,
            "i1_execution_preflight_input_ready": passed,
            "i1_execution_allowed": False,
        },
        "boundary": {
            "identity_registration_allowed": True,
            "signature_verification_allowed": True,
            "verifier_dispatch_allowed": False,
            "consensus_claim_allowed": False,
            "external_side_effect_allowed": False,
            "iem_mutation_allowed": False,
            "relation_mutation_allowed": False,
            "authorization_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "registration_does_not_dispatch_i1_verifiers",
            "registration_does_not_prove_verifier_consensus",
            "signature_control_does_not_prove_model_provider_independence",
            "service_token_is_bootstrap_only_and_is_not_stored_in_the_report",
            "registration_does_not_authorize_external_side_effects",
            "registration_does_not_unlock_production",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _register_identity(
    *,
    identity: dict[str, Any],
    backend_url: str,
    service_token_secret: str,
    agent_factory: Callable[..., Any],
) -> dict[str, Any]:
    alias = str(identity["identity_alias"])
    display_name = str(identity["display_name"])
    key_path = Path(str(identity["identity_key_path"]))
    expected_public_key = str(identity["public_key_hex"])
    expected_did = str(identity["did"])
    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode != 0o600:
        raise ValueError(f"identity key mode must be 0600, got {mode:04o}")

    agent = agent_factory(
        backend_url,
        timeout=10,
        auto_discover=False,
    )
    public_key = agent.load_identity(str(key_path))
    derived_did = did_from_public_key(public_key)
    if public_key != expected_public_key or derived_did != expected_did:
        raise ValueError("prepared identity key does not match manifest")

    agent.authenticate_service_token(
        service_id="i1_identity_registrar",
        secret=service_token_secret,
        scopes=["agents:write"],
    )
    registration = agent.a2a_quickstart(
        name=display_name,
        alias=alias,
        endpoint="",
        description="I.1 controlled verifier identity",
        public_key=public_key,
    )
    registered_did = str(
        _object(registration.get("agent")).get("did")
        or registration.get("did")
        or registration.get("agent_id")
        or ""
    )
    if registered_did != expected_did or agent.agent_id != expected_did:
        raise ValueError("backend registered DID does not match prepared identity")
    agent.save_identity(str(key_path))

    agent.authenticate(allow_legacy_fallback=False)
    auth_context = _object(agent.jwt_auth_context)
    auth_method = str(auth_context.get("auth_method") or "")
    did_challenge_auth = (
        "challenge" in auth_method
        and auth_context.get("evidence_allowed") is True
    )
    if not did_challenge_auth:
        raise ValueError("backend did not issue challenge-auth evidence context")

    message = (
        f"i1-signature-control:v1:{alias}:{expected_did}:"
        f"{secrets.token_hex(16)}"
    )
    signature = agent.sign(message.encode("utf-8"))
    verification = agent._a2a_request(  # noqa: SLF001
        "POST",
        "/identity/verify",
        {
            "agent_id": expected_did,
            "message": message,
            "signature_hex": signature,
        },
    )
    verified = (
        verification.get("verified") is True
        and verification.get("agent_id") == expected_did
    )
    if not verified:
        raise ValueError("signature verification did not confirm key control")

    return {
        "identity_alias": alias,
        "display_name": display_name,
        "provider_family": identity.get("provider_family"),
        "runtime_family": identity.get("runtime_family"),
        "roles": identity.get("roles", []),
        "did": expected_did,
        "public_key_sha256": _sha256_text(public_key),
        "identity_key_path": str(key_path),
        "identity_key_mode": f"{mode:04o}",
        "registration_verified": True,
        "bootstrap_auth_method": "service_token",
        "bootstrap_scope": "agents:write",
        "did_challenge_auth_proven": True,
        "auth_method": auth_method,
        "evidence_allowed": auth_context.get("evidence_allowed") is True,
        "signature_control_verified": True,
        "signature_message_sha256": _sha256_text(message),
        "signature_sha256": _sha256_text(signature),
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": _sha256(path)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation-report", required=True)
    parser.add_argument("--h3-qualification", required=True)
    parser.add_argument(
        "--backend-url",
        default="http://localhost:8099",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        preparation_report_path=Path(args.preparation_report).resolve(),
        h3_qualification_path=Path(args.h3_qualification).resolve(),
        backend_url=args.backend_url.rstrip("/"),
        output=Path(args.output).resolve(),
        service_token_secret=os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET"),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
