"""Preflight and sign a J1-D single-use execution authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_execution_authorization import (
    MAX_TTL_SECONDS,
    build_execution_authorization,
)
from benchmarks.j1_qualification_execution_authorization_gate import (
    load_authorization_source_context,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-execution-authorization-operation:v1"


def preflight_execution_authorization(**values: Any) -> dict[str, Any]:
    source = _load_source(**values)
    statement = authorization_statement(
        run_id=values["run_id"],
        ttl_seconds=values["ttl_seconds"],
        context=source["context"],
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": True,
        "state": "execution_authorization_preflight_passed_explicit_cost_approval_required",
        "run_id": values["run_id"],
        "source_artifacts": source["artifacts"],
        "execution_scope": source["context"]["execution_scope"],
        "cost_acknowledgement": source["context"]["cost_acknowledgement"],
        "controls": source["context"]["controls"],
        "ttl_seconds": values["ttl_seconds"],
        "approval_request": {
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode("utf-8")).hexdigest(),
            "approve_exact_execution_required": True,
            "acknowledge_exact_cost_ceiling_required": True,
            "acknowledge_single_use_failure_boundary_required": True,
        },
        "reviewer_did": source["reviewer_profile"]["reviewer"]["did"],
        "token_pin_state": source["token_pin_state"],
        "pin_read": False,
        "token_login_attempted": False,
        "signature_performed": False,
        "provider_network_probe_performed": False,
        "model_invocation_performed": False,
        "execution_boundary": _preflight_boundary(),
    }


def approve_execution_authorization(
    *,
    authorization_id: str,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    pin: str,
    **values: Any,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    source = _load_source(**values)
    expected_statement = authorization_statement(
        run_id=values["run_id"],
        ttl_seconds=values["ttl_seconds"],
        context=source["context"],
    )
    if (
        owner_statement != expected_statement
        or hashlib.sha256(owner_statement.encode("utf-8")).hexdigest()
        != owner_statement_sha256
    ):
        raise ValueError("execution authorization statement/hash mismatch")
    issued_at = datetime.now(timezone.utc).isoformat()
    output_root = Path(values["authorization_output_root"])
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewer = source["reviewer_profile"]
        with Pkcs11Ed25519Signer(
            str(Path(values["module_path"]).resolve()),
            values["token_label"],
            values["key_label"],
            reviewer["reviewer"]["public_key_hex"],
            pin,
            key_id=values["key_id_hex"],
        ) as signer:
            receipt = build_execution_authorization(
                authorization_id=authorization_id,
                issued_at=issued_at,
                ttl_seconds=values["ttl_seconds"],
                owner_authorization_id=owner_authorization_id,
                owner_statement_sha256=owner_statement_sha256,
                context=source["context"],
                reviewer_profile=reviewer,
                reviewer_profile_sha256=source["reviewer_profile_sha256"],
                implementation=source["implementation"],
                signer=signer,
            )
        receipt_path = output_root / "execution-authorization-receipt.json"
        write_private_json(receipt_path, receipt)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "single_use_authorization_issued_gate_required_before_claim",
            "run_id": values["run_id"],
            "authorization_id": authorization_id,
            "issued_at": issued_at,
            "valid_until": receipt["valid_until"],
            "authorization_receipt": _artifact(receipt_path),
            "owner_authorization": {
                "authorization_id": owner_authorization_id,
                "statement": owner_statement,
                "authorization_statement_sha256": owner_statement_sha256,
            },
            "source_artifacts": source["artifacts"],
            "readiness": {
                "single_use_authorization_issued": True,
                "authorization_gate_passed": False,
                "authorization_consumed": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": _preflight_boundary(),
        }
        write_private_json(
            output_root / "execution-authorization-operation-report.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def authorization_statement(
    *, run_id: str, ttl_seconds: int, context: dict[str, dict[str, Any]]
) -> str:
    source = context["source_binding"]
    scope = context["execution_scope"]
    aggregate = context["cost_acknowledgement"]["aggregate_ceiling"]
    return (
        f"I authorize exactly one J1-D qualification run {run_id}, bound to protocol "
        f"{source['qualification_protocol_sha256']}, roster {source['reviewed_roster_sha256']}, "
        f"cohort assignment {source['reviewed_assignment_sha256']}, "
        f"provider {scope['provider_id']}, model {scope['model_id']}, 40 participants, 20 pairs, "
        f"and {aggregate['authorized_task_executions']} task executions. I acknowledge aggregate "
        f"ceilings of {aggregate['max_tokens']} tokens and {aggregate['max_cost_microunits']} "
        f"microunits. Authorization TTL is {ttl_seconds} seconds; claim is single-use, any claimed "
        "failure requires new authorization, and Backend/Ledger writes remain prohibited."
    )


def _load_source(**values: Any) -> dict[str, Any]:
    output_root = Path(values["authorization_output_root"])
    protocol_path = Path(values["qualification_protocol_path"]).resolve()
    qualification_root = protocol_path.parent.parent
    execution_root = Path(values["execution_root"]).resolve()
    consumption_path = Path(values["consumption_path"]).resolve()
    if (
        output_root.resolve().parent != qualification_root
        or execution_root.parent != qualification_root
        or consumption_path.parent != output_root.resolve()
    ):
        raise ValueError(
            "authorization, execution, or consumption path escapes qualification root"
        )
    if output_root.exists():
        raise ValueError(f"authorization output already exists: {output_root}")
    if execution_root.exists():
        raise ValueError("execution root already exists")
    if consumption_path.exists():
        raise ValueError("authorization consumption already exists")
    ttl_seconds = values["ttl_seconds"]
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("authorization TTL must be between 1 and 1800 seconds")
    failures: list[str] = []
    source = load_authorization_source_context(
        qualification_protocol_path=Path(values["qualification_protocol_path"]),
        reviewed_roster_path=Path(values["reviewed_roster_path"]),
        roster_gate_report_path=Path(values["roster_gate_report_path"]),
        reviewed_assignment_path=Path(values["reviewed_assignment_path"]),
        assignment_gate_report_path=Path(values["assignment_gate_report_path"]),
        admission_request_path=Path(values["admission_request_path"]),
        provider_admission_report_path=Path(values["provider_admission_report_path"]),
        provider_env_path=Path(values["provider_env_path"]),
        reviewer_profile_path=Path(values["reviewer_profile_path"]),
        evidence_root=Path(values["evidence_root"]),
        run_id=values["run_id"],
        execution_root=Path(values["execution_root"]),
        consumption_path=Path(values["consumption_path"]),
        agent_revision=values["agent_revision"],
        failures=failures,
    )
    if failures:
        raise ValueError(f"execution authorization source invalid: {failures}")
    _validate_reviewer_configuration(source["reviewer_profile"], values)
    pin_state = inspect_token_pin_state(
        module_path=values["module_path"], token_label=values["token_label"]
    )
    if not (
        pin_state["token_initialized"]
        and pin_state["user_pin_initialized"]
        and pin_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"reviewer token not ready: {pin_state}")
    source["token_pin_state"] = pin_state
    return source


def _validate_reviewer_configuration(
    profile: dict[str, Any], values: dict[str, Any]
) -> None:
    key = profile["pkcs11_key"]
    module = str(Path(values["module_path"]).resolve())
    expected = {
        "module_path": module,
        "token_label": values["token_label"],
        "key_label": values["key_label"],
        "key_id_hex": str(values["key_id_hex"]).lower(),
    }
    drift = [
        field
        for field, expected_value in expected.items()
        if key.get(field) != expected_value
    ]
    if drift:
        raise ValueError(f"reviewer PKCS#11 configuration mismatch: {drift}")
    if (
        key.get("module_sha256")
        != hashlib.sha256(Path(module).read_bytes()).hexdigest()
    ):
        raise ValueError("reviewer PKCS#11 module hash mismatch")


def _preflight_boundary() -> dict[str, bool]:
    return {
        "authorization_preparation_only": True,
        "authorization_consumed": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=MAX_TTL_SECONDS)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--roster-gate-report", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate-report", type=Path, required=True)
    parser.add_argument("--admission-request", type=Path, required=True)
    parser.add_argument("--provider-admission-report", type=Path, required=True)
    parser.add_argument("--provider-env", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--consumption-path", type=Path, required=True)
    parser.add_argument("--authorization-output-root", type=Path, required=True)
    parser.add_argument("--preflight-report", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--approve-exact-execution", action="store_true")
    parser.add_argument("--acknowledge-exact-cost", action="store_true")
    parser.add_argument("--acknowledge-single-use-failure", action="store_true")
    parser.add_argument("--authorization-id")
    parser.add_argument("--owner-authorization-id")
    parser.add_argument("--owner-statement")
    parser.add_argument("--owner-statement-sha256")
    parser.add_argument("--pin-file", type=Path)
    args = parser.parse_args()
    values = {
        "run_id": args.run_id,
        "ttl_seconds": args.ttl_seconds,
        "qualification_protocol_path": args.qualification_protocol,
        "reviewed_roster_path": args.reviewed_roster,
        "roster_gate_report_path": args.roster_gate_report,
        "reviewed_assignment_path": args.reviewed_assignment,
        "assignment_gate_report_path": args.assignment_gate_report,
        "admission_request_path": args.admission_request,
        "provider_admission_report_path": args.provider_admission_report,
        "provider_env_path": args.provider_env,
        "reviewer_profile_path": args.reviewer_profile,
        "evidence_root": args.evidence_root,
        "module_path": args.module,
        "token_label": args.token_label,
        "key_label": args.key_label,
        "key_id_hex": args.key_id,
        "agent_revision": args.agent_revision,
        "execution_root": args.execution_root,
        "consumption_path": args.consumption_path,
        "authorization_output_root": args.authorization_output_root,
    }
    try:
        preflight = preflight_execution_authorization(**values)
        write_private_json(args.preflight_report, preflight)
        if args.preflight_only:
            print(json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if not (
            args.approve_exact_execution
            and args.acknowledge_exact_cost
            and args.acknowledge_single_use_failure
        ):
            raise ValueError(
                "exact execution, cost, and single-use failure acknowledgements are required"
            )
        required = (
            args.authorization_id,
            args.owner_authorization_id,
            args.owner_statement,
            args.owner_statement_sha256,
        )
        if any(value is None for value in required):
            raise ValueError("execution authorization metadata is incomplete")
        pin = read_pin(args.pin_file)
        try:
            report = approve_execution_authorization(
                **values,
                authorization_id=str(args.authorization_id),
                owner_authorization_id=str(args.owner_authorization_id),
                owner_statement=str(args.owner_statement),
                owner_statement_sha256=str(args.owner_statement_sha256),
                pin=pin,
            )
        finally:
            pin = ""
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_execution_authorization_operation",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
