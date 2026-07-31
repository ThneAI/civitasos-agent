"""Atomically claim and execute one authorized J1-D transport admission soak."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_admission import _load_private_env
from benchmarks.j1.qualification_http_transport import PreparedHTTPSPost
from benchmarks.j1.qualification_provider_broker import SanitizedProviderFailure
from benchmarks.j1.qualification_transport_reliability import (
    SOAK_CALL_COUNT,
    synthetic_probe_body,
)
from benchmarks.j1.qualification_transport_soak import (
    GATE_REPORT_SCHEMA,
    REPORT_SCHEMA,
    SoakResponseFailure,
    authorization_statement,
    build_claim,
    normalize_response,
    validate_execution_plan,
)


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_transport_soak.py"
PREFLIGHT_SOURCE = Path(__file__).with_name("j1_qualification_transport_soak.py")
OPERATION_SOURCE = Path(__file__)
TransportFactory = Callable[[str], PreparedHTTPSPost]


def execute_soak(
    *,
    claimed_at: str,
    authorization_statement_value: str,
    plan_path: Path,
    preflight_path: Path,
    provider_env_path: Path,
    claim_root: Path,
    output_root: Path,
    repository_root: Path,
    transport_factory: TransportFactory = PreparedHTTPSPost,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"transport soak output exists: {output_root}")
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    implementation = _clean_pushed_implementation(repository_root)
    expected_statement = authorization_statement(
        plan_raw_sha256=hashlib.sha256(plan_raw).hexdigest(),
        plan=plan,
    )
    failures = validate_execution_plan(plan)
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    if failures or not (
        plan.get("implementation") == implementation
        and preflight.get("state")
        == "transport_soak_ready_exact_owner_authorization_required"
        and preflight.get("passed") is True
        and preflight.get("failure_reasons") == []
        and preflight.get("preflight_sha256") == canonical_sha256(preflight_body)
        and preflight.get("plan")
        == _ref(plan_path, plan["plan_sha256"], plan_raw)
        and preflight.get("owner_authorization", {}).get(
            "required_exact_statement"
        )
        == expected_statement
        and preflight.get("owner_authorization", {}).get("statement_sha256")
        == hashlib.sha256(expected_statement.encode()).hexdigest()
        and authorization_statement_value == expected_statement
    ):
        raise ValueError("transport soak authorization source mismatch")
    _replay_sources(plan)
    authorization_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    claim_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    claim_root.chmod(0o700)
    claim_path = claim_root / f"{authorization_sha256}.claim.json"
    if claim_path.exists():
        raise ValueError("transport soak authorization already claimed")
    plan_ref = _ref(plan_path, plan["plan_sha256"], plan_raw)
    preflight_ref = _ref(
        preflight_path,
        preflight["preflight_sha256"],
        preflight_raw,
    )
    claim = build_claim(
        claimed_at=claimed_at,
        authorization_statement_sha256=authorization_sha256,
        plan_ref=plan_ref,
        preflight_ref=preflight_ref,
        output_root_sha256=hashlib.sha256(
            str(output_root.resolve()).encode()
        ).hexdigest(),
        plan=plan,
    )
    _write_exclusive(claim_path, claim)
    claim_ref = _ref(
        claim_path,
        claim["claim_sha256"],
        claim_path.read_bytes(),
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    journal_path = output_root / "transport-admission-soak-journal.json"
    report_path = output_root / "transport-admission-soak-report.json"
    gate_path = output_root / "transport-admission-soak-gate.json"
    journal: dict[str, Any] = {
        "schema_version": "j1-qualification-transport-admission-soak-journal:v1",
        "soak_id": plan["soak_id"],
        "state": "authorization_claimed_before_credential_access",
        "authorization_statement_sha256": authorization_sha256,
        "claim": claim_ref,
        "provider_env_read_count": 0,
        "provider_dispatch_count": 0,
        "completed_call_count": 0,
        "post_dispatch_retry_count": 0,
        "current_ordinal": None,
    }
    write_private_json(journal_path, journal)
    started = monotonic()
    receipts: list[dict[str, Any]] = []
    api_key = ""
    failure: dict[str, Any] | None = None
    try:
        journal["state"] = "credential_read_intent_persisted"
        journal["provider_env_read_count"] = 1
        write_private_json(journal_path, journal)
        api_key = _read_provider_env(provider_env_path, plan)
        journal["state"] = "credential_validated"
        write_private_json(journal_path, journal)
        url = f"{plan['provider']['base_url']}{plan['provider']['endpoint']}"
        for ordinal in range(1, SOAK_CALL_COUNT + 1):
            if monotonic() - started >= plan["execution_policy"][
                "absolute_duration_seconds"
            ]:
                raise SoakResponseFailure(
                    "internal",
                    "absolute_deadline_before_dispatch",
                    "TransportSoakDeadlineError",
                )
            body = synthetic_probe_body(
                model=plan["provider"]["model"],
                ordinal=ordinal,
            )
            expected_request_sha256 = plan["synthetic_requests"][
                "request_body_canonical_sha256"
            ][ordinal - 1]
            if canonical_sha256(body) != expected_request_sha256:
                raise SoakResponseFailure(
                    "internal",
                    "request_binding_before_dispatch",
                    "TransportSoakRequestBindingError",
                )
            transport = transport_factory(url)
            journal["current_ordinal"] = ordinal
            journal["state"] = "connection_setup_in_progress_pre_dispatch"
            write_private_json(journal_path, journal)
            try:
                transport.prepare()
                journal["state"] = "connection_prepared_dispatch_not_started"
                journal["current_connect_attempt_count"] = (
                    transport.connect_attempt_count
                )
                write_private_json(journal_path, journal)
                journal["state"] = "dispatch_intent_persisted_single_use"
                journal["provider_dispatch_count"] += 1
                write_private_json(journal_path, journal)
                status, response_body = transport.post_json_once(
                    api_key=api_key,
                    body=body,
                    user_agent="civitasos-j1-transport-soak/1",
                )
            finally:
                journal["current_connect_attempt_count"] = (
                    transport.connect_attempt_count
                )
                transport.close()
            result = normalize_response(
                status=status,
                body=response_body,
                plan=plan,
            )
            response_body = b""
            receipt = {
                "ordinal": ordinal,
                "request_body_canonical_sha256": expected_request_sha256,
                "connect_attempt_count": transport.connect_attempt_count,
                "http_request_count": transport.http_request_count,
                "post_dispatch_retry_count": 0,
                "response": {
                    "http_status": result["http_status"],
                    "raw_response_sha256": result["raw_response_sha256"],
                    "response_id_sha256": result["response_id_sha256"],
                    "content_sha256": result["content_sha256"],
                    "content_utf8_bytes": result["content_utf8_bytes"],
                    "response_model": result["response_model"],
                    "response_content_persisted": False,
                },
                "usage": result["usage"],
                "actual_cost_microunits": result["actual_cost_microunits"],
            }
            receipt["receipt_sha256"] = canonical_sha256(receipt)
            receipts.append(receipt)
            journal["completed_call_count"] = len(receipts)
            journal["state"] = "call_reconciled"
            write_private_json(journal_path, journal)
    except Exception as error:
        failure = _sanitize_failure(
            error,
            dispatch_performed=journal["provider_dispatch_count"] > len(receipts),
            ordinal=journal.get("current_ordinal"),
            connect_attempt_count=journal.get("current_connect_attempt_count", 0),
        )
    finally:
        api_key = ""
    elapsed = max(0.0, monotonic() - started)
    report = _build_report(
        plan=plan,
        plan_ref=plan_ref,
        preflight_ref=preflight_ref,
        claim_ref=claim_ref,
        authorization_sha256=authorization_sha256,
        provider_env_path=provider_env_path,
        journal=journal,
        receipts=receipts,
        failure=failure,
        elapsed_seconds=elapsed,
        implementation=implementation,
    )
    write_private_json(report_path, report)
    passed = failure is None and len(receipts) == SOAK_CALL_COUNT
    journal["state"] = (
        "soak_passed_authorization_consumed"
        if passed
        else "soak_failed_authorization_consumed_no_retry"
    )
    journal["current_ordinal"] = None
    journal.pop("current_connect_attempt_count", None)
    if failure is not None:
        journal["sanitized_failure"] = failure
    write_private_json(journal_path, journal)
    gate = {
        "schema_version": GATE_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": [] if passed else ["transport_admission_soak_failed"],
        "state": (
            "transport_admission_soak_passed"
            if passed
            else "transport_admission_soak_failed_authorization_consumed"
        ),
        "authorization": {
            "statement_sha256": authorization_sha256,
            "claim": claim_ref,
            "consumed": True,
            "reusable": False,
        },
        "report": _ref(report_path, report["report_sha256"], report_path.read_bytes()),
        "journal": _ref(
            journal_path,
            canonical_sha256(journal),
            journal_path.read_bytes(),
        ),
        "readiness": {
            "transport_admission_passed": passed,
            "new_outcome_sensitive_execution_stack_allowed": passed,
            "provider_or_model_execution_authorized": False,
        },
        "execution_boundary": report["execution_boundary"],
    }
    gate["report_sha256"] = canonical_sha256(gate)
    write_private_json(gate_path, gate)
    return gate


def _build_report(
    *,
    plan: dict[str, Any],
    plan_ref: dict[str, str],
    preflight_ref: dict[str, str],
    claim_ref: dict[str, str],
    authorization_sha256: str,
    provider_env_path: Path,
    journal: dict[str, Any],
    receipts: list[dict[str, Any]],
    failure: dict[str, Any] | None,
    elapsed_seconds: float,
    implementation: dict[str, str],
) -> dict[str, Any]:
    actual_tokens = sum(item["usage"]["total"] for item in receipts)
    actual_cost = sum(item["actual_cost_microunits"] for item in receipts)
    unknown = int(bool(failure and failure["provider_outcome_unknown"]))
    histogram: dict[str, int] = {}
    for item in receipts:
        key = str(item["connect_attempt_count"])
        histogram[key] = histogram.get(key, 0) + 1
    if failure is not None and failure["connect_attempt_count"] > 0:
        key = str(failure["connect_attempt_count"])
        histogram[key] = histogram.get(key, 0) + 1
    value = {
        "schema_version": REPORT_SCHEMA,
        "soak_id": plan["soak_id"],
        "completed_at": datetime.now(UTC).isoformat(),
        "status": "passed" if failure is None else "failed",
        "source_binding": {
            "plan": plan_ref,
            "preflight": preflight_ref,
            "claim": claim_ref,
        },
        "authorization": {
            "statement_sha256": authorization_sha256,
            "consumed": True,
            "reusable": False,
        },
        "provider": {
            "provider_id": plan["provider"]["provider_id"],
            "model": plan["provider"]["model"],
            "base_url_sha256": hashlib.sha256(
                plan["provider"]["base_url"].encode()
            ).hexdigest(),
        },
        "scope": {
            "required_call_count": SOAK_CALL_COUNT,
            "provider_dispatch_count": journal["provider_dispatch_count"],
            "completed_call_count": len(receipts),
            "unattempted_call_count": SOAK_CALL_COUNT
            - journal["provider_dispatch_count"],
            "provider_outcome_unknown_count": unknown,
            "post_dispatch_retry_count": 0,
            "elapsed_seconds": round(elapsed_seconds, 6),
        },
        "credential": {
            "basename": provider_env_path.name,
            "read_count": journal["provider_env_read_count"],
            "value_persisted": False,
            "hash_persisted": False,
        },
        "budget": {
            "reserved_tokens": plan["budget"]["aggregate_reserved_tokens"],
            "known_actual_tokens": actual_tokens,
            "reserved_cost_microunits": plan["budget"][
                "aggregate_max_microunits"
            ],
            "known_actual_cost_microunits": actual_cost,
            "within_known_ceiling": (
                actual_tokens <= plan["budget"]["aggregate_reserved_tokens"]
                and actual_cost <= plan["budget"]["aggregate_max_microunits"]
            ),
        },
        "connect_attempt_histogram": histogram,
        "call_receipts": receipts,
        "sanitized_failure": failure,
        "implementation": implementation,
        "execution_boundary": {
            "transport_admission_soak_only": True,
            "provider_credential_read_count": journal["provider_env_read_count"],
            "credential_value_or_hash_persisted": False,
            "provider_api_call_count": journal["provider_dispatch_count"],
            "model_invocation_count": journal["provider_dispatch_count"],
            "response_content_persisted": False,
            "exception_message_persisted": False,
            "participant_data_used": False,
            "participant_container_started_or_modified": False,
            "agent_or_controlled_experiment_executed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
            "effectiveness_claim_authorized": False,
            "si13_maturity_upgrade_authorized": False,
        },
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _sanitize_failure(
    error: BaseException,
    *,
    dispatch_performed: bool,
    ordinal: Any,
    connect_attempt_count: int,
) -> dict[str, Any]:
    if isinstance(error, SanitizedProviderFailure):
        category = error.failure_category
        stage = error.failure_stage
        source = error.source_exception_type
        unknown = dispatch_performed or stage == "http_dispatch_ambiguous"
    elif isinstance(error, SoakResponseFailure):
        category = error.failure_category
        stage = error.failure_stage
        source = error.source_exception_type
        unknown = False
    else:
        category = "internal"
        stage = (
            "post_dispatch_unclassified"
            if dispatch_performed
            else "pre_dispatch_unclassified"
        )
        source = type(error).__name__
        unknown = dispatch_performed
    return {
        "ordinal": ordinal,
        "failure_category": category,
        "failure_stage": stage,
        "source_exception_type": source,
        "dispatch_performed": dispatch_performed,
        "provider_outcome_unknown": unknown,
        "connect_attempt_count": connect_attempt_count,
        "retry_performed": False,
    }


def _read_provider_env(path: Path, plan: dict[str, Any]) -> str:
    failures: list[str] = []
    values = _load_private_env(path, failures)
    if failures:
        raise ValueError(f"transport provider environment invalid: {failures}")
    expected = {
        "BETA6_EXTERNAL_AGENT_PROVIDER": plan["provider"]["provider_id"],
        "BETA6_EXTERNAL_AGENT_API_BASE_URL": plan["provider"]["base_url"],
        "BETA6_EXTERNAL_AGENT_MODEL": plan["provider"]["model"],
    }
    for name, expected_value in expected.items():
        if values.get(name, "").rstrip("/") != expected_value:
            raise ValueError(f"transport provider configuration mismatch: {name}")
    api_key = values.get("BETA6_EXTERNAL_AGENT_API_KEY", "")
    if not api_key:
        raise ValueError("transport provider API key missing")
    return api_key


def _replay_sources(plan: dict[str, Any]) -> None:
    for name, reference in plan["source_artifacts"].items():
        path = Path(reference["path"])
        value, raw = _read_private(path)
        canonical_values = {
            item
            for field, item in value.items()
            if field.endswith("_sha256")
        }
        if (
            hashlib.sha256(raw).hexdigest() != reference["sha256"]
            or reference["canonical_sha256"] not in canonical_values
        ):
            raise ValueError(f"transport soak source drift: {name}")


def _clean_pushed_implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before transport soak")
    revision = _git(root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("transport soak execution revision is not pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "preflight_source_sha256": hashlib.sha256(
            PREFLIGHT_SOURCE.read_bytes()
        ).hexdigest(),
        "execution_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _ref(
    path: Path, canonical_digest: str, raw: bytes
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claimed-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--provider-env", type=Path, required=True)
    parser.add_argument("--claim-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    datetime.fromisoformat(args.claimed_at.replace("Z", "+00:00"))
    gate = execute_soak(
        claimed_at=args.claimed_at,
        authorization_statement_value=args.authorization_statement,
        plan_path=args.plan,
        preflight_path=args.preflight,
        provider_env_path=args.provider_env,
        claim_root=args.claim_root,
        output_root=args.output_root,
        repository_root=args.repository_root,
    )
    print(json.dumps(gate, ensure_ascii=False, sort_keys=True))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
