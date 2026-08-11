"""Consume one authorization for one synthetic J1-D provider admission probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_http_transport import PreparedHTTPSPost
from benchmarks.j1.qualification_admission import _load_private_env
from benchmarks.j1.qualification_provider_admission_probe import (
    GATE_SCHEMA,
    PROBE_BOUNDARY,
    build_claim,
    build_probe_receipt,
    normalize_probe_response,
    validate_probe_receipt,
    validate_probe_sources,
)
from benchmarks.j1_qualification_infrastructure_rebind import _read_private
from benchmarks.j1_qualification_provider_admission_refresh import (
    _inspect_current_inventory,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_provider_admission_probe.py"
)
OPERATION_SOURCE = Path(__file__)
TRANSPORT_DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_http_transport.py"
)
OUTCOME_IMPLEMENTATION_SOURCES = {
    "domain_source_sha256": (
        Path(__file__).parent
        / "j1"
        / "qualification_outcome_sensitive_provider_admission.py"
    ),
    "operation_source_sha256": (
        Path(__file__).parent
        / "j1_qualification_outcome_sensitive_provider_admission.py"
    ),
    "probe_domain_source_sha256": DOMAIN_SOURCE,
    "probe_operation_source_sha256": OPERATION_SOURCE,
    "outcome_probe_operation_source_sha256": (
        Path(__file__).parent
        / "j1_qualification_outcome_sensitive_provider_probe.py"
    ),
    "transport_domain_source_sha256": TRANSPORT_DOMAIN_SOURCE,
}
CONFIRMATORY_IMPLEMENTATION_SOURCES = {
    "domain_source_sha256": (
        Path(__file__).parent
        / "j1"
        / "qualification_outcome_sensitive_confirmatory_provider_admission.py"
    ),
    "operation_source_sha256": (
        Path(__file__).parent
        / "j1_qualification_outcome_sensitive_confirmatory_provider_admission.py"
    ),
    "probe_domain_source_sha256": DOMAIN_SOURCE,
    "probe_operation_source_sha256": OPERATION_SOURCE,
    "confirmatory_probe_operation_source_sha256": (
        Path(__file__).parent
        / "j1_qualification_outcome_sensitive_confirmatory_provider_probe.py"
    ),
    "transport_domain_source_sha256": TRANSPORT_DOMAIN_SOURCE,
}
Transport = Callable[[str, str, dict[str, Any]], tuple[int, bytes]]
PreparedTransportFactory = Callable[[str], PreparedHTTPSPost]
SourceValidator = Callable[..., list[str]]
SourceReplayer = Callable[[dict[str, Any]], dict[str, dict[str, Any]]]
MAX_RESPONSE_BYTES = 1_048_576


def execute_probe(
    *,
    probe_id: str,
    claimed_at: str,
    authorization_statement: str,
    plan_path: Path,
    preflight_path: Path,
    provider_env_path: Path,
    claim_root: Path,
    output_root: Path,
    repository_root: Path,
    transport: Transport | None = None,
    prepared_transport_factory: PreparedTransportFactory = PreparedHTTPSPost,
    source_validator: SourceValidator = validate_probe_sources,
    source_replayer: SourceReplayer | None = None,
) -> dict[str, Any]:
    _require_rfc3339(claimed_at)
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    plan_raw_sha256 = hashlib.sha256(plan_raw).hexdigest()
    preflight_raw_sha256 = hashlib.sha256(preflight_raw).hexdigest()
    failures = source_validator(
        plan=plan,
        plan_raw_sha256=plan_raw_sha256,
        preflight=preflight,
        authorization_statement=authorization_statement,
    )
    if failures:
        raise ValueError(f"provider admission probe source invalid: {failures}")
    source_values = (source_replayer or _replay_plan_sources)(plan)
    inventory_before, inventory_failures = _inspect_current_inventory(
        infrastructure=source_values["infrastructure"],
        activation=source_values["activation"],
    )
    if inventory_failures:
        raise ValueError(
            f"provider admission probe inventory invalid: {inventory_failures}"
        )
    implementation = _implementation(repository_root, plan=plan)
    if output_root.exists():
        raise ValueError(f"provider admission probe output exists: {output_root}")
    authorization_sha256 = hashlib.sha256(authorization_statement.encode()).hexdigest()
    claim_path = claim_root.resolve() / f"{authorization_sha256}.claim.json"
    if claim_path.exists():
        raise ValueError("provider admission probe authorization already claimed")
    output_root.mkdir(mode=0o700)
    output_root.chmod(0o700)
    claim = build_claim(
        probe_id=probe_id,
        claimed_at=claimed_at,
        authorization_statement_sha256=authorization_sha256,
        plan_raw_sha256=plan_raw_sha256,
        plan_canonical_sha256=plan["plan_sha256"],
        preflight_raw_sha256=preflight_raw_sha256,
        preflight_canonical_sha256=preflight["preflight_sha256"],
        output_root_sha256=hashlib.sha256(
            str(output_root.resolve()).encode()
        ).hexdigest(),
        plan=plan,
    )
    try:
        _write_exclusive_private_json(claim_path, claim)
    except Exception:
        output_root.rmdir()
        raise
    claim_raw_sha256 = hashlib.sha256(claim_path.read_bytes()).hexdigest()
    journal_path = output_root / "provider-admission-probe-journal.json"
    journal = {
        "schema_version": "j1-qualification-provider-admission-probe-journal:v1",
        "probe_id": probe_id,
        "state": "authorization_claimed_call_reserved",
        "authorization_statement_sha256": authorization_sha256,
        "claim_artifact_sha256": claim_raw_sha256,
        "claim_sha256": claim["claim_sha256"],
        "provider_env_read_count": 0,
        "provider_call_count": 0,
        "reservation": claim["reservation"],
    }
    write_private_json(journal_path, journal)
    provider_env_read_count = 0
    provider_call_count = 0
    transport_evidence: dict[str, Any] | None = None
    prepared_transport: PreparedHTTPSPost | None = None
    api_key = ""
    try:
        api_key = _read_provider_configuration(
            provider_env_path,
            plan=plan,
        )
        provider_env_read_count = 1
        journal["provider_env_read_count"] = 1
        journal["state"] = "credential_validated_call_reserved"
        write_private_json(journal_path, journal)
        provider = plan["frozen_stack"]
        request_body = plan["probe_contract"]["request_body"]
        url = f"{provider['base_url']}{plan['probe_contract']['path']}"
        if transport is None:
            prepared_transport = prepared_transport_factory(url)
            journal["state"] = "connection_setup_in_progress_pre_dispatch"
            write_private_json(journal_path, journal)
            prepared_transport.prepare()
            journal["connect_attempt_count"] = (
                prepared_transport.connect_attempt_count
            )
            journal["state"] = "connection_prepared_dispatch_not_started"
            write_private_json(journal_path, journal)
        provider_call_count = 1
        journal["provider_call_count"] = 1
        journal["state"] = "provider_call_dispatched_no_retry"
        write_private_json(journal_path, journal)
        if prepared_transport is not None:
            status, body = prepared_transport.post_json_once(
                api_key=api_key,
                body=request_body,
                user_agent="civitasos-j1d-admission-probe/2",
            )
            provider_call_count = prepared_transport.http_request_count
        else:
            status, body = transport(url, api_key, request_body)
        api_key = ""
        transport_evidence = _sanitized_transport_evidence(status=status, body=body)
        if prepared_transport is not None:
            transport_evidence.update(
                _prepared_transport_evidence(prepared_transport)
            )
        provider_result = normalize_probe_response(
            status=status,
            body=body,
            plan=plan,
        )
        inventory_after, inventory_failures = _inspect_current_inventory(
            infrastructure=source_values["infrastructure"],
            activation=source_values["activation"],
        )
        if inventory_failures:
            raise ValueError(
                f"provider admission probe post-inventory invalid: {inventory_failures}"
            )
        receipt = build_probe_receipt(
            probe_id=probe_id,
            completed_at=_now(),
            authorization_statement_sha256=authorization_sha256,
            claim_raw_sha256=claim_raw_sha256,
            claim_canonical_sha256=claim["claim_sha256"],
            plan=plan,
            plan_raw_sha256=plan_raw_sha256,
            preflight_raw_sha256=preflight_raw_sha256,
            provider_result=provider_result,
            inventory_before=inventory_before,
            inventory_after=inventory_after,
            implementation=implementation,
            credential_basename=provider_env_path.name,
        )
        receipt_failures = validate_probe_receipt(
            receipt,
            plan=plan,
            expected_authorization_sha256=authorization_sha256,
        )
        if receipt_failures:
            raise ValueError(
                f"provider admission probe receipt invalid: {receipt_failures}"
            )
        receipt_path = output_root / "provider-admission-probe-receipt.json"
        write_private_json(receipt_path, receipt)
        journal["state"] = "probe_admitted_authorization_consumed"
        write_private_json(journal_path, journal)
        report = {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "failure_reasons": [],
            "state": "live_provider_admission_refreshed_execution_still_blocked",
            "probe_id": probe_id,
            "authorization": {
                "statement_sha256": authorization_sha256,
                "claim": _artifact(claim_path, claim["claim_sha256"]),
                "consumed": True,
                "reusable": False,
            },
            "source_binding": {
                "plan_artifact_sha256": plan_raw_sha256,
                "plan_sha256": plan["plan_sha256"],
                "preflight_artifact_sha256": preflight_raw_sha256,
                "preflight_sha256": preflight["preflight_sha256"],
            },
            "receipt": _artifact(receipt_path, receipt["receipt_sha256"]),
            "journal": _artifact(journal_path),
            "sanitized_transport_evidence": transport_evidence,
            "checks": {
                "single_use_claim_persisted_before_credential_access": True,
                "budget_reserved_before_provider_call": True,
                "credential_read_exactly_once": True,
                "one_https_post_with_bounded_pre_dispatch_connect_retries": True,
                "provider_model_identity_matched": True,
                "usage_and_cost_reconciled": True,
                "response_content_not_persisted": True,
                "participant_inventory_unchanged_and_stopped": True,
            },
            "readiness": {
                "live_provider_admission_refreshed": True,
                "real_evaluator_frozen": False,
                "post_run_receipt_and_closeout_frozen": False,
                "execution_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
            "next_blockers": [
                "real_evaluator_freeze_required",
                "post_run_receipt_and_closeout_gate_required",
                "new_execution_preflight_required",
            ],
            "implementation": implementation,
            "execution_boundary": PROBE_BOUNDARY,
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "provider-admission-probe-gate-report.json",
            report,
        )
        return report
    except Exception as error:
        api_key = ""
        if prepared_transport is not None:
            provider_call_count = prepared_transport.http_request_count
            transport_evidence = _prepared_transport_failure_evidence(
                prepared_transport,
                error=error,
                prior=transport_evidence,
            )
        journal["state"] = "probe_failed_authorization_consumed_no_retry"
        journal["provider_env_read_count"] = provider_env_read_count
        journal["provider_call_count"] = provider_call_count
        if prepared_transport is not None:
            journal["connect_attempt_count"] = (
                prepared_transport.connect_attempt_count
            )
        write_private_json(journal_path, journal)
        report = _failure_report(
            probe_id=probe_id,
            authorization_sha256=authorization_sha256,
            claim_path=claim_path,
            claim=claim,
            plan=plan,
            plan_raw_sha256=plan_raw_sha256,
            preflight=preflight,
            preflight_raw_sha256=preflight_raw_sha256,
            journal_path=journal_path,
            implementation=implementation,
            provider_env_read_count=provider_env_read_count,
            provider_call_count=provider_call_count,
            transport_evidence=transport_evidence,
            error=error,
        )
        write_private_json(
            output_root / "provider-admission-probe-gate-report.json",
            report,
        )
        return report
    finally:
        api_key = ""
        if prepared_transport is not None:
            prepared_transport.close()


def _replay_plan_sources(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for name, reference in plan["source_binding"].items():
        path = Path(reference["path"])
        value, raw = _read_private(path)
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise ValueError(f"provider admission probe source drift: {name}")
        if _canonical_source_sha256(name, value) != reference["canonical_sha256"]:
            raise ValueError(f"provider admission probe canonical drift: {name}")
        values[name] = value
    required = {
        "protocol",
        "design",
        "bundle",
        "roster",
        "assignment",
        "roster_assignment_gate",
        "infrastructure",
        "activation",
        "activation_gate",
        "runner_manifest",
    }
    optional = {"prior_failed_probe_gate", "prior_probe_claim"}
    extras = set(values) - required
    if not required.issubset(values) or extras not in (set(), optional):
        raise ValueError("provider admission probe source set invalid")
    return values


def _read_provider_configuration(path: Path, *, plan: dict[str, Any]) -> str:
    failures: list[str] = []
    values = _load_private_env(path, failures)
    if failures:
        raise ValueError(f"provider environment invalid: {failures}")
    stack = plan["frozen_stack"]
    expected = {
        "BETA6_EXTERNAL_AGENT_PROVIDER": stack["provider_id"],
        "BETA6_EXTERNAL_AGENT_API_BASE_URL": stack["base_url"],
        "BETA6_EXTERNAL_AGENT_MODEL": stack["model_id"],
    }
    for name, expected_value in expected.items():
        configured = values.get(name, "").rstrip("/")
        if configured != expected_value:
            raise ValueError(f"provider environment {name} mismatch")
    api_key = values.get("BETA6_EXTERNAL_AGENT_API_KEY", "")
    if not api_key:
        raise ValueError("provider environment API key missing")
    return api_key


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _https_post_once(url: str, api_key: str, body: dict[str, Any]) -> tuple[int, bytes]:
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "civitasos-j1d-admission-probe/1",
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
    )
    try:
        with opener.open(request, timeout=30) as response:
            status = int(response.status)
            result = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        result = error.read(MAX_RESPONSE_BYTES + 1)
    if len(result) > MAX_RESPONSE_BYTES:
        raise ValueError("probe provider response exceeded byte ceiling")
    return status, result


def _sanitized_transport_evidence(*, status: int, body: bytes) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "http_status": status,
        "raw_response_sha256": hashlib.sha256(body).hexdigest(),
        "raw_response_bytes": len(body),
        "json_object": False,
        "response_model": None,
        "response_id_sha256": None,
        "choice_count": 0,
        "content_kind": "unavailable",
        "content_sha256": None,
        "finish_reason": None,
        "usage": None,
        "raw_response_persisted": False,
        "response_content_persisted": False,
    }
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return evidence
    if not isinstance(value, dict):
        return evidence
    evidence["json_object"] = True
    if isinstance(value.get("model"), str):
        evidence["response_model"] = value["model"]
    if value.get("id") is not None:
        evidence["response_id_sha256"] = hashlib.sha256(
            str(value["id"]).encode()
        ).hexdigest()
    choices = value.get("choices")
    if isinstance(choices, list):
        evidence["choice_count"] = len(choices)
        if choices and isinstance(choices[0], dict):
            evidence["finish_reason"] = choices[0].get("finish_reason")
            message = choices[0].get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if content is None:
                    evidence["content_kind"] = "null"
                    encoded = b"null"
                elif isinstance(content, str):
                    evidence["content_kind"] = "string"
                    encoded = content.encode()
                else:
                    evidence["content_kind"] = type(content).__name__
                    encoded = json.dumps(
                        content,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                evidence["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    usage = value.get("usage")
    if isinstance(usage, dict):
        allowed = (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_cache_hit_tokens",
            "prompt_cache_miss_tokens",
        )
        evidence["usage"] = {
            key: usage[key]
            for key in allowed
            if type(usage.get(key)) is int and usage[key] >= 0
        }
    return evidence


def _prepared_transport_evidence(
    transport: PreparedHTTPSPost,
) -> dict[str, Any]:
    return {
        "connect_attempt_count": transport.connect_attempt_count,
        "http_request_count": transport.http_request_count,
        "post_dispatch_retry_count": 0,
        "transport_policy": transport.policy.as_dict(),
    }


def _prepared_transport_failure_evidence(
    transport: PreparedHTTPSPost,
    *,
    error: Exception,
    prior: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence = dict(prior or {})
    evidence.update(_prepared_transport_evidence(transport))
    category = getattr(error, "failure_category", None)
    stage = getattr(error, "failure_stage", None)
    source_type = getattr(error, "source_exception_type", None)
    if all(isinstance(value, str) and value for value in (category, stage, source_type)):
        evidence["sanitized_failure"] = {
            "category": category,
            "stage": stage,
            "source_exception_type": source_type,
            "exception_message_persisted": False,
        }
    else:
        evidence["sanitized_failure"] = {
            "category": "internal",
            "stage": (
                "post_dispatch_unclassified"
                if transport.http_request_count
                else "pre_dispatch_unclassified"
            ),
            "source_exception_type": type(error).__name__,
            "exception_message_persisted": False,
        }
    return evidence


def _failure_report(
    *,
    probe_id: str,
    authorization_sha256: str,
    claim_path: Path,
    claim: dict[str, Any],
    plan: dict[str, Any],
    plan_raw_sha256: str,
    preflight: dict[str, Any],
    preflight_raw_sha256: str,
    journal_path: Path,
    implementation: dict[str, str],
    provider_env_read_count: int,
    provider_call_count: int,
    transport_evidence: dict[str, Any] | None,
    error: Exception,
) -> dict[str, Any]:
    boundary = {
        **PROBE_BOUNDARY,
        "provider_admission_refreshed": False,
        "credential_file_accessed_once": provider_env_read_count == 1,
        "provider_api_call_count": provider_call_count,
        "model_invocation_count": provider_call_count,
    }
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": False,
        "failure_reasons": [_failure_code(error)],
        "state": "provider_admission_probe_failed_authorization_consumed",
        "probe_id": probe_id,
        "authorization": {
            "statement_sha256": authorization_sha256,
            "claim": _artifact(claim_path, claim["claim_sha256"]),
            "consumed": True,
            "reusable": False,
        },
        "source_binding": {
            "plan_artifact_sha256": plan_raw_sha256,
            "plan_sha256": plan["plan_sha256"],
            "preflight_artifact_sha256": preflight_raw_sha256,
            "preflight_sha256": preflight["preflight_sha256"],
        },
        "journal": _artifact(journal_path),
        "provider_env_read_count": provider_env_read_count,
        "provider_call_count": provider_call_count,
        "sanitized_transport_evidence": transport_evidence,
        "retry_performed": False,
        "readiness": {
            "live_provider_admission_refreshed": False,
            "execution_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": implementation,
        "execution_boundary": boundary,
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _failure_code(error: Exception) -> str:
    category = getattr(error, "failure_category", None)
    stage = getattr(error, "failure_stage", None)
    if isinstance(category, str) and isinstance(stage, str):
        return f"provider_{category}_{stage}"
    known = {
        "probe provider response is not valid JSON": "provider_response_json_invalid",
        "probe provider response must be an object": "provider_response_object_invalid",
        "probe provider HTTP status was not accepted": "provider_http_status_rejected",
        "probe provider response model mismatch": "provider_model_mismatch",
        "probe provider response choices invalid": "provider_choices_invalid",
        "probe provider response content invalid": "provider_content_invalid",
        "probe provider usage exceeded token reservation": "provider_token_overrun",
        "probe provider usage exceeded cost reservation": "provider_cost_overrun",
        "probe provider response exceeded byte ceiling": "provider_response_too_large",
    }
    return known.get(str(error), type(error).__name__)


def _write_exclusive_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _implementation(repository_root: Path, *, plan: dict[str, Any]) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before provider admission probe")
    revision = _git(root, "rev-parse", "HEAD").strip()
    planned_revision = plan["implementation"]["source_revision"]
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", planned_revision, revision],
        cwd=root,
        check=False,
    )
    if ancestor.returncode != 0:
        raise ValueError("provider admission plan implementation is not an ancestor")
    if plan.get("schema_version") == (
        "j1-qualification-outcome-sensitive-provider-admission-plan:v2"
    ):
        _validate_bound_implementation(
            plan,
            revision=revision,
            sources=OUTCOME_IMPLEMENTATION_SOURCES,
            label="outcome",
        )
    if plan.get("schema_version") == (
        "j1-qualification-outcome-sensitive-confirmatory-provider-admission-plan:v1"
    ):
        _validate_bound_implementation(
            plan,
            revision=revision,
            sources=CONFIRMATORY_IMPLEMENTATION_SOURCES,
            label="confirmatory",
        )
    return {
        "source_revision": revision,
        "plan_source_revision": planned_revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "transport_domain_source_sha256": hashlib.sha256(
            TRANSPORT_DOMAIN_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_bound_implementation(
    plan: dict[str, Any],
    *,
    revision: str,
    sources: dict[str, Path],
    label: str,
) -> None:
    planned = plan.get("implementation")
    if not isinstance(planned, dict) or planned.get("source_revision") != revision:
        raise ValueError(f"{label} provider admission implementation revision drift")
    current = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sources.items()
    }
    if any(planned.get(name) != digest for name, digest in current.items()):
        raise ValueError(f"{label} provider admission implementation source drift")


def _canonical_source_sha256(name: str, value: dict[str, Any]) -> str:
    fields = {
        "protocol": "amended_protocol_sha256",
        "design": "amended_design_sha256",
        "bundle": "bundle_sha256",
        "roster": "reviewed_rebound_roster_sha256",
        "assignment": "reviewed_rebound_assignment_sha256",
        "roster_assignment_gate": "report_sha256",
        "infrastructure": "reviewed_infrastructure_rebind_sha256",
        "activation": "activation_sha256",
        "activation_gate": "report_sha256",
        "runner_manifest": "manifest_sha256",
        "prior_failed_probe_gate": "report_sha256",
        "prior_probe_claim": "claim_sha256",
    }
    return str(value.get(fields.get(name, ""), ""))


def _artifact(path: Path, canonical_sha256_value: str | None = None) -> dict[str, str]:
    value = {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    if canonical_sha256_value:
        value["canonical_sha256"] = canonical_sha256_value
    return value


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _require_rfc3339(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("probe timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("probe timestamp must include timezone")


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-id", required=True)
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
        default=Path(__file__).parents[1],
    )
    args = parser.parse_args()
    report = execute_probe(
        probe_id=args.probe_id,
        claimed_at=args.claimed_at,
        authorization_statement=args.authorization_statement,
        plan_path=args.plan,
        preflight_path=args.preflight,
        provider_env_path=args.provider_env,
        claim_root=args.claim_root,
        output_root=args.output_root,
        repository_root=args.repository_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
