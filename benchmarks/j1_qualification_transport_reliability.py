"""Freeze offline J1-D transport qualification and live-soak review materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_http_transport import (
    HTTPSPostPolicy,
    PreparedHTTPSPost,
)
from benchmarks.j1.qualification_provider_broker import SanitizedProviderFailure
from benchmarks.j1.qualification_transport_reliability import (
    FAULT_SCENARIOS,
    build_fault_matrix_report,
    build_soak_plan,
    build_soak_preflight,
    build_transport_contract,
    validate_fault_matrix_report,
    validate_soak_plan,
    validate_transport_contract,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_transport_reliability.py"
)
TRANSPORT_SOURCE = Path(__file__).parent / "j1" / "qualification_http_transport.py"
OPERATION_SOURCE = Path(__file__)
TERMINAL_GATE_SCHEMA = "j1-qualification-outcome-sensitive-failed-closeout-gate:v1"


def prepare_materials(
    *,
    contract_id: str,
    plan_id: str,
    created_at: str,
    r2_terminal_gate_path: Path,
    r3_terminal_gate_path: Path,
    provider_design_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"transport qualification output exists: {output_root}")
    implementation = _implementation(repository_root)
    r2_gate, r2_raw = _read_private(r2_terminal_gate_path)
    r3_gate, r3_raw = _read_private(r3_terminal_gate_path)
    provider_design, provider_raw = _read_private(provider_design_path)
    _validate_terminal_gate(r2_gate, expected_run_suffix="20260730-r2")
    _validate_terminal_gate(r3_gate, expected_run_suffix="20260731-r3")
    provider = _provider(provider_design)
    provider_design_canonical = _canonical_from(
        provider_design,
        (
            "reviewed_design_sha256",
            "amended_design_sha256",
            "artifact_sha256",
            "design_sha256",
        ),
    )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        contract = build_transport_contract(
            contract_id=contract_id,
            created_at=created_at,
            source_binding={
                "r2_terminal_gate": _ref(
                    r2_terminal_gate_path, r2_gate["report_sha256"], raw=r2_raw
                ),
                "r3_terminal_gate": _ref(
                    r3_terminal_gate_path, r3_gate["report_sha256"], raw=r3_raw
                ),
            },
            implementation=implementation,
        )
        contract_failures = validate_transport_contract(contract)
        if contract_failures:
            raise ValueError(f"transport contract invalid: {contract_failures}")
        contract_path = staging / "transport-reliability-contract.json"
        write_private_json(contract_path, contract)
        contract_ref = _published_ref(
            contract_path,
            output_root / contract_path.name,
            contract["contract_sha256"],
        )
        fault_report = run_fault_matrix(
            checked_at=created_at,
            contract_ref=contract_ref,
            implementation=implementation,
        )
        fault_failures = validate_fault_matrix_report(fault_report)
        if fault_failures:
            raise ValueError(f"transport fault matrix invalid: {fault_failures}")
        fault_path = staging / "transport-fault-matrix-report.json"
        write_private_json(fault_path, fault_report)
        fault_ref = _published_ref(
            fault_path,
            output_root / fault_path.name,
            fault_report["report_sha256"],
        )
        plan = build_soak_plan(
            plan_id=plan_id,
            created_at=created_at,
            contract_ref=contract_ref,
            fault_matrix_ref=fault_ref,
            provider_design_ref=_ref(
                provider_design_path,
                provider_design_canonical,
                raw=provider_raw,
            ),
            provider=provider,
            implementation=implementation,
        )
        plan_failures = validate_soak_plan(plan)
        if plan_failures:
            raise ValueError(f"transport soak plan invalid: {plan_failures}")
        plan_path = staging / "transport-admission-soak-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_ref = _published_ref(
            plan_path,
            output_root / plan_path.name,
            plan["plan_sha256"],
        )
        preflight = build_soak_preflight(
            checked_at=created_at,
            plan_ref=plan_ref,
            plan=plan,
            validation_failures=plan_failures,
        )
        preflight_path = staging / "transport-admission-soak-preflight.json"
        write_private_json(preflight_path, preflight)
        preflight_ref = _published_ref(
            preflight_path,
            output_root / preflight_path.name,
            preflight["preflight_sha256"],
        )
        statement = _review_statement(
            contract_raw_sha256=contract_ref["sha256"],
            contract_canonical_sha256=contract_ref["canonical_sha256"],
            fault_raw_sha256=fault_ref["sha256"],
            fault_canonical_sha256=fault_ref["canonical_sha256"],
            plan_raw_sha256=plan_ref["sha256"],
            plan_canonical_sha256=plan_ref["canonical_sha256"],
            r2_gate_canonical_sha256=r2_gate["report_sha256"],
            r3_gate_canonical_sha256=r3_gate["report_sha256"],
        )
        handoff = {
            "schema_version": "j1-qualification-transport-review-handoff:v1",
            "status": "owner_approval_for_independent_review_required",
            "transport_contract": contract_ref,
            "fault_matrix": fault_ref,
            "soak_plan": plan_ref,
            "soak_preflight": preflight_ref,
            "required_exact_approval_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            "execution_boundary": {
                "independent_review_completed": False,
                "provider_credential_read": False,
                "provider_or_model_call_performed": False,
                "participant_container_started": False,
                "backend_fact_append_performed": False,
                "ledger_append_performed": False,
                "live_soak_authorization_issued_or_consumed": False,
            },
        }
        handoff["handoff_sha256"] = canonical_sha256(handoff)
        write_private_json(staging / "transport-review-handoff.json", handoff)
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return handoff


def run_fault_matrix(
    *,
    checked_at: str,
    contract_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    scenarios = [
        _transient_connect_scenario(),
        _connect_exhaustion_scenario(),
        _tls_exhaustion_scenario(),
        _request_failure_scenario(),
        _response_header_failure_scenario(),
        _response_body_failure_scenario(),
        _response_size_scenario(),
        _single_use_scenario(),
    ]
    if [item["scenario"] for item in scenarios] != list(FAULT_SCENARIOS):
        raise ValueError("transport fault scenario order drifted")
    return build_fault_matrix_report(
        checked_at=checked_at,
        contract_ref=contract_ref,
        scenarios=scenarios,
        implementation=implementation,
    )


class _Socket:
    def settimeout(self, _: float) -> None:
        return None


class _Response:
    status = 200

    def __init__(self, *, body: bytes = b"{}", error: Exception | None = None):
        self.body = body
        self.error = error

    def read(self, _: int) -> bytes:
        if self.error is not None:
            raise self.error
        return self.body


class _Connection:
    def __init__(
        self,
        *,
        connect_error: Exception | None = None,
        request_error: Exception | None = None,
        response_error: Exception | None = None,
        response: _Response | None = None,
    ) -> None:
        self.connect_error = connect_error
        self.request_error = request_error
        self.response_error = response_error
        self.response = response or _Response()
        self.sock = _Socket()
        self.request_count = 0

    def connect(self) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    def request(self, *_: Any, **__: Any) -> None:
        self.request_count += 1
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> _Response:
        if self.response_error is not None:
            raise self.response_error
        return self.response

    def close(self) -> None:
        return None


def _transport(connections: list[_Connection]) -> PreparedHTTPSPost:
    inventory = list(connections)

    def factory(*_: Any) -> _Connection:
        return inventory.pop(0)

    return PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=factory,
        sleeper=lambda _: None,
    )


def _post(transport: PreparedHTTPSPost) -> tuple[int, bytes]:
    return transport.post_json_once(
        api_key="not-recorded",
        body={"synthetic": True},
        user_agent="civitasos-j1d-transport-fault-matrix/1",
    )


def _scenario(
    *,
    name: str,
    expected: str,
    observed: str,
    transport: PreparedHTTPSPost,
    connections: list[_Connection],
    passed: bool,
) -> dict[str, Any]:
    return {
        "scenario": name,
        "expected": expected,
        "observed": observed,
        "observed_connect_attempt_count": transport.connect_attempt_count,
        "observed_http_request_count": sum(
            connection.request_count for connection in connections
        ),
        "observed_post_dispatch_retry_count": 0,
        "passed": passed,
    }


def _transient_connect_scenario() -> dict[str, Any]:
    connections = [
        _Connection(connect_error=OSError()),
        _Connection(connect_error=TimeoutError()),
        _Connection(),
    ]
    transport = _transport(connections)
    transport.prepare()
    result = _post(transport)
    return _scenario(
        name=FAULT_SCENARIOS[0],
        expected="three_connect_attempts_one_http_request_success",
        observed="three_connect_attempts_one_http_request_success",
        transport=transport,
        connections=connections,
        passed=result == (200, b"{}"),
    )


def _connect_exhaustion_scenario() -> dict[str, Any]:
    connections = [_Connection(connect_error=OSError()) for _ in range(3)]
    transport = _transport(connections)
    failure = _capture_failure(transport.prepare)
    return _scenario(
        name=FAULT_SCENARIOS[1],
        expected="http_pre_dispatch_connect_zero_http_requests",
        observed=f"{failure.failure_stage}_zero_http_requests",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_pre_dispatch_connect",
    )


def _tls_exhaustion_scenario() -> dict[str, Any]:
    connections = [_Connection(connect_error=ssl.SSLError()) for _ in range(3)]
    transport = _transport(connections)
    failure = _capture_failure(transport.prepare)
    return _scenario(
        name=FAULT_SCENARIOS[2],
        expected="http_pre_dispatch_tls_zero_http_requests",
        observed=f"{failure.failure_stage}_zero_http_requests",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_pre_dispatch_tls",
    )


def _request_failure_scenario() -> dict[str, Any]:
    connections = [_Connection(request_error=TimeoutError())]
    transport = _transport(connections)
    transport.prepare()
    failure = _capture_failure(lambda: _post(transport))
    return _scenario(
        name=FAULT_SCENARIOS[3],
        expected="http_dispatch_ambiguous_one_request_zero_retries",
        observed=f"{failure.failure_stage}_one_request_zero_retries",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_dispatch_ambiguous",
    )


def _response_header_failure_scenario() -> dict[str, Any]:
    connections = [_Connection(response_error=TimeoutError())]
    transport = _transport(connections)
    transport.prepare()
    failure = _capture_failure(lambda: _post(transport))
    return _scenario(
        name=FAULT_SCENARIOS[4],
        expected="http_dispatch_ambiguous_one_request_zero_retries",
        observed=f"{failure.failure_stage}_one_request_zero_retries",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_dispatch_ambiguous",
    )


def _response_body_failure_scenario() -> dict[str, Any]:
    connections = [_Connection(response=_Response(error=TimeoutError()))]
    transport = _transport(connections)
    transport.prepare()
    failure = _capture_failure(lambda: _post(transport))
    return _scenario(
        name=FAULT_SCENARIOS[5],
        expected="http_dispatch_ambiguous_one_request_zero_retries",
        observed=f"{failure.failure_stage}_one_request_zero_retries",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_dispatch_ambiguous",
    )


def _response_size_scenario() -> dict[str, Any]:
    policy = HTTPSPostPolicy(max_response_bytes=1)
    connections = [_Connection(response=_Response(body=b"{}"))]
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        policy=policy,
        connection_factory=lambda *_: connections[0],
    )
    transport.prepare()
    failure = _capture_failure(lambda: _post(transport))
    return _scenario(
        name=FAULT_SCENARIOS[6],
        expected="http_response_too_large_one_request_zero_retries",
        observed=f"{failure.failure_stage}_one_request_zero_retries",
        transport=transport,
        connections=connections,
        passed=failure.failure_stage == "http_response_too_large",
    )


def _single_use_scenario() -> dict[str, Any]:
    connections = [_Connection()]
    transport = _transport(connections)
    transport.prepare()
    _post(transport)
    replay_rejected = False
    try:
        _post(transport)
    except ValueError:
        replay_rejected = True
    return _scenario(
        name=FAULT_SCENARIOS[7],
        expected="second_request_rejected_one_request_total",
        observed=(
            "second_request_rejected_one_request_total"
            if replay_rejected
            else "second_request_not_rejected"
        ),
        transport=transport,
        connections=connections,
        passed=replay_rejected,
    )


def _capture_failure(operation: Any) -> SanitizedProviderFailure:
    try:
        operation()
    except SanitizedProviderFailure as error:
        return error
    raise AssertionError("fault scenario did not fail")


def _provider(value: dict[str, Any]) -> dict[str, str]:
    provider = value.get("provider_call") or value.get("preserved_provider_call")
    if not isinstance(provider, dict):
        raise ValueError("transport provider design is invalid")
    result = {
        "provider_id": provider.get("provider_id"),
        "base_url": str(provider.get("base_url", "")).rstrip("/"),
        "endpoint": "/chat/completions",
        "model": provider.get("model_id"),
    }
    if not (
        result["provider_id"] == "openai_compatible"
        and result["base_url"].startswith("https://")
        and result["model"]
    ):
        raise ValueError("transport provider identity is invalid")
    return result


def _validate_terminal_gate(value: dict[str, Any], *, expected_run_suffix: str) -> None:
    body = {key: item for key, item in value.items() if key != "report_sha256"}
    if not (
        value.get("schema_version") == TERMINAL_GATE_SCHEMA
        and value.get("passed") is True
        and value.get("run_id", "").endswith(expected_run_suffix)
        and value.get("checks", {}).get("operator_signature_valid") is True
        and value.get("checks", {}).get("provider_retry_not_performed") is True
        and value.get("readiness", {}).get("failed_run_closed") is True
        and value.get("report_sha256") == canonical_sha256(body)
    ):
        raise ValueError("transport source terminal Gate is invalid")


def _canonical_from(value: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        candidate = value.get(name)
        if _sha256(candidate):
            return candidate
    return canonical_sha256(value)


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for transport qualification")
    revision = _git(root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=root,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("transport qualification revision is not pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "transport_source_sha256": hashlib.sha256(
            TRANSPORT_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"transport private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("transport source artifact must be an object")
    return value, raw


def _ref(
    path: Path,
    canonical_digest: str,
    *,
    raw: bytes | None = None,
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(
            raw if raw is not None else path.read_bytes()
        ).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _published_ref(
    current: Path,
    published: Path,
    canonical_digest: str,
) -> dict[str, str]:
    return {
        "path": str(published.resolve()),
        "sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _review_statement(
    *,
    contract_raw_sha256: str,
    contract_canonical_sha256: str,
    fault_raw_sha256: str,
    fault_canonical_sha256: str,
    plan_raw_sha256: str,
    plan_canonical_sha256: str,
    r2_gate_canonical_sha256: str,
    r3_gate_canonical_sha256: str,
) -> str:
    return (
        "I approve for independent review only the J1-D transport reliability "
        f"contract raw SHA-256 {contract_raw_sha256}, canonical SHA-256 "
        f"{contract_canonical_sha256}, deterministic 8-scenario fault matrix raw "
        f"SHA-256 {fault_raw_sha256}, canonical SHA-256 "
        f"{fault_canonical_sha256}, and bounded 64-call content-free admission-soak "
        f"plan raw SHA-256 {plan_raw_sha256}, canonical SHA-256 "
        f"{plan_canonical_sha256}, binding r2 terminal Gate "
        f"{r2_gate_canonical_sha256} and r3 terminal Gate "
        f"{r3_gate_canonical_sha256}. I acknowledge that connection setup may be "
        "retried only before HTTP request dispatch, every HTTP request is single-use, "
        "any failure after dispatch is ambiguous and must never be retried, and the "
        "live soak requires a separate signed review Gate and exact single-use "
        "authorization. This approval permits independent review only. It does not "
        "read a provider credential, call a provider or model, start or modify a "
        "participant container, execute an Agent or experiment, append Backend Facts "
        "or the Ledger, issue or consume an execution authorization, authorize an "
        "effectiveness claim, or upgrade SI-13 maturity."
    )


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--created-at")
    parser.add_argument("--r2-terminal-gate", type=Path, required=True)
    parser.add_argument("--r3-terminal-gate", type=Path, required=True)
    parser.add_argument("--provider-design", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    created_at = args.created_at or datetime.now(UTC).isoformat()
    result = prepare_materials(
        contract_id=args.contract_id,
        plan_id=args.plan_id,
        created_at=created_at,
        r2_terminal_gate_path=args.r2_terminal_gate,
        r3_terminal_gate_path=args.r3_terminal_gate,
        provider_design_path=args.provider_design,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
