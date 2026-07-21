"""Validate a signed J1-D single-use authorization without consuming it."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_admission import evaluate_admission, validate_request
from benchmarks.j1.qualification_cohort_assignment import validate_reviewed_assignment
from benchmarks.j1.qualification_execution_authorization import (
    build_authorization_context,
    validate_execution_authorization,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_roster import (
    validate_qualification_protocol,
    validate_roster,
)


GATE_SCHEMA = "j1-qualification-execution-authorization-gate:v1"
ASSIGNMENT_GATE_SCHEMA = "j1-qualification-cohort-assignment-gate:v1"
ROSTER_GATE_SCHEMA = "j1-qualification-roster-gate:v2"
ADMISSION_GATE_SCHEMA = "j1-qualification-admission-gate:v1"
CONTRACT_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_execution_authorization.py"
)
OPERATION_SOURCE = Path(__file__).parent / "j1_qualification_execution_authorization.py"
GATE_SOURCE = Path(__file__)


def run_gate(
    *,
    authorization_receipt_path: Path,
    qualification_protocol_path: Path,
    reviewed_roster_path: Path,
    roster_gate_report_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_report_path: Path,
    admission_request_path: Path,
    provider_admission_report_path: Path,
    provider_env_path: Path,
    reviewer_profile_path: Path,
    evidence_root: Path,
    run_id: str,
    execution_root: Path,
    consumption_path: Path,
    agent_revision: str,
    output_path: Path,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    source = load_authorization_source_context(
        qualification_protocol_path=qualification_protocol_path,
        reviewed_roster_path=reviewed_roster_path,
        roster_gate_report_path=roster_gate_report_path,
        reviewed_assignment_path=reviewed_assignment_path,
        assignment_gate_report_path=assignment_gate_report_path,
        admission_request_path=admission_request_path,
        provider_admission_report_path=provider_admission_report_path,
        provider_env_path=provider_env_path,
        reviewer_profile_path=reviewer_profile_path,
        evidence_root=evidence_root,
        run_id=run_id,
        execution_root=execution_root,
        consumption_path=consumption_path,
        agent_revision=agent_revision,
        failures=failures,
    )
    receipt, receipt_raw = _read_json(
        authorization_receipt_path, "authorization_receipt_unreadable", failures
    )
    if receipt and source:
        failures.extend(
            validate_execution_authorization(
                receipt,
                expected_context=source["context"],
                reviewer_profile=source["reviewer_profile"],
                reviewer_profile_sha256=source["reviewer_profile_sha256"],
                expected_implementation=source["implementation"],
                current_time=current_time or datetime.now(timezone.utc),
                require_current=True,
            )
        )
    if consumption_path.exists():
        failures.append("authorization_already_consumed")
    if execution_root.exists():
        failures.append("execution_root_already_exists")

    failure_reasons = list(dict.fromkeys(failures))
    passed = not failure_reasons
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failure_reasons,
        "checked_at": (current_time or datetime.now(timezone.utc))
        .astimezone(timezone.utc)
        .isoformat(),
        "run_id": run_id,
        "authorization_receipt": _artifact(authorization_receipt_path, receipt_raw),
        "source_artifacts": source.get("artifacts", {}) if source else {},
        "execution_root": str(execution_root.resolve()),
        "authorization_consumption_path": str(consumption_path.resolve()),
        "readiness": {
            "provider_configuration_admitted": bool(source),
            "qualification_protocol_frozen": bool(source),
            "real_participant_roster_bound": bool(source),
            "single_use_authorization_issued": passed,
            "single_use_authorization_unconsumed": passed,
            "controlled_experiment_execution_ready": passed,
            "state": (
                "j1d_single_use_authorization_ready_for_atomic_claim"
                if passed
                else "blocked_j1d_execution_authorization"
            ),
        },
        "execution_boundary": {
            "authorization_validation_only": True,
            "authorization_consumed": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "agent_execution_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def load_authorization_source_context(
    *,
    qualification_protocol_path: Path,
    reviewed_roster_path: Path,
    roster_gate_report_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_report_path: Path,
    admission_request_path: Path,
    provider_admission_report_path: Path,
    provider_env_path: Path,
    reviewer_profile_path: Path,
    evidence_root: Path,
    run_id: str,
    execution_root: Path,
    consumption_path: Path,
    agent_revision: str,
    failures: list[str],
) -> dict[str, Any]:
    protocol, protocol_raw = _read_json(
        qualification_protocol_path, "qualification_protocol_unreadable", failures
    )
    roster, roster_raw = _read_json(
        reviewed_roster_path, "reviewed_roster_unreadable", failures
    )
    roster_gate, roster_gate_raw = _read_json(
        roster_gate_report_path, "roster_gate_report_unreadable", failures
    )
    assignment, assignment_raw = _read_json(
        reviewed_assignment_path, "reviewed_assignment_unreadable", failures
    )
    assignment_gate, assignment_gate_raw = _read_json(
        assignment_gate_report_path, "assignment_gate_report_unreadable", failures
    )
    request, request_raw = _read_json(
        admission_request_path, "admission_request_unreadable", failures, private=False
    )
    admission, admission_raw = _read_json(
        provider_admission_report_path, "provider_admission_report_unreadable", failures
    )
    reviewer, reviewer_raw = _read_json(
        reviewer_profile_path, "reviewer_profile_unreadable", failures
    )
    if failures:
        return {}

    request_hash = canonical_sha256(request)
    protocol_hash = canonical_sha256(protocol)
    failures.extend(validate_request(request))
    failures.extend(
        validate_qualification_protocol(protocol, admission_request_sha256=request_hash)
    )
    stack = protocol.get("frozen_stack", {})
    corpus = protocol.get("task_corpus", {})
    failures.extend(
        validate_roster(
            roster,
            admission_request_sha256=request_hash,
            qualification_protocol_sha256=protocol_hash,
            expected_stack={
                "provider_id": stack.get("provider_id", ""),
                "model_id": stack.get("model_id", ""),
                "budget_id": stack.get("budget_id", ""),
                "corpus_id": corpus.get("corpus_id", ""),
                "verifier_id": stack.get("verifier_id", ""),
            },
        )
    )
    _validate_roster_gate(
        roster_gate,
        roster_gate_report_path=roster_gate_report_path,
        protocol_path=qualification_protocol_path,
        protocol_hash=protocol_hash,
        roster_path=reviewed_roster_path,
        roster=roster,
        failures=failures,
    )
    failures.extend(validate_reviewed_assignment(assignment))
    _validate_assignment_gate(
        assignment_gate,
        assignment_gate_report_path=assignment_gate_report_path,
        assignment_path=reviewed_assignment_path,
        assignment=assignment,
        protocol_path=qualification_protocol_path,
        roster_path=reviewed_roster_path,
        failures=failures,
    )
    _validate_provider_admission(
        admission,
        request_path=admission_request_path,
        request_raw=request_raw,
        request_hash=request_hash,
        request=request,
        provider_env_path=provider_env_path,
        protocol=protocol,
        failures=failures,
    )
    failures.extend(validate_reviewer_identity_profile(reviewer))
    _validate_isolation(evidence_root, roster, failures)
    implementation = _implementation(agent_revision, failures)
    if failures:
        return {}
    context = build_authorization_context(
        run_id=run_id,
        protocol=protocol,
        protocol_artifact_sha256=hashlib.sha256(protocol_raw).hexdigest(),
        roster=roster,
        roster_artifact_sha256=hashlib.sha256(roster_raw).hexdigest(),
        roster_gate_artifact_sha256=hashlib.sha256(roster_gate_raw).hexdigest(),
        reviewed_assignment=assignment,
        reviewed_assignment_artifact_sha256=hashlib.sha256(assignment_raw).hexdigest(),
        assignment_gate_artifact_sha256=hashlib.sha256(assignment_gate_raw).hexdigest(),
        admission_request=request,
        admission_request_artifact_sha256=hashlib.sha256(request_raw).hexdigest(),
        provider_admission_report=admission,
        provider_admission_artifact_sha256=hashlib.sha256(admission_raw).hexdigest(),
        execution_root=execution_root,
        consumption_path=consumption_path,
    )
    return {
        "context": context,
        "reviewer_profile": reviewer,
        "reviewer_profile_sha256": hashlib.sha256(reviewer_raw).hexdigest(),
        "implementation": implementation,
        "artifacts": {
            "qualification_protocol": _artifact(
                qualification_protocol_path, protocol_raw
            ),
            "reviewed_roster": _artifact(reviewed_roster_path, roster_raw),
            "roster_gate_report": _artifact(roster_gate_report_path, roster_gate_raw),
            "reviewed_assignment": _artifact(reviewed_assignment_path, assignment_raw),
            "assignment_gate_report": _artifact(
                assignment_gate_report_path, assignment_gate_raw
            ),
            "admission_request": _artifact(admission_request_path, request_raw),
            "provider_admission_report": _artifact(
                provider_admission_report_path, admission_raw
            ),
            "reviewer_profile": _artifact(reviewer_profile_path, reviewer_raw),
        },
    }


def _validate_assignment_gate(
    gate: dict[str, Any],
    *,
    assignment_gate_report_path: Path,
    assignment_path: Path,
    assignment: dict[str, Any],
    protocol_path: Path,
    roster_path: Path,
    failures: list[str],
) -> None:
    if not (
        gate.get("schema_version") == ASSIGNMENT_GATE_SCHEMA
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and gate.get("participant_count") == 40
        and gate.get("pair_count") == 20
        and gate.get("readiness", {}).get("cohort_assignment_bound") is True
        and gate.get("readiness", {}).get("single_use_authorization_issued") is False
    ):
        failures.append("assignment_gate_report_invalid")
    expected = {
        "reviewed_assignment": assignment_path,
        "qualification_protocol": protocol_path,
        "reviewed_roster": roster_path,
    }
    for field, path in expected.items():
        reference = gate.get("artifacts", {}).get(field, {})
        if (
            reference.get("path") != str(path.resolve())
            or reference.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            failures.append(f"assignment_gate_{field}_binding_invalid")
    if assignment_gate_report_path.stat().st_mode & 0o077:
        failures.append("assignment_gate_report_permissions_invalid")


def _validate_roster_gate(
    gate: dict[str, Any],
    *,
    roster_gate_report_path: Path,
    protocol_path: Path,
    protocol_hash: str,
    roster_path: Path,
    roster: dict[str, Any],
    failures: list[str],
) -> None:
    if not (
        gate.get("schema_version") == ROSTER_GATE_SCHEMA
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("qualification_protocol_sha256") == protocol_hash
        and gate.get("roster_sha256") == roster.get("roster_sha256")
        and gate.get("participant_count") == 40
        and gate.get("readiness", {}).get("real_participant_roster_bound") is True
        and gate.get("readiness", {}).get("signed_roster_review_verified") is True
        and gate.get("readiness", {}).get("single_use_authorization_issued") is False
    ):
        failures.append("roster_gate_report_invalid")
    artifacts = gate.get("artifacts", {})
    expected = {
        "reviewed_roster": (
            roster_path,
            hashlib.sha256(roster_path.read_bytes()).hexdigest(),
        ),
        "qualification_protocol": (
            protocol_path,
            hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        ),
    }
    for field, (path, digest) in expected.items():
        reference = artifacts.get(field, {})
        if (
            reference.get("path") != str(path.resolve())
            or reference.get("sha256") != digest
        ):
            failures.append(f"roster_gate_{field}_binding_invalid")
    if roster_gate_report_path.stat().st_mode & 0o077:
        failures.append("roster_gate_report_permissions_invalid")


def _validate_provider_admission(
    report: dict[str, Any],
    *,
    request_path: Path,
    request_raw: bytes,
    request_hash: str,
    request: dict[str, Any],
    provider_env_path: Path,
    protocol: dict[str, Any],
    failures: list[str],
) -> None:
    if not (
        report.get("schema_version") == ADMISSION_GATE_SCHEMA
        and report.get("passed") is True
        and report.get("failure_reasons") == []
        and report.get("source_request", {}).get("path") == str(request_path.resolve())
        and report.get("source_request", {}).get("sha256")
        == hashlib.sha256(request_raw).hexdigest()
        and report.get("admission", {}).get("request_sha256") == request_hash
    ):
        failures.append("provider_admission_report_invalid")
    fresh = evaluate_admission(request, env_file=provider_env_path)
    if fresh.get("passed") is not True:
        failures.append("live_provider_admission_invalid")
    admitted = fresh.get("provider_admission", {})
    stack = protocol.get("frozen_stack", {})
    provider = request.get("provider", {})
    if not (
        admitted.get("kind") == stack.get("provider_id") == provider.get("kind")
        and admitted.get("model") == stack.get("model_id") == provider.get("model")
        and provider.get("temperature") == stack.get("temperature") == 0
        and admitted.get("api_key_present") is True
        and admitted.get("network_probe_performed") is False
        and admitted.get("model_invocation_performed") is False
    ):
        failures.append("provider_protocol_binding_invalid")


def _validate_isolation(
    evidence_root: Path, roster: dict[str, Any], failures: list[str]
) -> None:
    if (
        evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.stat().st_mode & 0o077
    ):
        failures.append("evidence_root_invalid")
        return
    expected = {
        item["participant_id"]: item["isolation_root_sha256"]
        for item in roster.get("participants", [])
        if isinstance(item, dict)
    }
    ids: list[str] = []
    seen: set[str] = set()
    for path in sorted(evidence_root.glob("*.isolation.json")):
        value, raw = _read_json(path, "isolation_artifact_unreadable", failures)
        participant_id = str(value.get("participant_id", ""))
        if (
            participant_id in seen
            or expected.get(participant_id) != hashlib.sha256(raw).hexdigest()
        ):
            failures.append("isolation_roster_binding_invalid")
        seen.add(participant_id)
        ids.append(str(value.get("isolation_id", "")))
    if len(ids) != 40 or seen != set(expected):
        failures.append("isolation_inventory_invalid")
        return
    result = subprocess.run(
        ["docker", "inspect", *ids], check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        failures.append("participant_isolation_inspect_failed")
        return
    inspected = json.loads(result.stdout)
    if len(inspected) != 40 or any(
        item.get("State", {}).get("Running") is not False for item in inspected
    ):
        failures.append("participant_isolation_must_be_stopped")


def _implementation(agent_revision: str, failures: list[str]) -> dict[str, str]:
    revision = agent_revision.lower()
    if not (
        7 <= len(revision) <= 64
        and all(char in "0123456789abcdef" for char in revision)
    ):
        failures.append("authorization_agent_revision_invalid")
    sources = (CONTRACT_SOURCE, OPERATION_SOURCE, GATE_SOURCE)
    if any(not path.is_file() for path in sources):
        failures.append("authorization_implementation_source_missing")
        return {}
    repository = GATE_SOURCE.parent.parent
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode != 0 or head.stdout.strip().lower() != revision:
        failures.append("authorization_agent_revision_not_checked_out")
    if status.returncode != 0 or status.stdout.strip():
        failures.append("authorization_agent_worktree_dirty")
    return {
        "agent_revision": revision,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
    }


def _read_json(
    path: Path, failure: str, failures: list[str], *, private: bool = True
) -> tuple[dict[str, Any], bytes]:
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or (private and path.stat().st_mode & 0o077)
        ):
            raise ValueError("artifact missing, symlinked, or permissions too open")
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("artifact must be a JSON object")
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(failure)
        return {}, b""


def _artifact(path: Path, raw: bytes) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization-receipt", type=Path, required=True)
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
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--consumption-path", type=Path, required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        authorization_receipt_path=args.authorization_receipt,
        qualification_protocol_path=args.qualification_protocol,
        reviewed_roster_path=args.reviewed_roster,
        roster_gate_report_path=args.roster_gate_report,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_report_path=args.assignment_gate_report,
        admission_request_path=args.admission_request,
        provider_admission_report_path=args.provider_admission_report,
        provider_env_path=args.provider_env,
        reviewer_profile_path=args.reviewer_profile,
        evidence_root=args.evidence_root,
        run_id=args.run_id,
        execution_root=args.execution_root,
        consumption_path=args.consumption_path,
        agent_revision=args.agent_revision,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
