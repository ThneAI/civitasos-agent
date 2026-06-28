"""Authorize H.3 production transition after P1-R reaches 16/16.

This gate is the explicit transition decision point. P1-R assembles and maps
evidence; this gate records the operator decision that H.3 is no longer
blocked and the project may enter the next stage. It does not deploy, start
runtime, open ingress, or write production runtime receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_json, write_json_object
from benchmarks.p1r_real_source_confirmation_gate import CHAIN_SCHEMA as P1R_CHAIN_SCHEMA
from benchmarks.p1r_real_source_confirmation_gate import ROUND2_EVENT_ORDER

SCHEMA_VERSION = "h3-production-transition-authorization-gate:v1"
REQUIRED_OPERATOR_DECISION = "authorize_h3_production_transition"
NON_CLAIMS = (
    "transition_gate_does_not_deploy_or_start_runtime",
    "transition_gate_does_not_open_public_ingress",
    "transition_gate_does_not_write_production_runtime_receipts",
    "transition_gate_authorizes_stage_progression_only",
)


def run_gate(
    *,
    p1r_summary_path: Path,
    output: Path,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    transition_id: str | None = None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    p1r = _load_p1r_summary(p1r_summary_path, checks, failures)
    _validate_operator_decision(
        checks=checks,
        failures=failures,
        operator_id=operator_id,
        operator_decision=operator_decision,
        operator_statement=operator_statement,
    )
    p1r_artifacts = object_value(p1r.get("artifacts")) if p1r else {}
    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": sorted(set(failures)),
        "checked_at": _now(),
        "transition_id": transition_id or f"h3-transition:{sha256_json([str(p1r_summary_path.resolve()), operator_id, operator_statement])[:16]}",
        "source_artifacts": {
            "p1r_summary": artifact_ref(p1r_summary_path) if p1r_summary_path.is_file() else {"path": str(p1r_summary_path)},
            "p1r_production_evidence_submission": p1r_artifacts.get("production_evidence_submission"),
            "p1r_gap_map": p1r_artifacts.get("gap_map"),
        },
        "authorization": {
            "operator_id": operator_id,
            "operator_decision": operator_decision,
            "required_operator_decision": REQUIRED_OPERATOR_DECISION,
            "operator_statement": operator_statement,
            "operator_statement_sha256": sha256_json(operator_statement),
        },
        "readiness": {
            "decision": "h3_production_transition_authorized" if passed else "blocked_h3_production_transition",
            "h3_production_transition_authorized": passed,
            "production_transition_allowed": passed,
            "next_stage": "post_h3_multi_agent_production_stage" if passed else None,
            "runtime_execution_allowed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "boundary": _boundary(production_transition_allowed=passed),
        "checks": checks,
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _load_p1r_summary(path: Path, checks: dict[str, bool], failures: list[str]) -> dict[str, Any]:
    try:
        payload = read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        check(checks, failures, "p1r_summary_readable", False)
        failures.append(f"p1r_summary_unreadable:{exc}")
        return {}
    readiness = object_value(payload.get("readiness"))
    boundary = object_value(payload.get("boundary"))
    artifacts = object_value(payload.get("artifacts"))
    check(checks, failures, "p1r_schema_valid", payload.get("schema_version") == P1R_CHAIN_SCHEMA)
    check(checks, failures, "p1r_passed", payload.get("passed") is True)
    check(checks, failures, "p1r_production_satisfied_16", payload.get("production_satisfied_count") == len(ROUND2_EVENT_ORDER))
    check(checks, failures, "p1r_production_missing_0", payload.get("production_missing_count") == 0)
    check(checks, failures, "p1r_round2_submission_ready", readiness.get("round2_production_evidence_submission_ready") is True)
    check(checks, failures, "p1r_gap_map_complete", readiness.get("h3_gap_map_complete") is True)
    check(checks, failures, "p1r_kept_transition_separate", readiness.get("production_transition_allowed") is False)
    check(checks, failures, "p1r_submission_written", boundary.get("production_evidence_submission_written") is True)
    check(checks, failures, "p1r_transition_not_previously_authorized", boundary.get("production_transition_allowed") is False)
    _check_artifact_ref("p1r_production_evidence_submission", artifacts.get("production_evidence_submission"), checks, failures)
    _check_artifact_ref("p1r_gap_map", artifacts.get("gap_map"), checks, failures)
    return payload


def _check_artifact_ref(name: str, value: Any, checks: dict[str, bool], failures: list[str]) -> None:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    check(checks, failures, f"{name}_artifact_ref_present", bool(ref.get("path")) and bool(ref.get("sha256")))
    check(checks, failures, f"{name}_artifact_exists", path.is_file())
    if path.is_file():
        check(checks, failures, f"{name}_artifact_hash_matches", artifact_ref(path).get("sha256") == ref.get("sha256"))


def _validate_operator_decision(
    *,
    checks: dict[str, bool],
    failures: list[str],
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
) -> None:
    statement = operator_statement.strip()
    check(checks, failures, "operator_id_present", bool(operator_id.strip()))
    check(checks, failures, "operator_decision_authorizes_transition", operator_decision == REQUIRED_OPERATOR_DECISION)
    check(checks, failures, "operator_statement_present", bool(statement))
    check(
        checks,
        failures,
        "operator_statement_declares_h3_transition",
        "h.3" in statement.lower() or "h3" in statement.lower(),
    )
    check(
        checks,
        failures,
        "operator_statement_declares_production",
        "production" in statement.lower() or "生产" in statement,
    )


def _boundary(*, production_transition_allowed: bool) -> dict[str, bool]:
    return {
        "production_transition_allowed": production_transition_allowed,
        "runtime_execution_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorize H.3 production transition after P1-R")
    parser.add_argument("--p1r-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--operator-decision", required=True)
    parser.add_argument("--operator-statement", required=True)
    parser.add_argument("--transition-id")
    args = parser.parse_args()
    report = run_gate(
        p1r_summary_path=args.p1r_summary,
        output=args.output,
        operator_id=args.operator_id,
        operator_decision=args.operator_decision,
        operator_statement=args.operator_statement,
        transition_id=args.transition_id,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
