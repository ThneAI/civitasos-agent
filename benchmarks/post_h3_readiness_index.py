"""Build a lightweight PostH3 readiness index.

The index summarizes observer-mode readiness and the minimal production task
chain blueprint. It is intentionally artifact-only and does not authorize
runtime execution, public ingress, deploy, production data access, or
production receipt writes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, write_json_object
from benchmarks.post_h3_minimal_production_task_chain import CHAIN_SCHEMA as MINIMAL_CHAIN_SCHEMA
from benchmarks.post_h3_observer_mode_readiness_gate import CHAIN_SCHEMA as POST_H3AC_SCHEMA

SCHEMA_VERSION = "post-h3-readiness-index:v1"


def build_index(
    *,
    post_h3ac_summary_path: Path,
    output: Path,
    minimal_chain_summary_path: Path | None = None,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    ac = _read_report(post_h3ac_summary_path, checks, failures, "post_h3ac")
    minimal = _read_report(minimal_chain_summary_path, checks, failures, "minimal_chain") if minimal_chain_summary_path else None

    ac_readiness = object_value(ac.get("readiness")) if ac else {}
    check(checks, failures, "post_h3ac_schema", ac.get("schema_version") == POST_H3AC_SCHEMA if ac else False)
    check(checks, failures, "post_h3ac_passed", ac.get("passed") is True if ac else False)
    check(checks, failures, "post_h3ac_observer_mode_continues", ac_readiness.get("observer_mode_continues") is True)
    check(checks, failures, "post_h3ac_no_execution_allowed", ac_readiness.get("runtime_execution_performed") is False)
    check(checks, failures, "post_h3ac_no_production_receipt", ac_readiness.get("production_runtime_receipt_write_allowed") is False)

    minimal_ready = False
    if minimal is not None:
        minimal_readiness = object_value(minimal.get("readiness"))
        check(checks, failures, "minimal_chain_schema", minimal.get("schema_version") == MINIMAL_CHAIN_SCHEMA)
        check(checks, failures, "minimal_chain_passed", minimal.get("passed") is True)
        check(checks, failures, "minimal_chain_blueprint_ready", minimal_readiness.get("minimal_production_task_chain_blueprint_ready") is True)
        check(checks, failures, "minimal_chain_no_execution_allowed", minimal_readiness.get("production_task_execution_allowed") is False)
        minimal_ready = (
            minimal.get("schema_version") == MINIMAL_CHAIN_SCHEMA
            and minimal.get("passed") is True
            and minimal_readiness.get("minimal_production_task_chain_blueprint_ready") is True
        )

    passed = bool(checks) and all(checks.values()) and not failures
    ac_ready = ac.get("passed") is True and ac_readiness.get("observer_mode_continues") is True if ac else False
    status = (
        "post_h3_observer_ready_minimal_production_task_chain_blueprint_ready"
        if ac_ready and minimal_ready
        else (
            "post_h3_observer_ready_waiting_minimal_production_task_chain_blueprint"
            if ac_ready
            else "post_h3_observer_readiness_blocked"
        )
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "artifacts": {
            "post_h3ac_summary": artifact_ref(post_h3ac_summary_path) if post_h3ac_summary_path.is_file() else None,
            "minimal_production_task_chain_summary": (
                artifact_ref(minimal_chain_summary_path)
                if minimal_chain_summary_path and minimal_chain_summary_path.is_file()
                else None
            ),
        },
        "readiness": {
            "post_h3_observer_mode_ready": ac_ready,
            "minimal_production_task_chain_blueprint_ready": minimal_ready,
            "production_task_execution_allowed": False,
            "next_single_use_gate_input_ready": False,
            "artifact_only": True,
            "next_action": (
                "review minimal production task intake gate design"
                if minimal_ready
                else "run post_h3_minimal_production_task_chain blueprint"
            ),
        },
        "boundary": {
            "artifact_only": True,
            "runtime_execution_allowed": False,
            "external_public_ingress_allowed": False,
            "deploy_allowed": False,
            "production_data_access_allowed": False,
            "production_runtime_receipt_write_allowed": False,
            "source_tree_write_allowed": False,
            "git_write_allowed": False,
        },
    }
    write_json_object(output, report)
    return report


def _read_report(path: Path | None, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any] | None:
    if path is None:
        return None
    check(checks, failures, f"{label}_present", path.is_file())
    if not path.is_file():
        return None
    try:
        return read_json_object(path)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{label}_unreadable:{exc}")
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--post-h3ac-summary", type=Path, required=True)
    parser.add_argument("--minimal-chain-summary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_index(
        post_h3ac_summary_path=args.post_h3ac_summary,
        minimal_chain_summary_path=args.minimal_chain_summary,
        output=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
