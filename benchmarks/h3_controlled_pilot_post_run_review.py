"""Revalidate immutable H.3 controlled-pilot outputs without rerunning Agents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_controlled_pilot_runner import (
    LEGACY_TASK_SCHEMA_VERSION,
    POST_RUN_RECEIPT_SCHEMA_VERSION,
    TASK_SCHEMA_VERSION,
    _reconcile_generations,
    _valid_agent_payload,
)


SCHEMA_VERSION = "h3-controlled-pilot-post-run-contract-review:v1"


def review_post_run_receipt(
    *,
    post_run_receipt_path: Path,
    output_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    receipt_path = _resolve(post_run_receipt_path, agent_root)
    output = _resolve(output_path, agent_root)
    failures: list[str] = []
    receipt = _read_json(receipt_path, failures, "post-run receipt")
    task_ref = _object(_object(receipt).get("task"))
    task_path = Path(str(task_ref.get("path") or "/missing-task"))
    task = _read_json(task_path, failures, "controlled task")
    reports: list[dict[str, Any]] = []

    if _object(receipt).get("schema_version") != POST_RUN_RECEIPT_SCHEMA_VERSION:
        failures.append("post-run receipt schema mismatch")
    if _object(task).get("schema_version") not in {
        TASK_SCHEMA_VERSION,
        LEGACY_TASK_SCHEMA_VERSION,
    }:
        failures.append("controlled task schema mismatch")
    if task_path.is_file() and _sha256(task_path) != task_ref.get("sha256"):
        failures.append("controlled task hash mismatch")
    side_effects = _object(_object(receipt).get("side_effects"))
    profile = str(_object(receipt).get("validation_profile") or "development")
    if profile not in {"development", "qualification"}:
        failures.append("post-run receipt profile unsupported")
    if _object(receipt).get("development_only") is not (profile == "development"):
        failures.append("post-run receipt development flag mismatch")
    boundary = _object(_object(receipt).get("boundary"))
    if boundary.get("production_use_allowed") is not False:
        failures.append("post-run receipt production boundary mismatch")
    if boundary.get("result_valid_for_qualification") is not False:
        failures.append("post-run result must remain pending qualification review")
    if any(
        side_effects.get(field) is not False
        for field in (
            "production_state_mutated",
            "iem_state_mutated",
            "relation_state_mutated",
            "authorization_state_mutated",
            "normative_state_mutated",
        )
    ):
        failures.append("forbidden state mutation observed")

    for ref in _object(receipt).get("generation_reports", []):
        ref = _object(ref)
        path = Path(str(ref.get("path") or "/missing-generation-report"))
        report = _read_json(path, failures, "generation report")
        if path.is_file() and _sha256(path) != ref.get("sha256"):
            failures.append(f"generation report hash mismatch: {path}")
        if report is not None:
            normalized = dict(report)
            normalized["passed"] = _valid_agent_payload(
                _object(report.get("response")),
                _object(task),
                strict_evidence_refs=profile == "qualification",
            )
            reports.append(normalized)
    all_valid = bool(reports) and all(item["passed"] is True for item in reports)
    if not all_valid:
        failures.append("generation payload contract remains invalid")
    reconciliation = _reconcile_generations(reports)
    passed = not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "source_post_run_receipt": _artifact_ref(receipt_path),
        "source_task": _artifact_ref(task_path) if task_path.is_file() else None,
        "generation_report_count": len(reports),
        "valid_generation_report_count": sum(
            item.get("passed") is True for item in reports
        ),
        "reconciliation": reconciliation,
        "readiness": {
            "controlled_pilot_outputs_valid_for_operator_review": passed,
            "original_post_run_receipt_rewritten": False,
            "automatic_state_change_allowed": False,
            "decision": (
                "h3_controlled_pilot_outputs_ready_for_operator_review"
                if passed
                else "blocked_h3_controlled_pilot_post_run_contract_review"
            ),
        },
        "non_claims": [
            "review_does_not_rerun_agents",
            "review_does_not_rewrite_original_receipt",
            "review_does_not_change_trust_authorization_or_normative_state",
            "review_is_not_qualification_evidence",
        ],
    }
    _write_json(output, report)
    return report


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_json(
    path: Path,
    failures: list[str],
    label: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    return value


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--post-run-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = review_post_run_receipt(
        post_run_receipt_path=args.post_run_receipt,
        output_path=args.output,
        agent_root=root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
