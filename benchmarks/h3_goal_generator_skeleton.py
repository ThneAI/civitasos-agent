"""H.3 Goal Generator skeleton gate.

This module is intentionally artifact-only. It reads an H.2-E closure report and
decides whether the project may enter the H.3 Goal Generator skeleton stage. It
does not generate executable goals, start runtime components, call LLMs, or
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-generator-skeleton:v1"
H2_CLOSURE_SCHEMA_VERSION = "h2-value-calibration-closure:v1"
H2_READY_DECISION = "ready_for_h3_goal_generator_skeleton"
STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS = [
    "post_delivery_dispute",
    "post_delivery_failure",
    "relation_repair_relapse",
    "governance_rollback",
    "economic_deviation",
]


def build_h3_goal_generator_skeleton(
    *,
    h2_closure_report_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    h2_closure_report_path = _resolve_path(h2_closure_report_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    closure = _read_json(h2_closure_report_path, failures)

    readiness: dict[str, Any] = {}
    closure_boundary: dict[str, Any] = {}
    closure_evidence: dict[str, Any] = {}
    if closure is None:
        _fail(checks, failures, "h2_closure_present", f"missing H2 closure report: {h2_closure_report_path}")
    else:
        checks["h2_closure_present"] = True
        _require_equal(
            "h2_closure_schema_version",
            closure.get("schema_version"),
            H2_CLOSURE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("h2_closure_passed", bool(closure.get("passed")), checks=checks, failures=failures)
        readiness = _object(closure.get("h3_goal_generator_readiness"))
        closure_boundary = _object(closure.get("closure_boundary"))
        closure_evidence = _object(closure.get("evidence"))
        _require_bool("h2_readiness_ready", bool(readiness.get("ready")), checks=checks, failures=failures)
        _require_equal(
            "h2_readiness_decision",
            readiness.get("decision"),
            H2_READY_DECISION,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "h2_closure_artifact_only",
            closure_boundary.get("artifact_only") is True,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "h2_runtime_mutation_disallowed",
            closure_boundary.get("runtime_mutation_allowed") is False,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "h2_normative_mutation_disallowed",
            closure_boundary.get("normative_local_mutation_allowed") is False,
            checks=checks,
            failures=failures,
        )

    backend_kinds = _event_kinds(closure_evidence.get("backend_sourced_repeated_outcome_event_kinds"))
    missing_full_backend_kinds = _missing_event_kinds(STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS, backend_kinds)
    minimum_ready = not failures and all(checks.values())
    full_behavior_ready = minimum_ready and not missing_full_backend_kinds

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": minimum_ready,
        "failure_reasons": failures,
        "h2_closure_report_path": str(h2_closure_report_path),
        "checks": checks,
        "readiness": {
            "minimum_skeleton_ready": minimum_ready,
            "full_goal_generator_behavior_ready": full_behavior_ready,
            "decision": "h3_skeleton_ready" if minimum_ready else "blocked_before_h3_skeleton",
            "allowed_scope": (
                "artifact-only skeleton; no executable goal emission"
                if minimum_ready
                else "do not create H3 goal generator artifacts until H2-E closure is ready"
            ),
        },
        "h3_boundary": {
            "artifact_only": True,
            "goal_emission_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
            "full_behavior_requires_standard_backend_sourced_repeated_kinds": True,
        },
        "goal_generator_state": {
            "mode": "skeleton",
            "candidate_goal_count": 0,
            "candidate_goals": [],
            "deferred_until": "full five-kind backend-sourced H2-E closure",
        },
        "evidence": {
            "h2_readiness": readiness,
            "h2_closure_boundary": closure_boundary,
            "backend_sourced_repeated_outcome_event_kinds": backend_kinds,
            "missing_full_backend_sourced_repeated_outcome_event_kinds": missing_full_backend_kinds,
        },
        "non_claims": [
            "does_not_generate_executable_goals",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_generate_or_execute_full_h3_goal_generator_behavior",
        ],
    }


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None
    return payload


def _event_kinds(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item or "").strip() for item in value if str(item or "").strip()})


def _missing_event_kinds(required: list[str], observed: list[str]) -> list[str]:
    observed_set = set(observed)
    return [event_kind for event_kind in required if event_kind not in observed_set]


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _require_equal(
    name: str,
    actual: object,
    expected: object,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h2-closure-report", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_generator_skeleton(
        h2_closure_report_path=Path(args.h2_closure_report),
        agent_root=agent_root,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
