"""Validate J.1 mentorship contracts without activating a mentorship."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from benchmarks.j1.contracts import BUNDLE_SCHEMA, canonical_sha256, contract_hashes, validate_bundle


REPORT_SCHEMA = "j1-mentorship-contract-gate-report:v1"
DEFAULT_BUNDLE = Path(__file__).parent / "j1" / "fixtures" / "mentorship_contract_bundle.json"

Mutation = Callable[[dict[str, Any]], None]


def run_gate(*, bundle_path: Path, output_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    bundle = _read_bundle(bundle_path, failures)
    validation_failures = validate_bundle(bundle)
    _check(checks, failures, "contract_bundle_valid", not validation_failures)
    failures.extend(
        item for item in validation_failures if item not in failures
    )

    negative_controls = (
        _run_negative_controls(bundle) if not validation_failures else []
    )
    _check(
        checks,
        failures,
        "all_negative_controls_rejected",
        len(negative_controls) == 8
        and all(item["rejected"] is True for item in negative_controls),
    )
    _check(
        checks,
        failures,
        "canonical_hash_stable",
        canonical_sha256(bundle)
        == canonical_sha256(json.loads(json.dumps(bundle, sort_keys=True))),
    )
    _check(
        checks,
        failures,
        "execution_boundary_closed",
        _execution_boundary_closed(bundle),
    )
    _check(
        checks,
        failures,
        "fixture_schema_valid",
        bundle.get("schema_version") == BUNDLE_SCHEMA,
    )

    passed = not failures and all(checks.values())
    report = {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifact": _artifact_ref(bundle_path),
        "bundle_sha256": canonical_sha256(bundle),
        "contract_hashes": contract_hashes(bundle) if bundle else {},
        "negative_controls": negative_controls,
        "readiness": {
            "j1_contracts_complete": passed,
            "state": (
                "j1_contracts_validated_not_started"
                if passed
                else "blocked_j1_contract_validation"
            ),
            "ready_for_j1_backend_fact_implementation": passed,
            "mentorship_runtime_ready": False,
            "j1_controlled_experiment_ready": False,
        },
        "execution_boundary": {
            "contract_fixture_only": True,
            "mentorship_activation_allowed": False,
            "fact_append_allowed": False,
            "runtime_advice_injection_allowed": False,
            "agent_or_model_execution_allowed": False,
            "external_side_effect_allowed": False,
            "production_transition_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "non_claims": [
            "j1a_validates_contracts_only",
            "j1a_does_not_implement_backend_fact_lifecycle",
            "j1a_does_not_run_mentor_or_apprentice_agents",
            "j1a_does_not_prove_mentorship_effectiveness",
            "j1a_does_not_claim_group_intelligence",
        ],
    }
    _write_private_json(output_path, report)
    return report


def _run_negative_controls(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    controls: tuple[tuple[str, str, Mutation], ...] = (
        (
            "self_mentorship",
            "mentor_and_apprentice_must_differ",
            lambda value: value["relation"].__setitem__(
                "apprentice_did", value["relation"]["mentor_did"]
            ),
        ),
        (
            "raw_memory_access",
            "raw_memory_access_must_be_false",
            lambda value: value["relation"]["memory_projection"].__setitem__(
                "raw_memory_access_allowed", True
            ),
        ),
        (
            "automatic_matching",
            "automatic_matching_must_be_false",
            lambda value: value["relation"]["lifecycle"].__setitem__(
                "automatic_matching_allowed", True
            ),
        ),
        (
            "direct_execution",
            "advice_direct_execution_allowed_must_be_false",
            lambda value: value["advice"]["boundary"].__setitem__(
                "direct_execution_allowed", True
            ),
        ),
        (
            "normative_mutation",
            "advice_normative_mutation_allowed_must_be_false",
            lambda value: value["advice"]["boundary"].__setitem__(
                "normative_mutation_allowed", True
            ),
        ),
        (
            "mentor_decides_for_apprentice",
            "decision_actor_must_be_apprentice",
            lambda value: value["decision"].__setitem__(
                "decided_by", value["relation"]["mentor_did"]
            ),
        ),
        (
            "single_occurrence_pattern",
            "observation_requires_repeated_occurrences",
            lambda value: value["observation"].__setitem__(
                "occurrence_refs", value["observation"]["occurrence_refs"][:1]
            ),
        ),
        (
            "production_transition",
            "production_transition_allowed_must_be_false",
            lambda value: value["execution_boundary"].__setitem__(
                "production_transition_allowed", True
            ),
        ),
    )
    results = []
    for control_id, expected_failure, mutate in controls:
        candidate = copy.deepcopy(bundle)
        mutate(candidate)
        observed = validate_bundle(candidate)
        results.append(
            {
                "control_id": control_id,
                "expected_failure": expected_failure,
                "observed_failures": observed,
                "rejected": expected_failure in observed,
            }
        )
    return results


def _execution_boundary_closed(bundle: dict[str, Any]) -> bool:
    boundary = bundle.get("execution_boundary")
    if not isinstance(boundary, dict) or boundary.get("contract_fixture_only") is not True:
        return False
    return all(
        boundary.get(field) is False
        for field in (
            "mentorship_activation_allowed",
            "automatic_matching_allowed",
            "fact_append_allowed",
            "runtime_advice_injection_allowed",
            "agent_or_model_execution_allowed",
            "external_side_effect_allowed",
            "production_transition_allowed",
            "production_receipt_write_allowed",
        )
    )


def _read_bundle(path: Path, failures: list[str]) -> dict[str, Any]:
    if not path.is_file():
        failures.append("contract_bundle_missing")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        failures.append("contract_bundle_invalid_json")
        return {}
    if not isinstance(value, dict):
        failures.append("contract_bundle_must_be_object")
        return {}
    return value


def _artifact_ref(path: Path) -> dict[str, str | None]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()
        if resolved.is_file()
        else None,
    }


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _check(
    checks: dict[str, bool], failures: list[str], name: str, passed: bool
) -> None:
    checks[name] = bool(passed)
    if not passed and name not in failures:
        failures.append(name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(bundle_path=args.bundle, output_path=args.output)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
