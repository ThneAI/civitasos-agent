"""J1-D qualification provider admission Gate; never invokes a model."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Callable

from benchmarks.j1.controlled_comparison import (
    artifact_ref,
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_admission import evaluate_admission


GATE_SCHEMA = "j1-qualification-admission-gate:v1"
DEFAULT_REQUEST = (
    Path(__file__).parent / "j1" / "fixtures" / "qualification_admission_request.json"
)
DEVELOPMENT_PROTOCOL = (
    Path(__file__).parent / "j1" / "fixtures" / "controlled_comparison_protocol.json"
)
Mutation = Callable[[dict[str, Any]], None]


def run_gate(
    *, request_path: Path, env_file: Path, output_path: Path
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        request = read_json_object(request_path)
    except (OSError, ValueError, json.JSONDecodeError):
        request = {}
        failures.append("admission_request_unreadable")
    try:
        development_protocol = read_json_object(DEVELOPMENT_PROTOCOL)
    except (OSError, ValueError, json.JSONDecodeError):
        development_protocol = {}
        failures.append("development_protocol_unreadable")
    admission = evaluate_admission(request, env_file=env_file)
    controls = _negative_controls(request, env_file) if request else []
    checks = {
        "provider_admission_valid": admission.get("passed") is True,
        "source_development_protocol_bound": bool(development_protocol)
        and request.get("source_development_protocol_sha256")
        == canonical_sha256(development_protocol),
        "all_negative_controls_rejected": len(controls) == 6
        and all(item["rejected"] for item in controls),
        "no_network_or_model_invocation": admission.get("provider_admission", {}).get(
            "network_probe_performed"
        )
        is False
        and admission.get("provider_admission", {}).get("model_invocation_performed")
        is False,
        "execution_remains_blocked": admission.get("readiness", {}).get(
            "controlled_experiment_execution_ready"
        )
        is False,
    }
    failures.extend(name for name, passed in checks.items() if not passed)
    passed = not failures and all(checks.values())
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "checks": checks,
        "source_request": artifact_ref(request_path)
        if request_path.is_file()
        else None,
        "source_development_protocol": (
            artifact_ref(DEVELOPMENT_PROTOCOL)
            if DEVELOPMENT_PROTOCOL.is_file()
            else None
        ),
        "provider_env": {
            "basename": env_file.name,
            "mode": oct(env_file.stat().st_mode & 0o777)
            if env_file.is_file()
            else None,
            "content_recorded": False,
            "sha256_recorded": False,
        },
        "admission": admission,
        "negative_controls": controls,
        "readiness": admission.get("readiness", {}),
        "execution_boundary": admission.get("execution_boundary", {}),
        "non_claims": admission.get("non_claims", []),
    }
    write_private_json(output_path, report)
    return report


def _negative_controls(request: dict[str, Any], env_file: Path) -> list[dict[str, Any]]:
    controls: tuple[tuple[str, str, Mutation], ...] = (
        (
            "provider_http_transport",
            "provider_base_url_invalid",
            lambda value: value["provider"].__setitem__(
                "base_url", "http://api.deepseek.com"
            ),
        ),
        (
            "synthetic_model",
            "provider_model_invalid",
            lambda value: value["provider"].__setitem__("model", "synthetic-agent"),
        ),
        (
            "budget_increase",
            "qualification_budget_invalid",
            lambda value: value["qualification_budget_ceiling"].__setitem__(
                "max_pairs", 40
            ),
        ),
        (
            "synthetic_roster",
            "roster_contract_invalid",
            lambda value: value["roster_contract"].__setitem__(
                "synthetic_participants_allowed", True
            ),
        ),
        (
            "long_authorization_ttl",
            "authorization_contract_invalid",
            lambda value: value["authorization_contract"].__setitem__(
                "maximum_ttl_seconds", 86400
            ),
        ),
        (
            "provider_call_enabled",
            "provider_api_call_allowed_must_be_false",
            lambda value: value["execution_boundary"].__setitem__(
                "provider_api_call_allowed", True
            ),
        ),
    )
    results = []
    for control_id, expected, mutation in controls:
        candidate = copy.deepcopy(request)
        mutation(candidate)
        report = evaluate_admission(candidate, env_file=env_file)
        results.append(
            {
                "control_id": control_id,
                "expected_failure": expected,
                "observed_failures": report["failure_reasons"],
                "rejected": report["passed"] is False
                and expected in report["failure_reasons"],
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, default=DEFAULT_REQUEST)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        request_path=args.request,
        env_file=args.env_file,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
