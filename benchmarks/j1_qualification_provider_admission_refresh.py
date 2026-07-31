"""Generate a J1-D provider admission refresh plan without provider access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_activation import inspect_projection
from benchmarks.j1.qualification_provider_admission_refresh import (
    OFFLINE_BOUNDARY,
    PREFLIGHT_SCHEMA,
    build_refresh_plan,
    probe_authorization_statement,
    validate_refresh_plan,
    validate_source_chain,
)
from benchmarks.j1_qualification_infrastructure_rebind import _read_private


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_provider_admission_refresh.py"
)
OPERATION_SOURCE = Path(__file__)


def generate_refresh_preflight(
    *,
    refresh_id: str,
    created_at: str,
    protocol_path: Path,
    design_path: Path,
    bundle_path: Path,
    roster_path: Path,
    assignment_path: Path,
    roster_assignment_gate_path: Path,
    infrastructure_path: Path,
    activation_path: Path,
    activation_gate_path: Path,
    runner_manifest_path: Path,
    repository_root: Path,
    output_root: Path,
    prior_failed_probe_gate_path: Path | None = None,
    prior_claim_path: Path | None = None,
) -> dict[str, Any]:
    _require_rfc3339(created_at)
    if output_root.exists():
        raise ValueError(f"provider admission refresh output exists: {output_root}")
    paths = {
        "protocol": protocol_path,
        "design": design_path,
        "bundle": bundle_path,
        "roster": roster_path,
        "assignment": assignment_path,
        "roster_assignment_gate": roster_assignment_gate_path,
        "infrastructure": infrastructure_path,
        "activation": activation_path,
        "activation_gate": activation_gate_path,
        "runner_manifest": runner_manifest_path,
    }
    if (prior_failed_probe_gate_path is None) != (prior_claim_path is None):
        raise ValueError("prior failed probe Gate and claim must be supplied together")
    if prior_failed_probe_gate_path and prior_claim_path:
        paths["prior_failed_probe_gate"] = prior_failed_probe_gate_path
        paths["prior_probe_claim"] = prior_claim_path
    values: dict[str, dict[str, Any]] = {}
    raw_values: dict[str, bytes] = {}
    for name, path in paths.items():
        values[name], raw_values[name] = _read_private(path)
    raw_sha256 = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in raw_values.items()
    }
    failures = validate_source_chain(
        protocol=values["protocol"],
        design=values["design"],
        bundle=values["bundle"],
        roster=values["roster"],
        assignment=values["assignment"],
        roster_assignment_gate=values["roster_assignment_gate"],
        infrastructure=values["infrastructure"],
        activation=values["activation"],
        activation_gate=values["activation_gate"],
        runner_manifest=values["runner_manifest"],
        raw_sha256=raw_sha256,
    )
    if failures:
        raise ValueError(f"provider admission refresh source invalid: {failures}")
    prior_failed_probe = _validate_prior_failed_probe(values, raw_sha256)
    inventory_snapshot, inventory_failures = _inspect_current_inventory(
        infrastructure=values["infrastructure"],
        activation=values["activation"],
    )
    if inventory_failures:
        raise ValueError(
            f"provider admission refresh inventory invalid: {inventory_failures}"
        )
    implementation = _implementation(repository_root)
    source_binding = {
        name: {
            "path": str(paths[name].resolve()),
            "sha256": raw_sha256[name],
            "canonical_sha256": _canonical_artifact_sha256(name, values[name]),
        }
        for name in paths
    }
    output_root.mkdir(mode=0o700)
    output_root.chmod(0o700)
    plan = build_refresh_plan(
        refresh_id=refresh_id,
        created_at=created_at,
        source_binding=source_binding,
        protocol=values["protocol"],
        design=values["design"],
        inventory_snapshot=inventory_snapshot,
        implementation=implementation,
        prior_failed_probe=prior_failed_probe,
    )
    plan_failures = validate_refresh_plan(plan)
    if plan_failures:
        output_root.rmdir()
        raise ValueError(f"provider admission refresh plan invalid: {plan_failures}")
    plan_path = output_root / "provider-admission-refresh-plan.review-required.json"
    write_private_json(plan_path, plan)
    plan_raw_sha256 = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    statement = probe_authorization_statement(
        plan_raw_sha256=plan_raw_sha256,
        plan_canonical_sha256=plan["plan_sha256"],
        provider_id=plan["frozen_stack"]["provider_id"],
        base_url=plan["frozen_stack"]["base_url"],
        model_id=plan["frozen_stack"]["model_id"],
        request_body_sha256=plan["probe_contract"]["request_body_sha256"],
        maximum_cost_microunits=plan["pricing_and_budget"]["maximum_cost_microunits"],
        max_input_tokens=plan["probe_contract"]["max_input_tokens"],
        max_output_tokens=plan["probe_contract"]["max_output_tokens"],
    )
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "provider_admission_refresh_candidate_ready_owner_authorization_required",
        "refresh_id": refresh_id,
        "created_at": created_at,
        "plan": {
            "path": str(plan_path.resolve()),
            "sha256": plan_raw_sha256,
            "canonical_sha256": plan["plan_sha256"],
        },
        "checks": {
            "amended_protocol_and_design_bound": True,
            "reviewed_roster_and_assignment_bound": True,
            "reviewed_infrastructure_and_activation_bound": True,
            "exact_40_stopped_containers_revalidated": True,
            "provider_request_is_synthetic_and_bounded": True,
            "provider_budget_reserved_under_reviewed_rates": True,
            "credential_not_accessed": True,
            "network_and_model_not_invoked": True,
            "prior_failed_probe_and_consumed_claim_bound": (
                prior_failed_probe is not None
            ),
        },
        "inventory_snapshot": inventory_snapshot,
        "owner_authorization": {
            "required": True,
            "statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "offline_preflight_complete": True,
            "owner_probe_authorization_required": True,
            "live_provider_admission_refreshed": False,
            "controlled_experiment_execution_ready": False,
        },
        "implementation": implementation,
        "execution_boundary": OFFLINE_BOUNDARY,
    }
    report["preflight_sha256"] = canonical_sha256(report)
    write_private_json(
        output_root / "provider-admission-refresh-preflight.json",
        report,
    )
    return report


def _inspect_current_inventory(
    *,
    infrastructure: dict[str, Any],
    activation: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    isolations = infrastructure["isolations"]
    isolation_index = {item["participant_id"]: item for item in isolations}
    activation_records = activation["containers"]
    authorization_sha256 = _creation_authorization_sha256(activation)
    if authorization_sha256 is None:
        return _empty_inventory_snapshot(), [
            "refresh_inventory_creation_authorization_invalid"
        ]
    reviewed_sha256 = infrastructure["reviewed_infrastructure_rebind_sha256"]
    rebind_id = infrastructure["rebind_id"]
    uid = os.getuid()
    gid = os.getgid()
    failures: list[str] = []
    projections = []
    for record in activation_records:
        participant_id = record["participant_id"]
        isolation = isolation_index.get(participant_id)
        if not isolation:
            failures.append("refresh_inventory_participant_missing")
            continue
        current, inspect_failures = inspect_projection(
            _docker_inspect(record["container"]["container_id"]),
            isolation=isolation,
            rebind_id=rebind_id,
            reviewed_canonical_sha256=reviewed_sha256,
            authorization_sha256=authorization_sha256,
            uid=uid,
            gid=gid,
        )
        failures.extend(inspect_failures)
        if current != record["container"]:
            failures.append("refresh_inventory_activation_projection_drift")
        projections.append(
            {
                "participant_id": participant_id,
                "container_id": current.get("container_id"),
                "container_name": current.get("container_name"),
                "config_sha256": current.get("actual_container_config_sha256"),
                "state": current.get("state"),
            }
        )
    snapshot = {
        "participant_count": len(projections),
        "container_count": len(projections),
        "created_count": sum(
            item.get("state") == {"status": "created", "running": False}
            for item in projections
        ),
        "running_count": sum(
            bool(_object(item.get("state")).get("running")) for item in projections
        ),
        "container_set_sha256": canonical_sha256(
            sorted(projections, key=lambda item: str(item["participant_id"]))
        ),
        "container_details_persisted": False,
    }
    if not (
        snapshot["participant_count"] == 40
        and snapshot["container_count"] == 40
        and snapshot["created_count"] == 40
        and snapshot["running_count"] == 0
    ):
        failures.append("refresh_inventory_complete_set_invalid")
    return snapshot, list(dict.fromkeys(failures))


def _creation_authorization_sha256(activation: dict[str, Any]) -> str | None:
    authorization = _object(activation.get("authorization")).get("statement_sha256")
    if _sha256(authorization):
        return str(authorization)
    values = {
        _object(_object(record.get("container")).get("labels")).get(
            "civitasos.j1d.creation-authorization"
        )
        for record in activation.get("containers", [])
        if isinstance(record, dict)
    }
    if len(values) != 1:
        return None
    value = next(iter(values))
    return str(value) if _sha256(value) else None


def _empty_inventory_snapshot() -> dict[str, Any]:
    return {
        "participant_count": 0,
        "container_count": 0,
        "created_count": 0,
        "running_count": 0,
        "container_set_sha256": canonical_sha256([]),
        "container_details_persisted": False,
    }


def _docker_inspect(container_id: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "container", "inspect", container_id],
        check=True,
        capture_output=True,
        text=True,
    )
    values = json.loads(result.stdout)
    if not (isinstance(values, list) and len(values) == 1):
        raise ValueError("docker inspect returned an invalid result")
    return values[0]


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before refresh plan generation")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _canonical_artifact_sha256(name: str, value: dict[str, Any]) -> str:
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
    return str(value[fields[name]])


def _validate_prior_failed_probe(
    values: dict[str, dict[str, Any]],
    raw_sha256: dict[str, str],
) -> dict[str, Any] | None:
    gate = values.get("prior_failed_probe_gate")
    claim = values.get("prior_probe_claim")
    if gate is None and claim is None:
        return None
    if not isinstance(gate, dict) or not isinstance(claim, dict):
        raise ValueError("prior failed probe Evidence incomplete")
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    claim_body = {key: item for key, item in claim.items() if key != "claim_sha256"}
    authorization = gate.get("authorization", {})
    claim_ref = (
        authorization.get("claim", {}) if isinstance(authorization, dict) else {}
    )
    valid = (
        gate.get("schema_version")
        == "j1-qualification-provider-admission-probe-gate:v1"
        and gate.get("passed") is False
        and gate.get("state")
        == "provider_admission_probe_failed_authorization_consumed"
        and gate.get("failure_reasons") == ["provider_content_invalid"]
        and gate.get("report_sha256") == canonical_sha256(gate_body)
        and authorization.get("consumed") is True
        and authorization.get("reusable") is False
        and claim.get("schema_version")
        == "j1-qualification-provider-admission-probe-claim:v1"
        and claim.get("single_use") is True
        and claim.get("claim_sha256") == canonical_sha256(claim_body)
        and claim.get("authorization_statement_sha256")
        == authorization.get("statement_sha256")
        and claim_ref.get("sha256") == raw_sha256.get("prior_probe_claim")
        and claim_ref.get("canonical_sha256") == claim.get("claim_sha256")
    )
    if not valid:
        raise ValueError("prior failed probe Evidence invalid")
    return {
        "gate_artifact_sha256": raw_sha256["prior_failed_probe_gate"],
        "gate_sha256": gate["report_sha256"],
        "claim_artifact_sha256": raw_sha256["prior_probe_claim"],
        "claim_sha256": claim["claim_sha256"],
        "authorization_statement_sha256": authorization["statement_sha256"],
        "failure_reasons": gate["failure_reasons"],
        "authorization_consumed": True,
        "authorization_reusable": False,
        "new_exact_authorization_required": True,
    }


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
        raise ValueError("refresh timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("refresh timestamp must include timezone")


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--roster-assignment-gate", type=Path, required=True)
    parser.add_argument("--infrastructure", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--activation-gate", type=Path, required=True)
    parser.add_argument("--runner-manifest", type=Path, required=True)
    parser.add_argument("--prior-failed-probe-gate", type=Path)
    parser.add_argument("--prior-claim", type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = generate_refresh_preflight(
        refresh_id=args.refresh_id,
        created_at=args.created_at,
        protocol_path=args.protocol,
        design_path=args.design,
        bundle_path=args.bundle,
        roster_path=args.roster,
        assignment_path=args.assignment,
        roster_assignment_gate_path=args.roster_assignment_gate,
        infrastructure_path=args.infrastructure,
        activation_path=args.activation,
        activation_gate_path=args.activation_gate,
        runner_manifest_path=args.runner_manifest,
        repository_root=args.repository_root,
        output_root=args.output_root,
        prior_failed_probe_gate_path=args.prior_failed_probe_gate,
        prior_claim_path=args.prior_claim,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
