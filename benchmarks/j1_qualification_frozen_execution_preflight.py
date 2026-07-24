"""Generate the offline frozen-stack J1-D execution preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_closeout_contracts import (
    validate_closeout_contract,
    validate_post_run_contract,
)
from benchmarks.j1.qualification_frozen_execution_preflight import (
    MAX_TTL_SECONDS,
    SOURCE_NAMES,
    build_execution_plan,
    build_preflight,
)
from benchmarks.j1.qualification_infrastructure_activation import (
    validate_reviewed_activation_source,
)
from benchmarks.j1.qualification_real_evaluator import (
    validate_real_evaluator_manifest,
)
from benchmarks.j1_qualification_evaluation_closeout_candidate import (
    _source_binding,
    _validate_sources,
)
from benchmarks.j1_qualification_provider_admission_refresh import (
    _inspect_current_inventory,
)


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_frozen_execution_preflight.py"
)
OPERATION_SOURCE = Path(__file__)
CANONICAL_FIELDS = {
    "amended_protocol": "amended_protocol_sha256",
    "amended_design": "amended_design_sha256",
    "reviewed_verifier": "manifest_sha256",
    "rebound_roster": "reviewed_rebound_roster_sha256",
    "rebound_assignment": "reviewed_rebound_assignment_sha256",
    "signed_advice_manifest": "manifest_sha256",
    "reviewed_infrastructure": "reviewed_infrastructure_rebind_sha256",
    "infrastructure_promotion_gate": "report_sha256",
    "infrastructure_activation": "activation_sha256",
    "infrastructure_activation_gate": "report_sha256",
    "provider_admission_receipt": "receipt_sha256",
    "provider_admission_gate": "report_sha256",
    "frozen_real_evaluator": "manifest_sha256",
    "frozen_post_run_contract": "contract_sha256",
    "frozen_operator_closeout_contract": "contract_sha256",
    "frozen_evaluation_closeout_bundle": "frozen_bundle_sha256",
    "evaluation_closeout_promotion_gate": "report_sha256",
}


def generate_frozen_execution_preflight(
    *,
    run_id: str,
    created_at: str,
    source_paths: dict[str, Path],
    repository_root: Path,
    output_root: Path,
    execution_root: Path,
    authorization_output_root: Path,
    authorization_consumption_path: Path,
    post_run_output_root: Path,
) -> dict[str, Any]:
    _require_rfc3339(created_at)
    if set(source_paths) != SOURCE_NAMES:
        raise ValueError("frozen execution source path set is invalid")
    if output_root.exists():
        raise ValueError(f"frozen execution preflight output exists: {output_root}")
    future_paths = {
        "execution_root": execution_root,
        "authorization_output_root": authorization_output_root,
        "authorization_consumption_path": authorization_consumption_path,
        "post_run_output_root": post_run_output_root,
    }
    _validate_future_paths(output_root=output_root, future_paths=future_paths)
    artifacts = {name: _read_private(path, name) for name, path in source_paths.items()}
    _validate_frozen_stack(artifacts)
    inventory_snapshot, inventory_failures = _inspect_current_inventory(
        infrastructure=artifacts["reviewed_infrastructure"]["value"],
        activation=artifacts["infrastructure_activation"]["value"],
    )
    if inventory_failures:
        raise ValueError(
            f"frozen execution container inventory invalid: {inventory_failures}"
        )
    provider_inventory = artifacts["provider_admission_receipt"]["value"]["inventory"]
    if (
        inventory_snapshot != provider_inventory["before"]
        or inventory_snapshot != provider_inventory["after"]
    ):
        raise ValueError("frozen execution container inventory drifted since admission")
    implementation = _implementation(repository_root)
    source_artifacts = {
        name: {
            "path": str(item["path"]),
            "sha256": item["sha256"],
            "canonical_sha256": _canonical(name, item["value"]),
        }
        for name, item in artifacts.items()
    }
    design = artifacts["amended_design"]["value"]
    provider = design["preserved_provider_call"]
    budget = design["preserved_budget_reservation"]
    protocol_maximum = (
        artifacts["amended_protocol"]["value"]["amended_frozen_stack"]["budget"][
            "max_cost_microunits"
        ]
        * 40
    )
    plan = build_execution_plan(
        run_id=run_id,
        created_at=created_at,
        ttl_seconds=MAX_TTL_SECONDS,
        source_artifacts=source_artifacts,
        execution_scope={
            "provider_id": provider["provider_id"],
            "provider_host": "api.deepseek.com",
            "model_id": provider["model_id"],
            "temperature": provider["temperature"],
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "matched_pair_count": 20,
            "task_count_per_participant": provider["calls_per_participant"],
            "authorized_task_executions": 320,
            "same_stack_for_both_cohorts": True,
            "cohort_source": "reviewed_rebound_assignment",
            "outcome_evaluator_status": "operator_reviewed_frozen",
            "post_run_contract_status": "operator_reviewed_frozen",
            "operator_closeout_contract_status": "operator_reviewed_frozen",
        },
        cost_acknowledgement={
            "currency": "usd_microunit",
            "authorized_provider_calls": 320,
            "aggregate_reserved_tokens": budget["aggregate_reserved_tokens"],
            "aggregate_reserved_cost_microunits": budget[
                "aggregate_reserved_microunits"
            ],
            "aggregate_protocol_max_cost_microunits": protocol_maximum,
            "reservation_required_before_each_call": True,
            "actual_usage_reconciliation_required": True,
            "budget_overrun_fail_stop_required": True,
        },
        controls={
            "single_use": True,
            "atomic_claim_create_exclusive": True,
            "claimed_failure_requires_new_authorization": True,
            "unclaimed_expiry_requires_new_authorization": True,
            "container_state_recheck_before_claim": True,
            "provider_admission_recheck_before_claim": True,
            "post_run_receipt_required": True,
            "operator_closeout_required": True,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "effectiveness_claim_before_closeout_allowed": False,
            **{name: str(path.resolve()) for name, path in future_paths.items()},
        },
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        plan_path = output_root / "frozen-stack-execution-plan.review-required.json"
        write_private_json(plan_path, plan)
        plan_bytes = plan_path.read_bytes()
        preflight = build_preflight(
            plan_path=str(plan_path.resolve()),
            plan_bytes=plan_bytes,
            plan=plan,
            created_at=created_at,
            inventory_snapshot=inventory_snapshot,
        )
        write_private_json(
            output_root / "frozen-stack-execution-preflight.json",
            preflight,
        )
        return preflight
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_frozen_stack(artifacts: dict[str, dict[str, Any]]) -> None:
    active = {
        name: artifacts[name]
        for name in (
            "amended_protocol",
            "amended_design",
            "reviewed_verifier",
            "rebound_roster",
            "rebound_assignment",
            "provider_admission_gate",
            "provider_admission_receipt",
        )
    }
    _validate_sources(active)
    active_binding = _source_binding(active)
    for name, item in artifacts.items():
        field = CANONICAL_FIELDS.get(name)
        if field and not _self_hash(item["value"], field):
            raise ValueError(f"{name} canonical self-hash invalid")

    protocol = artifacts["amended_protocol"]["value"]
    design = artifacts["amended_design"]["value"]
    roster = artifacts["rebound_roster"]["value"]
    assignment = artifacts["rebound_assignment"]["value"]
    advice = artifacts["signed_advice_manifest"]["value"]
    advice_gate = artifacts["signed_advice_gate"]["value"]
    infrastructure = artifacts["reviewed_infrastructure"]["value"]
    infrastructure_gate = artifacts["infrastructure_promotion_gate"]["value"]
    activation = artifacts["infrastructure_activation"]["value"]
    activation_gate = artifacts["infrastructure_activation_gate"]["value"]
    provider_receipt = artifacts["provider_admission_receipt"]["value"]
    provider_gate = artifacts["provider_admission_gate"]["value"]
    evaluator = artifacts["frozen_real_evaluator"]["value"]
    post_run = artifacts["frozen_post_run_contract"]["value"]
    closeout = artifacts["frozen_operator_closeout_contract"]["value"]
    bundle = artifacts["frozen_evaluation_closeout_bundle"]["value"]
    promotion_gate = artifacts["evaluation_closeout_promotion_gate"]["value"]

    if (
        design.get("signed_advice_parent", {}).get("manifest_sha256")
        != advice.get("manifest_sha256")
        or protocol.get("source_binding", {}).get(
            "signed_advice_manifest_artifact_sha256"
        )
        != artifacts["signed_advice_manifest"]["sha256"]
        or len(design.get("task_contracts", [])) != 8
        or design.get("preserved_provider_call", {}).get("calls_per_participant") != 8
        or design.get("preserved_budget_reservation", {}).get(
            "aggregate_reserved_tokens"
        )
        != 800000
        or design.get("preserved_budget_reservation", {}).get(
            "aggregate_reserved_microunits"
        )
        != 487360
        or protocol.get("amended_frozen_stack", {})
        .get("budget", {})
        .get("max_cost_microunits")
        != 100000
    ):
        raise ValueError("amended design execution scope or advice binding invalid")
    if roster.get("inventory") != {
        "consent_extension_count": 40,
        "control_participant_count": 20,
        "mentor_participant_count": 20,
        "participant_count": 40,
    } or assignment.get("inventory") != {
        "control_participant_count": 20,
        "mentor_participant_count": 20,
        "pair_count": 20,
        "participant_count": 40,
    }:
        raise ValueError("rebound roster or assignment inventory invalid")
    expected_advice_inventory = {
        "all_signatures_verified": True,
        "cohort": "mentor",
        "control_advice_count": 0,
        "participant_count": 20,
        "signed_advice_count": 160,
        "task_count": 8,
        "unique_signed_advice_count": 160,
    }
    if not (
        advice.get("schema_version")
        == "j1-qualification-treatment-advice-signed-manifest:v1"
        and advice.get("status") == "signed_non_executable_gate_required"
        and advice.get("inventory") == expected_advice_inventory
        and advice_gate.get("schema_version")
        == "j1-qualification-treatment-advice-gate:v1"
        and advice_gate.get("passed") is True
        and advice_gate.get("failure_reasons") == []
        and advice_gate.get("inventory") == expected_advice_inventory
        and advice_gate.get("signature_verification")
        == {"expected": 160, "failure_count": 0, "verified": 160}
        and advice_gate.get("signed_manifest_sha256") == advice["manifest_sha256"]
        and advice_gate.get("artifacts", {}).get("signed_manifest", {}).get("sha256")
        == artifacts["signed_advice_manifest"]["sha256"]
    ):
        raise ValueError("signed treatment advice or Gate invalid")

    activation_failures = validate_reviewed_activation_source(
        reviewed=infrastructure,
        reviewed_raw=artifacts["reviewed_infrastructure"]["raw"],
        gate=infrastructure_gate,
    )
    if activation_failures:
        raise ValueError(
            f"reviewed infrastructure activation source invalid: {activation_failures}"
        )
    if not (
        activation.get("inventory")
        == {
            "container_created_count": 40,
            "container_started_count": 0,
            "control_count": 20,
            "mentor_count": 20,
            "participant_count": 40,
        }
        and activation_gate.get("passed") is True
        and activation_gate.get("failure_reasons") == []
        and activation_gate.get("state")
        == "replacement_containers_created_provider_admission_required"
        and activation_gate.get("activation")
        == _artifact_ref(
            "infrastructure_activation",
            artifacts["infrastructure_activation"],
        )
        and activation_gate.get("readiness", {}).get("participant_containers_created")
        == 40
        and activation_gate.get("readiness", {}).get("participant_containers_started")
        == 0
    ):
        raise ValueError("infrastructure activation or Gate invalid")
    if not (
        provider_receipt.get("inventory", {}).get("unchanged") is True
        and provider_receipt["inventory"]["before"]
        == provider_receipt["inventory"]["after"]
        and provider_gate.get("receipt")
        == _artifact_ref(
            "provider_admission_receipt",
            artifacts["provider_admission_receipt"],
        )
    ):
        raise ValueError("provider admission binding invalid")

    if bundle.get("source_binding") != active_binding:
        raise ValueError("frozen evaluation bundle active-stack binding invalid")
    contract_binding = {
        key: value
        for key, value in active_binding.items()
        if not key.endswith("_artifact_sha256")
    }
    evaluator_failures = validate_real_evaluator_manifest(
        evaluator,
        expected_source_binding=active_binding,
        expected_implementation=evaluator.get("implementation"),
        expected_status="operator_reviewed_frozen",
    )
    post_run_failures = validate_post_run_contract(
        post_run,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        source_binding=contract_binding,
        implementation=post_run.get("implementation"),
        expected_status="operator_reviewed_frozen",
    )
    closeout_failures = validate_closeout_contract(
        closeout,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=contract_binding,
        implementation=closeout.get("implementation"),
        expected_status="operator_reviewed_frozen",
    )
    validation_failures = evaluator_failures + post_run_failures + closeout_failures
    if validation_failures:
        raise ValueError(
            f"frozen evaluation/closeout artifact invalid: {validation_failures}"
        )
    expected_frozen = {
        "real_evaluator": _artifact_ref(
            "frozen_real_evaluator",
            artifacts["frozen_real_evaluator"],
        ),
        "post_run_contract": _artifact_ref(
            "frozen_post_run_contract",
            artifacts["frozen_post_run_contract"],
        ),
        "operator_closeout_contract": _artifact_ref(
            "frozen_operator_closeout_contract",
            artifacts["frozen_operator_closeout_contract"],
        ),
    }
    if not (
        bundle.get("schema_version")
        == "j1-qualification-evaluation-closeout-frozen-bundle:v1"
        and bundle.get("status") == "operator_reviewed_frozen"
        and bundle.get("frozen_artifacts") == expected_frozen
        and bundle.get("readiness")
        == {
            "controlled_experiment_execution_ready": False,
            "evaluation_closeout_frozen": True,
            "execution_authorization_issued": False,
            "execution_preflight_allowed": True,
        }
        and promotion_gate.get("passed") is True
        and promotion_gate.get("failure_reasons") == []
        and promotion_gate.get("state")
        == "evaluation_closeout_review_passed_execution_preflight_allowed"
        and promotion_gate.get("frozen_bundle")
        == _artifact_ref(
            "frozen_evaluation_closeout_bundle",
            artifacts["frozen_evaluation_closeout_bundle"],
        )
        and promotion_gate.get("frozen_artifacts") == expected_frozen
        and promotion_gate.get("readiness") == bundle.get("readiness")
    ):
        raise ValueError("frozen evaluation/closeout bundle or promotion Gate invalid")

    participant_ids = {item["participant_id"] for item in roster["participants"]}
    assignment_ids = {
        participant_id
        for item in assignment["assignments"]
        for participant_id in (
            item["mentor"]["participant_id"],
            item["control"]["participant_id"],
        )
    }
    isolation_ids = {item["participant_id"] for item in infrastructure["isolations"]}
    activation_ids = {item["participant_id"] for item in activation["containers"]}
    if not participant_ids == assignment_ids == isolation_ids == activation_ids:
        raise ValueError("participant identity set drifted across frozen stack")


def _read_private(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"{label} artifact must not be a symlink")
    resolved = path.resolve()
    if not resolved.is_file() or resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"{label} artifact must be a mode-0600 regular file")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} artifact must contain a JSON object")
    return {
        "path": resolved,
        "raw": raw,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "ref": {
            "path": str(resolved),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "value": value,
    }


def _artifact_ref(name: str, item: dict[str, Any]) -> dict[str, str]:
    return {
        "path": str(item["path"]),
        "sha256": item["sha256"],
        "canonical_sha256": _canonical(name, item["value"]),
    }


def _canonical(name: str, value: dict[str, Any]) -> str:
    field = CANONICAL_FIELDS.get(name)
    return str(value[field]) if field else canonical_sha256(value)


def _self_hash(value: dict[str, Any], field: str) -> bool:
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before frozen execution preflight")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_future_paths(*, output_root: Path, future_paths: dict[str, Path]) -> None:
    output_parent = output_root.resolve().parent
    if not output_parent.is_dir():
        raise ValueError("qualification evidence root does not exist")
    resolved = {name: path.resolve() for name, path in future_paths.items()}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("future execution paths must be distinct")
    for name, path in resolved.items():
        if path.exists():
            raise ValueError(f"{name} already exists: {path}")
        if output_parent not in path.parents:
            raise ValueError(f"{name} must stay inside qualification evidence root")


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
        raise ValueError("frozen execution timestamp invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("frozen execution timestamp must include timezone")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--created-at", required=True)
    for name in sorted(SOURCE_NAMES):
        parser.add_argument(f"--{name.replace('_', '-')}", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--authorization-output-root", type=Path, required=True)
    parser.add_argument("--authorization-consumption-path", type=Path, required=True)
    parser.add_argument("--post-run-output-root", type=Path, required=True)
    args = parser.parse_args()
    source_paths = {name: getattr(args, name) for name in SOURCE_NAMES}
    report = generate_frozen_execution_preflight(
        run_id=args.run_id,
        created_at=args.created_at,
        source_paths=source_paths,
        repository_root=args.repository_root,
        output_root=args.output_root,
        execution_root=args.execution_root,
        authorization_output_root=args.authorization_output_root,
        authorization_consumption_path=args.authorization_consumption_path,
        post_run_output_root=args.post_run_output_root,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
