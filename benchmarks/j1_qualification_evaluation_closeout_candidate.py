"""Build the offline J1-D real-evaluator and closeout review candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_closeout_contracts import (
    build_closeout_contract,
    build_post_run_contract,
)
from benchmarks.j1.qualification_real_evaluator import (
    SOURCE_FIELDS,
    build_real_evaluator_manifest,
)


PREFLIGHT_SCHEMA = "j1-qualification-evaluation-closeout-preflight:v1"
BUNDLE_SCHEMA = "j1-qualification-evaluation-closeout-candidate-bundle:v1"
DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_real_evaluator.py"
CLOSEOUT_SOURCE = Path(__file__).parent / "j1" / "qualification_closeout_contracts.py"
OPERATION_SOURCE = Path(__file__)


def build_candidate(
    *,
    candidate_id: str,
    protocol_path: Path,
    design_path: Path,
    verifier_path: Path,
    roster_path: Path,
    assignment_path: Path,
    provider_gate_path: Path,
    provider_receipt_path: Path,
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"candidate output already exists: {output_root}")
    created = created_at or datetime.now(timezone.utc).isoformat()
    paths = {
        "amended_protocol": protocol_path,
        "amended_design": design_path,
        "reviewed_verifier": verifier_path,
        "rebound_roster": roster_path,
        "rebound_assignment": assignment_path,
        "provider_admission_gate": provider_gate_path,
        "provider_admission_receipt": provider_receipt_path,
    }
    artifacts = {
        name: _read_private_artifact(path, name) for name, path in paths.items()
    }
    _validate_sources(artifacts)
    source_binding = _source_binding(artifacts)
    if set(source_binding) != SOURCE_FIELDS:
        raise ValueError("candidate source-binding field set is invalid")
    implementation = _implementation(repository_root)
    evaluator = build_real_evaluator_manifest(
        evaluator_id=f"{candidate_id}:real-evaluator",
        created_at=created,
        source_binding=source_binding,
        implementation=implementation,
    )
    contract_source = {
        "amended_protocol_sha256": source_binding["amended_protocol_sha256"],
        "amended_design_sha256": source_binding["amended_design_sha256"],
        "reviewed_verifier_sha256": source_binding["reviewed_verifier_sha256"],
        "rebound_roster_sha256": source_binding["rebound_roster_sha256"],
        "rebound_assignment_sha256": source_binding["rebound_assignment_sha256"],
        "provider_admission_gate_sha256": source_binding[
            "provider_admission_gate_sha256"
        ],
        "provider_admission_receipt_sha256": source_binding[
            "provider_admission_receipt_sha256"
        ],
    }
    closeout_implementation = {
        "source_revision": implementation["source_revision"],
        "source_sha256": implementation["closeout_source_sha256"],
    }
    post_run = build_post_run_contract(
        contract_id=f"{candidate_id}:post-run",
        created_at=created,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        source_binding=contract_source,
        implementation=closeout_implementation,
    )
    closeout = build_closeout_contract(
        contract_id=f"{candidate_id}:operator-closeout",
        created_at=created,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=contract_source,
        implementation=closeout_implementation,
    )

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    evaluator_path = output_root / "real-evaluator.review-required.json"
    post_run_path = output_root / "post-run-contract.review-required.json"
    closeout_path = output_root / "operator-closeout-contract.review-required.json"
    write_private_json(evaluator_path, evaluator)
    write_private_json(post_run_path, post_run)
    write_private_json(closeout_path, closeout)
    bundle = _bundle(
        candidate_id=candidate_id,
        created_at=created,
        source_binding=source_binding,
        evaluator_path=evaluator_path,
        evaluator=evaluator,
        post_run_path=post_run_path,
        post_run=post_run,
        closeout_path=closeout_path,
        closeout=closeout,
        implementation=implementation,
    )
    bundle_path = output_root / "evaluation-closeout-candidate-bundle.json"
    write_private_json(bundle_path, bundle)
    bundle_ref = _artifact(bundle_path, canonical_field="bundle_sha256")
    statement = approval_statement(
        bundle_artifact_sha256=bundle_ref["sha256"],
        bundle=bundle,
    )
    preflight = {
        "schema_version": PREFLIGHT_SCHEMA,
        "candidate_id": candidate_id,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "evaluation_closeout_candidate_ready_owner_independent_review_"
            "approval_required"
        ),
        "source_artifacts": {name: item["ref"] for name, item in artifacts.items()},
        "candidate_bundle": bundle_ref,
        "checks": {
            "amended_protocol_and_design_bound": True,
            "reviewed_verifier_v2_bound": True,
            "rebound_roster_and_assignment_bound": True,
            "successful_live_provider_admission_bound": True,
            "qualification_only_evaluator_implemented": True,
            "post_run_and_closeout_contracts_frozen_as_candidates": True,
            "model_judge_and_operator_metric_override_forbidden": True,
            "no_execution_or_external_write_performed": True,
        },
        "owner_approval": {
            "required": True,
            "statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "readiness": {
            "evaluation_closeout_candidate_complete": True,
            "independent_review_required": True,
            "evaluation_closeout_frozen": False,
            "execution_preflight_allowed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": _boundary(),
        "implementation": implementation,
    }
    preflight["preflight_sha256"] = canonical_sha256(preflight)
    write_private_json(
        output_root / "evaluation-closeout-candidate-preflight.json", preflight
    )
    return preflight


def approval_statement(*, bundle_artifact_sha256: str, bundle: dict[str, Any]) -> str:
    artifacts = bundle["candidate_artifacts"]
    return (
        "I approve for independent review only the J1-D real-evaluator and closeout "
        f"candidate bundle artifact raw SHA-256 {bundle_artifact_sha256}, canonical "
        f"SHA-256 {bundle['bundle_sha256']}, containing real evaluator "
        f"{artifacts['real_evaluator']['canonical_sha256']}, post-run contract "
        f"{artifacts['post_run_contract']['canonical_sha256']}, and operator closeout "
        f"contract {artifacts['operator_closeout_contract']['canonical_sha256']}, "
        "bound to the amended protocol/design, reviewed Verifier v2, rebound "
        "roster/assignment, and successful live provider-admission receipt frozen in "
        "that bundle. I acknowledge that independent human review and a signed "
        "promotion Gate remain required before execution preflight. This approval "
        "does not freeze or promote the candidates, start any participant container, "
        "authorize provider or model calls, execute any Agent or experiment, append "
        "Backend Facts, append the Ledger, issue or consume an execution "
        "authorization, or authorize an effectiveness claim."
    )


def _validate_sources(artifacts: dict[str, dict[str, Any]]) -> None:
    protocol = artifacts["amended_protocol"]["value"]
    design = artifacts["amended_design"]["value"]
    verifier = artifacts["reviewed_verifier"]["value"]
    roster = artifacts["rebound_roster"]["value"]
    assignment = artifacts["rebound_assignment"]["value"]
    gate = artifacts["provider_admission_gate"]["value"]
    receipt = artifacts["provider_admission_receipt"]["value"]
    checks = {
        "amended_protocol": (
            protocol.get("schema_version") == "j1-qualification-protocol-amendment:v1"
            and protocol.get("status")
            == "reviewed_plan_derived_consent_extension_required"
            and _self_hash(protocol, "amended_protocol_sha256")
        ),
        "amended_design": (
            design.get("schema_version")
            == "j1-qualification-execution-design-amendment:v1"
            and _self_hash(design, "amended_design_sha256")
        ),
        "reviewed_verifier": (
            verifier.get("schema_version") == "j1-qualification-verifier-manifest:v2"
            and verifier.get("status") == "operator_reviewed"
            and _self_hash(verifier, "manifest_sha256")
        ),
        "rebound_roster": (
            roster.get("schema_version")
            == "j1-qualification-roster-rebound:operator-reviewed:v1"
            and roster.get("status") == "operator_reviewed"
            and len(roster.get("participants", [])) == 40
            and _self_hash(roster, "reviewed_rebound_roster_sha256")
        ),
        "rebound_assignment": (
            assignment.get("schema_version")
            == ("j1-qualification-cohort-assignment-rebound:operator-reviewed:v1")
            and assignment.get("status") == "operator_reviewed"
            and len(assignment.get("assignments", [])) == 20
            and _self_hash(assignment, "reviewed_rebound_assignment_sha256")
        ),
        "provider_gate": (
            gate.get("passed") is True
            and gate.get("state")
            == "live_provider_admission_refreshed_execution_still_blocked"
            and gate.get("readiness", {}).get("live_provider_admission_refreshed")
            is True
            and _self_hash(gate, "report_sha256")
        ),
        "provider_receipt": (
            receipt.get("schema_version")
            == "j1-qualification-provider-admission-probe-receipt:v1"
            and receipt.get("status") == "admitted"
            and receipt.get("inventory", {}).get("unchanged") is True
            and receipt.get("inventory", {}).get("after", {}).get("running_count") == 0
            and _self_hash(receipt, "receipt_sha256")
        ),
    }
    if not all(checks.values()):
        raise ValueError(
            f"evaluation/closeout source validation failed: "
            f"{[name for name, passed in checks.items() if not passed]}"
        )
    if (
        protocol.get("amended_frozen_stack", {}).get("verifier_manifest_sha256")
        != verifier.get("manifest_sha256")
        or design.get("amendment_id") != protocol.get("amendment_id")
        or design.get("source_binding") != protocol.get("source_binding")
        or assignment.get("operator_reviewed_roster_sha256")
        != roster.get("reviewed_rebound_roster_sha256")
        or gate.get("receipt", {}).get("sha256")
        != artifacts["provider_admission_receipt"]["ref"]["sha256"]
        or gate.get("receipt", {}).get("canonical_sha256")
        != receipt.get("receipt_sha256")
    ):
        raise ValueError("evaluation/closeout source cross-binding failed")


def _source_binding(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    values = {
        "amended_protocol": "amended_protocol_sha256",
        "amended_design": "amended_design_sha256",
        "reviewed_verifier": "manifest_sha256",
        "rebound_roster": "reviewed_rebound_roster_sha256",
        "rebound_assignment": "reviewed_rebound_assignment_sha256",
        "provider_admission_gate": "report_sha256",
        "provider_admission_receipt": "receipt_sha256",
    }
    result: dict[str, str] = {}
    for name, canonical_field in values.items():
        result[f"{name}_artifact_sha256"] = artifacts[name]["ref"]["sha256"]
        result[f"{name}_sha256"] = artifacts[name]["value"][canonical_field]
    return result


def _bundle(
    *,
    candidate_id: str,
    created_at: str,
    source_binding: dict[str, str],
    evaluator_path: Path,
    evaluator: dict[str, Any],
    post_run_path: Path,
    post_run: dict[str, Any],
    closeout_path: Path,
    closeout: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "candidate_id": candidate_id,
        "status": "review_required",
        "created_at": created_at,
        "source_binding": source_binding,
        "candidate_artifacts": {
            "real_evaluator": _artifact(
                evaluator_path,
                canonical_field="manifest_sha256",
                value=evaluator,
            ),
            "post_run_contract": _artifact(
                post_run_path,
                canonical_field="contract_sha256",
                value=post_run,
            ),
            "operator_closeout_contract": _artifact(
                closeout_path,
                canonical_field="contract_sha256",
                value=closeout,
            ),
        },
        "review_scope": {
            "paired_analysis_and_bootstrap": True,
            "outcome_and_pair_completeness": True,
            "budget_and_safety_reconciliation": True,
            "operator_closeout_claim_boundary": True,
            "source_or_candidate_author": "AI-assisted implementation",
            "independent_human_review_required": True,
        },
        "readiness": {
            "candidate_complete": True,
            "operator_reviewed": False,
            "execution_preflight_allowed": False,
        },
        "execution_boundary": _boundary(),
        "implementation": implementation,
    }
    value["bundle_sha256"] = canonical_sha256(value)
    failures = _validate_bundle(value)
    if failures:
        raise ValueError(f"evaluation/closeout candidate bundle invalid: {failures}")
    return value


def _implementation(repository_root: Path) -> dict[str, str]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(revision) != 40:
        raise ValueError("Agent source revision is invalid")
    return {
        "source_revision": revision,
        "evaluator_source_sha256": hashlib.sha256(
            DOMAIN_SOURCE.read_bytes()
        ).hexdigest(),
        "closeout_source_sha256": hashlib.sha256(
            CLOSEOUT_SOURCE.read_bytes()
        ).hexdigest(),
        "freeze_operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    source = bundle.get("source_binding")
    candidates = bundle.get("candidate_artifacts")
    if not (
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("status") == "review_required"
        and isinstance(source, dict)
        and set(source) == SOURCE_FIELDS
        and all(_sha256(item) for item in source.values())
    ):
        failures.append("candidate_bundle_identity_or_source_invalid")
    candidate_values = candidates if isinstance(candidates, dict) else {}
    if not (
        set(candidate_values)
        == {
            "real_evaluator",
            "post_run_contract",
            "operator_closeout_contract",
        }
        and all(
            isinstance(item, dict)
            and _sha256(item.get("sha256"))
            and _sha256(item.get("canonical_sha256"))
            for item in candidate_values.values()
        )
    ):
        failures.append("candidate_bundle_artifacts_invalid")
    if bundle.get("execution_boundary") != _boundary():
        failures.append("candidate_bundle_boundary_invalid")
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    if bundle.get("bundle_sha256") != canonical_sha256(body):
        failures.append("candidate_bundle_hash_invalid")
    return failures


def _read_private_artifact(path: Path, label: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} artifact is not a regular file")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"{label} artifact must be mode 0600")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} artifact must be a JSON object")
    return {
        "value": value,
        "ref": {"path": str(resolved), "sha256": hashlib.sha256(raw).hexdigest()},
    }


def _self_hash(value: dict[str, Any], field: str) -> bool:
    body = {key: item for key, item in value.items() if key != field}
    return value.get(field) == canonical_sha256(body)


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _artifact(
    path: Path,
    *,
    canonical_field: str,
    value: dict[str, Any] | None = None,
) -> dict[str, str]:
    artifact = value or json.loads(path.read_text())
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": artifact[canonical_field],
    }


def _boundary() -> dict[str, bool]:
    return {
        "candidate_generation_only": True,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
        "effectiveness_claim_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build an offline J1-D evaluation/closeout review candidate."
    )
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--provider-gate", type=Path, required=True)
    parser.add_argument("--provider-receipt", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = build_candidate(
        candidate_id=args.candidate_id,
        protocol_path=args.protocol,
        design_path=args.design,
        verifier_path=args.verifier,
        roster_path=args.roster,
        assignment_path=args.assignment,
        provider_gate_path=args.provider_gate,
        provider_receipt_path=args.provider_receipt,
        output_root=args.output_root,
        repository_root=args.repository_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
