"""Claim and execute one fully reviewed J1-D r4 qualification run."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_admission import _load_private_env
from benchmarks.j1.qualification_container_runner_v4 import (
    ParticipantContainerClient,
    isolation_index,
)
from benchmarks.j1.qualification_execution_materials_v4 import (
    replay_material_bindings,
    validate_material_paths,
)
from benchmarks.j1.qualification_live_adapter_v4 import (
    LiveExecutionAdapter,
    load_live_materials,
)
from benchmarks.j1.qualification_live_boundaries_v4 import (
    OpenAICompatibleQualificationProvider,
    Pkcs11ParticipantSigner,
    load_participant_profiles,
)
from benchmarks.j1.qualification_orchestrator_v4 import run_live_orchestrator
from benchmarks.j1_qualification_execution_entry_v4 import (
    AtomicClaimPersistedError,
    claim_and_build_entry_gate,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


def execute_claimed_run(
    *,
    claim_context: dict[str, Any],
    authorization_path: Path,
    provider_env_path: Path,
    task_source_path: Path,
    signed_advice_root: Path,
    participant_profiles_root: Path,
    module_path: str,
    token_label: str,
    pin: str,
    failure_boundary: dict[str, int] | None = None,
) -> dict[str, Any]:
    authorization = claim_context["authorization"]
    contract = claim_context["contract"]
    activation = claim_context["activation"]
    plan = claim_context["plan"]
    execution_root = Path(authorization["controls"]["execution_root"])
    if execution_root.exists():
        raise ValueError("r4 live execution root already exists")
    execution_root.mkdir(parents=True, mode=0o700)
    execution_root.chmod(0o700)
    boundary = failure_boundary if failure_boundary is not None else {}
    boundary.update(
        {
            "provider_credential_read_count": 0,
            "provider_api_call_count": 0,
            "participant_container_start_count": 0,
            "participant_signature_count": 0,
        }
    )
    validate_material_paths(
        plan["material_bindings"],
        task_source_path=task_source_path,
        signed_advice_root=signed_advice_root,
        participant_profiles_root=participant_profiles_root,
    )
    replay_material_bindings(plan["material_bindings"])
    design_path = Path(contract["source_artifacts"]["amended_design"]["path"])
    design = _read_object(design_path)
    assignment_path = Path(contract["source_artifacts"]["rebound_assignment"]["path"])
    profiles = load_participant_profiles(participant_profiles_root)
    materials = load_live_materials(
        run_id=authorization["run_id"],
        authorization_id=authorization["authorization_id"],
        authorization_path=authorization_path,
        task_source_path=task_source_path,
        signed_advice_root=signed_advice_root,
        reviewed_assignment_path=assignment_path,
    )
    _validate_task_inputs(contract, materials.task_inputs)
    boundary["provider_credential_read_count"] = 1
    values = _provider_values(provider_env_path, contract)
    api_key = values.pop("BETA6_EXTERNAL_AGENT_API_KEY")
    provider = OpenAICompatibleQualificationProvider(
        run_id=authorization["run_id"],
        api_key=api_key,
        authorization_sha256=hashlib.sha256(
            authorization_path.read_bytes()
        ).hexdigest(),
        amended_design=design,
        budget_path=execution_root / "provider-budget.sqlite3",
    )
    api_key = ""
    library = pkcs11.lib(str(Path(module_path).resolve()))
    token = library.get_token(token_label=token_label)
    with token.open(user_pin=pin, rw=False) as session:
        signer = Pkcs11ParticipantSigner(session=session, profiles=profiles)
        adapter = LiveExecutionAdapter(
            materials=materials,
            containers=ParticipantContainerClient(
                isolations=isolation_index(activation)
            ),
            provider=provider,
            signer=signer,
            evidence_root=execution_root / "evidence",
        )
        report = run_live_orchestrator(
            contract=contract,
            run_id=authorization["run_id"],
            root=execution_root,
            adapter=adapter,
        )
    pin = ""
    report["source_binding"] = {
        "claim": claim_context["claim"],
        "entry_gate": claim_context["entry_gate"],
        "execution_plan_sha256": plan["plan_sha256"],
    }
    report["report_sha256"] = canonical_sha256(
        {key: item for key, item in report.items() if key != "report_sha256"}
    )
    write_private_json(execution_root / "live-execution-report.json", report)
    return report


def _provider_values(path: Path, contract: dict[str, Any]) -> dict[str, str]:
    failures: list[str] = []
    values = _load_private_env(path, failures)
    design = _read_object(Path(contract["source_artifacts"]["amended_design"]["path"]))
    provider = design.get("preserved_provider_call") or design["provider_call"]
    expected = {
        "BETA6_EXTERNAL_AGENT_PROVIDER": provider["provider_id"],
        "BETA6_EXTERNAL_AGENT_API_BASE_URL": provider["base_url"],
        "BETA6_EXTERNAL_AGENT_MODEL": provider["model_id"],
    }
    if failures or not values.get("BETA6_EXTERNAL_AGENT_API_KEY"):
        raise ValueError("r4 provider environment is unavailable")
    for name, expected_value in expected.items():
        if values.get(name, "").rstrip("/") != str(expected_value).rstrip("/"):
            raise ValueError(f"r4 provider configuration mismatch: {name}")
    return values


def _validate_task_inputs(
    contract: dict[str, Any], task_inputs: dict[str, dict[str, Any]]
) -> None:
    expected = {
        task["task"]["task_id"]: task["task"]["task_input_sha256"]
        for task in contract["task_executions"]
    }
    if set(expected) != set(task_inputs):
        raise ValueError("r4 task input corpus does not match execution contract")
    for task_id, digest in expected.items():
        source = task_inputs[task_id]
        if not (
            source.get("input_sha256") == digest
            and hashlib.sha256(str(source.get("input", "")).encode()).hexdigest()
            == digest
        ):
            raise ValueError("r4 task input content drifted")


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"r4 source artifact must contain an object: {path}")
    return value


def _failure_evidence(
    *,
    authorization_path: Path,
    state: str,
    error: Exception,
    claim_path: str | None,
    execution_started: bool,
    execution_root: Path | None,
    failure_boundary: dict[str, int],
) -> dict[str, Any]:
    pre_orchestrator = bool(
        execution_started
        and execution_root is not None
        and not (execution_root / "execution-journal.sqlite3").exists()
    )
    value = {
        "schema_version": "j1-qualification-r4-execution-failure:v1",
        "recorded_at": datetime.now(UTC).isoformat(),
        "state": state,
        "authorization_artifact_sha256": (
            hashlib.sha256(authorization_path.read_bytes()).hexdigest()
            if authorization_path.is_file()
            else None
        ),
        "claim_path": claim_path,
        "failure_type": type(error).__name__,
        "failure_reason": str(error),
        "failure_stage": "pre_orchestrator" if pre_orchestrator else "execution_entry",
        "execution_started": execution_started,
        "automatic_retry_performed": False,
        "authorization_reusable": False if claim_path else None,
        "signed_closeout_required": bool(claim_path),
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }
    if pre_orchestrator:
        value.update(failure_boundary)
    value["report_sha256"] = canonical_sha256(value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-authorization-id", required=True)
    parser.add_argument("--owner-statement", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--issuance-gate", type=Path, required=True)
    parser.add_argument("--claim-preflight", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--provider-env", type=Path, required=True)
    parser.add_argument("--task-source", type=Path, required=True)
    parser.add_argument("--signed-advice-root", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    args = parser.parse_args()
    context: dict[str, Any] | None = None
    failure_boundary: dict[str, int] = {}
    try:
        context = claim_and_build_entry_gate(
            owner_authorization_id=args.owner_authorization_id,
            owner_statement=args.owner_statement,
            authorization_path=args.authorization,
            issuance_gate_path=args.issuance_gate,
            claim_preflight_path=args.claim_preflight,
            reviewer_profile_path=args.reviewer_profile,
            task_source_path=args.task_source,
            signed_advice_root=args.signed_advice_root,
            participant_profiles_root=args.participant_profiles_root,
            repository_root=args.repository_root,
        )
        # Secrets are read only after the persisted claim and entry Gate validate.
        pin = read_pin(args.pin_file)
        report = execute_claimed_run(
            claim_context=context,
            authorization_path=args.authorization,
            provider_env_path=args.provider_env,
            task_source_path=args.task_source,
            signed_advice_root=args.signed_advice_root,
            participant_profiles_root=args.participant_profiles_root,
            module_path=args.module,
            token_label=args.token_label,
            pin=pin,
            failure_boundary=failure_boundary,
        )
    except Exception as error:
        claim_path = None
        if isinstance(error, AtomicClaimPersistedError):
            claim_path = str(error.claim_path.resolve())
        elif context is not None:
            claim_path = context["claim"]["path"]
        execution_root = (
            Path(context["authorization"]["controls"]["execution_root"])
            if context is not None
            else None
        )
        evidence = _failure_evidence(
            authorization_path=args.authorization,
            state=(
                "claimed_execution_failed_closeout_required"
                if claim_path
                else "preclaim_execution_blocked"
            ),
            error=error,
            claim_path=claim_path,
            execution_started=(execution_root is not None and execution_root.exists()),
            execution_root=execution_root,
            failure_boundary=failure_boundary,
        )
        output = (
            Path(context["authorization"]["controls"]["execution_root"])
            if context is not None
            else args.authorization.parent
        )
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private_json(output / "live-execution-failure.json", evidence)
        print(json.dumps(evidence, sort_keys=True))
        return 2 if claim_path else 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
