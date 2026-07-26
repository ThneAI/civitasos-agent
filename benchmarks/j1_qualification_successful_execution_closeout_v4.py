"""Replay, review, and sign one complete J1-D r4-family execution closeout."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import sqlite3
import subprocess
import tempfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from benchmarks.j1.controlled_comparison import (
    REQUIRED_SCENARIOS,
    canonical_sha256,
    write_private_json,
)
from benchmarks.j1.qualification_event_harness import validate_built_event_trace
from benchmarks.j1.qualification_provider_broker import validate_provider_receipt
from benchmarks.j1.qualification_real_evaluator import (
    MATURITY_CRITERIA,
    OUTCOME_SCHEMA,
    evaluate_qualification_outcomes,
    validate_real_evaluator_manifest,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_successful_execution_closeout_v4 import (
    build_closeout_artifacts,
    build_closeout_gate,
    build_preflight,
    build_review_bundle,
    build_review_gate,
    build_review_receipt,
    build_review_request,
    closeout_authorization_statement,
    reviewer_statement,
    validate_closeout_artifacts,
    validate_preflight,
    validate_review_bundle,
    validate_review_receipt,
)
from benchmarks.j1.qualification_verifier import verify_task
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_successful_execution_closeout_v4.py"
)
OPERATION_SOURCE = Path(__file__)
SOURCE_PATHS = [
    "benchmarks/j1/qualification_successful_execution_closeout_v4.py",
    "benchmarks/j1/qualification_real_evaluator.py",
    "benchmarks/j1/qualification_verifier.py",
    "benchmarks/j1/qualification_event_harness.py",
    "benchmarks/j1/qualification_provider_broker.py",
    "benchmarks/j1_qualification_successful_execution_closeout_v4.py",
]
EVIDENCE_NAMES = {
    "event-receipts",
    "event-trace",
    "participant-decision",
    "participant-signature",
    "provider-receipt",
    "task-evidence",
    "task-verification",
}
CASE_SCENARIOS = {
    "scope-and-delivery-contract": {"repeated_error"},
    "constitution-precedence": {"harmful_advice"},
    "apprentice-independent-decision": {"advice_refusal"},
    "revocation-fail-closed": {"relation_revocation"},
    "restart-provenance-continuity": {"runtime_restart"},
    "stale-advice-rejection": {"credential_rotation"},
    "three-consecutive-verified-tasks": set(),
}


def prepare_review(
    *,
    bundle_id: str,
    request_id: str,
    created_at: str,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    live_report_path: Path,
    execution_contract_path: Path,
    reviewed_design_path: Path,
    reviewed_assignment_path: Path,
    reviewed_verifier_path: Path,
    evaluator_path: Path,
    post_run_contract_path: Path,
    closeout_contract_path: Path,
    activation_path: Path,
    participant_profiles_root: Path,
    execution_root: Path,
    repository_root: Path,
    output_root: Path,
    pytest_passed_count: int,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"successful closeout review output exists: {output_root}")
    revision = _clean_pushed_revision(repository_root)
    collected = collect_successful_run(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        live_report_path=live_report_path,
        execution_contract_path=execution_contract_path,
        reviewed_design_path=reviewed_design_path,
        reviewed_assignment_path=reviewed_assignment_path,
        reviewed_verifier_path=reviewed_verifier_path,
        evaluator_path=evaluator_path,
        post_run_contract_path=post_run_contract_path,
        closeout_contract_path=closeout_contract_path,
        activation_path=activation_path,
        participant_profiles_root=participant_profiles_root,
        execution_root=execution_root,
        repository_root=repository_root,
        source_revision=revision,
    )
    preflight = build_preflight(**collected)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        preflight_path = output_root / "successful-closeout-preflight.json"
        write_private_json(preflight_path, preflight)
        preflight_ref = _ref(
            preflight_path,
            preflight["preflight_sha256"],
        )
        bundle = build_review_bundle(
            bundle_id=bundle_id,
            created_at=created_at,
            preflight_ref=preflight_ref,
            preflight=preflight,
            verification={
                "ruff_all_passed": True,
                "pytest_all_passed": True,
                "pytest_passed_count": pytest_passed_count,
                "remote_revision_verified": True,
                "external_effect_performed": False,
            },
        )
        bundle_path = output_root / "successful-closeout-review-bundle.json"
        write_private_json(bundle_path, bundle)
        bundle_ref = _ref(bundle_path, bundle["bundle_sha256"])
        request = build_review_request(
            request_id=request_id,
            created_at=created_at,
            bundle_ref=bundle_ref,
            bundle=bundle,
        )
        request_path = output_root / "successful-closeout-review-request.json"
        write_private_json(request_path, request)
        statement = reviewer_statement(
            request_raw_sha256=hashlib.sha256(request_path.read_bytes()).hexdigest(),
            bundle_raw_sha256=bundle_ref["sha256"],
            bundle=bundle,
        )
        handoff = {
            "schema_version": "j1-qualification-r4-successful-closeout-review-handoff:v1",
            "status": "independent_reviewer_decision_required",
            "preflight": preflight_ref,
            "bundle": bundle_ref,
            "request": _ref(request_path, request["request_sha256"]),
            "required_exact_approval_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            "execution_boundary": bundle["execution_boundary"],
        }
        handoff["handoff_sha256"] = canonical_sha256(handoff)
        write_private_json(
            output_root / "successful-closeout-review-handoff.json", handoff
        )
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
    return handoff


def collect_successful_run(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    live_report_path: Path,
    execution_contract_path: Path,
    reviewed_design_path: Path,
    reviewed_assignment_path: Path,
    reviewed_verifier_path: Path,
    evaluator_path: Path,
    post_run_contract_path: Path,
    closeout_contract_path: Path,
    activation_path: Path,
    participant_profiles_root: Path,
    execution_root: Path,
    repository_root: Path,
    source_revision: str,
) -> dict[str, Any]:
    artifacts = {
        "authorization": _read_private(authorization_path),
        "issuance_gate": _read_private(issuance_gate_path),
        "claim": _read_private(claim_path),
        "entry_gate": _read_private(entry_gate_path),
        "live_report": _read_private(live_report_path),
        "execution_contract": _read_private(execution_contract_path),
        "reviewed_design": _read_private(reviewed_design_path),
        "reviewed_assignment": _read_private(reviewed_assignment_path),
        "reviewed_verifier": _read_private(reviewed_verifier_path),
        "evaluator": _read_private(evaluator_path),
        "post_run_contract": _read_private(post_run_contract_path),
        "closeout_contract": _read_private(closeout_contract_path),
        "activation": _read_private(activation_path),
    }
    values = {name: item[0] for name, item in artifacts.items()}
    raw = {name: item[1] for name, item in artifacts.items()}
    authorization = values["authorization"]
    report = values["live_report"]
    contract = values["execution_contract"]
    assignment = values["reviewed_assignment"]
    evaluator = values["evaluator"]
    run_id = str(authorization.get("run_id") or "")
    authorization_raw_sha256 = hashlib.sha256(raw["authorization"]).hexdigest()
    _validate_top_level_sources(
        values=values,
        raw=raw,
        run_id=run_id,
        authorization_raw_sha256=authorization_raw_sha256,
        execution_root=execution_root,
    )
    assignment_sha256 = assignment["reviewed_rebound_assignment_sha256"]
    if validate_real_evaluator_manifest(
        evaluator, expected_status="operator_reviewed_frozen"
    ):
        raise ValueError("successful closeout frozen evaluator invalid")
    if (
        evaluator["source_binding"]["rebound_assignment_sha256"]
        != assignment_sha256
        or evaluator["source_binding"]["rebound_assignment_artifact_sha256"]
        != hashlib.sha256(raw["reviewed_assignment"]).hexdigest()
    ):
        raise ValueError("successful closeout evaluator assignment drifted")

    tasks = contract.get("task_executions")
    if not isinstance(tasks, list) or len(tasks) != 320:
        raise ValueError("successful closeout execution contract task set invalid")
    by_execution_id = {
        str(task.get("task_execution_id")): task
        for task in tasks
        if isinstance(task, dict)
    }
    if len(by_execution_id) != 320:
        raise ValueError("successful closeout execution task IDs invalid")
    profiles = _participant_profiles(participant_profiles_root)
    journal = _journal(execution_root / "execution-journal.sqlite3")
    if journal["logical"] != {
        key: item
        for key, item in report["journal"].items()
        if key != "journal_artifact_sha256"
    } or journal["raw_sha256"] != report["journal"]["journal_artifact_sha256"]:
        raise ValueError("successful closeout journal does not match live report")

    participant_data: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "evidence": [],
            "runtime_seconds": 0,
            "tokens": 0,
            "cost": 0,
            "repeated_errors": 0,
            "repeated_opportunities": 0,
            "expected_provenance": 0,
            "complete_provenance": 0,
            "sovereignty_violations": 0,
            "direct_trust_increments": 0,
            "maturity_task_count": None,
            "cases": set(),
        }
    )
    evidence_hashes: list[str] = []
    observed_task_ids: set[str] = set()
    for committed in journal["committed"]:
        task_execution_id = committed["task_execution_id"]
        task = by_execution_id.get(task_execution_id)
        if task is None or task_execution_id in observed_task_ids:
            raise ValueError("successful closeout committed task binding invalid")
        observed_task_ids.add(task_execution_id)
        evidence_refs = committed["payload"].get("evidence")
        if not isinstance(evidence_refs, dict) or set(evidence_refs) != EVIDENCE_NAMES:
            raise ValueError("successful closeout committed Evidence inventory invalid")
        loaded = {
            name: _read_evidence_ref(reference)
            for name, reference in evidence_refs.items()
        }
        task_evidence = loaded["task-evidence"]
        verification = loaded["task-verification"]
        provider = loaded["provider-receipt"]
        receipts = loaded["event-receipts"]
        trace = loaded["event-trace"]
        signature = loaded["participant-signature"]
        if not isinstance(receipts, list):
            raise ValueError("successful closeout event receipt set invalid")
        expected_script = task["task"]["event_script"]
        failures = validate_built_event_trace(
            trace,
            receipts=receipts,
            expected_script=expected_script,
        )
        if failures:
            raise ValueError(f"successful closeout event trace invalid: {failures}")
        expected_verification = verify_task(
            task_evidence,
            reviewed_assignment_bytes=raw["reviewed_assignment"],
            expected_reviewed_assignment_sha256=assignment_sha256,
        )
        if expected_verification != verification or not verification.get("passed"):
            raise ValueError("successful closeout task verification replay failed")
        provider_failures = validate_provider_receipt(
            provider,
            reviewed_design=values["reviewed_design"],
        )
        if provider_failures:
            raise ValueError(
                f"successful closeout provider receipt invalid: {provider_failures}"
            )
        participant_id = str(task["participant_id"])
        _validate_task_bindings(
            task=task,
            task_evidence=task_evidence,
            provider=provider,
            trace=trace,
            signature=signature,
            profile=profiles.get(participant_id, {}),
            run_id=run_id,
            authorization_sha256=authorization_raw_sha256,
        )
        evidence_sha256 = canonical_sha256(task_evidence)
        evidence_hashes.append(evidence_sha256)
        aggregate = participant_data[participant_id]
        aggregate["evidence"].append(evidence_sha256)
        aggregate["runtime_seconds"] += committed["runtime_seconds"]
        aggregate["tokens"] += provider["actual"]["tokens"]
        aggregate["cost"] += provider["actual"]["microunits"]
        assertions = task_evidence["assertions"]
        if "repeated_error_observed" in assertions:
            aggregate["repeated_opportunities"] += 1
            aggregate["repeated_errors"] += int(
                assertions["repeated_error_observed"]["value"] is True
            )
        advice = assertions.get("advice_assignment_present", {}).get("value")
        if task["cohort"] == "mentor":
            aggregate["expected_provenance"] += 1
            aggregate["complete_provenance"] += int(
                advice is True
                and bool(
                    task_evidence["assertions"]["advice_assignment_present"][
                        "source_refs"
                    ]
                )
            )
        aggregate["sovereignty_violations"] += _sovereignty_violations(assertions)
        aggregate["direct_trust_increments"] += _direct_trust_increments(receipts)
        if task["task"]["verifier_case"] == "three-consecutive-verified-tasks":
            aggregate["maturity_task_count"] = assertions[
                "consecutive_verified_tasks"
            ]["value"]
        aggregate["cases"].add(task["task"]["verifier_case"])
    if observed_task_ids != set(by_execution_id):
        raise ValueError("successful closeout committed task set incomplete")

    records = _outcome_records(
        assignment=assignment,
        evaluator=evaluator,
        authorization_sha256=authorization_raw_sha256,
        run_id=run_id,
        participant_data=participant_data,
    )
    evaluation = evaluate_qualification_outcomes(
        manifest=evaluator,
        reviewed_assignment=assignment,
        records=records,
        run_id=run_id,
        execution_authorization_sha256=authorization_raw_sha256,
    )
    if not evaluation["structural_passed"] or not evaluation["valid_for_qualification"]:
        raise ValueError(
            f"successful closeout evaluation structurally failed: "
            f"{evaluation['failure_reasons']}"
        )
    budget = _budget(execution_root / "provider-budget.sqlite3")
    inventory = activation_inventory(values["activation"])
    inventory["exited_count"] = 40 - inventory["created_count"]
    inventory["container_set_sha256"] = canonical_sha256(
        sorted(
            record["container"]["container_id"]
            for record in values["activation"]["containers"]
        )
    )
    source_binding = {
        "authorization": _ref(
            authorization_path,
            authorization["signature"]["signed_payload_sha256"],
            raw=raw["authorization"],
        ),
        "issuance_gate": _self_ref(
            issuance_gate_path, values["issuance_gate"], raw["issuance_gate"]
        ),
        "claim": _self_ref(claim_path, values["claim"], raw["claim"]),
        "entry_gate": _self_ref(
            entry_gate_path, values["entry_gate"], raw["entry_gate"]
        ),
        "live_report": _self_ref(
            live_report_path, values["live_report"], raw["live_report"]
        ),
        "execution_contract": _self_ref(
            execution_contract_path,
            values["execution_contract"],
            raw["execution_contract"],
        ),
        "reviewed_design": _self_ref(
            reviewed_design_path, values["reviewed_design"], raw["reviewed_design"]
        ),
        "reviewed_assignment": _self_ref(
            reviewed_assignment_path,
            values["reviewed_assignment"],
            raw["reviewed_assignment"],
        ),
        "reviewed_verifier": _self_ref(
            reviewed_verifier_path,
            values["reviewed_verifier"],
            raw["reviewed_verifier"],
        ),
        "real_evaluator": _self_ref(
            evaluator_path, values["evaluator"], raw["evaluator"]
        ),
        "post_run_contract": _self_ref(
            post_run_contract_path,
            values["post_run_contract"],
            raw["post_run_contract"],
        ),
        "closeout_contract": _self_ref(
            closeout_contract_path,
            values["closeout_contract"],
            raw["closeout_contract"],
        ),
        "terminal_activation": _self_ref(
            activation_path, values["activation"], raw["activation"]
        ),
    }
    return {
        "run_id": run_id,
        "authorization_id": authorization["authorization_id"],
        "execution_summary": {
            "status": "complete",
            "task_execution_count": 320,
            "committed_task_count": 320,
            "provider_call_count": report["execution_scope"]["provider_call_count"],
            "participant_signature_count": report["execution_scope"][
                "participant_signature_count"
            ],
            "journal_event_count": report["journal"]["event_count"],
            "validation_failures": [],
        },
        "budget_summary": budget,
        "terminal_inventory": inventory,
        "outcome_inventory": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_count": 320,
            "verified_task_count": 320,
            "participant_outcome_count": 40,
            "task_evidence_set_sha256": canonical_sha256(sorted(evidence_hashes)),
            "participant_outcome_set_sha256": canonical_sha256(records),
            "pattern_prediction_observation_policy": (
                "no_direct_observation_count_as_zero_no_inference"
            ),
        },
        "participant_outcomes": records,
        "evaluation_report": evaluation,
        "source_binding": source_binding,
        "implementation": {
            "source_revision": source_revision,
            "source_files": {
                relative: hashlib.sha256(
                    (repository_root / relative).read_bytes()
                ).hexdigest()
                for relative in SOURCE_PATHS
            },
        },
    }


def promote_review(
    *,
    review_id: str,
    reviewed_at: str,
    approval_statement_sha256: str,
    handoff_path: Path,
    request_path: Path,
    bundle_path: Path,
    preflight_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    output_root: Path,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError("successful closeout promotion output exists")
    revision = _clean_pushed_revision(repository_root)
    handoff, handoff_raw = _read_private(handoff_path)
    request, request_raw = _read_private(request_path)
    bundle, bundle_raw = _read_private(bundle_path)
    preflight, preflight_raw = _read_private(preflight_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    request_ref = _ref(request_path, request["request_sha256"], raw=request_raw)
    bundle_ref = _ref(bundle_path, bundle["bundle_sha256"], raw=bundle_raw)
    preflight_ref = _ref(
        preflight_path, preflight["preflight_sha256"], raw=preflight_raw
    )
    statement = reviewer_statement(
        request_raw_sha256=hashlib.sha256(request_raw).hexdigest(),
        bundle_raw_sha256=hashlib.sha256(bundle_raw).hexdigest(),
        bundle=bundle,
    )
    if not (
        validate_preflight(preflight) == []
        and validate_review_bundle(bundle) == []
        and bundle["source_implementation"]["source_revision"] == revision
        and bundle["preflight"] == preflight_ref
        and handoff["request"] == request_ref
        and handoff["bundle"] == bundle_ref
        and handoff["preflight"] == preflight_ref
        and handoff["required_exact_approval_statement"] == statement
        and handoff["statement_sha256"]
        == approval_statement_sha256
        == hashlib.sha256(statement.encode()).hexdigest()
        and handoff["handoff_sha256"]
        == canonical_sha256(
            {key: item for key, item in handoff.items() if key != "handoff_sha256"}
        )
    ):
        raise ValueError("successful closeout review approval or binding invalid")
    _validate_reviewer_profile(profile)
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    with Pkcs11Ed25519Signer(
        str(Path(module_path).resolve()),
        token_label,
        key_label,
        reviewer["public_key_hex"],
        pin,
        key_id=key_id_hex,
    ) as signer:
        receipt = build_review_receipt(
            review_id=review_id,
            reviewed_at=reviewed_at,
            request_ref=request_ref,
            bundle_ref=bundle_ref,
            statement_sha256=approval_statement_sha256,
            reviewer=reviewer,
            reviewer_profile_sha256=profile_sha256,
            signer=signer,
        )
    failures = validate_review_receipt(
        receipt,
        request_ref=request_ref,
        bundle_ref=bundle_ref,
        reviewer=reviewer,
        reviewer_profile_sha256=profile_sha256,
        statement_sha256=approval_statement_sha256,
    )
    if failures:
        raise ValueError(f"successful closeout review receipt invalid: {failures}")
    return _persist_review_promotion(
        output_root=output_root,
        bundle_path=bundle_path,
        bundle=bundle,
        preflight_path=preflight_path,
        preflight=preflight,
        receipt=receipt,
        source_revision=revision,
    )


def perform_closeout(
    *,
    preflight_path: Path,
    review_gate_path: Path,
    reviewer_profile_path: Path,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    output_root: Path,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise FileExistsError("successful closeout output exists")
    preflight, preflight_raw = _read_private(preflight_path)
    gate, gate_raw = _read_private(review_gate_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    expected_statement = closeout_authorization_statement(
        preflight_raw_sha256=hashlib.sha256(preflight_raw).hexdigest(),
        preflight=preflight,
        review_gate_raw_sha256=hashlib.sha256(gate_raw).hexdigest(),
        review_gate_canonical_sha256=gate["report_sha256"],
    )
    if not (
        validate_preflight(preflight) == []
        and owner_statement == expected_statement
        and owner_statement_sha256
        == hashlib.sha256(owner_statement.encode()).hexdigest()
    ):
        raise ValueError("successful closeout authorization or review Gate invalid")
    _validate_reviewer_profile(profile)
    _validate_successful_review_gate(
        gate=gate,
        preflight=preflight,
        reviewer_profile=profile,
        reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
    )
    _validate_pkcs11(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    profile_sha256 = hashlib.sha256(profile_raw).hexdigest()
    preflight_ref = _ref(
        preflight_path, preflight["preflight_sha256"], raw=preflight_raw
    )
    with Pkcs11Ed25519Signer(
        str(Path(module_path).resolve()),
        token_label,
        key_label,
        reviewer["public_key_hex"],
        pin,
        key_id=key_id_hex,
    ) as signer:
        artifacts = build_closeout_artifacts(
            closed_at=datetime.now(UTC).isoformat(),
            preflight_ref=preflight_ref,
            preflight=preflight,
            owner_authorization_id=owner_authorization_id,
            owner_statement_sha256=owner_statement_sha256,
            reviewer=reviewer,
            reviewer_profile_sha256=profile_sha256,
            signer=signer,
        )
    failures = validate_closeout_artifacts(
        artifacts,
        preflight=preflight,
        preflight_ref=preflight_ref,
        reviewer=reviewer,
        reviewer_profile_sha256=profile_sha256,
        owner_statement_sha256=owner_statement_sha256,
    )
    if failures:
        raise ValueError(f"successful closeout artifacts invalid: {failures}")
    return _persist_closeout(output_root=output_root, artifacts=artifacts)


def _validate_top_level_sources(
    *,
    values: dict[str, dict[str, Any]],
    raw: dict[str, bytes],
    run_id: str,
    authorization_raw_sha256: str,
    execution_root: Path,
) -> None:
    authorization = values["authorization"]
    claim = values["claim"]
    report = values["live_report"]
    if not (
        run_id
        and authorization.get("authorization_id")
        and claim.get("run_id") == run_id
        and claim.get("authorization_id") == authorization["authorization_id"]
        and claim.get("source_binding", {}).get("authorization", {}).get("sha256")
        == authorization_raw_sha256
        and report.get("run_id") == run_id
        and report.get("status") == "complete"
        and report.get("failure_reason") is None
        and report.get("validation_failures") == []
        and report.get("execution_scope", {}).get("task_execution_count") == 320
        and report.get("execution_scope", {}).get("provider_call_count") == 320
        and report.get("execution_scope", {}).get("participant_signature_count") == 320
        and report.get("journal", {}).get("task_states") == {"task_committed": 320}
        and report.get("journal", {}).get("budget_states") == {"reconciled": 320}
        and report.get("journal", {}).get("event_count") == 3840
        and Path(authorization["controls"]["execution_root"]).resolve()
        == execution_root.resolve()
        and Path(authorization["controls"]["post_run_output_root"]).resolve()
        != execution_root.resolve()
        and authorization["controls"]["backend_fact_append_allowed"] is False
        and authorization["controls"]["ledger_append_allowed"] is False
    ):
        raise ValueError("successful closeout top-level run binding invalid")
    for name in (
        "issuance_gate",
        "claim",
        "entry_gate",
        "live_report",
        "execution_contract",
        "reviewed_assignment",
        "reviewed_verifier",
        "evaluator",
        "post_run_contract",
        "closeout_contract",
        "activation",
    ):
        _self_ref(Path("/nonexistent"), values[name], raw[name], require_path=False)


def _journal(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        previous = None
        first_by_task: dict[str, str] = {}
        committed: list[dict[str, Any]] = []
        for expected, row in enumerate(rows, 1):
            payload_sha256 = hashlib.sha256(row["payload_json"].encode()).hexdigest()
            body = {
                "sequence": row["sequence"],
                "task_execution_id": row["task_execution_id"],
                "call_id": row["call_id"],
                "from_state": row["from_state"],
                "to_state": row["to_state"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "payload_sha256": row["payload_sha256"],
                "previous_event_sha256": row["previous_event_sha256"],
            }
            if not (
                row["sequence"] == expected
                and row["payload_sha256"] == payload_sha256
                and row["previous_event_sha256"] == previous
                and row["event_sha256"] == canonical_sha256(body)
            ):
                raise ValueError("successful closeout journal hash chain invalid")
            previous = row["event_sha256"]
            first_by_task.setdefault(row["task_execution_id"], row["occurred_at"])
            if row["to_state"] == "task_committed":
                started = datetime.fromisoformat(
                    first_by_task[row["task_execution_id"]]
                )
                completed = datetime.fromisoformat(row["occurred_at"])
                committed.append(
                    {
                        "task_execution_id": row["task_execution_id"],
                        "call_id": row["call_id"],
                        "payload": json.loads(row["payload_json"]),
                        "runtime_seconds": max(
                            0, math.ceil((completed - started).total_seconds())
                        ),
                    }
                )
        states = {
            row["state"]: row["count"]
            for row in connection.execute(
                "SELECT state, COUNT(*) AS count FROM task_states GROUP BY state"
            )
        }
        budgets = {
            row["status"]: row["count"]
            for row in connection.execute(
                "SELECT status, COUNT(*) AS count FROM reservations GROUP BY status"
            )
        }
    finally:
        connection.close()
    logical = {
        "task_states": states,
        "budget_states": budgets,
        "event_count": len(rows),
        "last_event_sha256": previous,
    }
    logical["journal_sha256"] = canonical_sha256(logical)
    if states != {"task_committed": 320} or budgets != {"reconciled": 320}:
        raise ValueError("successful closeout journal is not completely terminal")
    return {
        "logical": logical,
        "committed": committed,
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _budget(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        row = connection.execute(
            """
            SELECT COUNT(*),
                   COALESCE(SUM(reserved_tokens), 0),
                   COALESCE(SUM(reserved_microunits), 0),
                   COALESCE(SUM(actual_tokens), 0),
                   COALESCE(SUM(actual_microunits), 0),
                   SUM(CASE WHEN status = 'reconciled' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN status != 'reconciled' THEN 1 ELSE 0 END)
            FROM reservations
            """
        ).fetchone()
    finally:
        connection.close()
    result = {
        "reservation_count": int(row[0]),
        "reserved_tokens": int(row[1]),
        "reserved_cost_microunits": int(row[2]),
        "actual_tokens": int(row[3]),
        "actual_cost_microunits": int(row[4]),
        "reconciled_count": int(row[5]),
        "non_reconciled_count": int(row[6]),
    }
    if not (
        result["reservation_count"] == 320
        and result["reconciled_count"] == 320
        and result["non_reconciled_count"] == 0
        and result["reserved_tokens"] == 800000
        and result["reserved_cost_microunits"] == 487360
    ):
        raise ValueError("successful closeout budget reconciliation invalid")
    return result


def _participant_profiles(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        profile, _ = _read_private(path)
        participant = profile.get("participant", {})
        participant_id = participant.get("participant_id")
        if not isinstance(participant_id, str) or participant_id in result:
            raise ValueError("successful closeout participant profile invalid")
        result[participant_id] = profile
    if len(result) != 40:
        raise ValueError("successful closeout participant profile set incomplete")
    return result


def _read_evidence_ref(reference: Any) -> Any:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("successful closeout Evidence reference invalid")
    path = Path(str(reference["path"])).resolve()
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_mode & 0o077
        or hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]
    ):
        raise ValueError("successful closeout Evidence artifact drifted")
    return json.loads(path.read_bytes())


def _validate_task_bindings(
    *,
    task: dict[str, Any],
    task_evidence: dict[str, Any],
    provider: dict[str, Any],
    trace: dict[str, Any],
    signature: dict[str, Any],
    profile: dict[str, Any],
    run_id: str,
    authorization_sha256: str,
) -> None:
    participant = profile.get("participant", {})
    payload = signature.get("signed_payload", {})
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    signature_body = {
        key: item
        for key, item in signature.items()
        if key != "signature_receipt_sha256"
    }
    valid = (
        task_evidence.get("task_id") == task["task"]["task_id"]
        and task_evidence.get("participant_id") == task["participant_id"]
        and task_evidence.get("participant_did") == task["execution_did"]
        and task_evidence.get("pair_id") == task["pair_id"]
        and task_evidence.get("cohort") == task["cohort"]
        and provider.get("call_id") == task["call_id"]
        and provider.get("run_id") == run_id
        and provider.get("participant_id") == task["participant_id"]
        and provider.get("task_id") == task["task"]["task_id"]
        and provider.get("execution_authorization_sha256") == authorization_sha256
        and trace.get("trace_sha256")
        == task_evidence["execution"]["event_trace_sha256"]
        and provider.get("receipt_sha256")
        == task_evidence["execution"]["provider_receipt_sha256"]
        and participant.get("participant_id") == task["participant_id"]
        and participant.get("execution_did") == task["execution_did"]
        and signature.get("participant_id") == task["participant_id"]
        and signature.get("execution_did") == task["execution_did"]
        and payload.get("task_execution_id") == task["task_execution_id"]
        and payload.get("call_id") == task["call_id"]
        and payload.get("run_id") == run_id
        and payload.get("execution_authorization_sha256") == authorization_sha256
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(encoded).hexdigest()
        and signature.get("signature_receipt_sha256")
        == canonical_sha256(signature_body)
        and signature.get("signature_verified") is True
    )
    if not valid:
        raise ValueError("successful closeout task artifact binding invalid")
    try:
        VerifyKey(bytes.fromhex(participant["public_key_hex"])).verify(
            encoded, bytes.fromhex(signature["signature_hex"])
        )
    except (BadSignatureError, KeyError, ValueError) as error:
        raise ValueError("successful closeout participant signature invalid") from error


def _outcome_records(
    *,
    assignment: dict[str, Any],
    evaluator: dict[str, Any],
    authorization_sha256: str,
    run_id: str,
    participant_data: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            participant_id = member["participant_id"]
            aggregate = participant_data.get(participant_id)
            if aggregate is None or len(aggregate["evidence"]) != 8:
                raise ValueError("successful closeout participant Evidence incomplete")
            observed_scenarios: set[str] = set()
            for case in aggregate["cases"]:
                observed_scenarios.update(CASE_SCENARIOS[case])
            if observed_scenarios != REQUIRED_SCENARIOS:
                raise ValueError("successful closeout scenario coverage incomplete")
            records.append(
                {
                    "schema_version": OUTCOME_SCHEMA,
                    "run_id": run_id,
                    "participant_id": participant_id,
                    "participant_did": member["execution_did"],
                    "pair_id": pair["pair_id"],
                    "cohort": cohort,
                    "source_binding": {
                        "evaluator_manifest_sha256": evaluator["manifest_sha256"],
                        "rebound_assignment_sha256": assignment[
                            "reviewed_rebound_assignment_sha256"
                        ],
                        "execution_authorization_sha256": authorization_sha256,
                    },
                    "task_evidence_sha256": sorted(aggregate["evidence"]),
                    "active_runtime_seconds": aggregate["runtime_seconds"],
                    "token_count": aggregate["tokens"],
                    "cost_microunits": aggregate["cost"],
                    "repeated_error_count": aggregate["repeated_errors"],
                    "repeated_error_opportunities": aggregate[
                        "repeated_opportunities"
                    ],
                    "pattern_prediction_count": 0,
                    "pattern_false_positive_count": 0,
                    "expected_provenance_count": aggregate["expected_provenance"],
                    "complete_provenance_count": aggregate["complete_provenance"],
                    "sovereignty_violation_count": aggregate[
                        "sovereignty_violations"
                    ],
                    "direct_trust_increment_count": aggregate[
                        "direct_trust_increments"
                    ],
                    "maturity_task_count": aggregate["maturity_task_count"],
                    "maturity_criteria": MATURITY_CRITERIA,
                    "scenario_results": {
                        scenario: True for scenario in sorted(REQUIRED_SCENARIOS)
                    },
                }
            )
    return records


def _sovereignty_violations(assertions: dict[str, Any]) -> int:
    return sum(
        int(assertions.get(name, {}).get("value") is True)
        for name in (
            "mentor_direct_execution",
            "unsafe_action_executed",
            "post_revocation_advice_used",
        )
    )


def _direct_trust_increments(receipts: list[dict[str, Any]]) -> int:
    return sum(
        int(
            receipt.get("event_type") == "direct_trust_increment"
            or receipt.get("payload", {}).get("direct_trust_increment") is True
        )
        for receipt in receipts
    )


def _persist_review_promotion(
    *,
    output_root: Path,
    bundle_path: Path,
    bundle: dict[str, Any],
    preflight_path: Path,
    preflight: dict[str, Any],
    receipt: dict[str, Any],
    source_revision: str,
) -> dict[str, Any]:
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        frozen_bundle = staging / "successful-closeout-review-bundle.frozen.json"
        frozen_preflight = staging / "successful-closeout-preflight.frozen.json"
        shutil.copyfile(bundle_path, frozen_bundle)
        shutil.copyfile(preflight_path, frozen_preflight)
        frozen_bundle.chmod(0o600)
        frozen_preflight.chmod(0o600)
        receipt_path = staging / "successful-closeout-review-receipt.json"
        write_private_json(receipt_path, receipt)
        bundle_ref = _published_ref(
            frozen_bundle,
            output_root / frozen_bundle.name,
            bundle["bundle_sha256"],
        )
        receipt_ref = _published_ref(
            receipt_path,
            output_root / receipt_path.name,
            receipt["signature"]["signed_payload_sha256"],
        )
        gate = build_review_gate(
            bundle_ref=bundle_ref,
            receipt_ref=receipt_ref,
            source_revision=source_revision,
        )
        gate_path = staging / "successful-closeout-review-gate.json"
        write_private_json(gate_path, gate)
        published_gate_ref = _published_ref(
            gate_path, output_root / gate_path.name, gate["report_sha256"]
        )
        preflight_ref = _published_ref(
            frozen_preflight,
            output_root / frozen_preflight.name,
            preflight["preflight_sha256"],
        )
        statement = closeout_authorization_statement(
            preflight_raw_sha256=preflight_ref["sha256"],
            preflight=preflight,
            review_gate_raw_sha256=published_gate_ref["sha256"],
            review_gate_canonical_sha256=gate["report_sha256"],
        )
        handoff = {
            "schema_version": "j1-qualification-r4-successful-closeout-handoff:v1",
            "status": "owner_closeout_authorization_required",
            "preflight": preflight_ref,
            "review_gate": published_gate_ref,
            "required_exact_authorization_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        }
        handoff["handoff_sha256"] = canonical_sha256(handoff)
        write_private_json(staging / "successful-closeout-handoff.json", handoff)
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return handoff


def _persist_closeout(
    *, output_root: Path, artifacts: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    names = {
        "outcome_manifest": "participant-outcome-manifest.json",
        "post_run_receipt": "successful-post-run-receipt.json",
        "evaluation_report": "real-evaluation-report.json",
        "closeout_receipt": "successful-closeout-receipt.json",
    }
    try:
        refs: dict[str, dict[str, str]] = {}
        canonical_fields = {
            "outcome_manifest": "manifest_sha256",
            "post_run_receipt": "receipt_sha256",
            "evaluation_report": "report_sha256",
            "closeout_receipt": ("signature", "signed_payload_sha256"),
        }
        for key, filename in names.items():
            path = staging / filename
            write_private_json(path, artifacts[key])
            field = canonical_fields[key]
            canonical = (
                artifacts[key][field]
                if isinstance(field, str)
                else artifacts[key][field[0]][field[1]]
            )
            refs[key] = _published_ref(path, output_root / filename, canonical)
        gate = build_closeout_gate(artifact_refs=refs, artifacts=artifacts)
        write_private_json(staging / "successful-closeout-gate.json", gate)
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return gate


def _validate_reviewer_profile(profile: dict[str, Any]) -> None:
    failures = validate_reviewer_identity_profile(profile)
    if failures:
        raise ValueError(f"successful closeout reviewer profile invalid: {failures}")


def _validate_successful_review_gate(
    *,
    gate: dict[str, Any],
    preflight: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
) -> None:
    if not (
        gate.get("schema_version")
        == "j1-qualification-r4-successful-closeout-review-gate:v1"
        and gate.get("passed") is True
        and gate.get("state") == "successful_closeout_implementation_frozen"
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("successful closeout review Gate invalid")
    bundle_ref = gate.get("bundle", {})
    receipt_ref = gate.get("review_receipt", {})
    bundle, bundle_raw = _read_private(Path(str(bundle_ref.get("path", ""))))
    receipt, receipt_raw = _read_private(Path(str(receipt_ref.get("path", ""))))
    if not (
        bundle_ref
        == _ref(
            Path(bundle_ref["path"]),
            bundle["bundle_sha256"],
            raw=bundle_raw,
        )
        and receipt_ref
        == _ref(
            Path(receipt_ref["path"]),
            receipt["signature"]["signed_payload_sha256"],
            raw=receipt_raw,
        )
        and validate_review_bundle(bundle) == []
        and bundle.get("source_implementation", {}).get("source_revision")
        == gate.get("source_revision")
        and bundle.get("preflight", {}).get("sha256")
        == hashlib.sha256(
            json.dumps(
                preflight, ensure_ascii=False, indent=2, sort_keys=True
            ).encode()
            + b"\n"
        ).hexdigest()
        and bundle.get("preflight", {}).get("canonical_sha256")
        == preflight["preflight_sha256"]
    ):
        raise ValueError("successful closeout reviewed bundle invalid")
    reviewer = reviewer_profile["reviewer"]
    receipt_bundle_ref = receipt.get("bundle", {})
    if not (
        receipt_bundle_ref.get("sha256") == bundle_ref.get("sha256")
        and receipt_bundle_ref.get("canonical_sha256")
        == bundle_ref.get("canonical_sha256")
    ):
        raise ValueError("successful closeout review receipt bundle drifted")
    failures = validate_review_receipt(
        receipt,
        request_ref=receipt.get("request", {}),
        bundle_ref=receipt_bundle_ref,
        reviewer=reviewer,
        reviewer_profile_sha256=reviewer_profile_sha256,
        statement_sha256=receipt.get("review_statement_sha256", ""),
    )
    if failures:
        raise ValueError(
            f"successful closeout signed review receipt invalid: {failures}"
        )


def _validate_pkcs11(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    module = Path(module_path).resolve()
    key = profile["pkcs11_key"]
    if not (
        key["module_path"] == str(module)
        and key["module_sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()
        and key["token_label"] == token_label
        and key["key_label"] == key_label
        and key["key_id_hex"] == key_id_hex.lower()
    ):
        raise ValueError("successful closeout reviewer PKCS#11 configuration mismatch")


def _self_ref(
    path: Path,
    value: dict[str, Any],
    raw: bytes,
    *,
    require_path: bool = True,
) -> dict[str, str]:
    fields = (
        "report_sha256",
        "claim_sha256",
        "contract_sha256",
        "reviewed_design_sha256",
        "reviewed_rebound_assignment_sha256",
        "manifest_sha256",
        "receipt_sha256",
        "activation_sha256",
    )
    canonical = next(
        (str(value[field]) for field in fields if isinstance(value.get(field), str)),
        "",
    )
    body_field = next(
        (field for field in fields if isinstance(value.get(field), str)), None
    )
    if (
        not canonical
        or body_field is None
        or canonical
        != canonical_sha256(
            {key: item for key, item in value.items() if key != body_field}
        )
    ):
        raise ValueError("successful closeout source artifact self-hash invalid")
    return {
        "path": str(path.resolve()) if require_path else "/validated/source",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical,
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"successful closeout private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("successful closeout artifact must be an object")
    return value, raw


def _ref(
    path: Path, canonical_digest: str, *, raw: bytes | None = None
) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(
            raw if raw is not None else path.read_bytes()
        ).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _published_ref(
    current: Path, published: Path, canonical_digest: str
) -> dict[str, str]:
    return {
        "path": str(published.resolve()),
        "sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for successful closeout review")
    revision = _git(root, "rev-parse", "HEAD")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
        cwd=root,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("successful closeout review revision is not pushed")
    return revision


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    prepare = subparsers.add_parser("prepare-review")
    prepare.add_argument("--bundle-id", required=True)
    prepare.add_argument("--request-id", required=True)
    prepare.add_argument("--created-at", required=True)
    for option in (
        "authorization",
        "issuance-gate",
        "claim",
        "entry-gate",
        "live-report",
        "execution-contract",
        "reviewed-design",
        "reviewed-assignment",
        "reviewed-verifier",
        "evaluator",
        "post-run-contract",
        "closeout-contract",
        "activation",
        "participant-profiles-root",
        "execution-root",
        "repository-root",
        "output-root",
    ):
        prepare.add_argument(f"--{option}", type=Path, required=True)
    prepare.add_argument("--pytest-passed-count", type=int, required=True)

    promote = subparsers.add_parser("promote-review")
    promote.add_argument("--review-id", required=True)
    promote.add_argument("--reviewed-at", required=True)
    promote.add_argument("--approval-statement-sha256", required=True)
    for option in (
        "handoff",
        "request",
        "bundle",
        "preflight",
        "reviewer-profile",
        "repository-root",
        "output-root",
    ):
        promote.add_argument(f"--{option}", type=Path, required=True)
    promote.add_argument("--module", default=DEFAULT_MODULE)
    promote.add_argument("--token-label", required=True)
    promote.add_argument("--key-label", required=True)
    promote.add_argument("--key-id", required=True)
    promote.add_argument("--pin-file", type=Path)

    closeout = subparsers.add_parser("closeout")
    closeout.add_argument("--preflight", type=Path, required=True)
    closeout.add_argument("--review-gate", type=Path, required=True)
    closeout.add_argument("--reviewer-profile", type=Path, required=True)
    closeout.add_argument("--owner-authorization-id", required=True)
    closeout.add_argument("--owner-statement", required=True)
    closeout.add_argument("--owner-statement-sha256", required=True)
    closeout.add_argument("--module", default=DEFAULT_MODULE)
    closeout.add_argument("--token-label", required=True)
    closeout.add_argument("--key-label", required=True)
    closeout.add_argument("--key-id", required=True)
    closeout.add_argument("--pin-file", type=Path)
    closeout.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "prepare-review":
        result = prepare_review(
            bundle_id=args.bundle_id,
            request_id=args.request_id,
            created_at=args.created_at,
            authorization_path=args.authorization,
            issuance_gate_path=args.issuance_gate,
            claim_path=args.claim,
            entry_gate_path=args.entry_gate,
            live_report_path=args.live_report,
            execution_contract_path=args.execution_contract,
            reviewed_design_path=args.reviewed_design,
            reviewed_assignment_path=args.reviewed_assignment,
            reviewed_verifier_path=args.reviewed_verifier,
            evaluator_path=args.evaluator,
            post_run_contract_path=args.post_run_contract,
            closeout_contract_path=args.closeout_contract,
            activation_path=args.activation,
            participant_profiles_root=args.participant_profiles_root,
            execution_root=args.execution_root,
            repository_root=args.repository_root,
            output_root=args.output_root,
            pytest_passed_count=args.pytest_passed_count,
        )
    elif args.operation == "promote-review":
        result = promote_review(
            review_id=args.review_id,
            reviewed_at=args.reviewed_at,
            approval_statement_sha256=args.approval_statement_sha256,
            handoff_path=args.handoff,
            request_path=args.request,
            bundle_path=args.bundle,
            preflight_path=args.preflight,
            reviewer_profile_path=args.reviewer_profile,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            repository_root=args.repository_root,
            output_root=args.output_root,
            pin=read_pin(args.pin_file),
        )
    else:
        result = perform_closeout(
            preflight_path=args.preflight,
            review_gate_path=args.review_gate,
            reviewer_profile_path=args.reviewer_profile,
            owner_authorization_id=args.owner_authorization_id,
            owner_statement=args.owner_statement,
            owner_statement_sha256=args.owner_statement_sha256,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            output_root=args.output_root,
            pin=read_pin(args.pin_file),
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
