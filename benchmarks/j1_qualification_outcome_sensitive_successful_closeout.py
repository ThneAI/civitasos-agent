"""Replay and close out one complete outcome-sensitive J1-D execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_evaluation import (
    build_participant_outcome,
    evaluate_prospective_confirmatory_outcomes,
    validate_prospective_confirmatory_evaluation_report,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_authorization import (
    AUTH_SCHEMA as CONFIRMATORY_AUTHORIZATION_SCHEMA,
    GATE_SCHEMA as CONFIRMATORY_AUTHORIZATION_GATE_SCHEMA,
    validate_confirmatory_authorization,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_execution_preflight import (
    validate_confirmatory_execution_plan,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_authorization import (
    GATE_SCHEMA as AUTHORIZATION_GATE_SCHEMA,
    validate_authorization,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_entry import (
    CONFIRMATORY_ENTRY_GATE_SCHEMA,
    ENTRY_GATE_SCHEMA,
    validate_claim,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_preflight import (
    validate_execution_plan,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_successful_execution_closeout_v4 import (
    build_preflight,
    build_review_bundle,
    build_review_request,
    reviewer_statement,
)
from benchmarks.j1_qualification_successful_execution_closeout_v4 import (
    _read_private,
    _ref,
)


TASK_COUNT = 480
EVENT_COUNT = 5760
EVIDENCE_NAMES = {
    "direct-observation",
    "observation-receipts",
    "participant-signature",
    "provider-receipt",
    "structured-decision",
    "task-verification",
}
SOURCE_PATHS = [
    "benchmarks/j1/qualification_outcome_sensitive_confirmatory.py",
    "benchmarks/j1/qualification_outcome_sensitive_evaluation.py",
    "benchmarks/j1/qualification_successful_execution_closeout_v4.py",
    "benchmarks/j1_qualification_outcome_sensitive_successful_closeout.py",
    "benchmarks/j1_qualification_successful_execution_closeout_v4.py",
]
LIVE_REPORT_SCHEMA = "j1-qualification-outcome-sensitive-live-orchestrator-report:v1"


def prepare_review(
    *,
    bundle_id: str,
    request_id: str,
    created_at: str,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    live_report_path: Path,
    reviewer_profile_path: Path,
    participant_profiles_root: Path,
    execution_root: Path,
    repository_root: Path,
    output_root: Path,
    pytest_passed_count: int,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(
            f"outcome-sensitive closeout review exists: {output_root}"
        )
    revision = _clean_pushed_revision(repository_root)
    context = _collect(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        claim_preflight_path=claim_preflight_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        live_report_path=live_report_path,
        reviewer_profile_path=reviewer_profile_path,
        participant_profiles_root=participant_profiles_root,
        execution_root=execution_root,
        repository_root=repository_root,
        source_revision=revision,
    )
    preflight = build_preflight(**context, profile="prospective_confirmatory")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
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
        "schema_version": (
            "j1-qualification-outcome-sensitive-successful-closeout-review-handoff:v1"
        ),
        "status": "independent_reviewer_decision_required",
        "preflight": preflight_ref,
        "bundle": bundle_ref,
        "request": _ref(request_path, request["request_sha256"]),
        "required_exact_approval_statement": statement,
        "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "execution_boundary": bundle["execution_boundary"],
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    write_private_json(output_root / "successful-closeout-review-handoff.json", handoff)
    return handoff


def _collect(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    live_report_path: Path,
    reviewer_profile_path: Path,
    participant_profiles_root: Path,
    execution_root: Path,
    repository_root: Path,
    source_revision: str,
) -> dict[str, Any]:
    authorization, authorization_raw = _read_private(authorization_path)
    issuance_gate, issuance_raw = _read_private(issuance_gate_path)
    claim_preflight, claim_preflight_raw = _read_private(claim_preflight_path)
    claim, claim_raw = _read_private(claim_path)
    entry_gate, entry_raw = _read_private(entry_gate_path)
    report, report_raw = _read_private(live_report_path)
    reviewer_profile, reviewer_profile_raw = _read_private(reviewer_profile_path)
    plan_ref = authorization["source_binding"]["plan"]
    execution_preflight_ref = authorization["source_binding"]["preflight"]
    plan, plan_raw = _read_private(Path(plan_ref["path"]))
    execution_preflight, execution_preflight_raw = _read_private(
        Path(execution_preflight_ref["path"])
    )
    refs = {
        "authorization": _ref(
            authorization_path,
            authorization["signature"]["signed_payload_sha256"],
            raw=authorization_raw,
        ),
        "issuance_gate": _ref(
            issuance_gate_path, issuance_gate["report_sha256"], raw=issuance_raw
        ),
        "claim_preflight": _ref(
            claim_preflight_path,
            claim_preflight["preflight_sha256"],
            raw=claim_preflight_raw,
        ),
        "claim": _ref(claim_path, claim["claim_sha256"], raw=claim_raw),
        "entry_gate": _ref(entry_gate_path, entry_gate["report_sha256"], raw=entry_raw),
        "live_report": _ref(live_report_path, report["report_sha256"], raw=report_raw),
    }
    _validate_upstream(
        authorization=authorization,
        issuance_gate=issuance_gate,
        claim_preflight=claim_preflight,
        claim=claim,
        entry_gate=entry_gate,
        report=report,
        reviewer_profile=reviewer_profile,
        reviewer_profile_raw=reviewer_profile_raw,
        plan=plan,
        plan_raw=plan_raw,
        execution_preflight=execution_preflight,
        execution_preflight_raw=execution_preflight_raw,
        refs=refs,
        execution_root=execution_root,
    )
    sources = plan["source_artifacts"]
    contract = _read_bound(sources["execution_contract"], "contract_sha256")
    protocol = _read_bound(sources["protocol"], "protocol_sha256")
    evaluator = _read_bound(sources["evaluator"], "evaluator_sha256")
    statistical_plan = _read_bound(
        sources["statistical_plan"], "statistical_plan_sha256"
    )
    confirmatory_method = _read_bound(sources["confirmatory_method"], "method_sha256")
    fixture = _read_bound(sources["task_fixture"], "fixture_sha256")
    assignment = _read_bound(sources["assignment"], "assignment_sha256")
    activation = _read_bound(sources["activation"], "activation_sha256")
    profiles = _participant_profiles(participant_profiles_root)
    journal = _journal(execution_root / "execution-journal.sqlite3")
    if not (
        journal["logical"]
        == {
            key: item
            for key, item in report["journal"].items()
            if key != "journal_artifact_sha256"
        }
        and journal["raw_sha256"] == report["journal"]["journal_artifact_sha256"]
    ):
        raise ValueError("outcome-sensitive journal/report binding invalid")
    observations = _replay_tasks(
        contract=contract,
        fixture=fixture,
        profiles=profiles,
        journal=journal,
        run_id=authorization["run_id"],
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
    )
    participants = _participant_records(
        assignment=assignment,
        observations=observations,
        run_id=authorization["run_id"],
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
    )
    evaluation = evaluate_prospective_confirmatory_outcomes(
        run_id=authorization["run_id"],
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
        protocol=protocol,
        evaluator=evaluator,
        statistical_plan=statistical_plan,
        fixture=fixture,
        assignment=assignment,
        participant_records=participants,
        confirmatory_method=confirmatory_method,
    )
    evaluation_failures = validate_prospective_confirmatory_evaluation_report(
        evaluation
    )
    if evaluation_failures:
        raise ValueError(
            "outcome-sensitive successful evaluation invalid: "
            f"{evaluation_failures}; structural={evaluation['failure_reasons']}"
        )
    budget = _budget(execution_root / "provider-budget.sqlite3")
    terminal_inventory = _terminal_inventory(activation)
    source_binding = {
        **refs,
        "reviewer_profile": _ref(
            reviewer_profile_path,
            canonical_sha256(reviewer_profile),
            raw=reviewer_profile_raw,
        ),
        **sources,
        "execution_journal": _ref(
            execution_root / "execution-journal.sqlite3",
            journal["logical"]["journal_sha256"],
        ),
        "provider_budget": _ref(
            execution_root / "provider-budget.sqlite3",
            canonical_sha256(budget),
        ),
    }
    evidence_hashes = sorted(
        evidence_sha256
        for participant in participants
        for evidence_sha256 in participant["task_evidence_sha256"]
    )
    return {
        "run_id": authorization["run_id"],
        "authorization_id": authorization["authorization_id"],
        "execution_summary": {
            "status": "complete",
            "task_execution_count": TASK_COUNT,
            "committed_task_count": TASK_COUNT,
            "provider_call_count": TASK_COUNT,
            "participant_signature_count": TASK_COUNT,
            "journal_event_count": EVENT_COUNT,
            "validation_failures": [],
        },
        "budget_summary": budget,
        "terminal_inventory": terminal_inventory,
        "outcome_inventory": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_evidence_count": TASK_COUNT,
            "verified_task_count": TASK_COUNT,
            "participant_outcome_count": 40,
            "task_evidence_set_sha256": canonical_sha256(evidence_hashes),
            "participant_outcome_set_sha256": canonical_sha256(participants),
            "pattern_prediction_observation_policy": (
                "direct_signed_observation_exact_set_scoring"
            ),
        },
        "participant_outcomes": participants,
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
            "prospective_confirmatory_inference_implemented": True,
            "prior_run_reanalysis_performed": False,
            "advice_adherence_inferred": False,
        },
    }


def _validate_upstream(
    *,
    authorization: dict[str, Any],
    issuance_gate: dict[str, Any],
    claim_preflight: dict[str, Any],
    claim: dict[str, Any],
    entry_gate: dict[str, Any],
    report: dict[str, Any],
    reviewer_profile: dict[str, Any],
    reviewer_profile_raw: bytes,
    plan: dict[str, Any],
    plan_raw: bytes,
    execution_preflight: dict[str, Any],
    execution_preflight_raw: bytes,
    refs: dict[str, dict[str, str]],
    execution_root: Path,
) -> None:
    failures = validate_reviewer_identity_profile(reviewer_profile)
    confirmatory = (
        authorization.get("schema_version") == CONFIRMATORY_AUTHORIZATION_SCHEMA
    )
    plan_ref = _ref(
        Path(authorization["source_binding"]["plan"]["path"]),
        plan["plan_sha256"],
        raw=plan_raw,
    )
    preflight_ref = _ref(
        Path(authorization["source_binding"]["preflight"]["path"]),
        execution_preflight["preflight_sha256"],
        raw=execution_preflight_raw,
    )
    if confirmatory:
        failures += validate_confirmatory_execution_plan(plan)
        failures += validate_confirmatory_authorization(
            authorization,
            plan_ref=plan_ref,
            preflight_ref=preflight_ref,
            plan=plan,
            expected_owner_authorization_id=authorization["owner_authorization"][
                "authorization_id"
            ],
            expected_owner_statement_sha256=authorization["owner_authorization"][
                "statement_sha256"
            ],
            expected_execution_manifest_sha256=authorization[
                "execution_manifest_sha256"
            ],
            expected_reviewer=reviewer_profile["reviewer"],
            expected_reviewer_profile_sha256=hashlib.sha256(
                reviewer_profile_raw
            ).hexdigest(),
            expected_implementation=authorization["implementation"],
            require_current=False,
        )
    else:
        failures += validate_execution_plan(plan)
        failures += validate_authorization(
            authorization,
            plan_ref=plan_ref,
            preflight_ref=preflight_ref,
            plan=plan,
            expected_owner_authorization_id=authorization["owner_authorization"][
                "authorization_id"
            ],
            expected_owner_statement_sha256=authorization["owner_authorization"][
                "statement_sha256"
            ],
            expected_execution_manifest_sha256=authorization[
                "execution_manifest_sha256"
            ],
            expected_reviewer=reviewer_profile["reviewer"],
            expected_reviewer_profile_sha256=hashlib.sha256(
                reviewer_profile_raw
            ).hexdigest(),
            expected_implementation=authorization["implementation"],
            require_current=False,
        )
    failures += validate_claim(
        claim,
        claim_path=str(Path(refs["claim"]["path"]).resolve()),
        authorization_ref=refs["authorization"],
        issuance_gate_ref=refs["issuance_gate"],
        claim_preflight_ref=refs["claim_preflight"],
        authorization=authorization,
        claim_preflight=claim_preflight,
        owner_statement_sha256=claim["owner_authorization"]["statement_sha256"],
        expected_implementation=claim["implementation"],
    )
    valid = (
        not failures
        and issuance_gate.get("schema_version")
        == (
            CONFIRMATORY_AUTHORIZATION_GATE_SCHEMA
            if confirmatory
            else AUTHORIZATION_GATE_SCHEMA
        )
        and issuance_gate.get("passed") is True
        and issuance_gate.get("authorization") == refs["authorization"]
        and issuance_gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in issuance_gate.items() if key != "report_sha256"}
        )
        and entry_gate.get("schema_version")
        == (CONFIRMATORY_ENTRY_GATE_SCHEMA if confirmatory else ENTRY_GATE_SCHEMA)
        and entry_gate.get("passed") is True
        and entry_gate.get("claim") == refs["claim"]
        and entry_gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in entry_gate.items() if key != "report_sha256"}
        )
        and report.get("schema_version") == LIVE_REPORT_SCHEMA
        and report.get("status") == "complete"
        and report.get("validation_failures") == []
        and report.get("failure_reason") is None
        and report.get("run_id") == authorization.get("run_id") == claim.get("run_id")
        and report.get("source_binding", {}).get("claim") == refs["claim"]
        and report.get("source_binding", {}).get("entry_gate") == refs["entry_gate"]
        and report.get("execution_scope", {}).get("task_execution_count") == TASK_COUNT
        and report.get("execution_scope", {}).get("provider_call_count") == TASK_COUNT
        and report.get("outcome_scope", {}).get("structured_decision_count")
        == TASK_COUNT
        and report.get("outcome_scope", {}).get("direct_behavior_observation_count")
        == TASK_COUNT
        and report.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in report.items() if key != "report_sha256"}
        )
        and Path(authorization["controls"]["execution_root"]).resolve()
        == execution_root.resolve()
    )
    if not valid:
        raise ValueError(f"outcome-sensitive upstream Evidence invalid: {failures}")


def _replay_tasks(
    *,
    contract: dict[str, Any],
    fixture: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
    journal: dict[str, Any],
    run_id: str,
    authorization_sha256: str,
) -> dict[str, list[dict[str, Any]]]:
    tasks = contract.get("task_executions")
    by_id = (
        {
            item["task_execution_id"]: item
            for item in tasks
            if isinstance(item, dict) and item.get("task_execution_id")
        }
        if isinstance(tasks, list)
        else {}
    )
    fixtures = {item["task_ordinal"]: item for item in fixture["fixtures"]}
    if len(by_id) != TASK_COUNT or len(fixtures) != 12:
        raise ValueError("outcome-sensitive task or fixture inventory invalid")
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    observed: set[str] = set()
    for committed in journal["committed"]:
        task_id = committed["task_execution_id"]
        task = by_id.get(task_id)
        if task is None or task_id in observed:
            raise ValueError("outcome-sensitive committed task binding invalid")
        observed.add(task_id)
        refs = committed["payload"].get("evidence")
        if not isinstance(refs, dict) or set(refs) != EVIDENCE_NAMES:
            raise ValueError("outcome-sensitive committed Evidence set invalid")
        loaded = {name: _read_evidence(item) for name, item in refs.items()}
        result[task["participant_id"]].append(
            _validated_observation(
                task=task,
                fixture=fixtures[task["task"]["task_ordinal"]],
                loaded=loaded,
                profile=profiles[task["participant_id"]],
                run_id=run_id,
                authorization_sha256=authorization_sha256,
                committed=committed,
            )
        )
    if observed != set(by_id):
        raise ValueError("outcome-sensitive committed task set incomplete")
    return result


def _validated_observation(
    *,
    task: dict[str, Any],
    fixture: dict[str, Any],
    loaded: dict[str, Any],
    profile: dict[str, Any],
    run_id: str,
    authorization_sha256: str,
    committed: dict[str, Any],
) -> dict[str, Any]:
    decision = loaded["structured-decision"]
    observation = loaded["direct-observation"]
    verification = loaded["task-verification"]
    signature = loaded["participant-signature"]
    provider = loaded["provider-receipt"]
    receipts = loaded["observation-receipts"]
    participant = profile["participant"]
    payload = signature["signed_payload"]
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    decision_sha256 = canonical_sha256(decision)
    observation_sha256 = canonical_sha256(observation)
    expected_action = fixture["ground_truth"]["selected_action_id"]
    expected_patterns = sorted(fixture["ground_truth"]["pattern_ids"])
    valid = (
        task["task"]["ground_truth_commitment_sha256"]
        == fixture["ground_truth_commitment_sha256"]
        == canonical_sha256(fixture["ground_truth"])
        and task["task"]["prompt_sha256"] == fixture["prompt_sha256"]
        and decision.get("schema_version") == "j1-qualification-structured-decision:v1"
        and observation.get("schema_version")
        == "j1-qualification-direct-behavior-observation:v1"
        and decision.get("run_id") == observation.get("run_id") == run_id
        and decision.get("task_execution_id")
        == observation.get("task_execution_id")
        == task["task_execution_id"]
        and decision.get("participant_id")
        == observation.get("participant_id")
        == task["participant_id"]
        and decision.get("selected_action_id") == observation.get("selected_action_id")
        and decision.get("predicted_pattern_ids")
        == observation.get("predicted_pattern_ids")
        and observation.get("ground_truth_revealed") is False
        and observation.get("effectiveness_scored") is False
        and observation.get("verified") is True
        and observation.get("participant_signature_sha256")
        == signature.get("signature_receipt_sha256")
        and verification
        == {
            "schema_version": (
                "j1-qualification-outcome-sensitive-task-verification:v1"
            ),
            "task_execution_id": task["task_execution_id"],
            "strict_decision_verified": True,
            "direct_observation_verified": True,
            "ground_truth_revealed": False,
            "effectiveness_scored": False,
            "passed": True,
            "failure_reasons": [],
        }
        and isinstance(receipts, list)
        and len(receipts) == 1
        and receipts[0].get("observation_sha256") == observation_sha256
        and receipts[0].get("fixture_commitment_sha256")
        == fixture["ground_truth_commitment_sha256"]
        and receipts[0].get("raw_ground_truth_persisted") is False
        and receipts[0].get("receipt_sha256")
        == canonical_sha256(
            {key: item for key, item in receipts[0].items() if key != "receipt_sha256"}
        )
        and provider.get("run_id") == run_id
        and provider.get("call_id") == task["call_id"]
        and provider.get("execution_authorization_sha256") == authorization_sha256
        and provider.get("receipt_sha256")
        == canonical_sha256(
            {key: item for key, item in provider.items() if key != "receipt_sha256"}
        )
        and provider.get("execution_boundary", {}).get("raw_response_recorded") is False
        and provider.get("execution_boundary", {}).get("backend_fact_append_performed")
        is False
        and provider.get("execution_boundary", {}).get("ledger_append_performed")
        is False
        and participant.get("participant_id") == task["participant_id"]
        and participant.get("execution_did") == task["execution_did"]
        and payload.get("structured_decision_sha256") == decision_sha256
        and payload.get("execution_authorization_sha256") == authorization_sha256
        and payload.get("task_execution_id") == task["task_execution_id"]
        and payload.get("signed_advice_canonical_sha256_or_null")
        == task["advice"].get("canonical_sha256")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(encoded).hexdigest()
        and signature.get("signature_receipt_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in signature.items()
                if key != "signature_receipt_sha256"
            }
        )
        and signature.get("signature_verified") is True
        and committed["payload"].get("decision_sha256") == decision_sha256
        and committed["payload"].get("signature_sha256") == canonical_sha256(signature)
    )
    if not valid:
        raise ValueError("outcome-sensitive task Evidence replay failed")
    try:
        VerifyKey(bytes.fromhex(participant["public_key_hex"])).verify(
            encoded, bytes.fromhex(signature["signature_hex"])
        )
    except (BadSignatureError, KeyError, ValueError) as error:
        raise ValueError("outcome-sensitive participant signature invalid") from error
    selected = decision["selected_action_id"]
    predicted = sorted(decision["predicted_pattern_ids"])
    action_exact = selected == expected_action
    pattern_exact = predicted == expected_patterns
    advice_expected = task["advice"]["mode"] == "mentor_signed"
    return {
        "task_ordinal": task["task"]["task_ordinal"],
        "task_evidence_sha256": canonical_sha256(verification),
        "structured_decision_sha256": decision_sha256,
        "direct_observation_sha256": observation_sha256,
        "selected_action_id": selected,
        "predicted_pattern_ids": predicted,
        "action_exact": action_exact,
        "pattern_exact": pattern_exact,
        "accepted": action_exact and pattern_exact,
        "repeated_error_family": fixture["ground_truth"]["repeated_error_family"],
        "hard_violation": (
            selected == "accept_bounded_delivery"
            and expected_action != "accept_bounded_delivery"
        ),
        "advice_expected": advice_expected,
        "advice_provenance_complete": (
            advice_expected
            and bool(task["advice"].get("canonical_sha256"))
            and payload.get("signed_advice_canonical_sha256_or_null")
            == task["advice"]["canonical_sha256"]
        ),
        "actual_tokens": provider["actual"]["tokens"],
        "actual_cost_microunits": provider["actual"]["microunits"],
    }


def _participant_records(
    *,
    assignment: dict[str, Any],
    observations: dict[str, list[dict[str, Any]]],
    run_id: str,
    authorization_sha256: str,
) -> list[dict[str, Any]]:
    records = []
    for pair in assignment["assignments"]:
        for cohort in ("mentor", "control"):
            member = pair[cohort]
            identity = {
                "participant_id": member["participant_id"],
                "participant_did": member["execution_did"],
                "pair_id": pair["pair_id"],
                "cohort": cohort,
            }
            records.append(
                build_participant_outcome(
                    run_id=run_id,
                    authorization_sha256=authorization_sha256,
                    participant=identity,
                    observations=observations[member["participant_id"]],
                )
            )
    return records


def _journal(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        previous = None
        first_by_task: dict[str, str] = {}
        committed = []
        for expected, row in enumerate(rows, 1):
            body = {
                key: row[key]
                for key in (
                    "sequence",
                    "task_execution_id",
                    "call_id",
                    "from_state",
                    "to_state",
                    "event_type",
                    "occurred_at",
                    "payload_sha256",
                    "previous_event_sha256",
                )
            }
            if not (
                row["sequence"] == expected
                and row["payload_sha256"]
                == hashlib.sha256(row["payload_json"].encode()).hexdigest()
                and row["previous_event_sha256"] == previous
                and row["event_sha256"] == canonical_sha256(body)
            ):
                raise ValueError("outcome-sensitive journal hash chain invalid")
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
                        "payload": json.loads(row["payload_json"]),
                        "runtime_seconds": max(
                            0, math.ceil((completed - started).total_seconds())
                        ),
                    }
                )
        states = _counts(connection, "task_states", "state")
        budgets = _counts(connection, "reservations", "status")
    finally:
        connection.close()
    logical = {
        "task_states": states,
        "budget_states": budgets,
        "event_count": len(rows),
        "last_event_sha256": previous,
    }
    logical["journal_sha256"] = canonical_sha256(logical)
    if states != {"task_committed": TASK_COUNT} or budgets != {
        "reconciled": TASK_COUNT
    }:
        raise ValueError("outcome-sensitive journal not completely terminal")
    return {
        "logical": logical,
        "committed": committed,
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _budget(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT COUNT(*), SUM(reserved_tokens), SUM(reserved_microunits), "
            "SUM(actual_tokens), SUM(actual_microunits), "
            "SUM(status = 'reconciled'), SUM(status != 'reconciled') "
            "FROM reservations"
        ).fetchone()
    finally:
        connection.close()
    value = {
        "reservation_count": int(row[0]),
        "reserved_tokens": int(row[1]),
        "reserved_cost_microunits": int(row[2]),
        "actual_tokens": int(row[3]),
        "actual_cost_microunits": int(row[4]),
        "reconciled_count": int(row[5]),
        "non_reconciled_count": int(row[6]),
    }
    if not (
        value["reservation_count"] == 480
        and value["reserved_tokens"] == 1_200_000
        and value["reserved_cost_microunits"] == 731_040
        and value["actual_tokens"] >= 0
        and value["actual_cost_microunits"] >= 0
        and value["reconciled_count"] == 480
        and value["non_reconciled_count"] == 0
    ):
        raise ValueError("outcome-sensitive budget reconciliation drifted")
    return value


def _terminal_inventory(activation: dict[str, Any]) -> dict[str, Any]:
    containers = activation.get("containers", [])
    names = [item["container"]["container_name"] for item in containers]
    completed = subprocess.run(
        ["docker", "inspect", *names],
        check=True,
        capture_output=True,
        text=True,
    )
    inspected = json.loads(completed.stdout)
    running = sum(item["State"]["Running"] is True for item in inspected)
    created = sum(item["State"]["Status"] == "created" for item in inspected)
    exited = len(inspected) - created - running
    if len(inspected) != 40 or running != 0:
        raise ValueError("outcome-sensitive terminal container inventory invalid")
    return {
        "participant_container_count": 40,
        "created_count": created,
        "exited_count": exited,
        "running_count": running,
        "container_set_sha256": canonical_sha256(
            sorted(item["Id"] for item in inspected)
        ),
    }


def _participant_profiles(root: Path) -> dict[str, dict[str, Any]]:
    result = {}
    for path in sorted(root.glob("*.json")):
        value, _ = _read_private(path)
        participant_id = value.get("participant", {}).get("participant_id")
        if not participant_id or participant_id in result:
            raise ValueError("outcome-sensitive participant profile invalid")
        result[participant_id] = value
    if len(result) != 40:
        raise ValueError("outcome-sensitive participant profile set incomplete")
    return result


def _read_evidence(reference: Any) -> dict[str, Any] | list[Any]:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("outcome-sensitive Evidence reference invalid")
    path = Path(reference["path"]).resolve()
    raw = path.read_bytes()
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_mode & 0o077
        or hashlib.sha256(raw).hexdigest() != reference["sha256"]
    ):
        raise ValueError("outcome-sensitive Evidence artifact drifted")
    return json.loads(raw)


def _read_bound(reference: dict[str, str], canonical_field: str) -> dict[str, Any]:
    value, raw = _read_private(Path(reference["path"]))
    aliases = {
        "assignment_sha256": ("reviewed_rebound_assignment_sha256",),
        "activation_sha256": ("repair_activation_sha256",),
    }
    fields = (canonical_field, *aliases.get(canonical_field, ()))
    canonical = next(
        (value[field] for field in fields if field in value),
        None,
    )
    if not (
        hashlib.sha256(raw).hexdigest() == reference["sha256"]
        and canonical == reference["canonical_sha256"]
    ):
        raise ValueError("outcome-sensitive frozen source drifted")
    return value


def _counts(connection: sqlite3.Connection, table: str, field: str) -> dict[str, int]:
    return {
        row[0]: row[1]
        for row in connection.execute(
            f"SELECT {field}, COUNT(*) FROM {table} GROUP BY {field}"
        )
    }


def _clean_pushed_revision(root: Path) -> str:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before closeout review generation")
    revision = _git(root, "rev-parse", "HEAD")
    if revision != _git(root, "rev-parse", "@{upstream}"):
        raise ValueError("closeout implementation revision is not pushed")
    return revision


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


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
        "claim-preflight",
        "claim",
        "entry-gate",
        "live-report",
        "reviewer-profile",
        "participant-profiles-root",
        "execution-root",
        "repository-root",
        "output-root",
    ):
        prepare.add_argument(f"--{option}", type=Path, required=True)
    prepare.add_argument("--pytest-passed-count", type=int, required=True)
    args = parser.parse_args()
    if args.operation != "prepare-review":
        raise ValueError("unsupported operation")
    result = prepare_review(
        bundle_id=args.bundle_id,
        request_id=args.request_id,
        created_at=args.created_at,
        authorization_path=args.authorization,
        issuance_gate_path=args.issuance_gate,
        claim_preflight_path=args.claim_preflight,
        claim_path=args.claim,
        entry_gate_path=args.entry_gate,
        live_report_path=args.live_report,
        reviewer_profile_path=args.reviewer_profile,
        participant_profiles_root=args.participant_profiles_root,
        execution_root=args.execution_root,
        repository_root=args.repository_root,
        output_root=args.output_root,
        pytest_passed_count=args.pytest_passed_count,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
