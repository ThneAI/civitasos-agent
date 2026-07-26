"""Prepare and sign a closeout for one partially executed failed J1-D r4 run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_execution_authorization_v4 import (
    validate_authorization,
)
from benchmarks.j1.qualification_execution_entry_v4 import validate_claim
from benchmarks.j1.qualification_execution_preflight_v4 import (
    validate_execution_plan,
)
from benchmarks.j1.qualification_failed_execution_closeout_v4 import (
    build_closeout_artifacts,
    build_closeout_gate,
    build_preflight,
    validate_closeout_artifacts,
    validate_preflight,
)
from benchmarks.j1.qualification_failed_closeout_review_v4 import (
    validate_review_bundle as validate_closeout_review_bundle,
)
from benchmarks.j1.qualification_review_v4 import (
    validate_review_bundle as validate_execution_review_bundle,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_failed_execution_closeout_v4.py"
)
OPERATION_SOURCE = Path(__file__)


def generate_preflight(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    reviewer_profile_path: Path,
    live_report_path: Path,
    execution_root: Path,
    closeout_implementation_gate_path: Path,
    output_root: Path,
    repository_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError(f"failed closeout preflight output exists: {output_root}")
    context = _context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        claim_preflight_path=claim_preflight_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        live_report_path=live_report_path,
        execution_root=execution_root,
        closeout_implementation_gate_path=closeout_implementation_gate_path,
        repository_root=repository_root,
    )
    target = Path(context["authorization"]["controls"]["post_run_output_root"])
    if target.exists():
        raise FileExistsError("failed closeout target already exists")
    preflight = build_preflight(
        checked_at=datetime.now(UTC).isoformat(),
        run_id=context["authorization"]["run_id"],
        authorization_id=context["authorization"]["authorization_id"],
        source_binding=context["source_binding"],
        execution_summary=context["execution_summary"],
        failure=context["failure"],
        budget_summary=context["budget_summary"],
        terminal_inventory=context["terminal_inventory"],
        output_root=str(target.resolve()),
        implementation=context["implementation"],
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        write_private_json(
            output_root / "r4-failed-execution-closeout-preflight.json", preflight
        )
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
    return preflight


def perform_closeout(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    reviewer_profile_path: Path,
    live_report_path: Path,
    execution_root: Path,
    closeout_implementation_gate_path: Path,
    closeout_preflight_path: Path,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    context = _context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        claim_preflight_path=claim_preflight_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        live_report_path=live_report_path,
        execution_root=execution_root,
        closeout_implementation_gate_path=closeout_implementation_gate_path,
        repository_root=repository_root,
    )
    preflight, preflight_raw = _read_private(closeout_preflight_path)
    if validate_preflight(preflight):
        raise ValueError("failed closeout preflight validation failed")
    if not (
        preflight["source_binding"] == context["source_binding"]
        and preflight["execution_summary"] == context["execution_summary"]
        and preflight["failure"] == context["failure"]
        and preflight["budget_summary"] == context["budget_summary"]
        and preflight["terminal_inventory"] == context["terminal_inventory"]
        and preflight["implementation"] == context["implementation"]
        and owner_statement
        == preflight["owner_authorization"]["required_exact_statement"]
        and owner_statement_sha256
        == hashlib.sha256(owner_statement.encode()).hexdigest()
        == preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("failed closeout preflight or owner authorization drifted")
    profile = context["reviewer_profile"]
    _validate_reviewer_configuration(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    preflight_ref = _ref(
        closeout_preflight_path, preflight["preflight_sha256"], raw=preflight_raw
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
            owner_statement=owner_statement,
            reviewer=reviewer,
            reviewer_profile_sha256=context["reviewer_profile_sha256"],
            implementation=context["implementation"],
            signer=signer,
        )
    target = Path(preflight["output_root"])
    return _persist(
        target=target,
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifacts=artifacts,
        reviewer=reviewer,
        reviewer_profile_sha256=context["reviewer_profile_sha256"],
        implementation=context["implementation"],
    )


def _context(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    reviewer_profile_path: Path,
    live_report_path: Path,
    execution_root: Path,
    closeout_implementation_gate_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    authorization, authorization_raw = _read_private(authorization_path)
    issuance_gate, issuance_raw = _read_private(issuance_gate_path)
    claim_preflight, claim_preflight_raw = _read_private(claim_preflight_path)
    claim, claim_raw = _read_private(claim_path)
    entry_gate, entry_raw = _read_private(entry_gate_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    report, report_raw = _read_private(live_report_path)
    plan_ref = authorization["source_binding"]["plan"]
    plan_path = Path(plan_ref["path"])
    plan, plan_raw = _read_private(plan_path)
    execution_preflight_ref = authorization["source_binding"]["preflight"]
    execution_preflight_path = Path(execution_preflight_ref["path"])
    execution_preflight, execution_preflight_raw = _read_private(
        execution_preflight_path
    )
    if validate_execution_plan(plan):
        raise ValueError("failed closeout execution plan invalid")
    authorization_ref = _ref(
        authorization_path,
        authorization["signature"]["signed_payload_sha256"],
        raw=authorization_raw,
    )
    issuance_ref = _ref(
        issuance_gate_path, issuance_gate["report_sha256"], raw=issuance_raw
    )
    claim_preflight_ref = _ref(
        claim_preflight_path,
        claim_preflight["preflight_sha256"],
        raw=claim_preflight_raw,
    )
    claim_ref = _ref(claim_path, claim["claim_sha256"], raw=claim_raw)
    entry_ref = _ref(entry_gate_path, entry_gate["report_sha256"], raw=entry_raw)
    report_ref = _ref(live_report_path, report["report_sha256"], raw=report_raw)
    expected_plan_ref = _ref(plan_path, plan["plan_sha256"], raw=plan_raw)
    expected_execution_preflight_ref = _ref(
        execution_preflight_path,
        execution_preflight["preflight_sha256"],
        raw=execution_preflight_raw,
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    authorization_failures = validate_authorization(
        authorization,
        plan=plan,
        expected_plan_ref=expected_plan_ref,
        expected_preflight_ref=expected_execution_preflight_ref,
        expected_owner_statement_sha256=authorization["owner_authorization"][
            "statement_sha256"
        ],
        expected_reviewer=profile["reviewer"],
        expected_reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        expected_implementation=authorization["implementation"],
        require_current=False,
    )
    claim_failures = validate_claim(
        claim,
        claim_path=str(claim_path.resolve()),
        authorization_ref=authorization_ref,
        issuance_gate_ref=issuance_ref,
        claim_preflight_ref=claim_preflight_ref,
        authorization=authorization,
        claim_preflight=claim_preflight,
        owner_statement_sha256=claim["owner_authorization"]["statement_sha256"],
        expected_implementation=claim["implementation"],
    )
    if profile_failures or authorization_failures or claim_failures:
        raise ValueError(
            "failed closeout upstream signature or claim invalid: "
            f"{profile_failures + authorization_failures + claim_failures}"
        )
    common_gate_valid = (
        issuance_gate.get("passed") is True
        and issuance_gate.get("authorization") == authorization_ref
        and issuance_gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in issuance_gate.items() if key != "report_sha256"}
        )
        and claim_preflight.get("preflight_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in claim_preflight.items()
                if key != "preflight_sha256"
            }
        )
        and entry_gate.get("passed") is True
        and entry_gate.get("claim") == claim_ref
        and entry_gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in entry_gate.items() if key != "report_sha256"}
        )
        and report.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in report.items() if key != "report_sha256"}
        )
    )
    partial_report = (
        report.get("status") == "failed"
        and report.get("run_id") == authorization["run_id"]
        and report.get("source_binding", {}).get("claim") == claim_ref
        and report.get("source_binding", {}).get("entry_gate") == entry_ref
    )
    pre_orchestrator_report = (
        report.get("schema_version") == "j1-qualification-r4-execution-failure:v1"
        and report.get("state") == "claimed_execution_failed_closeout_required"
        and report.get("authorization_artifact_sha256")
        == hashlib.sha256(authorization_raw).hexdigest()
        and Path(str(report.get("claim_path", ""))).resolve() == claim_path.resolve()
        and report.get("execution_started") is True
        and report.get("automatic_retry_performed") is False
        and report.get("authorization_reusable") is False
        and report.get("signed_closeout_required") is True
        and report.get("backend_fact_append_performed") is False
        and report.get("ledger_append_performed") is False
    )
    if not (common_gate_valid and (partial_report or pre_orchestrator_report)):
        raise ValueError("failed closeout Gate or live report binding invalid")
    if (
        execution_root.resolve()
        != Path(authorization["controls"]["execution_root"]).resolve()
    ):
        raise ValueError("failed closeout execution root differs from authorization")
    journal_path = execution_root / "execution-journal.sqlite3"
    budget_path = execution_root / "provider-budget.sqlite3"
    if pre_orchestrator_report:
        execution_state = _pre_orchestrator_failure_state(
            report=report,
            report_path=live_report_path,
            execution_root=execution_root,
        )
        execution_summary = execution_state["execution_summary"]
        failure = execution_state["failure"]
        budget = execution_state["budget_summary"]
        journal = None
    else:
        journal = _journal_summary(journal_path)
        budget = _budget_summary(budget_path)
        if not _journal_matches_report(journal, report["journal"]):
            raise ValueError(
                "failed closeout execution journal differs from live report"
            )
        execution_scope = report["execution_scope"]
        states = journal["logical"]["task_states"]
        committed = int(states.get("task_committed", 0))
        failed = sum(
            int(states.get(name, 0))
            for name in (
                "task_failed_before_dispatch",
                "task_failed_after_response",
                "provider_outcome_unknown",
            )
        )
        unattempted = int(states.get("planned", 0))
        if not (
            committed + failed + unattempted == 320
            and execution_scope["provider_call_count"]
            == (
                budget["reconciled_provider_call_count"]
                + budget["overrun_provider_call_count"]
                + budget["provider_outcome_unknown_call_count"]
            )
            and execution_scope["participant_signature_count"] == committed
        ):
            raise ValueError("failed closeout execution or budget counts invalid")
        failure = journal["failure"]
        if report.get("failure_reason") != failure["state"]:
            raise ValueError("failed closeout terminal failure binding invalid")
        execution_summary = {
            "authorized_task_count": 320,
            "committed_task_count": committed,
            "failed_task_count": failed,
            "unattempted_task_count": unattempted,
            "provider_call_count": int(execution_scope["provider_call_count"]),
            "participant_signature_count": int(
                execution_scope["participant_signature_count"]
            ),
            "container_start_count": int(execution_scope["container_start_count"]),
            "container_stop_count": int(execution_scope["container_stop_count"]),
        }
    contract_ref = plan["source_artifacts"]["execution_contract"]
    contract, contract_raw = _read_private(Path(contract_ref["path"]))
    activation_ref = contract["source_artifacts"]["infrastructure_activation"]
    activation, activation_raw = _read_private(Path(activation_ref["path"]))
    if not (
        hashlib.sha256(contract_raw).hexdigest() == contract_ref["sha256"]
        and contract["contract_sha256"] == contract_ref["canonical_sha256"]
        and hashlib.sha256(activation_raw).hexdigest() == activation_ref["sha256"]
        and activation["activation_sha256"] == activation_ref["canonical_sha256"]
    ):
        raise ValueError("failed closeout contract or activation drifted")
    inventory = activation_inventory(activation)
    terminal_inventory = {
        **inventory,
        "exited_count": inventory["participant_container_count"]
        - inventory["created_count"]
        - inventory["running_count"],
    }
    if terminal_inventory["running_count"] != 0:
        raise ValueError("failed closeout requires all activation containers stopped")
    frozen_refs = {
        name: plan["source_artifacts"][name]
        for name in (
            "frozen_evaluation_closeout_bundle",
            "frozen_post_run_contract",
            "frozen_operator_closeout_contract",
        )
    }
    frozen_values = {
        name: _read_bound(reference) for name, reference in frozen_refs.items()
    }
    allowed = (
        frozen_values["frozen_operator_closeout_contract"]
        .get("operator_decision", {})
        .get("allowed", [])
    )
    if "record_failed_run" not in allowed:
        raise ValueError("frozen closeout contract forbids record_failed_run")
    implementation = _implementation(repository_root)
    closeout_review_refs = _validate_closeout_implementation_gate(
        closeout_implementation_gate_path,
        repository_root=repository_root,
        implementation=implementation,
    )
    source_binding = {
        "authorization": authorization_ref,
        "issuance_gate": issuance_ref,
        "claim_preflight": claim_preflight_ref,
        "claim": claim_ref,
        "entry_gate": entry_ref,
        "live_report": report_ref,
        **closeout_review_refs,
        **frozen_refs,
    }
    if journal is not None:
        source_binding["execution_journal"] = _ref(
            journal_path, journal["logical"]["journal_sha256"]
        )
        source_binding["provider_budget"] = _ref(budget_path, canonical_sha256(budget))
    return {
        "authorization": authorization,
        "reviewer_profile": profile,
        "reviewer_profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
        "source_binding": source_binding,
        "execution_summary": execution_summary,
        "failure": failure,
        "budget_summary": budget,
        "terminal_inventory": terminal_inventory,
        "implementation": implementation,
    }


def _pre_orchestrator_failure_state(
    *,
    report: dict[str, Any],
    report_path: Path,
    execution_root: Path,
) -> dict[str, Any]:
    files = {
        path.relative_to(execution_root)
        for path in execution_root.rglob("*")
        if path.is_file()
    }
    expected = {report_path.resolve().relative_to(execution_root.resolve())}
    if files != expected or any(
        path.is_symlink() for path in execution_root.rglob("*")
    ):
        raise ValueError(
            "pre-orchestrator failure root contains unexpected execution artifacts"
        )
    credential_reads = report.get("provider_credential_read_count", 1)
    container_starts = report.get("participant_container_start_count", 0)
    provider_calls = report.get("provider_api_call_count", 0)
    participant_signatures = report.get("participant_signature_count", 0)
    if not (
        credential_reads == 1
        and container_starts == 0
        and provider_calls == 0
        and participant_signatures == 0
    ):
        raise ValueError("pre-orchestrator failure boundary counts invalid")
    return {
        "execution_summary": {
            "authorized_task_count": 320,
            "committed_task_count": 0,
            "failed_task_count": 0,
            "unattempted_task_count": 320,
            "provider_call_count": 0,
            "participant_signature_count": 0,
            "container_start_count": 0,
            "container_stop_count": 0,
            "provider_credential_read_count": 1,
        },
        "failure": {
            "state": "pre_orchestrator_error",
            "reason": str(report.get("failure_reason") or report["failure_type"]),
            "task_execution_id": "not_started",
            "call_id": "not_dispatched",
            "provider_call_performed": False,
            "provider_retry_performed": False,
            "provider_credential_read_performed": True,
            "event_sha256": report["report_sha256"],
        },
        "budget_summary": {
            "reconciled_provider_call_count": 0,
            "overrun_provider_call_count": 0,
            "provider_outcome_unknown_call_count": 0,
            "reserved_tokens": 0,
            "reserved_cost_microunits": 0,
            "actual_tokens": 0,
            "actual_cost_microunits": 0,
            "unknown_reserved_tokens": 0,
            "unknown_reserved_cost_microunits": 0,
            "chargeable_token_upper_bound": 0,
            "chargeable_cost_upper_bound_microunits": 0,
        },
    }


def _journal_summary(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        previous = None
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
                raise ValueError("failed closeout journal hash chain invalid")
            previous = row["event_sha256"]
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
        logical = {
            "task_states": states,
            "budget_states": budgets,
            "event_count": len(rows),
            "last_event_sha256": previous,
        }
        logical["journal_sha256"] = canonical_sha256(logical)
        failure_rows = [
            row
            for row in rows
            if row["to_state"]
            in {
                "task_failed_before_dispatch",
                "task_failed_after_response",
                "provider_outcome_unknown",
            }
        ]
        if len(failure_rows) != 1:
            raise ValueError("failed closeout requires exactly one terminal failure")
        failed = failure_rows[0]
        payload = json.loads(failed["payload_json"])
        failure = {
            "state": failed["to_state"],
            "reason": str(payload.get("reason") or failed["event_type"]),
            "task_execution_id": failed["task_execution_id"],
            "call_id": failed["call_id"],
            "provider_call_performed": bool(
                payload.get("provider_call_performed", False)
            ),
            "provider_retry_performed": bool(
                payload.get("provider_retry_performed", False)
            ),
            "event_sha256": failed["event_sha256"],
        }
    finally:
        connection.close()
    return {
        "logical": logical,
        "failure": failure,
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _budget_summary(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        row = connection.execute(
            """
            SELECT
              COUNT(*),
              COALESCE(SUM(reserved_tokens), 0),
              COALESCE(SUM(reserved_microunits), 0),
              COALESCE(SUM(actual_tokens), 0),
              COALESCE(SUM(actual_microunits), 0),
              SUM(CASE WHEN status = 'reconciled' THEN 1 ELSE 0 END),
              SUM(CASE WHEN status = 'overrun' THEN 1 ELSE 0 END),
              SUM(CASE WHEN status IN ('failed', 'provider_outcome_unknown')
                       THEN 1 ELSE 0 END),
              COALESCE(SUM(
                CASE WHEN status IN ('failed', 'provider_outcome_unknown')
                     THEN reserved_tokens ELSE 0 END
              ), 0),
              COALESCE(SUM(
                CASE WHEN status IN ('failed', 'provider_outcome_unknown')
                     THEN reserved_microunits ELSE 0 END
              ), 0)
            FROM reservations
            """
        ).fetchone()
        statuses = connection.execute(
            "SELECT DISTINCT status FROM reservations"
        ).fetchall()
    finally:
        connection.close()
    observed_statuses = {str(item[0]) for item in statuses}
    terminal_statuses = {
        "reconciled",
        "overrun",
        "failed",
        "provider_outcome_unknown",
    }
    if not observed_statuses <= terminal_statuses:
        raise ValueError("failed closeout provider budget is not terminally accounted")
    actual_tokens = int(row[3])
    actual_cost = int(row[4])
    unknown_reserved_tokens = int(row[8])
    unknown_reserved_cost = int(row[9])
    return {
        "reconciled_provider_call_count": int(row[5]),
        "overrun_provider_call_count": int(row[6]),
        "provider_outcome_unknown_call_count": int(row[7]),
        "reserved_tokens": int(row[1]),
        "reserved_cost_microunits": int(row[2]),
        "actual_tokens": actual_tokens,
        "actual_cost_microunits": actual_cost,
        "unknown_reserved_tokens": unknown_reserved_tokens,
        "unknown_reserved_cost_microunits": unknown_reserved_cost,
        "chargeable_token_upper_bound": actual_tokens + unknown_reserved_tokens,
        "chargeable_cost_upper_bound_microunits": (
            actual_cost + unknown_reserved_cost
        ),
    }


def _validate_closeout_implementation_gate(
    path: Path,
    *,
    repository_root: Path,
    implementation: dict[str, str],
) -> dict[str, dict[str, str]]:
    gate, gate_raw = _read_private(path)
    bundle_ref = gate.get("review_bundle", {})
    gate_schema = gate.get("schema_version")
    if not (
        gate_schema
        in {
            "j1-qualification-r4-review-promotion-gate:v1",
            "j1-qualification-r4-failed-closeout-review-gate:v1",
        }
        and gate.get("passed") is True
        and gate.get("signature_valid") is True
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
        and isinstance(bundle_ref, dict)
    ):
        raise ValueError("failed closeout implementation review Gate invalid")
    bundle_path = Path(str(bundle_ref.get("path", "")))
    bundle, bundle_raw = _read_private(bundle_path)
    bundle_failures = (
        validate_closeout_review_bundle(bundle)
        if gate_schema == "j1-qualification-r4-failed-closeout-review-gate:v1"
        else validate_execution_review_bundle(bundle)
    )
    if (
        hashlib.sha256(bundle_raw).hexdigest() != bundle_ref.get("sha256")
        or bundle.get("bundle_sha256") != bundle_ref.get("canonical_sha256")
        or bundle_failures
    ):
        raise ValueError("failed closeout implementation review bundle invalid")
    source = bundle.get("source_implementation", {})
    source_files = source.get("source_files", {})
    expected_files = {
        "benchmarks/j1/qualification_failed_execution_closeout_v4.py": (
            implementation["domain_source_sha256"]
        ),
        "benchmarks/j1/qualification_provider_broker.py": hashlib.sha256(
            (repository_root / "benchmarks/j1/qualification_provider_broker.py")
            .read_bytes()
        ).hexdigest(),
        "benchmarks/j1_qualification_failed_execution_closeout_v4.py": (
            implementation["operation_source_sha256"]
        ),
    }
    reviewed_revision = (
        source.get("source_revision")
        if gate_schema == "j1-qualification-r4-failed-closeout-review-gate:v1"
        else source.get("review_material_revision")
    )
    if not (
        reviewed_revision == implementation["source_revision"]
        and all(source_files.get(name) == digest for name, digest in expected_files.items())
    ):
        raise ValueError("failed closeout implementation is not independently reviewed")
    return {
        "closeout_implementation_review_gate": _ref(
            path, gate["report_sha256"], raw=gate_raw
        ),
        "closeout_implementation_review_bundle": _ref(
            bundle_path, bundle["bundle_sha256"], raw=bundle_raw
        ),
    }


def _journal_matches_report(
    journal: dict[str, Any], report_journal: dict[str, Any]
) -> bool:
    logical = dict(report_journal)
    artifact_sha256 = logical.pop("journal_artifact_sha256", None)
    return (
        journal.get("logical") == logical
        and journal.get("raw_sha256") == artifact_sha256
    )


def _persist(
    *,
    target: Path,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    if target.exists():
        raise FileExistsError("failed closeout output already exists")
    parent = target.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=parent))
    staging.chmod(0o700)
    names = {
        "post_run_receipt": "failed-post-run-receipt.json",
        "evaluation_report": "failed-evaluation-report.json",
        "operator_closeout": "failed-operator-closeout.json",
    }
    try:
        for name, filename in names.items():
            write_private_json(staging / filename, artifacts[name])
        refs = {
            "post_run_receipt": _ref(
                target / names["post_run_receipt"],
                artifacts["post_run_receipt"]["receipt_sha256"],
                raw=(staging / names["post_run_receipt"]).read_bytes(),
            ),
            "evaluation_report": _ref(
                target / names["evaluation_report"],
                artifacts["evaluation_report"]["report_sha256"],
                raw=(staging / names["evaluation_report"]).read_bytes(),
            ),
            "operator_closeout": _ref(
                target / names["operator_closeout"],
                artifacts["operator_closeout"]["signature"]["signed_payload_sha256"],
                raw=(staging / names["operator_closeout"]).read_bytes(),
            ),
        }
        failures = validate_closeout_artifacts(
            artifacts,
            preflight_ref=preflight_ref,
            preflight=preflight,
            expected_reviewer=reviewer,
            expected_reviewer_profile_sha256=reviewer_profile_sha256,
            expected_implementation=implementation,
        )
        if failures:
            raise ValueError(
                f"failed closeout persistence validation failed: {failures}"
            )
        gate = build_closeout_gate(
            checked_at=datetime.now(UTC).isoformat(),
            preflight_ref=preflight_ref,
            preflight=preflight,
            artifact_refs=refs,
            artifacts=artifacts,
        )
        gate_path = staging / "failed-closeout-gate-report.json"
        write_private_json(gate_path, gate)
        _fsync_tree(staging)
        os.rename(staging, target)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "state": gate["state"],
        "run_id": preflight["run_id"],
        "output_root": str(target),
        "artifacts": refs,
        "gate": _ref(
            target / "failed-closeout-gate-report.json", gate["report_sha256"]
        ),
        "authorization_reusable": False,
        "partial_results_promotable": False,
        "future_run_requires_new_reviewed_stack": True,
    }


def _read_bound(reference: dict[str, str]) -> dict[str, Any]:
    value, raw = _read_private(Path(reference["path"]))
    canonical = next(
        (
            value[field]
            for field in (
                "frozen_bundle_sha256",
                "contract_sha256",
                "report_sha256",
            )
            if field in value
        ),
        None,
    )
    if (
        hashlib.sha256(raw).hexdigest() != reference["sha256"]
        or canonical != reference["canonical_sha256"]
    ):
        raise ValueError("failed closeout frozen source drifted")
    return value


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"failed closeout private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("failed closeout artifact must be an object")
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


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for failed execution closeout")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_reviewer_configuration(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    key = profile["pkcs11_key"]
    module = Path(module_path).resolve()
    if not (
        key.get("module_path") == str(module)
        and key.get("module_sha256") == hashlib.sha256(module.read_bytes()).hexdigest()
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
    ):
        raise ValueError("failed closeout reviewer PKCS#11 configuration mismatch")


def _fsync_tree(root: Path) -> None:
    for path in root.iterdir():
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--issuance-gate", type=Path, required=True)
    parser.add_argument("--claim-preflight", type=Path, required=True)
    parser.add_argument("--claim", type=Path, required=True)
    parser.add_argument("--entry-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--live-report", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument("--closeout-implementation-gate", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    preflight_parser = subparsers.add_parser("preflight")
    _add_common(preflight_parser)
    preflight_parser.add_argument("--output-root", type=Path, required=True)
    closeout_parser = subparsers.add_parser("closeout")
    _add_common(closeout_parser)
    closeout_parser.add_argument("--closeout-preflight", type=Path, required=True)
    closeout_parser.add_argument("--owner-authorization-id", required=True)
    closeout_parser.add_argument("--owner-statement", required=True)
    closeout_parser.add_argument("--owner-statement-sha256", required=True)
    closeout_parser.add_argument("--module", default=DEFAULT_MODULE)
    closeout_parser.add_argument("--token-label", required=True)
    closeout_parser.add_argument("--key-label", required=True)
    closeout_parser.add_argument("--key-id", required=True)
    closeout_parser.add_argument("--pin-file", type=Path)
    args = parser.parse_args()
    common = {
        "authorization_path": args.authorization,
        "issuance_gate_path": args.issuance_gate,
        "claim_preflight_path": args.claim_preflight,
        "claim_path": args.claim,
        "entry_gate_path": args.entry_gate,
        "reviewer_profile_path": args.reviewer_profile,
        "live_report_path": args.live_report,
        "execution_root": args.execution_root,
        "closeout_implementation_gate_path": args.closeout_implementation_gate,
        "repository_root": args.repository_root,
    }
    if args.operation == "preflight":
        result = generate_preflight(output_root=args.output_root, **common)
    else:
        result = perform_closeout(
            closeout_preflight_path=args.closeout_preflight,
            owner_authorization_id=args.owner_authorization_id,
            owner_statement=args.owner_statement,
            owner_statement_sha256=args.owner_statement_sha256,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            pin=read_pin(args.pin_file),
            **common,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
