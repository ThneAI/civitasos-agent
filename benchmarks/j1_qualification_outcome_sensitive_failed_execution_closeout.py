"""Prepare and sign a failed outcome-sensitive J1-D execution closeout."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_failed_closeout_review_v4 import (
    OUTCOME_BUNDLE_SCHEMA,
    OUTCOME_GATE_SCHEMA as OUTCOME_REVIEW_GATE_SCHEMA,
    validate_review_bundle,
)
from benchmarks.j1.qualification_failed_execution_closeout_v4 import (
    build_closeout_artifacts,
    build_preflight,
    validate_preflight,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_authorization import (
    GATE_SCHEMA as AUTHORIZATION_GATE_SCHEMA,
    validate_authorization,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_entry import (
    ENTRY_GATE_SCHEMA,
    validate_claim,
)
from benchmarks.j1.qualification_outcome_sensitive_execution_preflight import (
    validate_execution_plan,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_failed_execution_closeout_v4 import (
    _budget_summary,
    _git,
    _journal_matches_report,
    _journal_summary,
    _persist,
    _read_private,
    _ref,
    _validate_reviewer_configuration,
)
from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_failed_execution_closeout_v4.py"
)
OPERATION_SOURCE = Path(__file__)
LIVE_REPORT_SCHEMA = "j1-qualification-outcome-sensitive-live-orchestrator-report:v1"


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
        raise FileExistsError(
            f"outcome-sensitive failed closeout preflight exists: {output_root}"
        )
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
        raise FileExistsError("outcome-sensitive failed closeout target already exists")
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
        profile="outcome_sensitive",
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        write_private_json(
            output_root
            / "outcome-sensitive-failed-execution-closeout-preflight.json",
            preflight,
        )
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
    return preflight


def perform_closeout(
    *,
    closeout_preflight_path: Path,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    pin: str,
    **context_arguments: Any,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    context = _context(**context_arguments)
    preflight, preflight_raw = _read_private(closeout_preflight_path)
    if validate_preflight(preflight):
        raise ValueError("outcome-sensitive failed closeout preflight invalid")
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
        raise ValueError(
            "outcome-sensitive failed closeout preflight or authorization drifted"
        )
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
        closeout_preflight_path,
        preflight["preflight_sha256"],
        raw=preflight_raw,
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
    return _persist(
        target=Path(preflight["output_root"]),
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
    preflight_ref = authorization["source_binding"]["preflight"]
    plan, plan_raw = _read_private(Path(plan_ref["path"]))
    execution_preflight, execution_preflight_raw = _read_private(
        Path(preflight_ref["path"])
    )
    if validate_execution_plan(plan):
        raise ValueError("outcome-sensitive failed closeout execution plan invalid")

    refs = {
        "authorization": _ref(
            authorization_path,
            authorization["signature"]["signed_payload_sha256"],
            raw=authorization_raw,
        ),
        "issuance_gate": _ref(
            issuance_gate_path,
            issuance_gate["report_sha256"],
            raw=issuance_raw,
        ),
        "claim_preflight": _ref(
            claim_preflight_path,
            claim_preflight["preflight_sha256"],
            raw=claim_preflight_raw,
        ),
        "claim": _ref(claim_path, claim["claim_sha256"], raw=claim_raw),
        "entry_gate": _ref(
            entry_gate_path,
            entry_gate["report_sha256"],
            raw=entry_raw,
        ),
        "live_report": _ref(
            live_report_path,
            report["report_sha256"],
            raw=report_raw,
        ),
    }
    expected_plan_ref = _ref(Path(plan_ref["path"]), plan["plan_sha256"], raw=plan_raw)
    expected_preflight_ref = _ref(
        Path(preflight_ref["path"]),
        execution_preflight["preflight_sha256"],
        raw=execution_preflight_raw,
    )
    failures = validate_reviewer_identity_profile(profile)
    failures += validate_authorization(
        authorization,
        plan_ref=expected_plan_ref,
        preflight_ref=expected_preflight_ref,
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
        expected_reviewer=profile["reviewer"],
        expected_reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        expected_implementation=authorization["implementation"],
        require_current=False,
    )
    failures += validate_claim(
        claim,
        claim_path=str(claim_path.resolve()),
        authorization_ref=refs["authorization"],
        issuance_gate_ref=refs["issuance_gate"],
        claim_preflight_ref=refs["claim_preflight"],
        authorization=authorization,
        claim_preflight=claim_preflight,
        owner_statement_sha256=claim["owner_authorization"]["statement_sha256"],
        expected_implementation=claim["implementation"],
    )
    if failures:
        raise ValueError(
            f"outcome-sensitive failed closeout upstream Evidence invalid: {failures}"
        )
    _validate_gates_and_report(
        authorization=authorization,
        issuance_gate=issuance_gate,
        claim=claim,
        entry_gate=entry_gate,
        report=report,
        refs=refs,
    )
    if execution_root.resolve() != Path(
        authorization["controls"]["execution_root"]
    ).resolve():
        raise ValueError("outcome-sensitive failed closeout execution root drifted")

    journal_path = execution_root / "execution-journal.sqlite3"
    budget_path = execution_root / "provider-budget.sqlite3"
    journal = _journal_summary(journal_path)
    budget = _budget_summary(budget_path)
    if not _journal_matches_report(journal, report["journal"]):
        raise ValueError("outcome-sensitive failed closeout journal/report drifted")
    execution_summary = _execution_summary(report, journal, budget)
    failure = journal["failure"]
    if not (
        report["failure_reason"] == failure["state"]
        and report["failure_diagnostic"]
        == {
            name: failure[name]
            for name in (
                "failure_category",
                "failure_stage",
                "reason",
                "source_exception_type",
            )
        }
    ):
        raise ValueError("outcome-sensitive terminal failure diagnostic drifted")

    activation_ref = plan["source_artifacts"]["activation"]
    activation = _read_bound(
        activation_ref,
        canonical_fields=("activation_sha256",),
    )
    inventory = activation_inventory(activation)
    terminal_inventory = {
        **inventory,
        "exited_count": (
            inventory["participant_container_count"]
            - inventory["created_count"]
            - inventory["running_count"]
        ),
    }
    if terminal_inventory["running_count"] != 0:
        raise ValueError("outcome-sensitive closeout requires zero running containers")

    frozen_names = (
        "activation",
        "execution_contract",
        "frozen_execution_stack",
        "promotion_gate",
        "evaluator",
        "statistical_plan",
    )
    frozen_refs = {name: plan["source_artifacts"][name] for name in frozen_names}
    for name, reference in frozen_refs.items():
        if name != "activation":
            _read_bound(reference)
    implementation = _implementation(repository_root)
    review_refs = _validate_implementation_gate(
        closeout_implementation_gate_path,
        implementation=implementation,
    )
    source_binding = {
        **refs,
        **review_refs,
        **frozen_refs,
        "execution_journal": _ref(
            journal_path,
            journal["logical"]["journal_sha256"],
        ),
        "provider_budget": _ref(budget_path, canonical_sha256(budget)),
    }
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


def _validate_gates_and_report(
    *,
    authorization: dict[str, Any],
    issuance_gate: dict[str, Any],
    claim: dict[str, Any],
    entry_gate: dict[str, Any],
    report: dict[str, Any],
    refs: dict[str, dict[str, str]],
) -> None:
    if not (
        issuance_gate.get("schema_version") == AUTHORIZATION_GATE_SCHEMA
        and issuance_gate.get("passed") is True
        and issuance_gate.get("authorization") == refs["authorization"]
        and issuance_gate.get("report_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in issuance_gate.items()
                if key != "report_sha256"
            }
        )
        and entry_gate.get("schema_version") == ENTRY_GATE_SCHEMA
        and entry_gate.get("passed") is True
        and entry_gate.get("claim") == refs["claim"]
        and entry_gate.get("run_id") == authorization["run_id"] == claim["run_id"]
        and entry_gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in entry_gate.items() if key != "report_sha256"}
        )
        and report.get("schema_version") == LIVE_REPORT_SCHEMA
        and report.get("status") == "failed"
        and report.get("validation_failures") == []
        and report.get("run_id") == authorization["run_id"]
        and report.get("source_binding", {}).get("claim") == refs["claim"]
        and report.get("source_binding", {}).get("entry_gate") == refs["entry_gate"]
        and report.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in report.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("outcome-sensitive failed closeout Gate/report invalid")


def _execution_summary(
    report: dict[str, Any],
    journal: dict[str, Any],
    budget: dict[str, int],
) -> dict[str, int]:
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
    scope = report["execution_scope"]
    accounted_calls = (
        budget["reconciled_provider_call_count"]
        + budget["overrun_provider_call_count"]
        + budget["provider_outcome_unknown_call_count"]
    )
    if not (
        committed + failed + unattempted == 480
        and failed == 1
        and scope["task_execution_count"] == 480
        and scope["provider_call_count"] == accounted_calls
        and scope["participant_signature_count"]
        == journal["participant_signature_count"]
        == committed + journal["signed_failed_task_count"]
        and report["outcome_scope"]["structured_decision_count"] == committed
        and report["outcome_scope"]["direct_behavior_observation_count"] == committed
    ):
        raise ValueError("outcome-sensitive failed closeout execution counts invalid")
    return {
        "authorized_task_count": 480,
        "committed_task_count": committed,
        "failed_task_count": failed,
        "unattempted_task_count": unattempted,
        "provider_call_count": int(scope["provider_call_count"]),
        "participant_signature_count": int(scope["participant_signature_count"]),
        "signed_failed_task_count": journal["signed_failed_task_count"],
        "container_start_count": int(scope["container_start_count"]),
        "container_stop_count": int(scope["container_stop_count"]),
        "structured_decision_count": int(
            report["outcome_scope"]["structured_decision_count"]
        ),
        "direct_behavior_observation_count": int(
            report["outcome_scope"]["direct_behavior_observation_count"]
        ),
    }


def _read_bound(
    reference: dict[str, str],
    *,
    canonical_fields: tuple[str, ...] = (
        "frozen_stack_sha256",
        "contract_sha256",
        "report_sha256",
        "artifact_sha256",
        "bundle_sha256",
        "protocol_sha256",
        "evaluator_sha256",
        "statistical_plan_sha256",
        "plan_sha256",
    ),
) -> dict[str, Any]:
    value, raw = _read_private(Path(reference["path"]))
    canonical = next(
        (value[field] for field in canonical_fields if field in value),
        canonical_sha256(value),
    )
    if not (
        hashlib.sha256(raw).hexdigest() == reference["sha256"]
        and canonical == reference["canonical_sha256"]
    ):
        raise ValueError("outcome-sensitive failed closeout frozen source drifted")
    return value


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError(
            "repository must be clean for outcome-sensitive failed closeout"
        )
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_implementation_gate(
    path: Path,
    *,
    implementation: dict[str, str],
) -> dict[str, dict[str, str]]:
    gate, gate_raw = _read_private(path)
    bundle_ref = gate.get("review_bundle", {})
    bundle, bundle_raw = _read_private(Path(str(bundle_ref.get("path", ""))))
    files = bundle.get("source_implementation", {}).get("source_files", {})
    if not (
        gate.get("schema_version") == OUTCOME_REVIEW_GATE_SCHEMA
        and gate.get("passed") is True
        and gate.get("signature_valid") is True
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
        and bundle.get("schema_version") == OUTCOME_BUNDLE_SCHEMA
        and not validate_review_bundle(bundle)
        and hashlib.sha256(bundle_raw).hexdigest() == bundle_ref.get("sha256")
        and bundle.get("bundle_sha256") == bundle_ref.get("canonical_sha256")
        and bundle["source_implementation"]["source_revision"]
        == implementation["source_revision"]
        and files.get(
            "benchmarks/j1/qualification_failed_execution_closeout_v4.py"
        )
        == implementation["domain_source_sha256"]
        and files.get(
            "benchmarks/"
            "j1_qualification_outcome_sensitive_failed_execution_closeout.py"
        )
        == implementation["operation_source_sha256"]
    ):
        raise ValueError(
            "outcome-sensitive failed closeout implementation review invalid"
        )
    return {
        "closeout_implementation_review_gate": _ref(
            path,
            gate["report_sha256"],
            raw=gate_raw,
        ),
        "closeout_implementation_review_bundle": _ref(
            Path(bundle_ref["path"]),
            bundle["bundle_sha256"],
            raw=bundle_raw,
        ),
    }


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
    preflight = subparsers.add_parser("preflight")
    _add_common(preflight)
    preflight.add_argument("--output-root", type=Path, required=True)
    closeout = subparsers.add_parser("closeout")
    _add_common(closeout)
    closeout.add_argument("--closeout-preflight", type=Path, required=True)
    closeout.add_argument("--owner-authorization-id", required=True)
    closeout.add_argument("--owner-statement", required=True)
    closeout.add_argument("--owner-statement-sha256", required=True)
    closeout.add_argument("--module", default=DEFAULT_MODULE)
    closeout.add_argument("--token-label", required=True)
    closeout.add_argument("--key-label", required=True)
    closeout.add_argument("--key-id", required=True)
    closeout.add_argument("--pin-file", type=Path)
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
