#!/usr/bin/env python3
"""Close out one private Beta controlled proposer/reviewer execution.

This gate consumes a passed controlled proposer/reviewer execution summary,
collects the four Agent outputs, records operator reconciliation, and decides
whether the outputs should stop, be revised, close out without source mutation,
or become input to a later bounded apply authorization request. It never applies
code, commits, pushes, merges, deploys, opens public ingress, executes
production runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope

try:
    from beta_fe_four_agent_evidence import extract_verdict
except ModuleNotFoundError:
    from scripts.beta_fe_four_agent_evidence import extract_verdict

EXECUTION_SCHEMA = "private-beta-controlled-proposer-reviewer-execution:v1"
MEDIATION_SCHEMA = "private-beta-controlled-proposer-reviewer-mediation:v1"
TASK_RECEIPT_SCHEMA = "beta-fe26-agent-runner-task-receipt:v1"
CLOSEOUT_SCHEMA = "private-beta-controlled-proposer-reviewer-closeout:v1"
VALIDATION_SCHEMA = "private-beta-controlled-proposer-reviewer-closeout-validation:v1"
OPERATOR_DECISIONS = {
    "closeout_no_apply",
    "approve_bounded_apply_request",
    "request_revision",
    "reject",
}
FALSE_BOUNDARY_FIELDS = (
    "frontend_code_modified",
    "apply_allowed",
    "commit_allowed",
    "push_allowed",
    "merge_allowed",
    "deploy_allowed",
    "external_public_ingress_opened",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
)
NON_CLAIMS = (
    "private_beta_proposer_reviewer_closeout_does_not_modify_source",
    "private_beta_proposer_reviewer_closeout_does_not_authorize_apply_commit_push_merge_or_deploy",
    "private_beta_proposer_reviewer_closeout_does_not_open_public_ingress",
    "private_beta_proposer_reviewer_closeout_does_not_execute_production_runtime",
    "private_beta_proposer_reviewer_closeout_does_not_write_production_receipts",
    "bounded_apply_still_requires_separate_single_use_authorization",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    closeout = subparsers.add_parser("closeout", help="record operator reconciliation for one execution summary")
    closeout.add_argument("--execution-summary", required=True)
    closeout.add_argument("--frontend-root", required=True)
    closeout.add_argument("--output-root", required=True)
    closeout.add_argument("--operator-id", default="local-operator-cc")
    closeout.add_argument("--operator-decision", choices=sorted(OPERATOR_DECISIONS), required=True)
    closeout.add_argument("--operator-statement", required=True)
    closeout.add_argument("--selected-participant")
    closeout.add_argument("--allowed-changed-file", action="append", default=[])
    closeout.add_argument("--ack-reconciliation", action="store_true")

    validate = subparsers.add_parser("validate-closeout", help="validate a closeout artifact")
    validate.add_argument("--closeout", required=True)
    validate.add_argument("--output")

    args = parser.parse_args(argv)
    if args.command == "closeout":
        report = run_closeout(
            execution_summary_path=Path(args.execution_summary),
            frontend_root=Path(args.frontend_root),
            output_root=Path(args.output_root),
            operator_id=args.operator_id,
            operator_decision=args.operator_decision,
            operator_statement=args.operator_statement,
            selected_participant=args.selected_participant,
            allowed_changed_files=args.allowed_changed_file,
            ack_reconciliation=bool(args.ack_reconciliation),
        )
    else:
        report = validate_closeout(Path(args.closeout), output=Path(args.output) if args.output else None)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_closeout(
    *,
    execution_summary_path: Path,
    frontend_root: Path,
    output_root: Path,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    selected_participant: str | None = None,
    allowed_changed_files: list[str] | None = None,
    ack_reconciliation: bool = False,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    execution = _read_json(execution_summary_path, failures, "execution summary")
    _validate_execution_summary(execution, failures)
    mediation_path = _path_from_ref((execution.get("artifacts") or {}).get("mediation")) if isinstance(execution, dict) else None
    mediation = _read_json(mediation_path, failures, "mediation summary") if mediation_path else {}
    _validate_mediation_summary(mediation, failures)
    packet_path = _path_from_ref((execution.get("artifacts") or {}).get("packet")) if isinstance(execution, dict) else None
    packet = _read_json(packet_path, failures, "frontend packet summary") if packet_path else {}
    scenario_binding = _scenario_binding(packet)
    outputs = _collect_outputs(mediation, failures)
    verdicts = _verdict_counts(outputs)
    frontend_state = _frontend_state(frontend_root)
    selected_output = _select_output(outputs, selected_participant, failures)
    allowed = sorted({str(item).strip() for item in (allowed_changed_files or []) if str(item).strip()})
    _validate_operator_reconciliation(
        operator_id=operator_id,
        operator_decision=operator_decision,
        operator_statement=operator_statement,
        selected_output=selected_output,
        outputs=outputs,
        verdicts=verdicts,
        frontend_state=frontend_state,
        scenario_binding=scenario_binding,
        allowed_changed_files=allowed,
        ack_reconciliation=ack_reconciliation,
        failures=failures,
    )

    passed = not failures
    source_ref = artifact_ref(execution_summary_path) if execution_summary_path.is_file() else None
    closeout_id = f"private-beta-proposer-reviewer-closeout:{_digest([source_ref, operator_decision, selected_participant, operator_statement])[:24]}" if source_ref else ""
    readiness = _readiness(passed, operator_decision)
    report = {
        "schema_version": CLOSEOUT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="review",
            plane="governance",
            schema_version=CLOSEOUT_SCHEMA,
            artifact_id=closeout_id or "private-beta-proposer-reviewer-closeout:blocked",
            subject_id="private-beta-controlled-proposer-reviewer",
            producer="private_beta_proposer_reviewer_closeout",
            source_refs=[source_ref] if source_ref else [],
            scope="controlled_proposer_reviewer_output_reconciliation",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": _decision(passed, operator_decision),
        "failure_reasons": failures,
        "closeout_id": closeout_id,
        "source_execution_summary": source_ref,
        "source_mediation_summary": artifact_ref(mediation_path) if mediation_path and mediation_path.is_file() else None,
        "source_frontend_packet": artifact_ref(packet_path) if packet_path and packet_path.is_file() else None,
        "authorization_id": execution.get("authorization_id"),
        "scenario_binding": scenario_binding,
        "operator_reconciliation": {
            "operator_id": operator_id,
            "operator_decision": operator_decision,
            "operator_statement": operator_statement,
            "selected_participant": selected_output.get("participant_id") if selected_output else None,
            "selected_verdict": selected_output.get("verdict") if selected_output else None,
            "allowed_changed_files_for_future_request": allowed,
        },
        "agent_output_summary": {
            "output_count": len(outputs),
            "verdict_counts": verdicts,
            "outputs": outputs,
        },
        "frontend_state": frontend_state,
        "readiness": readiness,
        "bounded_apply_request_input": _bounded_apply_input(
            ready=readiness["bounded_apply_authorization_request_ready"],
            execution_summary_path=execution_summary_path,
            mediation_path=mediation_path,
            allowed_changed_files=allowed,
        ),
        "boundary": _boundary(),
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "private_beta_proposer_reviewer_closeout.json", report)
    summary = _summary(report, output_root / "private_beta_proposer_reviewer_closeout.json")
    _write_json(output_root / "private_beta_proposer_reviewer_closeout_summary.json", summary)
    return summary


def validate_closeout(path: Path, *, output: Path | None = None) -> dict[str, Any]:
    failures: list[str] = []
    closeout = _read_json(path, failures, "closeout")
    if closeout.get("schema_version") != CLOSEOUT_SCHEMA:
        failures.append(f"closeout schema_version must be {CLOSEOUT_SCHEMA}")
    if closeout.get("passed") is not True:
        failures.append("closeout must be passed")
    if str((closeout.get("operator_reconciliation") or {}).get("operator_decision") or "") not in OPERATOR_DECISIONS:
        failures.append("operator_decision is invalid")
    _validate_false_boundary(closeout.get("boundary"), failures, "closeout boundary")
    readiness = closeout.get("readiness") if isinstance(closeout.get("readiness"), dict) else {}
    if readiness.get("bounded_apply_authorization_granted") is not False:
        failures.append("closeout must not grant bounded apply authorization")
    source = closeout.get("source_execution_summary")
    if not isinstance(source, dict) or not source.get("path") or not source.get("sha256"):
        failures.append("closeout must include source execution summary artifact ref")
    report = {
        "schema_version": VALIDATION_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "closeout": artifact_ref(path) if path.is_file() else {"path": str(path.resolve()), "sha256": None},
        "closeout_id": closeout.get("closeout_id"),
        "readiness": {
            "closeout_valid": not failures,
            "bounded_apply_authorization_request_ready": readiness.get("bounded_apply_authorization_request_ready") is True and not failures,
        },
    }
    if output:
        _write_json(output, report)
    return report


def _validate_execution_summary(execution: Any, failures: list[str]) -> None:
    if not isinstance(execution, dict):
        failures.append("execution summary must be an object")
        return
    if execution.get("schema_version") != EXECUTION_SCHEMA:
        failures.append(f"execution summary schema_version must be {EXECUTION_SCHEMA}")
    if execution.get("passed") is not True:
        failures.append("execution summary must be passed")
    if execution.get("decision") != "private_beta_controlled_proposer_reviewer_execution_passed":
        failures.append("execution summary decision must be passed")
    readiness = execution.get("readiness") if isinstance(execution.get("readiness"), dict) else {}
    if readiness.get("proposer_reviewer_outputs_ready_for_closeout") is not True:
        failures.append("execution outputs must be ready for closeout")
    _validate_false_boundary(execution.get("boundary"), failures, "execution boundary", allow_true={"authorization_consumed", "agent_execution_performed", "patch_proposal_generated", "release_review_generated"})


def _validate_mediation_summary(mediation: Any, failures: list[str]) -> None:
    if not isinstance(mediation, dict):
        failures.append("mediation summary must be an object")
        return
    if mediation.get("schema_version") != MEDIATION_SCHEMA:
        failures.append(f"mediation summary schema_version must be {MEDIATION_SCHEMA}")
    if mediation.get("passed") is not True:
        failures.append("mediation summary must be passed")
    if int(mediation.get("task_receipt_count") or 0) < 1:
        failures.append("mediation summary must include task receipts")
    _validate_false_boundary(mediation.get("boundary"), failures, "mediation boundary", allow_true={"authorization_consumed", "agent_execution_performed", "patch_proposal_generated", "release_review_generated"})


def _collect_outputs(mediation: dict[str, Any], failures: list[str]) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []
    for ref in mediation.get("task_receipts") or []:
        receipt_path = _path_from_ref(ref)
        receipt = _read_json(receipt_path, failures, "task receipt") if receipt_path else {}
        if receipt.get("schema_version") != TASK_RECEIPT_SCHEMA:
            failures.append(f"task receipt schema_version must be {TASK_RECEIPT_SCHEMA}: {receipt_path}")
            continue
        generation_path = _path_from_ref(receipt.get("generation_response"))
        content = generation_path.read_text(encoding="utf-8") if generation_path and generation_path.is_file() else ""
        if not content:
            failures.append(f"generation content missing for {receipt.get('participant_id')}")
        verdict = extract_verdict(content)
        outputs.append(
            {
                "participant_id": receipt.get("participant_id"),
                "runner_kind": receipt.get("runner_kind"),
                "task_id": receipt.get("task_id"),
                "final_status": (receipt.get("final_task") or {}).get("status"),
                "claim_observed": receipt.get("claim_observed") is True,
                "generation_observed_after_claim": receipt.get("generation_observed_after_claim") is True,
                "delivery_observed": receipt.get("delivery_observed") is True,
                "verdict": verdict,
                "generation_response": artifact_ref(generation_path) if generation_path and generation_path.is_file() else None,
                "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None,
                "content_excerpt": content[:1400],
            }
        )
    return outputs


def _validate_operator_reconciliation(
    *,
    operator_id: str,
    operator_decision: str,
    operator_statement: str,
    selected_output: dict[str, Any] | None,
    outputs: list[dict[str, Any]],
    verdicts: dict[str, int],
    frontend_state: dict[str, Any],
    scenario_binding: dict[str, Any],
    allowed_changed_files: list[str],
    ack_reconciliation: bool,
    failures: list[str],
) -> None:
    if ack_reconciliation is not True:
        failures.append("explicit proposer/reviewer closeout acknowledgement is required")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if operator_decision not in OPERATOR_DECISIONS:
        failures.append("operator_decision is invalid")
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if not outputs:
        failures.append("at least one Agent output is required")
    if selected_output is None and operator_decision in {"closeout_no_apply", "approve_bounded_apply_request"}:
        failures.append("selected_participant is required for closeout_no_apply or approve_bounded_apply_request")
    if operator_decision == "approve_bounded_apply_request":
        if verdicts.get("reject", 0):
            failures.append("bounded apply request cannot be approved while any Agent verdict is reject")
        if verdicts.get("revise", 0) and not _statement_records_revision_constraints(operator_statement):
            failures.append("bounded apply request with revise verdict requires explicit revision constraints in operator_statement")
        if _is_app_shell_panel_registry_slice(scenario_binding) and frontend_state.get("app_shell_panel_registry_already_decomposed") is True:
            failures.append("bounded apply request is not appropriate: app shell/panel registry decomposition already exists")
        if not allowed_changed_files:
            failures.append("allowed_changed_files are required before bounded apply request input can be ready")
    if operator_decision == "closeout_no_apply":
        if _is_app_shell_panel_registry_slice(scenario_binding) and frontend_state.get("app_shell_panel_registry_already_decomposed") is not True:
            failures.append("closeout_no_apply requires evidence that app shell/panel registry decomposition already exists")
    if operator_decision == "request_revision" and not (verdicts.get("revise", 0) or verdicts.get("reject", 0)):
        failures.append("request_revision requires at least one revise or reject verdict")


def _select_output(outputs: list[dict[str, Any]], selected_participant: str | None, failures: list[str]) -> dict[str, Any] | None:
    if not selected_participant:
        return None
    for output in outputs:
        if output.get("participant_id") == selected_participant:
            return output
    failures.append(f"selected_participant not found in Agent outputs: {selected_participant}")
    return None


def _verdict_counts(outputs: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"proceed": 0, "revise": 0, "reject": 0, "inconclusive": 0}
    for output in outputs:
        verdict = str(output.get("verdict") or "inconclusive")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def _frontend_state(frontend_root: Path) -> dict[str, Any]:
    root = frontend_root.resolve()
    app_shell = root / "src/app/AppShell.tsx"
    registry = root / "src/app/panelRegistry.ts"
    registry_test = root / "src/app/panelRegistry.test.ts"
    return {
        "frontend_root": str(root),
        "head_commit": _git(root, "rev-parse", "HEAD"),
        "head_short": _git(root, "rev-parse", "--short", "HEAD"),
        "status_short": [line for line in _git(root, "status", "--short").splitlines() if line.strip()],
        "focus_file_lines": {
            "src/App.tsx": _line_count(root / "src/App.tsx"),
            "src/app/AppShell.tsx": _line_count(app_shell),
            "src/app/panelRegistry.ts": _line_count(registry),
            "src/app/panelRegistry.test.ts": _line_count(registry_test),
        },
        "app_shell_present": app_shell.is_file(),
        "panel_registry_present": registry.is_file(),
        "panel_registry_test_present": registry_test.is_file(),
        "app_shell_panel_registry_already_decomposed": app_shell.is_file() and registry.is_file() and registry_test.is_file(),
    }


def _scenario_binding(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "scenario_id": packet.get("scenario_id") if isinstance(packet, dict) else None,
        "patch_slice_id": packet.get("patch_slice_id") if isinstance(packet, dict) else None,
        "stage": packet.get("stage") if isinstance(packet, dict) else None,
    }


def _is_app_shell_panel_registry_slice(scenario_binding: dict[str, Any]) -> bool:
    return scenario_binding.get("patch_slice_id") == "app_shell_panel_registry_decomposition"


def _statement_records_revision_constraints(operator_statement: str) -> bool:
    statement = operator_statement.lower()
    return any(token in statement for token in ("revision", "revise", "constraint", "条件", "修订", "约束"))


def _readiness(passed: bool, operator_decision: str) -> dict[str, bool]:
    return {
        "proposer_reviewer_closeout_complete": passed,
        "operator_reconciliation_recorded": passed,
        "bounded_apply_authorization_request_ready": passed and operator_decision == "approve_bounded_apply_request",
        "bounded_apply_authorization_granted": False,
        "source_apply_ready": False,
        "commit_authorized": False,
        "push_authorized": False,
        "deploy_authorized": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _bounded_apply_input(*, ready: bool, execution_summary_path: Path, mediation_path: Path | None, allowed_changed_files: list[str]) -> dict[str, Any]:
    return {
        "ready": ready,
        "source_execution_summary": artifact_ref(execution_summary_path) if execution_summary_path.is_file() else None,
        "source_mediation_summary": artifact_ref(mediation_path) if mediation_path and mediation_path.is_file() else None,
        "allowed_changed_files": allowed_changed_files,
        "next_gate": "beta_fe3_bounded_apply_authorization_request" if ready else None,
        "single_use_authorization_required_separately": True,
    }


def _summary(closeout: dict[str, Any], closeout_path: Path) -> dict[str, Any]:
    readiness = closeout.get("readiness") if isinstance(closeout.get("readiness"), dict) else {}
    operator = closeout.get("operator_reconciliation") if isinstance(closeout.get("operator_reconciliation"), dict) else {}
    return {
        "schema_version": "private-beta-controlled-proposer-reviewer-closeout-summary:v1",
        "checked_at": _now(),
        "passed": closeout.get("passed") is True,
        "decision": closeout.get("decision"),
        "failure_reasons": closeout.get("failure_reasons", []),
        "closeout_id": closeout.get("closeout_id"),
        "closeout": artifact_ref(closeout_path) if closeout_path.is_file() else None,
        "operator_decision": operator.get("operator_decision"),
        "selected_participant": operator.get("selected_participant"),
        "verdict_counts": (closeout.get("agent_output_summary") or {}).get("verdict_counts"),
        "scenario_binding": closeout.get("scenario_binding"),
        "readiness": readiness,
        "boundary": closeout.get("boundary"),
        "h3_boundary": closeout.get("h3_boundary"),
    }


def _decision(passed: bool, operator_decision: str) -> str:
    if not passed:
        return "blocked"
    return {
        "closeout_no_apply": "controlled_proposer_reviewer_closed_without_apply",
        "approve_bounded_apply_request": "controlled_proposer_reviewer_ready_for_bounded_apply_request",
        "request_revision": "controlled_proposer_reviewer_revision_requested",
        "reject": "controlled_proposer_reviewer_rejected",
    }[operator_decision]


def _boundary() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARY_FIELDS}


def _validate_false_boundary(value: Any, failures: list[str], label: str, allow_true: set[str] | None = None) -> None:
    boundary = value if isinstance(value, dict) else {}
    allowed = allow_true or set()
    for key, current in boundary.items():
        if key in allowed:
            continue
        if key in FALSE_BOUNDARY_FIELDS and current is not False:
            failures.append(f"{label} must keep {key}=false")


def _path_from_ref(ref: Any) -> Path | None:
    if isinstance(ref, dict) and str(ref.get("path") or "").strip():
        return Path(str(ref["path"]))
    return None


def _read_json(path: Path | None, failures: list[str], label: str) -> dict[str, Any]:
    if path is None:
        failures.append(f"{label} path is missing")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
        return {}
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True)
    return result.stdout.strip()


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.is_file() else 0


if __name__ == "__main__":
    raise SystemExit(main())
