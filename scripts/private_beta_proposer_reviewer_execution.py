#!/usr/bin/env python3
"""Execute one private Beta controlled proposer/reviewer run.

This execution gate consumes a single-use private Beta proposer/reviewer
authorization, reuses previously registered CivitasOS Agent identities from the
source private Beta package, posts pool tasks, requires each Agent runner to
claim/generate/deliver, and writes runtime receipts. It never applies code,
commits, pushes, merges, deploys, opens public ingress, executes production
runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope

try:
    import beta_fe26_agent_runner_mediation as fe26
    import beta_fe_frontend_four_agent_orchestrator as four_agent
except ModuleNotFoundError:
    from scripts import beta_fe26_agent_runner_mediation as fe26
    from scripts import beta_fe_frontend_four_agent_orchestrator as four_agent

AUTHORIZATION_SCHEMA = "private-beta-controlled-proposer-reviewer-single-use-authorization:v1"
EXECUTION_SCHEMA = "private-beta-controlled-proposer-reviewer-execution:v1"
CONSUMPTION_SCHEMA = "private-beta-controlled-proposer-reviewer-authorization-consumption:v1"
LEASE_SCHEMA = "private-beta-controlled-proposer-reviewer-authorization-consumption-lease:v1"
PACKAGE_SCHEMA = "private-beta-deployment-package:v1"
FE26_SCHEMA = "beta-fe26-agent-runner-mediation-summary:v1"
TASK_RECEIPT_SCHEMA = "beta-fe26-agent-runner-task-receipt:v1"
NON_CLAIMS = (
    "private_beta_proposer_reviewer_execution_does_not_apply_code",
    "private_beta_proposer_reviewer_execution_does_not_commit_push_merge_or_deploy",
    "private_beta_proposer_reviewer_execution_does_not_open_public_ingress",
    "private_beta_proposer_reviewer_execution_does_not_write_production_receipts",
    "private_beta_proposer_reviewer_outputs_require_closeout_before_any_bounded_apply",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--backend-url", default=fe26.DEFAULT_BACKEND_URL)
    parser.add_argument("--scenario", choices=sorted(four_agent.SCENARIOS), default="fe13-app-shell-decomposition")
    parser.add_argument("--runner-spec", action="append", default=[])
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-token-secret-file")
    parser.add_argument("--service-id", default="private_beta_proposer_reviewer_execution")
    parser.add_argument("--authorization-consumption-path")
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-statement", default="Consume one private Beta proposer/reviewer authorization and execute only patch proposal/release review tasks.")
    parser.add_argument("--ack-consume-authorization", action="store_true")
    args = parser.parse_args(argv)
    summary = run_execution(
        authorization_path=Path(args.authorization),
        frontend_root=Path(args.frontend_root),
        output_root=Path(args.output_root),
        backend_url=args.backend_url,
        scenario_id=args.scenario,
        runner_specs=args.runner_spec,
        service_token_secret=fe26._resolve_service_token_secret(args.service_token_secret, args.service_token_secret_file),
        service_id=args.service_id,
        authorization_consumption_path=Path(args.authorization_consumption_path) if args.authorization_consumption_path else None,
        operator_id=args.operator_id,
        operator_statement=args.operator_statement,
        ack_consume_authorization=bool(args.ack_consume_authorization),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


def run_execution(
    *,
    authorization_path: Path,
    frontend_root: Path,
    output_root: Path,
    backend_url: str,
    scenario_id: str,
    runner_specs: list[str],
    service_token_secret: str | None,
    service_id: str,
    authorization_consumption_path: Path | None,
    operator_id: str,
    operator_statement: str,
    ack_consume_authorization: bool,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    authorization = _read_json(authorization_path, failures, "authorization")
    _validate_authorization(authorization, failures)
    package_path = _path_from_ref(authorization.get("source_private_beta_package"))
    package = _read_json(package_path, failures, "source private Beta package") if package_path else {}
    _validate_package(package, failures)
    source_mediation_path = _path_from_ref((package.get("source_artifacts") or {}).get("mediation_summary")) if isinstance(package, dict) else None
    source_mediation = _read_json(source_mediation_path, failures, "source FE26 mediation summary") if source_mediation_path else {}
    identities = _identity_context(source_mediation, failures)
    scope = authorization.get("authorized_scope") if isinstance(authorization.get("authorized_scope"), dict) else {}
    participants = _authorized_participants(scope)
    generators = _parse_generators(runner_specs, participants, failures)
    effective_service_token_secret = (
        service_token_secret
        or os.getenv("CIVITASOS_FE_MEDIATION_SERVICE_TOKEN_SECRET")
        or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET")
    )
    if not effective_service_token_secret:
        failures.append("service token secret is required via env or --service-token-secret-file")
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not operator_statement.strip():
        failures.append("operator_statement is required")
    if ack_consume_authorization is not True:
        failures.append("explicit authorization consumption acknowledgement is required")
    _validate_scenario_binding(authorization, scenario_id, failures)
    if failures:
        summary = _blocked_summary(output_root, authorization_path, failures)
        _write_json(output_root / "private_beta_proposer_reviewer_execution_summary.json", summary)
        return summary

    lease_path = authorization_consumption_path or _default_consumption_lease_path(authorization_path)
    consumption = _consume_authorization(
        authorization=authorization,
        authorization_path=authorization_path,
        output=output_root / "private_beta_proposer_reviewer_authorization_consumption.json",
        lease_path=lease_path,
        operator_id=operator_id,
        operator_statement=operator_statement,
    )
    if consumption.get("passed") is not True:
        summary = _blocked_summary(output_root, authorization_path, list(consumption.get("failure_reasons") or []), consumption=consumption)
        _write_json(output_root / "private_beta_proposer_reviewer_execution_summary.json", summary)
        return summary

    scenario = four_agent.SCENARIOS[scenario_id]
    packet = four_agent.write_packet(scenario=scenario, frontend_root=frontend_root.resolve(), output_root=output_root)
    packet_path = output_root / "frontend_four_agent_packet_summary.json"
    mediation_root = output_root / "mediation"
    mediation_root.mkdir(parents=True, exist_ok=True)
    client = fe26.HttpJsonClient(
        backend_url,
        service_token_secret=effective_service_token_secret,
        service_id=service_id,
        service_scopes=list(scope.get("service_token_scopes") or []),
        require_service_token=True,
    )
    try:
        receipts = _run_participants(
            client=client,
            packet=packet,
            packet_path=packet_path,
            identities=identities,
            generators=generators,
            participants=participants,
            mediation_root=mediation_root,
        )
        mediation = _write_mediation_summary(
            output=mediation_root / "private_beta_proposer_reviewer_mediation_summary.json",
            backend_url=backend_url,
            client=client,
            packet_path=packet_path,
            receipts=receipts,
            participants=participants,
        )
    except Exception as exc:  # noqa: BLE001
        mediation = _write_blocked_mediation_summary(
            output=mediation_root / "private_beta_proposer_reviewer_mediation_summary.json",
            backend_url=backend_url,
            packet_path=packet_path,
            participants=participants,
            mediation_root=mediation_root,
            error=str(exc),
        )
    receipt_report = _write_execution_receipt(
        output=output_root / "private_beta_proposer_reviewer_execution_receipt.json",
        authorization_path=authorization_path,
        consumption_path=output_root / "private_beta_proposer_reviewer_authorization_consumption.json",
        packet_path=packet_path,
        mediation_path=mediation_root / "private_beta_proposer_reviewer_mediation_summary.json",
        mediation=mediation,
        authorization=authorization,
    )
    summary = _summary(
        output_root=output_root,
        authorization_path=authorization_path,
        consumption_path=output_root / "private_beta_proposer_reviewer_authorization_consumption.json",
        packet_path=packet_path,
        mediation_path=mediation_root / "private_beta_proposer_reviewer_mediation_summary.json",
        receipt_path=output_root / "private_beta_proposer_reviewer_execution_receipt.json",
        consumption=consumption,
        mediation=mediation,
        receipt_report=receipt_report,
        authorization=authorization,
    )
    _write_json(output_root / "private_beta_proposer_reviewer_execution_summary.json", summary)
    return summary


def _validate_authorization(authorization: Any, failures: list[str]) -> None:
    if not isinstance(authorization, dict):
        failures.append("authorization must be an object")
        return
    if authorization.get("schema_version") != AUTHORIZATION_SCHEMA:
        failures.append(f"authorization schema_version must be {AUTHORIZATION_SCHEMA}")
    if authorization.get("passed") is not True:
        failures.append("authorization must be passed")
    if authorization.get("decision") != "controlled_proposer_reviewer_authorized_once":
        failures.append("authorization decision must authorize controlled proposer/reviewer once")
    if authorization.get("single_use") is not True or authorization.get("consumed") is not False:
        failures.append("authorization must be single_use and unconsumed")
    scope = authorization.get("authorized_scope") if isinstance(authorization.get("authorized_scope"), dict) else {}
    if scope.get("max_proposals") != 1:
        failures.append("authorization max_proposals must be 1")
    if int(scope.get("max_reviews") or 0) < 1:
        failures.append("authorization max_reviews must be positive")
    if set(scope.get("allowed_modes") or []) != {"patch_proposal", "release_review"}:
        failures.append("authorization must allow exactly patch_proposal and release_review")
    forbidden = set(scope.get("forbidden_actions") or [])
    required_forbidden = {"apply", "commit", "push", "merge", "deploy", "public_ingress", "production_runtime_execution", "production_receipt_write"}
    if not required_forbidden.issubset(forbidden):
        failures.append("authorization missing required forbidden actions")
    boundary = authorization.get("boundary") if isinstance(authorization.get("boundary"), dict) else {}
    if boundary.get("patch_proposal_allowed") is not True or boundary.get("release_review_allowed") is not True:
        failures.append("authorization boundary must allow patch proposal and release review")
    for key in ("apply_allowed", "commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "external_public_ingress_opened", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"authorization boundary must keep {key}=false")


def _validate_scenario_binding(authorization: dict[str, Any], scenario_id: str, failures: list[str]) -> None:
    scope = authorization.get("authorized_scope") if isinstance(authorization.get("authorized_scope"), dict) else {}
    bound_scenario = str(scope.get("scenario_id") or "").strip()
    bound_slice = str(scope.get("patch_slice_id") or "").strip()
    if not bound_scenario and not bound_slice:
        return
    if not bound_scenario or not bound_slice:
        failures.append("authorization scenario binding is incomplete")
        return
    if bound_scenario != scenario_id:
        failures.append(f"execution scenario must match authorization scenario_id: {bound_scenario}")
        return
    scenario = four_agent.SCENARIOS.get(scenario_id)
    if scenario is None:
        failures.append(f"execution scenario is unknown: {scenario_id}")
        return
    if scenario.patch_slice_id != bound_slice:
        failures.append(f"execution patch_slice_id must match authorization patch_slice_id: {bound_slice}")


def _validate_package(package: Any, failures: list[str]) -> None:
    if not isinstance(package, dict):
        failures.append("source private Beta package must be an object")
        return
    if package.get("schema_version") != PACKAGE_SCHEMA or package.get("passed") is not True:
        failures.append("source private Beta package must be passed")
    readiness = package.get("readiness") if isinstance(package.get("readiness"), dict) else {}
    if readiness.get("controlled_proposer_reviewer_extension_ready") is not True:
        failures.append("source private Beta package must be ready for controlled proposer/reviewer extension")


def _identity_context(source_mediation: Any, failures: list[str]) -> dict[str, Any]:
    if not isinstance(source_mediation, dict):
        failures.append("source FE26 mediation summary must be an object")
        return {"requester": {}, "workers": {}}
    if source_mediation.get("schema_version") != FE26_SCHEMA or source_mediation.get("passed") is not True:
        failures.append("source FE26 mediation summary must be passed")
    requester = source_mediation.get("requester") if isinstance(source_mediation.get("requester"), dict) else {}
    workers: dict[str, dict[str, Any]] = {}
    for ref in source_mediation.get("task_receipts") or []:
        path = _path_from_ref(ref)
        receipt = _read_json(path, failures, "source FE26 task receipt") if path else {}
        if receipt.get("schema_version") != TASK_RECEIPT_SCHEMA:
            failures.append(f"source FE26 task receipt schema_version must be {TASK_RECEIPT_SCHEMA}: {path}")
            continue
        participant_id = str(receipt.get("participant_id") or "")
        worker = receipt.get("worker") if isinstance(receipt.get("worker"), dict) else {}
        if participant_id and worker.get("did"):
            workers[participant_id] = worker
    if not requester.get("did"):
        failures.append("source FE26 mediation requester DID is required")
    return {"requester": requester, "workers": workers}


def _authorized_participants(scope: dict[str, Any]) -> list[str]:
    return [*list(scope.get("proposer_agents") or []), *list(scope.get("reviewer_agents") or [])]


def _parse_generators(runner_specs: list[str], participants: list[str], failures: list[str]) -> dict[str, fe26.AgentResponseGenerator]:
    try:
        generators = fe26._parse_runner_specs(runner_specs)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"runner spec parsing failed: {exc}")
        return {}
    missing = sorted(set(participants) - set(generators))
    if missing:
        failures.append(f"missing runner specs for authorized participant(s): {missing}")
    return generators


def _consume_authorization(*, authorization: dict[str, Any], authorization_path: Path, output: Path, lease_path: Path, operator_id: str, operator_statement: str) -> dict[str, Any]:
    failures: list[str] = []
    lease = {
        "schema_version": LEASE_SCHEMA,
        "consumed_at": _now(),
        "authorization_id": authorization.get("authorization_id"),
        "authorization": artifact_ref(authorization_path),
        "operator_id": operator_id,
        "operator_statement": operator_statement,
    }
    try:
        lease_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lease_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(lease, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError:
        failures.append(f"authorization already consumed: {lease_path}")
    passed = not failures
    report = {
        "schema_version": CONSUMPTION_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "failure_reasons": failures,
        "authorization_id": authorization.get("authorization_id"),
        "authorization": artifact_ref(authorization_path),
        "lease": artifact_ref(lease_path) if lease_path.is_file() else {"path": str(lease_path.resolve()), "sha256": None},
        "single_use_consumed": passed,
        "boundary": _boundary(authorization_consumed=passed, agent_execution_performed=False),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output, report)
    return report


def _run_participants(*, client: fe26.HttpJsonClient, packet: dict[str, Any], packet_path: Path, identities: dict[str, Any], generators: dict[str, fe26.AgentResponseGenerator], participants: list[str], mediation_root: Path) -> list[dict[str, Any]]:
    client.healthz()
    requester = identities["requester"]
    workers = identities["workers"]
    receipts: list[dict[str, Any]] = []
    packet_participants = {str(item.get("participant_id")): item for item in packet.get("participants", []) if isinstance(item, dict)}
    for participant_id in participants:
        participant = packet_participants[participant_id]
        worker = workers.get(participant_id)
        if not worker:
            raise RuntimeError(f"missing reusable worker identity for {participant_id}")
        prompt_ref = packet.get("agent_prompt_refs", {}).get(participant_id)
        prompt_path = Path(str((prompt_ref or {}).get("path") or ""))
        receipt = fe26._post_claim_generate_deliver(
            client=client,
            requester=requester,
            worker=worker,
            participant=participant,
            fe2_packet=packet,
            fe2_packet_summary_path=packet_path,
            prompt_path=prompt_path,
            generator=generators[participant_id],
            output_root=mediation_root,
            confirm_delivery=False,
        )
        receipts.append(receipt)
        _write_json(mediation_root / f"{participant_id}.task_receipt.json", receipt)
    return receipts


def _write_mediation_summary(*, output: Path, backend_url: str, client: fe26.HttpJsonClient, packet_path: Path, receipts: list[dict[str, Any]], participants: list[str]) -> dict[str, Any]:
    statuses = [str(receipt.get("final_task", {}).get("status") or "") for receipt in receipts]
    passed = len(receipts) == len(participants) and all(status in {"Delivered", "Completed"} for status in statuses)
    passed = passed and all(receipt.get("claim_observed") is True and receipt.get("generation_observed_after_claim") is True and receipt.get("delivery_observed") is True for receipt in receipts)
    report = {
        "schema_version": "private-beta-controlled-proposer-reviewer-mediation:v1",
        "checked_at": _now(),
        "passed": passed,
        "decision": "controlled_proposer_reviewer_mediation_passed" if passed else "blocked",
        "failure_reasons": [] if passed else ["all authorized proposer/reviewer tasks must claim, generate after claim, and deliver"],
        "backend_url": backend_url,
        "backend_auth": fe26._auth_report(client),
        "source_packet": artifact_ref(packet_path),
        "participant_ids": participants,
        "task_receipt_count": len(receipts),
        "task_receipts": [artifact_ref(output.parent / f"{receipt['participant_id']}.task_receipt.json") for receipt in receipts],
        "task_ids": [receipt.get("task_id") for receipt in receipts],
        "final_statuses": statuses,
        "claim_observed_count": sum(1 for receipt in receipts if receipt.get("claim_observed") is True),
        "generation_after_claim_observed_count": sum(1 for receipt in receipts if receipt.get("generation_observed_after_claim") is True),
        "delivery_observed_count": sum(1 for receipt in receipts if receipt.get("delivery_observed") is True),
        "boundary": _boundary(authorization_consumed=True, agent_execution_performed=bool(receipts)),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output, report)
    return report


def _write_blocked_mediation_summary(*, output: Path, backend_url: str, packet_path: Path, participants: list[str], mediation_root: Path, error: str) -> dict[str, Any]:
    partial_receipts = _load_partial_receipts(mediation_root)
    statuses = [str(receipt.get("final_task", {}).get("status") or "") for receipt in partial_receipts]
    report = {
        "schema_version": "private-beta-controlled-proposer-reviewer-mediation:v1",
        "checked_at": _now(),
        "passed": False,
        "decision": "blocked",
        "failure_reasons": [f"controlled proposer/reviewer runner failed: {error}"],
        "backend_url": backend_url,
        "backend_auth": {"auth_method": "unavailable_after_failure", "token_recorded": False},
        "source_packet": artifact_ref(packet_path) if packet_path.is_file() else {"path": str(packet_path.resolve()), "sha256": None},
        "participant_ids": participants,
        "task_receipt_count": len(partial_receipts),
        "task_receipts": [artifact_ref(mediation_root / f"{receipt['participant_id']}.task_receipt.json") for receipt in partial_receipts if receipt.get("participant_id")],
        "task_ids": [receipt.get("task_id") for receipt in partial_receipts],
        "final_statuses": statuses,
        "claim_observed_count": sum(1 for receipt in partial_receipts if receipt.get("claim_observed") is True),
        "generation_after_claim_observed_count": sum(1 for receipt in partial_receipts if receipt.get("generation_observed_after_claim") is True),
        "delivery_observed_count": sum(1 for receipt in partial_receipts if receipt.get("delivery_observed") is True),
        "boundary": _boundary(authorization_consumed=True, agent_execution_performed=bool(partial_receipts)),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output, report)
    return report


def _write_execution_receipt(*, output: Path, authorization_path: Path, consumption_path: Path, packet_path: Path, mediation_path: Path, mediation: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any]:
    passed = mediation.get("passed") is True
    report = {
        "schema_version": "private-beta-controlled-proposer-reviewer-execution-receipt:v1",
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version="private-beta-controlled-proposer-reviewer-execution-receipt:v1",
            artifact_id=f"private-beta-proposer-reviewer-exec:{str(authorization.get('authorization_id') or '').split(':')[-1]}",
            subject_id="private-beta-controlled-proposer-reviewer",
            producer="private_beta_proposer_reviewer_execution",
            source_refs=[artifact_ref(authorization_path), artifact_ref(consumption_path), artifact_ref(packet_path), artifact_ref(mediation_path)],
            scope="single_use_controlled_proposer_reviewer_execution",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "controlled_proposer_reviewer_execution_complete" if passed else "blocked",
        "failure_reasons": [] if passed else list(mediation.get("failure_reasons") or []),
        "authorization_id": authorization.get("authorization_id"),
        "authorization_consumed": True,
        "agent_execution_performed": mediation.get("task_receipt_count", 0) > 0,
        "mediation_summary": artifact_ref(mediation_path),
        "boundary": _boundary(authorization_consumed=True, agent_execution_performed=mediation.get("task_receipt_count", 0) > 0),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output, report)
    return report


def _summary(*, output_root: Path, authorization_path: Path, consumption_path: Path, packet_path: Path, mediation_path: Path, receipt_path: Path, consumption: dict[str, Any], mediation: dict[str, Any], receipt_report: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any]:
    passed = consumption.get("passed") is True and mediation.get("passed") is True and receipt_report.get("passed") is True
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "private_beta_controlled_proposer_reviewer_execution_passed" if passed else "blocked",
        "failure_reasons": _failures(consumption, mediation, receipt_report),
        "authorization_id": authorization.get("authorization_id"),
        "source_artifacts": {"authorization": artifact_ref(authorization_path)},
        "artifacts": {
            "authorization_consumption": artifact_ref(consumption_path),
            "packet": artifact_ref(packet_path),
            "mediation": artifact_ref(mediation_path),
            "execution_receipt": artifact_ref(receipt_path),
        },
        "task_receipt_count": mediation.get("task_receipt_count"),
        "claim_observed_count": mediation.get("claim_observed_count"),
        "generation_after_claim_observed_count": mediation.get("generation_after_claim_observed_count"),
        "delivery_observed_count": mediation.get("delivery_observed_count"),
        "readiness": {
            "controlled_proposer_reviewer_execution_complete": passed,
            "authorization_consumed": consumption.get("passed") is True,
            "proposer_reviewer_outputs_ready_for_closeout": passed,
            "bounded_apply_authorized": False,
            "commit_authorized": False,
            "push_authorized": False,
            "deploy_authorized": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "boundary": _boundary(authorization_consumed=consumption.get("passed") is True, agent_execution_performed=mediation.get("task_receipt_count", 0) > 0),
        "non_claims": list(NON_CLAIMS),
    }
    return report


def _blocked_summary(output_root: Path, authorization_path: Path, failures: list[str], consumption: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_version": EXECUTION_SCHEMA,
        "checked_at": _now(),
        "passed": False,
        "decision": "blocked",
        "failure_reasons": failures,
        "source_artifacts": {"authorization": artifact_ref(authorization_path) if authorization_path.is_file() else {"path": str(authorization_path.resolve()), "sha256": None}},
        "artifacts": {"authorization_consumption": consumption} if consumption else {},
        "readiness": {"controlled_proposer_reviewer_execution_complete": False, "authorization_consumed": consumption.get("passed") is True if consumption else False},
        "boundary": _boundary(authorization_consumed=consumption.get("passed") is True if consumption else False, agent_execution_performed=False),
        "non_claims": list(NON_CLAIMS),
    }


def _boundary(*, authorization_consumed: bool, agent_execution_performed: bool) -> dict[str, Any]:
    return {
        "authorization_consumed": authorization_consumed,
        "agent_execution_performed": agent_execution_performed,
        "patch_proposal_generated": agent_execution_performed,
        "release_review_generated": agent_execution_performed,
        "frontend_code_modified": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "external_public_ingress_opened": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "service_token_secret_recorded": False,
    }


def _failures(*reports: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for report in reports:
        for item in report.get("failure_reasons", []):
            text = str(item)
            if text and text not in seen:
                out.append(text)
                seen.add(text)
    return out


def _load_partial_receipts(mediation_root: Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for path in sorted(mediation_root.glob("*.task_receipt.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            receipts.append(value)
    return receipts


def _default_consumption_lease_path(authorization_path: Path) -> Path:
    return authorization_path.with_suffix(authorization_path.suffix + ".consumed.json")


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
    if isinstance(payload, dict):
        return payload
    failures.append(f"{label} must be a JSON object")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
