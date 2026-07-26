"""Prepare, review, promote, and execute one J1-D container repair."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_infrastructure_repair import (
    ACTIVATION_SCHEMA,
    BOUNDARY,
    REVIEWED_SCHEMA,
    build_repair_plan,
    build_review_receipt,
    build_review_request,
    build_reviewed_repair,
    owner_review_statement,
    repair_authorization_statement,
    reviewer_statement,
    validate_repair_plan,
    validate_review_receipt,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_infrastructure_rebind import _read_private
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_infrastructure_repair.py"
OPERATION_SOURCE = Path(__file__)


def prepare_candidate(
    *,
    repair_id: str,
    created_at: str,
    parent_activation_path: Path,
    target_container_name: str,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_new_root(output_root)
    parent, parent_raw = _read_private(parent_activation_path)
    implementation = _clean_pushed_implementation(repository_root)
    live_inventory = _live_inventory(parent)
    parent_ref = _ref(
        parent_activation_path,
        parent["activation_sha256"],
        raw=parent_raw,
    )
    plan = build_repair_plan(
        repair_id=repair_id,
        created_at=created_at,
        parent_activation_ref=parent_ref,
        parent_activation=parent,
        live_inventory=live_inventory,
        target_container_name=target_container_name,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_path = output_root / "infrastructure-repair-plan.json"
    write_private_json(plan_path, plan)
    statement = owner_review_statement(
        plan, hashlib.sha256(plan_path.read_bytes()).hexdigest()
    )
    preflight = {
        "schema_version": "j1-qualification-infrastructure-repair-preflight:v1",
        "passed": True,
        "failure_reasons": [],
        "state": "single_exited_container_repair_independent_review_required",
        "plan": _ref(plan_path, plan["plan_sha256"]),
        "inventory_precondition": plan["inventory_precondition"],
        "target": plan["target"],
        "required_exact_owner_review_statement": statement,
        "owner_review_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "readiness": {
            "single_exited_target_bound": True,
            "container_mutation_performed": False,
            "independent_review_complete": False,
            "repair_authorized": False,
        },
        "execution_boundary": BOUNDARY,
    }
    preflight["report_sha256"] = canonical_sha256(preflight)
    write_private_json(output_root / "infrastructure-repair-preflight.json", preflight)
    return preflight


def prepare_review(
    *,
    request_id: str,
    created_at: str,
    owner_statement: str,
    plan_path: Path,
    preflight_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_new_root(output_root)
    plan, plan_raw = _read_private(plan_path)
    preflight, _ = _read_private(preflight_path)
    parent_path = Path(plan["parent_activation"]["path"])
    parent, _ = _read_private(parent_path)
    implementation = _clean_pushed_implementation(repository_root)
    live_inventory = _live_inventory(parent)
    failures = validate_repair_plan(
        plan,
        parent_activation=parent,
        live_inventory=live_inventory,
        expected_implementation=implementation,
    )
    expected_statement = owner_review_statement(
        plan, hashlib.sha256(plan_raw).hexdigest()
    )
    if (
        failures
        or owner_statement != expected_statement
        or preflight.get("plan") != _ref(plan_path, plan["plan_sha256"], raw=plan_raw)
        or preflight.get("owner_review_statement_sha256")
        != hashlib.sha256(owner_statement.encode()).hexdigest()
    ):
        raise ValueError("infrastructure repair owner review binding invalid")
    plan_ref = _ref(plan_path, plan["plan_sha256"], raw=plan_raw)
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        plan_ref=plan_ref,
        plan=plan,
        owner_statement_sha256=hashlib.sha256(owner_statement.encode()).hexdigest(),
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    request_path = output_root / "infrastructure-repair-review-request.json"
    write_private_json(request_path, request)
    declaration = reviewer_statement(
        request, hashlib.sha256(request_path.read_bytes()).hexdigest()
    )
    handoff = {
        "schema_version": "j1-qualification-infrastructure-repair-review-handoff:v1",
        "passed": True,
        "state": "independent_reviewer_decision_required",
        "request": _ref(request_path, request["request_sha256"]),
        "required_exact_reviewer_statement": declaration,
        "reviewer_statement_sha256": hashlib.sha256(declaration.encode()).hexdigest(),
        "execution_boundary": BOUNDARY,
    }
    handoff["report_sha256"] = canonical_sha256(handoff)
    write_private_json(
        output_root / "infrastructure-repair-review-handoff.json", handoff
    )
    return handoff


def promote_review(
    *,
    review_id: str,
    reviewed_at: str,
    review_statement_value: str,
    plan_path: Path,
    review_request_path: Path,
    review_handoff_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    repository_root: Path,
    output_root: Path,
    pin: str,
) -> dict[str, Any]:
    _require_new_root(output_root)
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    plan, plan_raw = _read_private(plan_path)
    request, request_raw = _read_private(review_request_path)
    handoff, _ = _read_private(review_handoff_path)
    profile, profile_raw = _read_private(reviewer_profile_path)
    implementation = _clean_pushed_implementation(repository_root)
    if plan.get("implementation") != implementation:
        raise ValueError("infrastructure repair implementation revision drifted")
    plan_ref = _ref(plan_path, plan["plan_sha256"], raw=plan_raw)
    expected_owner_statement = owner_review_statement(
        plan, hashlib.sha256(plan_raw).hexdigest()
    )
    expected_request = build_review_request(
        request_id=request.get("request_id", ""),
        created_at=request.get("created_at", ""),
        plan_ref=plan_ref,
        plan=plan,
        owner_statement_sha256=hashlib.sha256(
            expected_owner_statement.encode()
        ).hexdigest(),
    )
    if request != expected_request:
        raise ValueError("infrastructure repair review request invalid")
    request_ref = _ref(review_request_path, request["request_sha256"], raw=request_raw)
    expected = reviewer_statement(request, hashlib.sha256(request_raw).hexdigest())
    if not (
        review_statement_value == expected
        and handoff.get("request") == request_ref
        and handoff.get("required_exact_reviewer_statement") == expected
        and handoff.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in handoff.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("infrastructure repair independent review statement invalid")
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    _validate_reviewer_key(
        profile,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    reviewer = profile["reviewer"]
    statement_sha256 = hashlib.sha256(review_statement_value.encode()).hexdigest()
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
            request=request,
            request_ref=request_ref,
            reviewer=reviewer,
            reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
            statement_sha256=statement_sha256,
            signer=signer,
        )
    receipt_failures = validate_review_receipt(
        receipt,
        request=request,
        request_ref=request_ref,
        reviewer_profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        statement_sha256=statement_sha256,
    )
    if receipt_failures:
        raise ValueError(f"infrastructure repair review invalid: {receipt_failures}")
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        receipt_path = staging / "infrastructure-repair-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_ref = _published_ref(
            receipt_path,
            output_root / receipt_path.name,
            receipt["signature"]["signed_payload_sha256"],
        )
        reviewed = build_reviewed_repair(
            plan=plan,
            plan_ref=plan_ref,
            receipt_ref=receipt_ref,
            receipt=receipt,
        )
        reviewed_path = staging / "infrastructure-repair.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        reviewed_ref = _published_ref(
            reviewed_path,
            output_root / reviewed_path.name,
            reviewed["reviewed_repair_sha256"],
        )
        gate = {
            "schema_version": "j1-qualification-infrastructure-repair-review-gate:v1",
            "passed": True,
            "failure_reasons": [],
            "state": "single_container_repair_promoted_exact_authorization_required",
            "review_receipt": receipt_ref,
            "reviewed_repair": reviewed_ref,
            "target": reviewed["target"],
            "readiness": {
                "independent_review_complete": True,
                "repair_promoted": True,
                "container_mutation_performed": False,
                "exact_repair_authorization_required": True,
            },
            "execution_boundary": BOUNDARY,
        }
        gate["report_sha256"] = canonical_sha256(gate)
        gate_path = staging / "infrastructure-repair-review-gate-report.json"
        write_private_json(gate_path, gate)
        statement = repair_authorization_statement(
            reviewed_raw_sha256=hashlib.sha256(reviewed_path.read_bytes()).hexdigest(),
            reviewed=reviewed,
            gate_raw_sha256=hashlib.sha256(gate_path.read_bytes()).hexdigest(),
            gate_canonical_sha256=gate["report_sha256"],
        )
        handoff = {
            "schema_version": (
                "j1-qualification-infrastructure-repair-authorization-handoff:v1"
            ),
            "state": "exact_single_container_repair_authorization_required",
            "promotion_gate": _published_ref(
                gate_path,
                output_root / gate_path.name,
                gate["report_sha256"],
            ),
            "required_exact_repair_authorization": statement,
            "repair_authorization_sha256": hashlib.sha256(
                statement.encode()
            ).hexdigest(),
            "execution_boundary": BOUNDARY,
        }
        handoff["report_sha256"] = canonical_sha256(handoff)
        write_private_json(
            staging / "infrastructure-repair-authorization-handoff.json",
            handoff,
        )
        os.rename(staging, output_root)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return handoff


def activate_repair(
    *,
    operation_id: str,
    created_at: str,
    authorization_statement: str,
    reviewed_path: Path,
    gate_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_new_root(output_root)
    reviewed, reviewed_raw = _read_private(reviewed_path)
    gate, gate_raw = _read_private(gate_path)
    implementation = _clean_pushed_implementation(repository_root)
    plan_path = Path(reviewed.get("plan", {}).get("path", ""))
    receipt_path = Path(reviewed.get("review_receipt", {}).get("path", ""))
    plan, plan_raw = _read_private(plan_path)
    receipt, receipt_raw = _read_private(receipt_path)
    request_path = Path(receipt.get("request", {}).get("path", ""))
    request, request_raw = _read_private(request_path)
    expected_plan_ref = _ref(plan_path, plan["plan_sha256"], raw=plan_raw)
    expected_request_ref = _ref(
        request_path, request["request_sha256"], raw=request_raw
    )
    receipt_failures = validate_review_receipt(
        receipt,
        request=request,
        request_ref=expected_request_ref,
        reviewer_profile_sha256=receipt.get("reviewer", {}).get("profile_sha256", ""),
        statement_sha256=receipt.get("review_statement_sha256", ""),
    )
    if not (
        reviewed.get("schema_version") == REVIEWED_SCHEMA
        and reviewed.get("status") == "operator_reviewed"
        and reviewed.get("reviewed_repair_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in reviewed.items()
                if key != "reviewed_repair_sha256"
            }
        )
        and reviewed.get("implementation") == implementation
        and reviewed.get("plan") == expected_plan_ref
        and reviewed.get("review_receipt")
        == _ref(
            receipt_path,
            receipt["signature"]["signed_payload_sha256"],
            raw=receipt_raw,
        )
        and request.get("plan") == expected_plan_ref
        and not receipt_failures
        and gate.get("passed") is True
        and gate.get("reviewed_repair")
        == _ref(
            reviewed_path,
            reviewed["reviewed_repair_sha256"],
            raw=reviewed_raw,
        )
        and gate.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in gate.items() if key != "report_sha256"}
        )
    ):
        raise ValueError("infrastructure repair reviewed source invalid")
    expected_statement = repair_authorization_statement(
        reviewed_raw_sha256=hashlib.sha256(reviewed_raw).hexdigest(),
        reviewed=reviewed,
        gate_raw_sha256=hashlib.sha256(gate_raw).hexdigest(),
        gate_canonical_sha256=gate["report_sha256"],
    )
    if authorization_statement != expected_statement:
        raise ValueError("single-container repair authorization mismatch")
    parent_path = Path(reviewed["parent_activation"]["path"])
    parent_activation, parent_raw = _read_private(parent_path)
    if reviewed["parent_activation"] != _ref(
        parent_path,
        parent_activation["activation_sha256"],
        raw=parent_raw,
    ):
        raise ValueError("infrastructure repair parent activation binding invalid")
    live_before = _live_inventory(parent_activation)
    target = reviewed["target"]
    target_name = target["container_name"]
    live_target = next(
        item for item in live_before if item["container_name"] == target_name
    )
    if not (
        live_target["container_id"] == target["exited_container_id"]
        and live_target["state"] == {"status": "exited", "running": False}
        and sum(item["state"]["status"] == "created" for item in live_before) == 39
        and sum(item["state"]["running"] for item in live_before) == 0
    ):
        raise ValueError("single-container repair live precondition drifted")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    journal_path = output_root / "infrastructure-repair-journal.json"
    quarantine_name = (
        f"{target_name}-quarantine-"
        f"{hashlib.sha256(operation_id.encode()).hexdigest()[:12]}"
    )
    journal = {
        "schema_version": "j1-qualification-infrastructure-repair-journal:v1",
        "operation_id": operation_id,
        "created_at": created_at,
        "authorization_sha256": hashlib.sha256(
            authorization_statement.encode()
        ).hexdigest(),
        "target_name": target_name,
        "prior_container_id": target["exited_container_id"],
        "quarantine_name": quarantine_name,
        "state": "precondition_validated",
        "replacement_container_id": None,
    }
    write_private_json(journal_path, journal)
    replacement_id: str | None = None
    quarantined = False
    prior_removed = False
    try:
        _docker(["container", "rename", target["exited_container_id"], quarantine_name])
        quarantined = True
        journal["state"] = "prior_container_quarantined"
        write_private_json(journal_path, journal)
        replacement_id = _create_from_projection(target["expected_created_projection"])
        journal["replacement_container_id"] = replacement_id
        journal["state"] = "replacement_created"
        write_private_json(journal_path, journal)
        live_after_create = _live_inventory(parent_activation)
        _validate_complete_inventory(
            parent_activation,
            live_before=live_before,
            live_after=live_after_create,
            target_name=target_name,
            prior_container_id=target["exited_container_id"],
        )
        journal["state"] = "complete_set_validated"
        write_private_json(journal_path, journal)
        _docker(["container", "rm", target["exited_container_id"]])
        quarantined = False
        prior_removed = True
        journal["state"] = "prior_container_removed"
        write_private_json(journal_path, journal)
        live_final = _live_inventory(parent_activation)
        _validate_complete_inventory(
            parent_activation,
            live_before=live_before,
            live_after=live_final,
            target_name=target_name,
            prior_container_id=target["exited_container_id"],
        )
        activation = {
            "schema_version": ACTIVATION_SCHEMA,
            "operation_id": operation_id,
            "created_at": created_at,
            "authorization_sha256": journal["authorization_sha256"],
            "parent_activation": reviewed["parent_activation"],
            "reviewed_repair": _ref(
                reviewed_path,
                reviewed["reviewed_repair_sha256"],
                raw=reviewed_raw,
            ),
            "target": {
                **copy.deepcopy(target),
                "replacement_container_id": replacement_id,
            },
            "inventory": {
                "participant_count": 40,
                "container_created_count": 40,
                "container_exited_count": 0,
                "container_started_count": 0,
            },
            "containers": _repaired_activation_records(parent_activation, live_final),
            "implementation": implementation,
            "execution_boundary": {
                **BOUNDARY,
                "participant_container_created": True,
            },
        }
        activation["activation_sha256"] = canonical_sha256(activation)
        activation_path = output_root / "infrastructure-repair-activation.json"
        write_private_json(activation_path, activation)
        journal["state"] = "completed"
        write_private_json(journal_path, journal)
        report = {
            "schema_version": "j1-qualification-infrastructure-repair-gate:v1",
            "passed": True,
            "failure_reasons": [],
            "state": "single_container_repaired_40_created_0_running",
            "activation": _ref(activation_path, activation["activation_sha256"]),
            "journal": _raw_ref(journal_path),
            "inventory": activation["inventory"],
            "parent_activation_immutable": True,
            "prior_container_id": target["exited_container_id"],
            "replacement_container_id": replacement_id,
            "execution_boundary": activation["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "infrastructure-repair-gate-report.json", report
        )
        return report
    except Exception as error:
        rollback_failures: list[str] = []
        if replacement_id and not prior_removed:
            result = _docker(
                ["container", "rm", replacement_id],
                check=False,
            )
            if result.returncode != 0:
                rollback_failures.append("replacement_container_remove_failed")
        if quarantined:
            result = _docker(
                ["container", "rename", target["exited_container_id"], target_name],
                check=False,
            )
            if result.returncode != 0:
                rollback_failures.append("prior_container_restore_failed")
        if prior_removed:
            journal["state"] = "repair_committed_evidence_write_failed"
        else:
            journal["state"] = (
                "rolled_back" if not rollback_failures else "rollback_failed"
            )
        journal["failure_type"] = type(error).__name__
        journal["rollback_failures"] = rollback_failures
        write_private_json(journal_path, journal)
        raise RuntimeError(
            f"single-container repair failed with {journal['state']}"
        ) from error


def _live_inventory(parent_activation: dict[str, Any]) -> list[dict[str, Any]]:
    records = parent_activation.get("containers", [])
    values = []
    for record in sorted(
        records,
        key=lambda item: str(item.get("container", {}).get("container_name")),
    ):
        expected = record["container"]
        inspected = _inspect(expected["container_name"])
        projection = _projection(inspected, expected=expected)
        values.append(projection)
    return values


def _projection(value: dict[str, Any], *, expected: dict[str, Any]) -> dict[str, Any]:
    config = value.get("Config") or {}
    host = value.get("HostConfig") or {}
    state = value.get("State") or {}
    labels = config.get("Labels") or {}
    expected_labels = expected.get("labels", {})
    mounts = sorted(
        [
            {
                "type": item.get("Type"),
                "source": item.get("Source"),
                "destination": item.get("Destination"),
                "rw": item.get("RW"),
            }
            for item in (value.get("Mounts") or [])
        ],
        key=lambda item: str(item["destination"]),
    )
    normalized = {
        "container_name": str(value.get("Name", "")).removeprefix("/"),
        "image_id": value.get("Image"),
        "entrypoint": config.get("Entrypoint"),
        "command": config.get("Cmd"),
        "runtime_user": config.get("User"),
        "labels": {key: labels.get(key) for key in sorted(expected_labels)},
        "runtime_boundary": {
            "network_mode": host.get("NetworkMode"),
            "read_only_rootfs": host.get("ReadonlyRootfs"),
            "cap_drop": host.get("CapDrop"),
            "no_new_privileges": "no-new-privileges:true"
            in (host.get("SecurityOpt") or []),
            "pids_limit": host.get("PidsLimit"),
            "memory_limit_bytes": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "privileged": host.get("Privileged"),
            "devices": host.get("Devices") or [],
            "tmpfs": host.get("Tmpfs") or {},
        },
        "mounts": mounts,
        "forbidden_environment_present": sorted(
            {
                "ANTHROPIC_API_KEY",
                "DEEPSEEK_API_KEY",
                "OPENAI_API_KEY",
                "PKCS11_PIN",
                "SOFTHSM2_CONF",
            }.intersection(
                {str(item).partition("=")[0] for item in (config.get("Env") or [])}
            )
        ),
    }
    config_sha256 = canonical_sha256(
        {
            **normalized,
            "state": {"status": "created", "running": False},
            "container_id": expected.get("container_id"),
        }
    )
    # Existing activation hashes include the old container ID. Bind security and
    # runtime configuration separately so a replacement ID can be proven valid.
    expected_config = {
        key: item
        for key, item in expected.items()
        if key not in {"container_id", "state", "actual_container_config_sha256"}
    }
    actual_config = copy.deepcopy(normalized)
    if actual_config != expected_config:
        raise ValueError(
            f"container configuration drifted: {normalized['container_name']}"
        )
    return {
        "container_name": normalized["container_name"],
        "container_id": value.get("Id"),
        "image_id": normalized["image_id"],
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
        },
        "config_sha256": expected.get("actual_container_config_sha256")
        or config_sha256,
    }


def _create_from_projection(expected: dict[str, Any]) -> str:
    boundary = expected["runtime_boundary"]
    command = [
        "docker",
        "create",
        "--name",
        expected["container_name"],
    ]
    for key, value in sorted(expected["labels"].items()):
        command.extend(["--label", f"{key}={value}"])
    command.extend(
        [
            "--network",
            boundary["network_mode"],
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(boundary["pids_limit"]),
            "--memory",
            str(boundary["memory_limit_bytes"]),
            "--cpus",
            _cpus(boundary["nano_cpus"]),
            "--user",
            expected["runtime_user"],
            "--tmpfs",
            f"/tmp:{boundary['tmpfs']['/tmp']}",
        ]
    )
    for mount in expected["mounts"]:
        value = f"type=bind,src={mount['source']},dst={mount['destination']}" + (
            "" if mount["rw"] else ",readonly"
        )
        command.extend(["--mount", value])
    command.append(expected["image_id"])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    container_id = result.stdout.strip()
    if result.returncode != 0:
        raise ValueError("docker create failed")
    if len(container_id) != 64 or any(
        char not in "0123456789abcdef" for char in container_id.lower()
    ):
        raise ValueError("docker create returned invalid container ID")
    return container_id


def _validate_complete_inventory(
    parent: dict[str, Any],
    *,
    live_before: list[dict[str, Any]],
    live_after: list[dict[str, Any]],
    target_name: str,
    prior_container_id: str,
) -> None:
    before = {item["container_name"]: item for item in live_before}
    after = {item["container_name"]: item for item in live_after}
    if not (
        len(after) == 40
        and set(after) == set(before)
        and all(
            item["state"] == {"status": "created", "running": False}
            for item in after.values()
        )
        and after[target_name]["container_id"] != prior_container_id
        and all(
            after[name]["container_id"] == before[name]["container_id"]
            for name in after
            if name != target_name
        )
        and all(
            after[name]["config_sha256"] == before[name]["config_sha256"]
            for name in after
        )
        and len(parent.get("containers", [])) == 40
    ):
        raise ValueError("infrastructure repair complete-set Gate failed")


def _repaired_activation_records(
    parent: dict[str, Any], live_inventory: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    live_index = {item["container_name"]: item for item in live_inventory}
    records = copy.deepcopy(parent["containers"])
    for record in records:
        container = record["container"]
        live = live_index[container["container_name"]]
        container["container_id"] = live["container_id"]
        container["state"] = copy.deepcopy(live["state"])
        container.pop("actual_container_config_sha256", None)
        container["actual_container_config_sha256"] = canonical_sha256(container)
    return sorted(records, key=lambda item: str(item["participant_id"]))


def _inspect(name: str) -> dict[str, Any]:
    result = _docker(["container", "inspect", name])
    values = json.loads(result.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError("docker inspect result invalid")
    return values[0]


def _docker(
    arguments: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def _clean_pushed_implementation(root: Path) -> dict[str, str]:
    root = root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for infrastructure repair")
    revision = _git(root, "rev-parse", "HEAD")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "@{upstream}"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        ).returncode
        != 0
    ):
        raise ValueError("infrastructure repair revision is not pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _validate_reviewer_key(
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
        key.get("module_path") == str(module)
        and key.get("module_sha256") == hashlib.sha256(module.read_bytes()).hexdigest()
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
    ):
        raise ValueError("reviewer PKCS#11 configuration mismatch")


def _require_new_root(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"infrastructure repair output exists: {path}")


def _ref(path: Path, canonical_sha: str, *, raw: bytes | None = None) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(
            raw if raw is not None else path.read_bytes()
        ).hexdigest(),
        "canonical_sha256": canonical_sha,
    }


def _raw_ref(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _published_ref(
    current: Path, published: Path, canonical_sha: str
) -> dict[str, str]:
    return {
        "path": str(published.resolve()),
        "sha256": hashlib.sha256(current.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_sha,
    }


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _cpus(nano_cpus: int) -> str:
    whole, fraction = divmod(nano_cpus, 1_000_000_000)
    return f"{whole}.{fraction:09d}".rstrip("0").rstrip(".")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--repair-id", required=True)
    candidate.add_argument("--created-at", default=None)
    candidate.add_argument("--parent-activation", type=Path, required=True)
    candidate.add_argument("--target-container", required=True)
    candidate.add_argument("--repository-root", type=Path, required=True)
    candidate.add_argument("--output-root", type=Path, required=True)
    review = commands.add_parser("review")
    review.add_argument("--request-id", required=True)
    review.add_argument("--created-at", default=None)
    review.add_argument("--owner-statement", required=True)
    review.add_argument("--plan", type=Path, required=True)
    review.add_argument("--preflight", type=Path, required=True)
    review.add_argument("--repository-root", type=Path, required=True)
    review.add_argument("--output-root", type=Path, required=True)
    promote = commands.add_parser("promote")
    promote.add_argument("--review-id", required=True)
    promote.add_argument("--reviewed-at", default=None)
    promote.add_argument("--review-statement", required=True)
    promote.add_argument("--plan", type=Path, required=True)
    promote.add_argument("--review-request", type=Path, required=True)
    promote.add_argument("--review-handoff", type=Path, required=True)
    promote.add_argument("--reviewer-profile", type=Path, required=True)
    promote.add_argument("--module", default=DEFAULT_MODULE)
    promote.add_argument("--token-label", required=True)
    promote.add_argument("--key-label", required=True)
    promote.add_argument("--key-id", required=True)
    promote.add_argument("--pin-file", type=Path)
    promote.add_argument("--repository-root", type=Path, required=True)
    promote.add_argument("--output-root", type=Path, required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--operation-id", required=True)
    activate.add_argument("--created-at", default=None)
    activate.add_argument("--authorization-statement", required=True)
    activate.add_argument("--reviewed-repair", type=Path, required=True)
    activate.add_argument("--promotion-gate", type=Path, required=True)
    activate.add_argument("--repository-root", type=Path, required=True)
    activate.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "candidate":
        result = prepare_candidate(
            repair_id=args.repair_id,
            created_at=args.created_at or _now(),
            parent_activation_path=args.parent_activation,
            target_container_name=args.target_container,
            repository_root=args.repository_root,
            output_root=args.output_root,
        )
    elif args.command == "review":
        result = prepare_review(
            request_id=args.request_id,
            created_at=args.created_at or _now(),
            owner_statement=args.owner_statement,
            plan_path=args.plan,
            preflight_path=args.preflight,
            repository_root=args.repository_root,
            output_root=args.output_root,
        )
    elif args.command == "promote":
        result = promote_review(
            review_id=args.review_id,
            reviewed_at=args.reviewed_at or _now(),
            review_statement_value=args.review_statement,
            plan_path=args.plan,
            review_request_path=args.review_request,
            review_handoff_path=args.review_handoff,
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
        result = activate_repair(
            operation_id=args.operation_id,
            created_at=args.created_at or _now(),
            authorization_statement=args.authorization_statement,
            reviewed_path=args.reviewed_repair,
            gate_path=args.promotion_gate,
            repository_root=args.repository_root,
            output_root=args.output_root,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
