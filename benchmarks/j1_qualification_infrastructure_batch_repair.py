"""Prepare, review, promote, and execute a complete-set J1-D batch repair."""

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
from benchmarks.j1.qualification_infrastructure_batch_repair import (
    ACTIVATION_SCHEMA,
    BOUNDARY,
    REVIEWED_SCHEMA,
    TARGET_COUNT,
    build_batch_repair_plan,
    build_review_receipt,
    build_review_request,
    build_reviewed_repair,
    owner_review_statement,
    repair_authorization_statement,
    reviewer_statement,
    validate_batch_repair_plan,
    validate_review_receipt,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_infrastructure_rebind import _read_private
from benchmarks.j1_qualification_infrastructure_repair import (
    _create_from_projection,
    _docker,
    _fsync_directory,
    _live_inventory,
    _published_ref,
    _raw_ref,
    _ref,
    _repaired_activation_records,
    _require_new_root,
    _validate_reviewer_key,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_infrastructure_batch_repair.py"
)
OPERATION_SOURCE = Path(__file__)


def prepare_candidate(
    *,
    repair_id: str,
    created_at: str,
    parent_activation_path: Path,
    target_container_names: list[str],
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    _require_new_root(output_root)
    parent, parent_raw = _read_private(parent_activation_path)
    implementation = _clean_pushed_implementation(repository_root)
    live_inventory = _live_inventory(parent)
    plan = build_batch_repair_plan(
        repair_id=repair_id,
        created_at=created_at,
        parent_activation_ref=_ref(
            parent_activation_path,
            parent["activation_sha256"],
            raw=parent_raw,
        ),
        parent_activation=parent,
        live_inventory=live_inventory,
        target_container_names=target_container_names,
        implementation=implementation,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_path = output_root / "infrastructure-batch-repair-plan.json"
    write_private_json(plan_path, plan)
    statement = owner_review_statement(
        plan, hashlib.sha256(plan_path.read_bytes()).hexdigest()
    )
    preflight = {
        "schema_version": (
            "j1-qualification-infrastructure-batch-repair-preflight:v1"
        ),
        "passed": True,
        "failure_reasons": [],
        "state": "complete_exited_set_batch_repair_independent_review_required",
        "plan": _ref(plan_path, plan["plan_sha256"]),
        "inventory_precondition": plan["inventory_precondition"],
        "targets": plan["targets"],
        "required_exact_owner_review_statement": statement,
        "owner_review_statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "readiness": {
            "complete_exited_target_set_bound": True,
            "container_mutation_performed": False,
            "independent_review_complete": False,
            "repair_authorized": False,
        },
        "execution_boundary": BOUNDARY,
    }
    preflight["report_sha256"] = canonical_sha256(preflight)
    write_private_json(
        output_root / "infrastructure-batch-repair-preflight.json", preflight
    )
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
    failures = validate_batch_repair_plan(
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
        raise ValueError("infrastructure batch repair owner review binding invalid")
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
    request_path = output_root / "infrastructure-batch-repair-review-request.json"
    write_private_json(request_path, request)
    declaration = reviewer_statement(
        request, hashlib.sha256(request_path.read_bytes()).hexdigest()
    )
    handoff = {
        "schema_version": (
            "j1-qualification-infrastructure-batch-repair-review-handoff:v1"
        ),
        "passed": True,
        "state": "independent_reviewer_decision_required",
        "request": _ref(request_path, request["request_sha256"]),
        "required_exact_reviewer_statement": declaration,
        "reviewer_statement_sha256": hashlib.sha256(declaration.encode()).hexdigest(),
        "execution_boundary": BOUNDARY,
    }
    handoff["report_sha256"] = canonical_sha256(handoff)
    write_private_json(
        output_root / "infrastructure-batch-repair-review-handoff.json", handoff
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
        raise ValueError("infrastructure batch repair implementation revision drifted")
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
        raise ValueError("infrastructure batch repair review request invalid")
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
        raise ValueError(
            "infrastructure batch repair independent review statement invalid"
        )
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
        raise ValueError(
            f"infrastructure batch repair review invalid: {receipt_failures}"
        )
    parent = output_root.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        receipt_path = staging / "infrastructure-batch-repair-review-receipt.json"
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
        reviewed_path = staging / "infrastructure-batch-repair.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        reviewed_ref = _published_ref(
            reviewed_path,
            output_root / reviewed_path.name,
            reviewed["reviewed_repair_sha256"],
        )
        gate = {
            "schema_version": (
                "j1-qualification-infrastructure-batch-repair-review-gate:v1"
            ),
            "passed": True,
            "failure_reasons": [],
            "state": "complete_exited_set_batch_repair_promoted",
            "review_receipt": receipt_ref,
            "reviewed_repair": reviewed_ref,
            "targets": reviewed["targets"],
            "readiness": {
                "independent_review_complete": True,
                "repair_promoted": True,
                "container_mutation_performed": False,
                "exact_repair_authorization_required": True,
            },
            "execution_boundary": BOUNDARY,
        }
        gate["report_sha256"] = canonical_sha256(gate)
        gate_path = staging / "infrastructure-batch-repair-review-gate-report.json"
        write_private_json(gate_path, gate)
        statement = repair_authorization_statement(
            reviewed_raw_sha256=hashlib.sha256(reviewed_path.read_bytes()).hexdigest(),
            reviewed=reviewed,
            gate_raw_sha256=hashlib.sha256(gate_path.read_bytes()).hexdigest(),
            gate_canonical_sha256=gate["report_sha256"],
        )
        handoff = {
            "schema_version": (
                "j1-qualification-infrastructure-batch-repair-"
                "authorization-handoff:v1"
            ),
            "state": "exact_complete_exited_set_repair_authorization_required",
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
            staging / "infrastructure-batch-repair-authorization-handoff.json",
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
        raise ValueError("infrastructure batch repair reviewed source invalid")
    expected_statement = repair_authorization_statement(
        reviewed_raw_sha256=hashlib.sha256(reviewed_raw).hexdigest(),
        reviewed=reviewed,
        gate_raw_sha256=hashlib.sha256(gate_raw).hexdigest(),
        gate_canonical_sha256=gate["report_sha256"],
    )
    if authorization_statement != expected_statement:
        raise ValueError("infrastructure batch repair authorization mismatch")
    parent_path = Path(reviewed["parent_activation"]["path"])
    parent, parent_raw = _read_private(parent_path)
    if reviewed["parent_activation"] != _ref(
        parent_path, parent["activation_sha256"], raw=parent_raw
    ):
        raise ValueError("infrastructure batch repair parent binding invalid")
    live_before = _live_inventory(parent)
    target_index = {target["container_name"]: target for target in reviewed["targets"]}
    exited_index = {
        item["container_name"]: item
        for item in live_before
        if item["state"] == {"status": "exited", "running": False}
    }
    if not (
        len(target_index) == TARGET_COUNT
        and set(target_index) == set(exited_index)
        and all(
            exited_index[name]["container_id"]
            == target_index[name]["exited_container_id"]
            for name in target_index
        )
        and sum(
            item["state"] == {"status": "created", "running": False}
            for item in live_before
        )
        == 38
        and not any(item["state"]["running"] for item in live_before)
    ):
        raise ValueError("infrastructure batch repair live precondition drifted")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    journal_path = output_root / "infrastructure-batch-repair-journal.json"
    entries = {
        name: {
            "target_name": name,
            "prior_container_id": target["exited_container_id"],
            "quarantine_name": (
                f"{name}-quarantine-"
                f"{hashlib.sha256(f'{operation_id}:{name}'.encode()).hexdigest()[:12]}"
            ),
            "quarantined": False,
            "replacement_container_id": None,
            "prior_removed": False,
        }
        for name, target in sorted(target_index.items())
    }
    journal = {
        "schema_version": (
            "j1-qualification-infrastructure-batch-repair-journal:v1"
        ),
        "operation_id": operation_id,
        "created_at": created_at,
        "authorization_sha256": hashlib.sha256(
            authorization_statement.encode()
        ).hexdigest(),
        "state": "precondition_validated",
        "entries": list(entries.values()),
    }

    def persist(state: str) -> None:
        journal["state"] = state
        journal["entries"] = list(entries.values())
        write_private_json(journal_path, journal)

    persist("precondition_validated")
    try:
        for name, entry in entries.items():
            _docker(
                [
                    "container",
                    "rename",
                    entry["prior_container_id"],
                    entry["quarantine_name"],
                ]
            )
            entry["quarantined"] = True
            persist(f"prior_container_quarantined:{name}")
        for name, entry in entries.items():
            replacement_id = _create_from_projection(
                target_index[name]["expected_created_projection"]
            )
            entry["replacement_container_id"] = replacement_id
            persist(f"replacement_created:{name}")
        live_after_create = _live_inventory(parent)
        _validate_complete_inventory(
            parent,
            live_before=live_before,
            live_after=live_after_create,
            target_index=target_index,
        )
        persist("complete_set_validated")
        for name, entry in entries.items():
            _docker(["container", "rm", entry["prior_container_id"]])
            entry["quarantined"] = False
            entry["prior_removed"] = True
            persist(f"prior_container_removed:{name}")
        live_final = _live_inventory(parent)
        _validate_complete_inventory(
            parent,
            live_before=live_before,
            live_after=live_final,
            target_index=target_index,
        )
        targets = [
            {
                **copy.deepcopy(target_index[name]),
                "replacement_container_id": entries[name][
                    "replacement_container_id"
                ],
            }
            for name in sorted(target_index)
        ]
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
            "targets": targets,
            "inventory": {
                "participant_count": 40,
                "container_created_count": 40,
                "container_exited_count": 0,
                "container_started_count": 0,
            },
            "containers": _repaired_activation_records(parent, live_final),
            "implementation": implementation,
            "execution_boundary": {
                **BOUNDARY,
                "participant_container_created": True,
            },
        }
        activation["activation_sha256"] = canonical_sha256(activation)
        activation_path = output_root / "infrastructure-batch-repair-activation.json"
        write_private_json(activation_path, activation)
        persist("completed")
        report = {
            "schema_version": "j1-qualification-infrastructure-batch-repair-gate:v1",
            "passed": True,
            "failure_reasons": [],
            "state": "complete_exited_set_repaired_40_created_0_running",
            "activation": _ref(activation_path, activation["activation_sha256"]),
            "journal": _raw_ref(journal_path),
            "inventory": activation["inventory"],
            "parent_activation_immutable": True,
            "target_replacements": [
                {
                    "container_name": target["container_name"],
                    "prior_container_id": target["exited_container_id"],
                    "replacement_container_id": target["replacement_container_id"],
                }
                for target in targets
            ],
            "execution_boundary": activation["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "infrastructure-batch-repair-gate-report.json", report
        )
        return report
    except Exception as error:
        committed = any(entry["prior_removed"] for entry in entries.values())
        rollback_failures = [] if committed else _rollback_entries(entries)
        journal["failure_type"] = type(error).__name__
        journal["rollback_failures"] = rollback_failures
        persist(
            "repair_committed_evidence_write_failed"
            if committed
            else ("rolled_back" if not rollback_failures else "rollback_failed")
        )
        raise RuntimeError(
            f"infrastructure batch repair failed with {journal['state']}"
        ) from error


def _rollback_entries(entries: dict[str, dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for entry in reversed(list(entries.values())):
        replacement_id = entry["replacement_container_id"]
        if replacement_id:
            result = _docker(["container", "rm", replacement_id], check=False)
            if result.returncode != 0:
                failures.append(f"replacement_remove_failed:{entry['target_name']}")
    for entry in reversed(list(entries.values())):
        if entry["quarantined"]:
            result = _docker(
                [
                    "container",
                    "rename",
                    entry["prior_container_id"],
                    entry["target_name"],
                ],
                check=False,
            )
            if result.returncode != 0:
                failures.append(f"prior_restore_failed:{entry['target_name']}")
    return failures


def _validate_complete_inventory(
    parent: dict[str, Any],
    *,
    live_before: list[dict[str, Any]],
    live_after: list[dict[str, Any]],
    target_index: dict[str, dict[str, Any]],
) -> None:
    before = {item["container_name"]: item for item in live_before}
    after = {item["container_name"]: item for item in live_after}
    target_names = set(target_index)
    if not (
        len(after) == 40
        and set(after) == set(before)
        and len(target_names) == TARGET_COUNT
        and all(
            item["state"] == {"status": "created", "running": False}
            for item in after.values()
        )
        and all(
            after[name]["container_id"]
            != target_index[name]["exited_container_id"]
            for name in target_names
        )
        and all(
            after[name]["container_id"] == before[name]["container_id"]
            for name in set(after) - target_names
        )
        and all(
            after[name]["config_sha256"] == before[name]["config_sha256"]
            for name in after
        )
        and len(parent.get("containers", [])) == 40
    ):
        raise ValueError("infrastructure batch repair complete-set Gate failed")


def _clean_pushed_implementation(root: Path) -> dict[str, str]:
    root = root.resolve()
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean for infrastructure batch repair")
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
        raise ValueError("infrastructure batch repair revision is not pushed")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--repair-id", required=True)
    candidate.add_argument("--created-at", default=None)
    candidate.add_argument("--parent-activation", type=Path, required=True)
    candidate.add_argument(
        "--target-container", action="append", required=True, dest="target_containers"
    )
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
        if len(args.target_containers) != TARGET_COUNT:
            parser.error(f"candidate requires exactly {TARGET_COUNT} --target-container")
        result = prepare_candidate(
            repair_id=args.repair_id,
            created_at=args.created_at or _now(),
            parent_activation_path=args.parent_activation,
            target_container_names=args.target_containers,
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
