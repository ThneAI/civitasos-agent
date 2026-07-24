"""Close out a claimed J1-D frozen run that never started execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_frozen_execution_abort_closeout import (
    build_abort_artifacts,
    build_closeout_gate,
    build_closeout_preflight,
    validate_abort_artifacts,
    validate_closeout_gate,
    validate_closeout_preflight,
)
from benchmarks.j1.qualification_frozen_execution_claim import (
    validate_claim_preflight,
    validate_claim_receipt,
    validate_execution_entry_gate,
)
from benchmarks.j1.qualification_frozen_execution_authorization import (
    validate_authorization,
    validate_gate_report,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_frozen_execution_claim import (
    _load_context,
    _read_private,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


DOMAIN_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_frozen_execution_abort_closeout.py"
)
OPERATION_SOURCE = Path(__file__)


def generate_abort_closeout_preflight(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    output_root: Path,
    repository_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"abort closeout preflight output exists: {output_root}")
    context = _closeout_context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        claim_preflight_path=claim_preflight_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        repository_root=repository_root,
    )
    target = Path(context["authorization"]["controls"]["post_run_output_root"])
    _require_terminal_paths(context, target)
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        preflight = build_closeout_preflight(
            checked_at=datetime.now(timezone.utc).isoformat(),
            claim_ref=context["claim_ref"],
            claim=context["claim"],
            entry_gate_ref=context["entry_gate_ref"],
            entry_gate=context["entry_gate"],
            frozen_bundle_ref=context["frozen_bundle_ref"],
            frozen_bundle=context["frozen_bundle"],
            post_run_contract_ref=context["post_run_contract_ref"],
            post_run_contract=context["post_run_contract"],
            closeout_contract_ref=context["closeout_contract_ref"],
            closeout_contract=context["closeout_contract"],
            inventory_snapshot=context["inventory_snapshot"],
            execution_manifest=context["execution_manifest"],
            output_root=str(target.resolve()),
            implementation=context["implementation"],
        )
        path = output_root / "claimed-abort-closeout-preflight.json"
        write_private_json(path, preflight)
        return preflight
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def perform_abort_closeout(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    closeout_preflight_path: Path,
    owner_authorization_id: str,
    owner_statement: str,
    owner_statement_sha256: str,
    repository_root: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    pin: str,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    context = _closeout_context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        claim_preflight_path=claim_preflight_path,
        claim_path=claim_path,
        entry_gate_path=entry_gate_path,
        repository_root=repository_root,
    )
    target = Path(context["authorization"]["controls"]["post_run_output_root"])
    _require_terminal_paths(context, target)
    preflight_artifact = _read_private(closeout_preflight_path, "abort_preflight")
    preflight = preflight_artifact["value"]
    failures = validate_closeout_preflight(
        preflight,
        claim_ref=context["claim_ref"],
        claim=context["claim"],
        entry_gate_ref=context["entry_gate_ref"],
        entry_gate=context["entry_gate"],
        frozen_bundle_ref=context["frozen_bundle_ref"],
        frozen_bundle=context["frozen_bundle"],
        post_run_contract_ref=context["post_run_contract_ref"],
        post_run_contract=context["post_run_contract"],
        closeout_contract_ref=context["closeout_contract_ref"],
        closeout_contract=context["closeout_contract"],
        inventory_snapshot=context["inventory_snapshot"],
        execution_manifest=context["execution_manifest"],
        output_root=str(target.resolve()),
        expected_implementation=context["implementation"],
    )
    if failures:
        raise ValueError(f"abort closeout preflight invalid: {failures}")
    expected_statement = preflight["owner_authorization"]["required_exact_statement"]
    if (
        owner_statement != expected_statement
        or hashlib.sha256(owner_statement.encode()).hexdigest()
        != owner_statement_sha256
        or owner_statement_sha256
        != preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("abort closeout owner statement/hash mismatch")
    reviewer = context["reviewer_profile"]["reviewer"]
    _validate_reviewer_configuration(
        context["reviewer_profile"],
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    with Pkcs11Ed25519Signer(
        str(Path(module_path).resolve()),
        token_label,
        key_label,
        reviewer["public_key_hex"],
        pin,
        key_id=key_id_hex,
    ) as signer:
        artifacts = build_abort_artifacts(
            closed_at=datetime.now(timezone.utc).isoformat(),
            preflight_ref=_artifact_ref(
                closeout_preflight_path,
                preflight["preflight_sha256"],
            ),
            preflight=preflight,
            owner_authorization_id=owner_authorization_id,
            owner_statement=owner_statement,
            reviewer=reviewer,
            reviewer_profile_sha256=context["reviewer_profile_sha256"],
            implementation=context["implementation"],
            signer=signer,
        )
    return _persist_closeout(
        target=target,
        preflight_path=closeout_preflight_path,
        preflight=preflight,
        artifacts=artifacts,
        context=context,
    )


def _persist_closeout(
    *,
    target: Path,
    preflight_path: Path,
    preflight: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    context: dict[str, Any],
) -> dict[str, Any]:
    parent = target.resolve().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        names = {
            "execution_journal": "execution-journal.json",
            "post_run_receipt": "post-run-receipt.json",
            "evaluation_report": "evaluation-report.json",
            "operator_closeout_receipt": "operator-closeout-receipt.json",
        }
        paths: dict[str, Path] = {}
        for name, filename in names.items():
            paths[name] = staging / filename
            write_private_json(paths[name], artifacts[name])
        artifact_refs = {
            name: _artifact_ref_from_raw(
                target / names[name],
                paths[name],
                _canonical_hash(name, artifacts[name]),
            )
            for name in names
        }
        failures = validate_abort_artifacts(
            **artifacts,
            preflight_ref=_artifact_ref(preflight_path, preflight["preflight_sha256"]),
            preflight=preflight,
            expected_reviewer=context["reviewer_profile"]["reviewer"],
            expected_reviewer_profile_sha256=context["reviewer_profile_sha256"],
            expected_implementation=context["implementation"],
        )
        if failures:
            raise ValueError(f"persisted abort closeout invalid: {failures}")
        gate = build_closeout_gate(
            checked_at=datetime.now(timezone.utc).isoformat(),
            preflight_ref=_artifact_ref(preflight_path, preflight["preflight_sha256"]),
            preflight=preflight,
            artifact_refs=artifact_refs,
            artifacts=artifacts,
        )
        gate_path = staging / "claimed-abort-closeout-gate-report.json"
        write_private_json(gate_path, gate)
        gate_failures = validate_closeout_gate(
            gate,
            preflight_ref=_artifact_ref(preflight_path, preflight["preflight_sha256"]),
            preflight=preflight,
            artifact_refs=artifact_refs,
            artifacts=artifacts,
        )
        if gate_failures:
            raise ValueError(f"persisted abort closeout Gate invalid: {gate_failures}")
        _fsync_tree(staging)
        if target.exists():
            raise FileExistsError(f"abort closeout output already exists: {target}")
        os.rename(staging, target)
        _fsync_directory(parent)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "state": gate["state"],
        "run_id": preflight["run_id"],
        "output_root": str(target.resolve()),
        "artifacts": {
            name: {
                **_artifact_ref(
                    target / names[name], _canonical_hash(name, artifacts[name])
                )
            }
            for name in names
        },
        "gate": _artifact_ref(
            target / "claimed-abort-closeout-gate-report.json",
            gate["report_sha256"],
        ),
        "execution_started": False,
        "provider_api_call_performed": False,
        "authorization_reusable": False,
        "future_run_requires_new_authorization": True,
    }


def _closeout_context(
    *,
    authorization_path: Path,
    issuance_gate_path: Path,
    reviewer_profile_path: Path,
    claim_preflight_path: Path,
    claim_path: Path,
    entry_gate_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    context = _load_context(
        authorization_path=authorization_path,
        issuance_gate_path=issuance_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        repository_root=repository_root,
        require_clean_repository=True,
    )
    claim_preflight = _read_private(claim_preflight_path, "claim_preflight")
    claim = _read_private(claim_path, "claim")
    entry_gate = _read_private(entry_gate_path, "entry_gate")
    contract = context["contract_values"]
    authorization_failures = validate_authorization(
        context["authorization"],
        plan_path=contract["plan_path"],
        plan_bytes=contract["plan_bytes"],
        plan=contract["plan"],
        preflight_path=contract["frozen_preflight_path"],
        preflight_bytes=contract["frozen_preflight_bytes"],
        preflight=contract["frozen_preflight"],
        reviewer_profile=contract["reviewer_profile"],
        reviewer_profile_sha256=contract["reviewer_profile_sha256"],
        expected_implementation=contract["expected_authorization_implementation"],
        require_current=False,
    )
    if authorization_failures:
        raise ValueError(
            f"abort closeout authorization invalid: {authorization_failures}"
        )
    issuance_failures = validate_gate_report(
        context["issuance_gate"],
        authorization_path=str(context["authorization_artifact"]["path"]),
        authorization_bytes=context["authorization_artifact"]["raw"],
        authorization=context["authorization"],
        plan=contract["plan"],
        preflight=contract["frozen_preflight"],
        expected_inventory_snapshot=context["inventory_snapshot"],
    )
    if issuance_failures:
        raise ValueError(f"abort closeout issuance Gate invalid: {issuance_failures}")
    claim_preflight_failures = validate_claim_preflight(
        claim_preflight["value"],
        **contract,
        expected_inventory_snapshot=context["inventory_snapshot"],
        expected_execution_manifest=context["execution_manifest"],
        expected_implementation=claim["value"]["implementation"],
        require_current=False,
    )
    if claim_preflight_failures:
        raise ValueError(
            f"abort closeout claim preflight invalid: {claim_preflight_failures}"
        )
    claim_failures = validate_claim_receipt(
        claim["value"],
        claim_path=str(claim["path"]),
        authorization_path=str(context["authorization_artifact"]["path"]),
        authorization_bytes=context["authorization_artifact"]["raw"],
        authorization=context["authorization"],
        issuance_gate_path=str(context["issuance_gate_artifact"]["path"]),
        issuance_gate_bytes=context["issuance_gate_artifact"]["raw"],
        issuance_gate=context["issuance_gate"],
        claim_preflight_path=str(claim_preflight["path"]),
        claim_preflight_bytes=claim_preflight["raw"],
        claim_preflight=claim_preflight["value"],
        expected_implementation=claim["value"]["implementation"],
    )
    if claim_failures:
        raise ValueError(f"abort closeout claim invalid: {claim_failures}")
    entry_failures = validate_execution_entry_gate(
        entry_gate["value"],
        claim_path=str(claim["path"]),
        claim_bytes=claim["raw"],
        claim=claim["value"],
        expected_inventory_snapshot=context["inventory_snapshot"],
        expected_execution_manifest=context["execution_manifest"],
    )
    if entry_failures:
        raise ValueError(f"abort closeout entry Gate invalid: {entry_failures}")
    plan = contract["plan"]
    sources = plan["source_artifacts"]
    frozen_bundle = _bound_artifact(sources["frozen_evaluation_closeout_bundle"])
    post_run = _bound_artifact(sources["frozen_post_run_contract"])
    closeout = _bound_artifact(sources["frozen_operator_closeout_contract"])
    profile_failures = validate_reviewer_identity_profile(
        context["contract_values"]["reviewer_profile"]
    )
    if profile_failures:
        raise ValueError(f"abort closeout reviewer invalid: {profile_failures}")
    return {
        **context,
        "claim": claim["value"],
        "claim_ref": _artifact_ref(claim["path"], claim["value"]["claim_sha256"]),
        "entry_gate": entry_gate["value"],
        "entry_gate_ref": _artifact_ref(
            entry_gate["path"], entry_gate["value"]["report_sha256"]
        ),
        "frozen_bundle": frozen_bundle["value"],
        "frozen_bundle_ref": frozen_bundle["ref"],
        "post_run_contract": post_run["value"],
        "post_run_contract_ref": post_run["ref"],
        "closeout_contract": closeout["value"],
        "closeout_contract_ref": closeout["ref"],
        "reviewer_profile": context["contract_values"]["reviewer_profile"],
        "reviewer_profile_sha256": context["contract_values"][
            "reviewer_profile_sha256"
        ],
        "implementation": closeout_implementation(repository_root),
    }


def closeout_implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean for abort closeout")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _bound_artifact(ref: dict[str, str]) -> dict[str, Any]:
    artifact = _read_private(Path(ref["path"]), "frozen_closeout_source")
    canonical = _canonical_from_value(artifact["value"])
    if artifact["sha256"] != ref["sha256"] or canonical != ref["canonical_sha256"]:
        raise ValueError("frozen closeout source drifted")
    return {
        "value": artifact["value"],
        "ref": _artifact_ref(artifact["path"], canonical),
    }


def _require_terminal_paths(context: dict[str, Any], target: Path) -> None:
    execution_root = Path(context["authorization"]["controls"]["execution_root"])
    if execution_root.exists():
        raise ValueError("abort closeout requires absent execution root")
    if target.exists():
        raise ValueError("abort closeout output already exists")
    manifest = context["execution_manifest"]
    if (
        context["inventory_snapshot"]["running_count"] != 0
        or manifest["input_file_count"] != 0
        or manifest["output_file_count"] != 0
        or manifest["symlink_count"] != 0
    ):
        raise ValueError("abort closeout requires zero execution side effects")


def _validate_reviewer_configuration(
    profile: dict[str, Any],
    *,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
) -> None:
    key = profile["pkcs11_key"]
    if not (
        key.get("module_path") == str(Path(module_path).resolve())
        and key.get("token_label") == token_label
        and key.get("key_label") == key_label
        and key.get("key_id_hex") == key_id_hex.lower()
    ):
        raise ValueError("abort closeout reviewer PKCS#11 configuration mismatch")


def _canonical_hash(name: str, value: dict[str, Any]) -> str:
    fields = {
        "execution_journal": "journal_sha256",
        "post_run_receipt": "receipt_sha256",
        "evaluation_report": "report_sha256",
    }
    if name in fields:
        return value[fields[name]]
    return hashlib.sha256(
        json.dumps(
            {key: item for key, item in value.items() if key != "signature"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _canonical_from_value(value: dict[str, Any]) -> str:
    for field in (
        "frozen_bundle_sha256",
        "contract_sha256",
        "manifest_sha256",
        "report_sha256",
    ):
        if field in value:
            return str(value[field])
    return canonical_sha256(value)


def _artifact_ref(path: Path, canonical: str) -> dict[str, str]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def _artifact_ref_from_raw(
    final_path: Path, raw_path: Path, canonical: str
) -> dict[str, str]:
    return {
        "path": str(final_path.resolve()),
        "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


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


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("preflight", "closeout"):
        command = subparsers.add_parser(name)
        command.add_argument("--authorization", type=Path, required=True)
        command.add_argument("--issuance-gate", type=Path, required=True)
        command.add_argument("--reviewer-profile", type=Path, required=True)
        command.add_argument("--claim-preflight", type=Path, required=True)
        command.add_argument("--claim", type=Path, required=True)
        command.add_argument("--entry-gate", type=Path, required=True)
        command.add_argument(
            "--repository-root", type=Path, default=Path(__file__).parents[1]
        )
        if name == "preflight":
            command.add_argument("--output-root", type=Path, required=True)
        else:
            command.add_argument("--closeout-preflight", type=Path, required=True)
            command.add_argument("--owner-authorization-id", required=True)
            command.add_argument("--owner-statement", required=True)
            command.add_argument("--owner-statement-sha256", required=True)
            command.add_argument("--module", default=DEFAULT_MODULE)
            command.add_argument("--token-label", required=True)
            command.add_argument("--key-label", required=True)
            command.add_argument("--key-id", required=True)
    args = parser.parse_args()
    common = {
        "authorization_path": args.authorization,
        "issuance_gate_path": args.issuance_gate,
        "reviewer_profile_path": args.reviewer_profile,
        "claim_preflight_path": args.claim_preflight,
        "claim_path": args.claim,
        "entry_gate_path": args.entry_gate,
        "repository_root": args.repository_root,
    }
    try:
        if args.operation == "preflight":
            result = generate_abort_closeout_preflight(
                **common, output_root=args.output_root
            )
        else:
            result = perform_abort_closeout(
                **common,
                closeout_preflight_path=args.closeout_preflight,
                owner_authorization_id=args.owner_authorization_id,
                owner_statement=args.owner_statement,
                owner_statement_sha256=args.owner_statement_sha256,
                module_path=args.module,
                token_label=args.token_label,
                key_label=args.key_label,
                key_id_hex=args.key_id,
                pin=read_pin(None),
            )
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "state": "blocked_claimed_abort_closeout",
                    "error_class": type(error).__name__,
                    "error": str(error),
                    "execution_started": False,
                    "provider_credential_read": False,
                    "provider_api_call_performed": False,
                    "backend_fact_append_performed": False,
                    "ledger_append_performed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
