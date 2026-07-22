"""Sign an owner-approved J1-D execution design independent review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_execution_design import (
    build_execution_design_review_receipt,
    build_reviewed_execution_design,
    validate_execution_design,
    validate_execution_design_review_receipt,
    validate_reviewed_execution_design_binding,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_execution_design import (
    approval_statement,
    validate_execution_design_sources,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-execution-design-review-operation:v1"
DESIGN_CONTRACT_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_execution_design.py"
)
OPERATION_SOURCE = Path(__file__)
GATE_SOURCE = Path(__file__).parent / "j1_qualification_execution_design_review_gate.py"


def approve_execution_design_review(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    design_path: Path,
    candidate_preflight_path: Path,
    qualification_protocol_path: Path,
    corpus_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise ValueError(
            f"execution design review output already exists: {output_root}"
        )
    values = _load_context(
        design_path=design_path,
        candidate_preflight_path=candidate_preflight_path,
        qualification_protocol_path=qualification_protocol_path,
        corpus_path=corpus_path,
        reviewed_assignment_path=reviewed_assignment_path,
        assignment_gate_path=assignment_gate_path,
        reviewer_profile_path=reviewer_profile_path,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    preflight = values["preflight"]
    expected_statement = approval_statement(
        values["design"], hashlib.sha256(values["design_raw"]).hexdigest()
    )
    expected_statement_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    if not (
        preflight.get("approval_request", {}).get("required_exact_statement")
        == expected_statement
        and preflight.get("approval_request", {}).get("statement_sha256")
        == expected_statement_sha256
        and authorization_statement_sha256 == expected_statement_sha256
    ):
        raise ValueError("execution design approval statement/hash mismatch")
    if not _text(review_id) or not _text(authorization_id) or not _rfc3339(reviewed_at):
        raise ValueError("execution design review metadata invalid")
    implementation = _implementation(agent_revision)

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewer = values["reviewer"]
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            reviewer["reviewer"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            receipt = build_execution_design_review_receipt(
                review_id=review_id,
                reviewed_at=reviewed_at,
                authorization_id=authorization_id,
                authorization_statement_sha256=authorization_statement_sha256,
                design=values["design"],
                design_artifact_sha256=hashlib.sha256(values["design_raw"]).hexdigest(),
                protocol=values["protocol"],
                corpus=values["corpus"],
                reviewed_assignment=values["assignment"],
                reviewer_profile=reviewer,
                reviewer_profile_sha256=hashlib.sha256(
                    values["reviewer_raw"]
                ).hexdigest(),
                implementation=implementation,
                signer=signer,
            )
        receipt_path = output_root / "execution-design-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        reviewed = build_reviewed_execution_design(
            design=values["design"],
            receipt=receipt,
            receipt_artifact_sha256=receipt_sha256,
        )
        reviewed_path = output_root / "execution-design.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        failures = validate_execution_design_review_receipt(
            receipt,
            design=values["design"],
            design_artifact_sha256=hashlib.sha256(values["design_raw"]).hexdigest(),
            protocol=values["protocol"],
            corpus=values["corpus"],
            reviewed_assignment=values["assignment"],
            reviewer_profile=reviewer,
            reviewer_profile_sha256=hashlib.sha256(values["reviewer_raw"]).hexdigest(),
            implementation=implementation,
        )
        failures.extend(
            validate_reviewed_execution_design_binding(
                reviewed,
                design=values["design"],
                receipt=receipt,
                receipt_artifact_sha256=receipt_sha256,
            )
        )
        if failures:
            raise ValueError(f"reviewed execution design invalid: {failures}")
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "execution_design_reviewed_mentor_and_harness_required",
            "review_id": review_id,
            "reviewed_at": reviewed_at,
            "design": _artifact(design_path),
            "review_receipt": _artifact(receipt_path),
            "reviewed_design": {
                **_artifact(reviewed_path),
                "canonical_sha256": reviewed["reviewed_design_sha256"],
            },
            "authorization": {
                "authorization_id": authorization_id,
                "authorization_statement_sha256": authorization_statement_sha256,
            },
            "pin_recorded": False,
            "execution_boundary": _execution_boundary(),
        }
        write_private_json(
            output_root / "execution-design-review-operation.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _load_context(**paths: Any) -> dict[str, Any]:
    design, design_raw = _read_private(Path(paths["design_path"]))
    preflight, _ = _read_private(Path(paths["candidate_preflight_path"]))
    protocol, protocol_raw = _read_private(Path(paths["qualification_protocol_path"]))
    corpus, corpus_raw = _read_private(Path(paths["corpus_path"]))
    assignment, assignment_raw = _read_private(Path(paths["reviewed_assignment_path"]))
    assignment_gate, assignment_gate_raw = _read_private(
        Path(paths["assignment_gate_path"])
    )
    reviewer, reviewer_raw = _read_private(Path(paths["reviewer_profile_path"]))
    validate_execution_design_sources(
        protocol=protocol,
        protocol_path=Path(paths["qualification_protocol_path"]),
        protocol_raw=protocol_raw,
        corpus=corpus,
        corpus_path=Path(paths["corpus_path"]),
        corpus_raw=corpus_raw,
        assignment=assignment,
        assignment_path=Path(paths["reviewed_assignment_path"]),
        assignment_raw=assignment_raw,
        assignment_gate=assignment_gate,
    )
    failures = validate_execution_design(
        design,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
    )
    if failures:
        raise ValueError(f"execution design candidate invalid: {failures}")
    design_artifact = {
        "path": str(Path(paths["design_path"]).resolve()),
        "sha256": hashlib.sha256(design_raw).hexdigest(),
    }
    expected_sources = {
        "qualification_protocol": _artifact_bytes(
            Path(paths["qualification_protocol_path"]), protocol_raw
        ),
        "corpus": _artifact_bytes(Path(paths["corpus_path"]), corpus_raw),
        "reviewed_assignment": _artifact_bytes(
            Path(paths["reviewed_assignment_path"]), assignment_raw
        ),
        "assignment_gate": _artifact_bytes(
            Path(paths["assignment_gate_path"]), assignment_gate_raw
        ),
    }
    if not (
        preflight.get("passed") is True
        and preflight.get("state")
        == "execution_design_prepared_independent_review_required"
        and preflight.get("design", {}).get("path") == design_artifact["path"]
        and preflight.get("design", {}).get("sha256") == design_artifact["sha256"]
        and preflight.get("design", {}).get("canonical_sha256")
        == design.get("design_sha256")
        and preflight.get("source_artifacts") == expected_sources
        and preflight.get("readiness", {}).get("execution_design_reviewed") is False
        and preflight.get("readiness", {}).get("controlled_experiment_execution_ready")
        is False
    ):
        raise ValueError("execution design candidate preflight drift")
    reviewer_failures = validate_reviewer_identity_profile(reviewer)
    if reviewer_failures:
        raise ValueError(f"reviewer identity profile invalid: {reviewer_failures}")
    _validate_reviewer_configuration(reviewer, paths)
    pin_state = inspect_token_pin_state(
        module_path=str(Path(paths["module_path"]).resolve()),
        token_label=str(paths["token_label"]),
    )
    if not (
        pin_state["token_initialized"]
        and pin_state["user_pin_initialized"]
        and pin_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"reviewer token not ready: {pin_state}")
    return {
        "design": design,
        "design_raw": design_raw,
        "preflight": preflight,
        "protocol": protocol,
        "corpus": corpus,
        "assignment": assignment,
        "reviewer": reviewer,
        "reviewer_raw": reviewer_raw,
    }


def _validate_reviewer_configuration(
    profile: dict[str, Any], values: dict[str, Any]
) -> None:
    key = profile["pkcs11_key"]
    module = str(Path(values["module_path"]).resolve())
    expected = {
        "module_path": module,
        "token_label": values["token_label"],
        "key_label": values["key_label"],
        "key_id_hex": str(values["key_id_hex"]).lower(),
    }
    if any(
        key.get(field) != expected_value for field, expected_value in expected.items()
    ):
        raise ValueError("reviewer PKCS#11 configuration mismatch")
    if (
        key.get("module_sha256")
        != hashlib.sha256(Path(module).read_bytes()).hexdigest()
    ):
        raise ValueError("reviewer PKCS#11 module hash mismatch")


def _implementation(agent_revision: str) -> dict[str, str]:
    repository = OPERATION_SOURCE.parent.parent
    revision = agent_revision.lower()
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode or head.stdout.strip().lower() != revision:
        raise ValueError("execution design review revision is not checked out")
    if status.returncode or status.stdout.strip():
        raise ValueError("execution design review worktree must be clean")
    return {
        "agent_revision": revision,
        "design_contract_source_sha256": hashlib.sha256(
            DESIGN_CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "execution_design_review_only": True,
        "mentor_identity_provisioned": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_bytes(path, path.read_bytes())


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--authorization-id", required=True)
    parser.add_argument("--authorization-statement-sha256", required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--candidate-preflight", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    pin = ""
    try:
        pin = read_pin(args.pin_file)
        report = approve_execution_design_review(
            review_id=args.review_id,
            reviewed_at=datetime.now(timezone.utc).isoformat(),
            authorization_id=args.authorization_id,
            authorization_statement_sha256=args.authorization_statement_sha256,
            design_path=args.design,
            candidate_preflight_path=args.candidate_preflight,
            qualification_protocol_path=args.qualification_protocol,
            corpus_path=args.corpus,
            reviewed_assignment_path=args.reviewed_assignment,
            assignment_gate_path=args.assignment_gate,
            reviewer_profile_path=args.reviewer_profile,
            module_path=args.module,
            token_label=args.token_label,
            key_label=args.key_label,
            key_id_hex=args.key_id,
            agent_revision=args.agent_revision,
            pin=pin,
            output_root=args.output_root,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_execution_design_review",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    finally:
        pin = ""
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
