"""Generate reviewed-plan-derived J1-D protocol/design amendment materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_cohort_amendment import (
    build_amendment_bundle,
    build_design_amendment,
    build_protocol_amendment,
    validate_amendment_bundle,
    validate_design_amendment,
    validate_protocol_amendment,
)
from benchmarks.j1.qualification_verifier import validate_verifier_manifest


REPORT_SCHEMA = "j1-qualification-protocol-design-amendment-operation:v1"
DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_cohort_amendment.py"
OPERATION_SOURCE = Path(__file__)


def generate_amendment_materials(
    *,
    created_at: str,
    base_protocol_path: Path,
    base_reviewed_design_path: Path,
    reviewed_corpus_v2_path: Path,
    reviewed_verifier_v2_path: Path,
    signed_advice_manifest_path: Path,
    reviewed_migration_plan_path: Path,
    migration_review_gate_path: Path,
    migration_review_receipt_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"amendment material output already exists: {output_root}")
    paths = {
        "base_protocol": base_protocol_path,
        "base_reviewed_design": base_reviewed_design_path,
        "reviewed_corpus_v2": reviewed_corpus_v2_path,
        "reviewed_verifier_v2": reviewed_verifier_v2_path,
        "signed_advice_manifest": signed_advice_manifest_path,
        "reviewed_migration_plan": reviewed_migration_plan_path,
        "migration_review_gate": migration_review_gate_path,
        "migration_review_receipt": migration_review_receipt_path,
    }
    sources = {name: _read_private(path) for name, path in paths.items()}
    _validate_sources(paths=paths, sources=sources)
    implementation = _implementation(repository_root)
    source_binding = {
        f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    inputs = {name: value for name, (value, _) in sources.items()}
    protocol_inputs = {
        "created_at": created_at,
        "source_binding": source_binding,
        "base_protocol": inputs["base_protocol"],
        "reviewed_corpus_v2": inputs["reviewed_corpus_v2"],
        "reviewed_verifier_v2": inputs["reviewed_verifier_v2"],
        "reviewed_migration_plan": inputs["reviewed_migration_plan"],
    }
    design_inputs = {
        "created_at": created_at,
        "source_binding": source_binding,
        "base_reviewed_design": inputs["base_reviewed_design"],
        "signed_advice_manifest": inputs["signed_advice_manifest"],
        "reviewed_migration_plan": inputs["reviewed_migration_plan"],
    }
    protocol = build_protocol_amendment(**protocol_inputs)
    design = build_design_amendment(**design_inputs)
    if validate_protocol_amendment(protocol, **protocol_inputs):
        raise ValueError("generated protocol amendment failed validation")
    if validate_design_amendment(design, **design_inputs):
        raise ValueError("generated design amendment failed validation")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        protocol_path = output_root / "qualification-protocol.amendment.json"
        design_path = output_root / "execution-design.amendment.json"
        write_private_json(protocol_path, protocol)
        write_private_json(design_path, design)
        bundle_inputs = {
            "created_at": created_at,
            "source_binding": source_binding,
            "protocol_amendment_artifact": _artifact(protocol_path),
            "protocol_amendment": protocol,
            "design_amendment_artifact": _artifact(design_path),
            "design_amendment": design,
            "reviewed_migration_plan": inputs["reviewed_migration_plan"],
            "implementation": implementation,
        }
        bundle = build_amendment_bundle(**bundle_inputs)
        failures = validate_amendment_bundle(bundle, **bundle_inputs)
        if failures:
            raise ValueError(f"generated amendment bundle invalid: {failures}")
        bundle_path = output_root / "protocol-design-amendment-bundle.json"
        write_private_json(bundle_path, bundle)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "protocol_design_amendment_materials_ready_consent_extension_required",
            "created_at": created_at,
            "protocol_amendment": {
                **_artifact(protocol_path),
                "canonical_sha256": protocol["amended_protocol_sha256"],
            },
            "design_amendment": {
                **_artifact(design_path),
                "canonical_sha256": design["amended_design_sha256"],
            },
            "bundle": {
                **_artifact(bundle_path),
                "canonical_sha256": bundle["bundle_sha256"],
            },
            "source_artifacts": {
                name: _artifact_bytes(paths[name], raw)
                for name, (_, raw) in sources.items()
            },
            "blockers": bundle["blockers"],
            "readiness": bundle["readiness"],
            "implementation": implementation,
            "execution_boundary": bundle["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(output_root / "amendment-material-operation.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_sources(
    *,
    paths: dict[str, Path],
    sources: dict[str, tuple[dict[str, Any], bytes]],
) -> None:
    values = {name: value for name, (value, _) in sources.items()}
    hashes = {
        name: hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in sources.items()
    }
    plan = values["reviewed_migration_plan"]
    gate = values["migration_review_gate"]
    receipt = values["migration_review_receipt"]
    expected_plan_sources = {
        "base_protocol": "base_protocol_artifact_sha256",
        "base_reviewed_design": "base_reviewed_design_artifact_sha256",
        "reviewed_corpus_v2": "reviewed_corpus_v2_artifact_sha256",
        "reviewed_verifier_v2": "reviewed_verifier_v2_artifact_sha256",
        "signed_advice_manifest": "signed_advice_manifest_artifact_sha256",
    }
    failures = []
    for source_name, binding_name in expected_plan_sources.items():
        if plan.get("source_binding", {}).get(binding_name) != hashes[source_name]:
            failures.append(f"amendment_{source_name}_binding_invalid")
    if not (
        values["base_protocol"].get("status") == "frozen"
        and values["base_reviewed_design"].get("status") == "operator_reviewed"
        and values["reviewed_corpus_v2"].get("status") == "operator_reviewed"
        and values["signed_advice_manifest"].get("status")
        == "signed_non_executable_gate_required"
        and plan.get("status") == "operator_reviewed"
    ):
        failures.append("amendment_source_state_invalid")
    failures.extend(
        validate_verifier_manifest(
            values["reviewed_verifier_v2"], expected_status="operator_reviewed"
        )
    )
    if not (
        gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state")
        == "cohort_migration_review_passed_amendment_generation_required"
        and gate.get("review_receipt_signature_valid") is True
        and gate.get("reviewed_plan")
        == {
            **_artifact_bytes(paths["reviewed_migration_plan"], sources["reviewed_migration_plan"][1]),
            "canonical_sha256": plan.get("reviewed_plan_sha256"),
        }
        and gate.get("review_receipt", {}).get("sha256")
        == hashes["migration_review_receipt"]
        and plan.get("operator_review", {}).get("review_receipt_sha256")
        == hashes["migration_review_receipt"]
        and receipt.get("review_request_sha256")
        == plan.get("operator_review", {}).get("review_request_sha256")
    ):
        failures.append("amendment_review_gate_binding_invalid")
    if failures:
        raise ValueError(f"protocol/design amendment source invalid: {failures}")


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError("repository must be clean before freezing amendment materials")
    hashes = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (DOMAIN_SOURCE, OPERATION_SOURCE)
    }
    return {
        "source_revision": _git(root, "rev-parse", "HEAD").strip(),
        "source_sha256": canonical_sha256(hashes),
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_bytes(path, path.read_bytes())


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-protocol", type=Path, required=True)
    parser.add_argument("--base-reviewed-design", type=Path, required=True)
    parser.add_argument("--reviewed-corpus-v2", type=Path, required=True)
    parser.add_argument("--reviewed-verifier-v2", type=Path, required=True)
    parser.add_argument("--signed-advice-manifest", type=Path, required=True)
    parser.add_argument("--reviewed-migration-plan", type=Path, required=True)
    parser.add_argument("--migration-review-gate", type=Path, required=True)
    parser.add_argument("--migration-review-receipt", type=Path, required=True)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = generate_amendment_materials(
        created_at=datetime.now(timezone.utc).isoformat(),
        base_protocol_path=args.base_protocol,
        base_reviewed_design_path=args.base_reviewed_design,
        reviewed_corpus_v2_path=args.reviewed_corpus_v2,
        reviewed_verifier_v2_path=args.reviewed_verifier_v2,
        signed_advice_manifest_path=args.signed_advice_manifest,
        reviewed_migration_plan_path=args.reviewed_migration_plan,
        migration_review_gate_path=args.migration_review_gate,
        migration_review_receipt_path=args.migration_review_receipt,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
