"""Prepare a private J1-D treatment, event, and pricing review candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_execution_design import build_execution_design


REPORT_SCHEMA = "j1-qualification-execution-design-operation:v1"


def prepare_execution_design(
    *,
    design_id: str,
    created_at: str,
    pricing_observed_at: str,
    qualification_protocol_path: Path,
    corpus_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"execution design output already exists: {output_root}")
    protocol, protocol_raw = _read_private(qualification_protocol_path)
    corpus, corpus_raw = _read_private(corpus_path)
    assignment, assignment_raw = _read_private(reviewed_assignment_path)
    assignment_gate, assignment_gate_raw = _read_private(assignment_gate_path)
    _validate_sources(
        protocol=protocol,
        protocol_path=qualification_protocol_path,
        protocol_raw=protocol_raw,
        corpus=corpus,
        corpus_path=corpus_path,
        corpus_raw=corpus_raw,
        assignment=assignment,
        assignment_path=reviewed_assignment_path,
        assignment_raw=assignment_raw,
        assignment_gate=assignment_gate,
    )
    design = build_execution_design(
        design_id=design_id,
        created_at=created_at,
        protocol=protocol,
        corpus=corpus,
        reviewed_assignment=assignment,
        pricing_observed_at=pricing_observed_at,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        design_path = output_root / "execution-design.review-required.json"
        write_private_json(design_path, design)
        raw_sha256 = hashlib.sha256(design_path.read_bytes()).hexdigest()
        statement = approval_statement(design, raw_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "execution_design_prepared_independent_review_required",
            "design": {
                **_artifact(design_path),
                "canonical_sha256": design["design_sha256"],
                "task_count": 8,
                "mentor_templates": 8,
                "control_advice_items": 0,
            },
            "source_artifacts": {
                "qualification_protocol": _artifact_bytes(
                    qualification_protocol_path, protocol_raw
                ),
                "corpus": _artifact_bytes(corpus_path, corpus_raw),
                "reviewed_assignment": _artifact_bytes(
                    reviewed_assignment_path, assignment_raw
                ),
                "assignment_gate": _artifact_bytes(
                    assignment_gate_path, assignment_gate_raw
                ),
            },
            "pricing_summary": design["pricing"],
            "budget_reservation": design["budget_reservation"],
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "independent_treatment_and_pricing_review_required": True,
            },
            "readiness": {
                "execution_design_prepared": True,
                "execution_design_reviewed": False,
                "mentor_identity_provisioned": False,
                "provider_broker_ready": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": design["execution_boundary"],
        }
        write_private_json(output_root / "execution-design-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def approval_statement(design: dict[str, Any], raw_sha256: str) -> str:
    rates = design["pricing"]["rates_microunits"]
    return (
        "I approve for independent review only the J1-D execution design artifact "
        f"{raw_sha256}, canonical design {design['design_sha256']}, containing 8 frozen "
        "mentor treatment templates, an empty advice projection for every control task, "
        f"and DeepSeek-V4-Pro USD-microunit rates per 1M tokens of {rates['input_cache_hit']} "
        f"cache-hit input, {rates['input_cache_miss']} cache-miss input, and {rates['output']} "
        "output. I acknowledge that a distinct mentor identity, mentor-signed advice, an "
        "executable isolation/event harness, provider broker, and single-use execution "
        "authorization are still required; this approval does not authorize model or Agent "
        "execution, Backend Fact append, or Ledger append."
    )


def _validate_sources(**values: Any) -> None:
    protocol = values["protocol"]
    corpus = values["corpus"]
    assignment = values["assignment"]
    gate = values["assignment_gate"]
    expected_artifacts = {
        "qualification_protocol": (
            values["protocol_path"],
            values["protocol_raw"],
        ),
        "reviewed_assignment": (
            values["assignment_path"],
            values["assignment_raw"],
        ),
    }
    if not (
        protocol.get("task_corpus", {}).get("artifact_sha256")
        == hashlib.sha256(values["corpus_raw"]).hexdigest()
        and protocol.get("task_corpus", {}).get("tasks_sha256")
        == corpus.get("tasks_sha256")
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and gate.get("readiness", {}).get("cohort_assignment_bound") is True
    ):
        raise ValueError("execution design source chain invalid")
    for field, (path, raw) in expected_artifacts.items():
        reference = gate.get("artifacts", {}).get(field, {})
        if reference != _artifact_bytes(path, raw):
            raise ValueError(f"execution design assignment Gate {field} drift")


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
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design-id", required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        now = datetime.now(timezone.utc).isoformat()
        report = prepare_execution_design(
            design_id=args.design_id,
            created_at=now,
            pricing_observed_at=now,
            qualification_protocol_path=args.qualification_protocol,
            corpus_path=args.corpus,
            reviewed_assignment_path=args.reviewed_assignment,
            assignment_gate_path=args.assignment_gate,
            output_root=args.output_root,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_execution_design_preparation",
            "error_class": type(error).__name__,
            "error": str(error),
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
