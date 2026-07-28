"""Generate an offline r11 null-result postmortem and amendment candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_null_result_postmortem import (
    build_amendment_candidate,
    build_postmortem,
    build_postmortem_gate,
)


OPERATION_SOURCE = Path(__file__)
DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_null_result_postmortem.py"
LIVE_EVIDENCE_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_live_evidence_v4.py"
)
REAL_EVALUATOR_SOURCE = Path(__file__).parent / "j1" / "qualification_real_evaluator.py"
REQUIRED_EVIDENCE = {
    "participant-decision",
    "event-receipts",
    "task-evidence",
    "task-verification",
}


def generate_postmortem(
    *,
    postmortem_id: str,
    candidate_id: str,
    execution_contract_path: Path,
    live_report_path: Path,
    outcome_manifest_path: Path,
    evaluation_report_path: Path,
    closeout_gate_path: Path,
    evidence_root: Path,
    output_root: Path,
    repository_root: Path,
    created_at: str | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"postmortem output already exists: {output_root}")
    created = created_at or datetime.now(UTC).isoformat()
    sources = {
        "execution_contract": _read_private_json(execution_contract_path),
        "live_report": _read_private_json(live_report_path),
        "outcome_manifest": _read_private_json(outcome_manifest_path),
        "evaluation_report": _read_private_json(evaluation_report_path),
        "closeout_gate": _read_private_json(closeout_gate_path),
    }
    task_records, evidence_set_sha256 = _read_task_records(evidence_root)
    implementation = _implementation(repository_root)
    source_binding = {name: item["ref"] for name, item in sources.items()}
    source_binding["task_evidence_root"] = {
        "path": str(evidence_root.resolve()),
        "sha256": evidence_set_sha256,
        "task_count": len(task_records),
    }
    postmortem = build_postmortem(
        postmortem_id=postmortem_id,
        created_at=created,
        source_binding=source_binding,
        implementation=implementation,
        contract=sources["execution_contract"]["value"],
        live_report=sources["live_report"]["value"],
        outcome_manifest=sources["outcome_manifest"]["value"],
        evaluation_report=sources["evaluation_report"]["value"],
        closeout_gate=sources["closeout_gate"]["value"],
        task_records=task_records,
    )
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    postmortem_path = output_root / "r11-null-result-postmortem.json"
    write_private_json(postmortem_path, postmortem)
    postmortem_ref = _artifact_ref(postmortem_path, postmortem["report_sha256"])
    candidate = build_amendment_candidate(
        candidate_id=candidate_id,
        created_at=created,
        postmortem_ref=postmortem_ref,
        implementation=implementation,
    )
    candidate_path = output_root / "outcome-sensitive-amendment-candidate.json"
    write_private_json(candidate_path, candidate)
    candidate_ref = _artifact_ref(candidate_path, candidate["candidate_sha256"])
    statement = owner_approval_statement(
        postmortem_ref=postmortem_ref,
        candidate_ref=candidate_ref,
    )
    gate = build_postmortem_gate(
        postmortem_ref=postmortem_ref,
        postmortem=postmortem,
        candidate_ref=candidate_ref,
        candidate=candidate,
        owner_statement=statement,
    )
    write_private_json(output_root / "null-result-postmortem-gate.json", gate)
    return gate


def owner_approval_statement(
    *,
    postmortem_ref: dict[str, str],
    candidate_ref: dict[str, str],
) -> str:
    return (
        "I approve for independent review only the J1-D r11 null-result "
        f"postmortem artifact raw SHA-256 {postmortem_ref['sha256']}, canonical "
        f"SHA-256 {postmortem_ref['canonical_sha256']}, and outcome-sensitive "
        f"amendment candidate raw SHA-256 {candidate_ref['sha256']}, canonical "
        f"SHA-256 {candidate_ref['canonical_sha256']}. I acknowledge that r11 "
        "proved the controlled execution and safety boundary but did not provide "
        "observable participant-decision effectiveness endpoints; r11 remains "
        "immutable and is neither reclassified as positive nor as a causal null. "
        "This approval permits only independent human review of the postmortem and "
        "candidate. It does not amend the protocol or evaluator, migrate participant "
        "consent, start a container, read a provider credential, call a provider or "
        "model, execute an Agent or task, append Backend Facts, append the Ledger, "
        "issue or consume an execution authorization, authorize an effectiveness "
        "claim, or upgrade SI-13 maturity."
    )


def _read_task_records(root: Path) -> tuple[list[dict[str, Any]], str]:
    resolved = root.resolve()
    if not resolved.is_dir() or resolved.is_symlink():
        raise ValueError("task Evidence root must be a regular directory")
    records = []
    refs = []
    for task_root in sorted(
        path for path in resolved.iterdir() if path.is_dir() and not path.is_symlink()
    ):
        values = {}
        task_refs = {}
        for name in sorted(REQUIRED_EVIDENCE):
            item = _read_private_json(
                task_root / f"{name}.json",
                object_required=name != "event-receipts",
            )
            if name == "event-receipts" and not isinstance(item["value"], list):
                raise ValueError(
                    f"event receipts must be a JSON array: {item['ref']['path']}"
                )
            values[name.replace("-", "_")] = item["value"]
            task_refs[name] = item["ref"]["sha256"]
        task_execution_id = values["participant_decision"].get("task_execution_id")
        records.append({"task_execution_id": task_execution_id, **values})
        refs.append(
            {
                "task_execution_id": task_execution_id,
                "artifacts": task_refs,
            }
        )
    if len(records) != 320:
        raise ValueError(f"expected 320 task Evidence directories, got {len(records)}")
    return records, canonical_sha256(refs)


def _read_private_json(path: Path, *, object_required: bool = True) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"artifact is not a regular file: {resolved}")
    if resolved.stat().st_mode & 0o777 != 0o600:
        raise ValueError(f"artifact must be mode 0600: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if object_required and not isinstance(value, dict):
        raise ValueError(f"artifact must be a JSON object: {resolved}")
    return {
        "value": value,
        "ref": {
            "path": str(resolved),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
    }


def _implementation(repository_root: Path) -> dict[str, str]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(revision) != 40:
        raise ValueError("Agent source revision is invalid")
    return {
        "source_revision": revision,
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
        "r11_live_evidence_source_sha256": hashlib.sha256(
            LIVE_EVIDENCE_SOURCE.read_bytes()
        ).hexdigest(),
        "r11_real_evaluator_source_sha256": hashlib.sha256(
            REAL_EVALUATOR_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _artifact_ref(path: Path, canonical: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay r11 and generate an offline null-result postmortem."
    )
    parser.add_argument("--postmortem-id", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--execution-contract", type=Path, required=True)
    parser.add_argument("--live-report", type=Path, required=True)
    parser.add_argument("--outcome-manifest", type=Path, required=True)
    parser.add_argument("--evaluation-report", type=Path, required=True)
    parser.add_argument("--closeout-gate", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    gate = generate_postmortem(
        postmortem_id=args.postmortem_id,
        candidate_id=args.candidate_id,
        execution_contract_path=args.execution_contract,
        live_report_path=args.live_report,
        outcome_manifest_path=args.outcome_manifest,
        evaluation_report_path=args.evaluation_report,
        closeout_gate_path=args.closeout_gate,
        evidence_root=args.evidence_root,
        output_root=args.output_root,
        repository_root=args.repository_root,
    )
    print(json.dumps(gate, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
