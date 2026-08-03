"""Replay r4 and generate an offline descriptive postmortem review handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_outcome_sensitive_evaluation import (
    validate_evaluation_report,
)
from benchmarks.j1.qualification_outcome_sensitive_postmortem import (
    build_postmortem,
    build_review_handoff,
    build_review_request,
    owner_review_statement,
)
from benchmarks.j1.qualification_successful_execution_closeout_v4 import (
    build_preflight,
    validate_closeout_artifacts,
    validate_preflight,
)
from benchmarks.j1_qualification_outcome_sensitive_successful_closeout import (
    _collect,
    _journal,
    _participant_profiles,
    _participant_records,
    _read_bound,
    _replay_tasks,
)
from benchmarks.j1_qualification_successful_execution_closeout_v4 import (
    _read_private,
    _ref,
)


OPERATION_SOURCE = Path(__file__)
DOMAIN_SOURCE = (
    Path(__file__).parent
    / "j1"
    / "qualification_outcome_sensitive_postmortem.py"
)
CLOSEOUT_SOURCE = (
    Path(__file__).parent
    / "j1_qualification_outcome_sensitive_successful_closeout.py"
)


def generate_postmortem(
    *,
    postmortem_id: str,
    request_id: str,
    created_at: str,
    preflight_path: Path,
    closeout_gate_path: Path,
    participant_profiles_root: Path,
    execution_root: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Replay the immutable run and publish private review-only artifacts."""
    if output_root.exists():
        raise FileExistsError(f"outcome-sensitive postmortem exists: {output_root}")
    current_revision = _clean_pushed_revision(repository_root)
    preflight, preflight_raw = _read_private(preflight_path)
    closeout_gate, closeout_gate_raw = _read_private(closeout_gate_path)
    if validate_preflight(preflight):
        raise ValueError("outcome-sensitive successful closeout preflight invalid")
    source = preflight["source_binding"]
    context = _collect(
        authorization_path=Path(source["authorization"]["path"]),
        issuance_gate_path=Path(source["issuance_gate"]["path"]),
        claim_preflight_path=Path(source["claim_preflight"]["path"]),
        claim_path=Path(source["claim"]["path"]),
        entry_gate_path=Path(source["entry_gate"]["path"]),
        live_report_path=Path(source["live_report"]["path"]),
        reviewer_profile_path=Path(source["reviewer_profile"]["path"]),
        participant_profiles_root=participant_profiles_root,
        execution_root=execution_root,
        repository_root=repository_root,
        source_revision=preflight["implementation"]["source_revision"],
    )
    replayed_preflight = build_preflight(**context, profile="outcome_sensitive")
    if replayed_preflight != preflight:
        raise ValueError("outcome-sensitive successful closeout preflight drifted")

    artifacts = _validate_terminal_closeout(
        preflight=preflight,
        preflight_path=preflight_path,
        preflight_raw=preflight_raw,
        closeout_gate=closeout_gate,
        closeout_gate_path=closeout_gate_path,
        closeout_gate_raw=closeout_gate_raw,
    )
    contract = _read_bound(source["execution_contract"], "contract_sha256")
    fixture = _read_bound(source["task_fixture"], "fixture_sha256")
    assignment = _read_bound(source["assignment"], "assignment_sha256")
    authorization_path = Path(source["authorization"]["path"])
    _, authorization_raw = _read_private(authorization_path)
    profiles = _participant_profiles(participant_profiles_root)
    journal = _journal(execution_root / "execution-journal.sqlite3")
    observations = _replay_tasks(
        contract=contract,
        fixture=fixture,
        profiles=profiles,
        journal=journal,
        run_id=preflight["run_id"],
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
    )
    participant_records = _participant_records(
        assignment=assignment,
        observations=observations,
        run_id=preflight["run_id"],
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
    )
    if participant_records != preflight["participant_outcomes"]:
        raise ValueError("outcome-sensitive participant outcome replay drifted")

    source_binding = {
        "successful_closeout_preflight": _ref(
            preflight_path,
            preflight["preflight_sha256"],
            raw=preflight_raw,
        ),
        "successful_closeout_gate": _ref(
            closeout_gate_path,
            closeout_gate["report_sha256"],
            raw=closeout_gate_raw,
        ),
        **{
            name: closeout_gate["artifacts"][name]
            for name in (
                "outcome_manifest",
                "post_run_receipt",
                "evaluation_report",
                "closeout_receipt",
            )
        },
        "execution_contract": source["execution_contract"],
        "task_fixture": source["task_fixture"],
        "execution_journal": source["execution_journal"],
        "task_evidence_reference_set": {
            "task_count": 480,
            "canonical_sha256": canonical_sha256(
                [
                    {
                        "task_execution_id": item["task_execution_id"],
                        "evidence": item["payload"]["evidence"],
                    }
                    for item in journal["committed"]
                ]
            ),
        },
    }
    implementation = {
        "source_revision": current_revision,
        "source_files": {
            str(path.relative_to(repository_root)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in (DOMAIN_SOURCE, OPERATION_SOURCE, CLOSEOUT_SOURCE)
        },
        "external_effect_performed": False,
    }
    postmortem = build_postmortem(
        postmortem_id=postmortem_id,
        created_at=created_at,
        source_binding=source_binding,
        implementation=implementation,
        participant_records=participant_records,
        observations=observations,
        evaluation_report=artifacts["evaluation_report"],
        closeout_gate=closeout_gate,
    )
    return _persist(
        postmortem=postmortem,
        request_id=request_id,
        created_at=created_at,
        output_root=output_root,
    )


def _validate_terminal_closeout(
    *,
    preflight: dict[str, Any],
    preflight_path: Path,
    preflight_raw: bytes,
    closeout_gate: dict[str, Any],
    closeout_gate_path: Path,
    closeout_gate_raw: bytes,
) -> dict[str, dict[str, Any]]:
    if not (
        closeout_gate.get("passed") is True
        and closeout_gate.get("state")
        == (
            "successful_run_closed_structural_pass_thresholds_not_met_"
            "no_maturity_upgrade"
        )
        and closeout_gate.get("report_sha256")
        == canonical_sha256(
            {
                key: item
                for key, item in closeout_gate.items()
                if key != "report_sha256"
            }
        )
        and hashlib.sha256(closeout_gate_raw).hexdigest()
        == _raw_sha256(closeout_gate_path)
    ):
        raise ValueError("outcome-sensitive successful closeout Gate invalid")
    loaded = {}
    for name, ref in closeout_gate.get("artifacts", {}).items():
        value, raw = _read_private(Path(ref["path"]))
        if not (
            hashlib.sha256(raw).hexdigest() == ref["sha256"]
            and _artifact_canonical(value) == ref["canonical_sha256"]
        ):
            raise ValueError(f"outcome-sensitive closeout artifact drifted: {name}")
        loaded[name] = value
    expected = {
        "outcome_manifest",
        "post_run_receipt",
        "evaluation_report",
        "closeout_receipt",
    }
    if set(loaded) != expected:
        raise ValueError("outcome-sensitive closeout artifact set invalid")
    reviewer_path = Path(preflight["source_binding"]["reviewer_profile"]["path"])
    reviewer_profile, reviewer_profile_raw = _read_private(reviewer_path)
    failures = validate_closeout_artifacts(
        loaded,
        preflight=preflight,
        preflight_ref=_ref(
            preflight_path,
            preflight["preflight_sha256"],
            raw=preflight_raw,
        ),
        reviewer=reviewer_profile["reviewer"],
        reviewer_profile_sha256=hashlib.sha256(reviewer_profile_raw).hexdigest(),
        owner_statement_sha256=loaded["closeout_receipt"]["owner_authorization"][
            "statement_sha256"
        ],
    )
    failures += validate_evaluation_report(loaded["evaluation_report"])
    if failures:
        raise ValueError(
            f"outcome-sensitive successful closeout replay invalid: {failures}"
        )
    return loaded


def _persist(
    *,
    postmortem: dict[str, Any],
    request_id: str,
    created_at: str,
    output_root: Path,
) -> dict[str, Any]:
    parent = output_root.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.", suffix=".staging", dir=parent)
    )
    staging.chmod(0o700)
    try:
        postmortem_path = staging / "outcome-sensitive-r4-postmortem.json"
        write_private_json(postmortem_path, postmortem)
        postmortem_ref = _published_ref(
            postmortem_path,
            output_root / postmortem_path.name,
            postmortem["report_sha256"],
        )
        request = build_review_request(
            request_id=request_id,
            created_at=created_at,
            postmortem_ref=postmortem_ref,
            postmortem=postmortem,
        )
        request_path = staging / "outcome-sensitive-r4-postmortem-review-request.json"
        write_private_json(request_path, request)
        request_ref = _published_ref(
            request_path,
            output_root / request_path.name,
            request["request_sha256"],
        )
        statement = owner_review_statement(
            postmortem_raw_sha256=postmortem_ref["sha256"],
            postmortem_canonical_sha256=postmortem_ref["canonical_sha256"],
            request_raw_sha256=request_ref["sha256"],
            request_canonical_sha256=request_ref["canonical_sha256"],
            run_id=postmortem["run_id"],
        )
        handoff = build_review_handoff(
            postmortem_ref=postmortem_ref,
            request_ref=request_ref,
            statement=statement,
        )
        write_private_json(
            staging / "outcome-sensitive-r4-postmortem-review-handoff.json",
            handoff,
        )
        os.rename(staging, output_root)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return json.loads(
        (output_root / "outcome-sensitive-r4-postmortem-review-handoff.json").read_text()
    )


def _published_ref(
    staging_path: Path,
    final_path: Path,
    canonical_sha256: str,
) -> dict[str, str]:
    return {
        "path": str(final_path.resolve()),
        "sha256": hashlib.sha256(staging_path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_sha256,
    }


def _artifact_canonical(value: dict[str, Any]) -> str:
    for key in ("manifest_sha256", "receipt_sha256", "report_sha256"):
        if isinstance(value.get(key), str):
            return str(value[key])
    signature = value.get("signature", {})
    if isinstance(signature, dict) and isinstance(
        signature.get("signed_payload_sha256"), str
    ):
        return str(signature["signed_payload_sha256"])
    raise ValueError("outcome-sensitive closeout artifact canonical hash missing")


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.resolve().read_bytes()).hexdigest()


def _clean_pushed_revision(repository_root: Path) -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise ValueError("Agent repository must be clean before postmortem generation")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    upstream = subprocess.run(
        ["git", "rev-parse", "@{upstream}"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if revision != upstream:
        raise ValueError("Agent revision must be pushed before postmortem generation")
    return revision


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay a complete outcome-sensitive r4 run and generate a private "
            "descriptive postmortem review handoff."
        )
    )
    parser.add_argument("--postmortem-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--created-at")
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--closeout-gate", type=Path, required=True)
    parser.add_argument("--participant-profiles-root", type=Path, required=True)
    parser.add_argument("--execution-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    handoff = generate_postmortem(
        postmortem_id=args.postmortem_id,
        request_id=args.request_id,
        created_at=args.created_at or datetime.now(UTC).isoformat(),
        preflight_path=args.preflight,
        closeout_gate_path=args.closeout_gate,
        participant_profiles_root=args.participant_profiles_root,
        execution_root=args.execution_root,
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(handoff, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
