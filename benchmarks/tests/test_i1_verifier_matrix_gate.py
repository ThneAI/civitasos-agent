from __future__ import annotations

import json
from pathlib import Path

from benchmarks.i1_verifier_preparation_gate import prepare_i1_verifier_assets
from benchmarks.i1_verifier_matrix_gate import run_gate


def test_i1_matrix_signs_all_verdicts_and_rejects_controls(tmp_path: Path) -> None:
    preparation = prepare_i1_verifier_assets(
        roster_path=Path("benchmarks/i1/verifier_identity_roster.json"),
        corpus_path=Path("benchmarks/i1/verifier_corpus.json"),
        negative_controls_path=Path("benchmarks/i1/verifier_negative_controls.json"),
        output_root=tmp_path / "prep",
    )
    registration = _write_registration(tmp_path, preparation)

    report = run_gate(
        preparation_report_path=tmp_path / "prep" / "i1_verifier_preparation_report.json",
        identity_registration_path=registration,
        output=tmp_path / "matrix.json",
    )

    assert report["passed"] is True
    assert report["metrics"]["signature_verified_count"] == 55
    assert report["metrics"]["positive_cases_accepted"] == 4
    assert report["metrics"]["negative_controls_rejected"] == 7
    assert report["checks"]["hash_drift_negative_control_rejected"] is True
    assert report["checks"]["replay_negative_control_rejected"] is True
    assert report["checks"]["provider_homogeneity_negative_control_rejected"] is True
    assert report["checks"]["identity_conflict_negative_control_rejected"] is True


def test_i1_matrix_fails_closed_without_registration(tmp_path: Path) -> None:
    preparation = prepare_i1_verifier_assets(
        roster_path=Path("benchmarks/i1/verifier_identity_roster.json"),
        corpus_path=Path("benchmarks/i1/verifier_corpus.json"),
        negative_controls_path=Path("benchmarks/i1/verifier_negative_controls.json"),
        output_root=tmp_path / "prep",
    )
    registration = _write_registration(tmp_path, preparation)
    value = json.loads(registration.read_text(encoding="utf-8"))
    value["passed"] = False
    registration.write_text(json.dumps(value), encoding="utf-8")

    report = run_gate(
        preparation_report_path=tmp_path / "prep" / "i1_verifier_preparation_report.json",
        identity_registration_path=registration,
        output=tmp_path / "matrix.json",
    )

    assert report["passed"] is False
    assert report["checks"]["identity_registration_prerequisites_complete"] is False


def _write_registration(tmp_path: Path, preparation: dict) -> Path:
    identities = preparation["identity_manifest"]["identities"]
    path = tmp_path / "registration.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "i1-identity-registration-gate:v1",
                "passed": True,
                "identity_receipts": [
                    {
                        "identity_alias": item["identity_alias"],
                        "did": item["did"],
                        "signature_control_verified": True,
                    }
                    for item in identities
                ],
                "readiness": {"i1_execution_preflight_input_ready": True},
            }
        ),
        encoding="utf-8",
    )
    return path
