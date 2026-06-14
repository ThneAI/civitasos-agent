from __future__ import annotations

import json
import stat
from pathlib import Path

from benchmarks.i1_verifier_preparation_gate import (
    REQUIRED_CONTROL_TYPES,
    prepare_i1_verifier_assets,
)


ROOT = Path(__file__).resolve().parents[2]
I1_ROOT = ROOT / "benchmarks" / "i1"


def test_prepare_i1_verifier_assets(tmp_path: Path) -> None:
    output_root = tmp_path / "prepared"

    report = prepare_i1_verifier_assets(
        roster_path=I1_ROOT / "verifier_identity_roster.json",
        corpus_path=I1_ROOT / "verifier_corpus.json",
        negative_controls_path=I1_ROOT / "verifier_negative_controls.json",
        output_root=output_root,
    )

    assert report["passed"] is True
    assert report["readiness"]["state"] == "i1_assets_prepared_not_started"
    assert report["readiness"]["i1_execution_allowed"] is False
    identities = report["identity_manifest"]["identities"]
    assert len(identities) == 5
    assert len({item["did"] for item in identities}) == 5
    assert all(
        stat.S_IMODE(Path(item["identity_key_path"]).stat().st_mode) == 0o600
        for item in identities
    )
    corpus = report["corpus_manifest"]
    assert corpus["positive_case_count"] == 4
    assert corpus["negative_control_count"] == 7
    assert set(corpus["control_types"]) == REQUIRED_CONTROL_TYPES
    assert (output_root / "i1_verifier_preparation_report.json").is_file()


def test_preparation_reuses_stable_local_identities(tmp_path: Path) -> None:
    output_root = tmp_path / "prepared"
    first = _prepare(output_root)
    second = _prepare(output_root)

    first_ids = {
        item["identity_alias"]: item["did"]
        for item in first["identity_manifest"]["identities"]
    }
    second_ids = {
        item["identity_alias"]: item["did"]
        for item in second["identity_manifest"]["identities"]
    }
    assert first_ids == second_ids


def test_preparation_rejects_proposer_in_default_quorum(tmp_path: Path) -> None:
    roster = json.loads(
        (I1_ROOT / "verifier_identity_roster.json").read_text(encoding="utf-8")
    )
    roster["default_verifier_allowlist"].append("deepseek-api-agent")
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")

    report = prepare_i1_verifier_assets(
        roster_path=roster_path,
        corpus_path=I1_ROOT / "verifier_corpus.json",
        negative_controls_path=I1_ROOT / "verifier_negative_controls.json",
        output_root=tmp_path / "prepared",
    )

    assert report["passed"] is False
    assert report["checks"]["proposer_excluded_from_default_quorum"] is False
    assert report["identity_manifest"]["identity_count"] == 0


def test_preparation_rejects_missing_negative_control(tmp_path: Path) -> None:
    controls = json.loads(
        (I1_ROOT / "verifier_negative_controls.json").read_text(encoding="utf-8")
    )
    controls["controls"] = [
        item
        for item in controls["controls"]
        if item["control_type"] != "hash_mismatch"
    ]
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(json.dumps(controls), encoding="utf-8")

    report = prepare_i1_verifier_assets(
        roster_path=I1_ROOT / "verifier_identity_roster.json",
        corpus_path=I1_ROOT / "verifier_corpus.json",
        negative_controls_path=controls_path,
        output_root=tmp_path / "prepared",
    )

    assert report["passed"] is False
    assert report["checks"]["negative_control_coverage_complete"] is False


def test_preparation_rejects_ineffective_negative_control(tmp_path: Path) -> None:
    controls = json.loads(
        (I1_ROOT / "verifier_negative_controls.json").read_text(encoding="utf-8")
    )
    side_effect = next(
        item
        for item in controls["controls"]
        if item["control_type"] == "side_effect_request"
    )
    side_effect["mutation"]["set_values"] = {
        "boundary.external_side_effect_allowed": False
    }
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(json.dumps(controls), encoding="utf-8")

    report = prepare_i1_verifier_assets(
        roster_path=I1_ROOT / "verifier_identity_roster.json",
        corpus_path=I1_ROOT / "verifier_corpus.json",
        negative_controls_path=controls_path,
        output_root=tmp_path / "prepared",
    )

    assert report["passed"] is False
    assert report["checks"]["negative_controls_effective"] is False


def _prepare(output_root: Path) -> dict:
    return prepare_i1_verifier_assets(
        roster_path=I1_ROOT / "verifier_identity_roster.json",
        corpus_path=I1_ROOT / "verifier_corpus.json",
        negative_controls_path=I1_ROOT / "verifier_negative_controls.json",
        output_root=output_root,
    )
