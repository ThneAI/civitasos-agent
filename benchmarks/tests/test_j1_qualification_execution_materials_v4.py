from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.j1.qualification_execution_materials_v4 import (
    build_material_bindings,
    replay_material_bindings,
    validate_material_bindings,
    validate_material_paths,
)


def _write_private(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _materials(tmp_path: Path) -> tuple[Path, Path, Path]:
    task_source = tmp_path / "task-source.json"
    advice = tmp_path / "signed-advice"
    profiles = tmp_path / "participant-profiles"
    _write_private(task_source, {"tasks": []})
    for index in range(160):
        _write_private(advice / f"advice-{index:03}.json", {"index": index})
    for index in range(40):
        _write_private(profiles / f"profile-{index:03}.json", {"index": index})
    return task_source, advice, profiles


def test_material_bindings_replay_private_input_manifests(tmp_path: Path) -> None:
    task_source, advice, profiles = _materials(tmp_path)

    bindings = build_material_bindings(
        task_source_path=task_source,
        signed_advice_root=advice,
        participant_profiles_root=profiles,
    )

    assert validate_material_bindings(bindings) == []
    assert bindings["signed_advice"]["file_count"] == 160
    assert bindings["participant_profiles"]["file_count"] == 40
    replay_material_bindings(bindings)


def test_material_paths_fail_before_claim_on_wrong_profile_root(
    tmp_path: Path,
) -> None:
    task_source, advice, profiles = _materials(tmp_path)
    bindings = build_material_bindings(
        task_source_path=task_source,
        signed_advice_root=advice,
        participant_profiles_root=profiles,
    )

    with pytest.raises(ValueError, match="participant_profiles_path_mismatch"):
        validate_material_paths(
            bindings,
            task_source_path=task_source,
            signed_advice_root=advice,
            participant_profiles_root=tmp_path / "public-evidence",
        )


def test_material_replay_rejects_content_drift(tmp_path: Path) -> None:
    task_source, advice, profiles = _materials(tmp_path)
    bindings = build_material_bindings(
        task_source_path=task_source,
        signed_advice_root=advice,
        participant_profiles_root=profiles,
    )
    _write_private(profiles / "profile-000.json", {"index": "drifted"})

    with pytest.raises(ValueError, match="participant_profiles_content_drift"):
        replay_material_bindings(bindings)
