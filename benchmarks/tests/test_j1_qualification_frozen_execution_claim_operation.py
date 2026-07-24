from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.j1_qualification_frozen_execution_claim import (
    _inspect_execution_workspace,
    _require_future_paths_absent,
)


def _activation(tmp_path: Path) -> dict:
    containers = []
    for index in range(40):
        participant_id = f"participant-{index:02d}"
        state = tmp_path / participant_id
        input_path = state / "input"
        output_path = state / "output"
        input_path.mkdir(parents=True)
        output_path.mkdir()
        containers.append(
            {
                "participant_id": participant_id,
                "container": {
                    "container_name": f"container-{index:02d}",
                    "mounts": [
                        {
                            "destination": "/input",
                            "source": str(input_path),
                        },
                        {
                            "destination": "/output",
                            "source": str(output_path),
                        },
                    ],
                },
            }
        )
    return {"containers": containers}


def _authorization(tmp_path: Path) -> dict:
    return {
        "execution_scope": {
            "participant_count": 40,
            "matched_pair_count": 20,
            "task_count_per_participant": 8,
            "authorized_task_executions": 320,
            "provider_id": "openai_compatible",
            "model_id": "deepseek-v4-pro",
            "temperature": 0,
        },
        "controls": {
            "authorization_consumption_path": str(tmp_path / "claim.json"),
            "execution_root": str(tmp_path / "run"),
            "post_run_output_root": str(tmp_path / "post-run"),
        },
    }


def test_workspace_inspection_binds_exact_empty_isolated_set(
    tmp_path: Path,
) -> None:
    activation = _activation(tmp_path)
    authorization = _authorization(tmp_path)
    inventory = {
        "container_count": 40,
        "running_count": 0,
        "container_set_sha256": "a" * 64,
    }

    manifest = _inspect_execution_workspace(
        activation=activation,
        authorization=authorization,
        inventory_snapshot=inventory,
    )

    assert manifest["input_directory_count"] == 40
    assert manifest["output_directory_count"] == 40
    assert manifest["input_file_count"] == 0
    assert manifest["output_file_count"] == 0
    assert manifest["symlink_count"] == 0
    assert len(manifest["workspace_set_sha256"]) == 64


def test_workspace_inspection_exposes_files_and_rejects_symlink_directory(
    tmp_path: Path,
) -> None:
    activation = _activation(tmp_path)
    authorization = _authorization(tmp_path)
    inventory = {
        "container_count": 40,
        "running_count": 0,
        "container_set_sha256": "a" * 64,
    }
    output = Path(
        activation["containers"][0]["container"]["mounts"][1]["source"]
    )
    (output / "unexpected.json").write_text("{}")

    manifest = _inspect_execution_workspace(
        activation=activation,
        authorization=authorization,
        inventory_snapshot=inventory,
    )
    assert manifest["output_file_count"] == 1

    original = Path(
        activation["containers"][1]["container"]["mounts"][0]["source"]
    )
    replacement = tmp_path / "linked-input"
    original.rename(replacement)
    original.symlink_to(replacement, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        _inspect_execution_workspace(
            activation=activation,
            authorization=authorization,
            inventory_snapshot=inventory,
        )


def test_future_path_guard_fails_before_claim_or_execution_side_effect(
    tmp_path: Path,
) -> None:
    authorization = _authorization(tmp_path)
    _require_future_paths_absent(authorization)

    Path(authorization["controls"]["execution_root"]).mkdir()
    with pytest.raises(ValueError, match="execution_root"):
        _require_future_paths_absent(authorization)
