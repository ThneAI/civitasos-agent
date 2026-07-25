from __future__ import annotations

import copy
import json
import subprocess

import pytest

from benchmarks.j1_qualification_runtime_inventory_v4 import activation_inventory


def _activation() -> dict:
    return {
        "containers": [
            {
                "participant_id": f"participant-{index:02d}",
                "container": {
                    "container_id": f"{index + 1:064x}",
                    "container_name": f"civitas-j1q-runner-current-{index:02d}",
                    "image_id": "sha256:" + "a" * 64,
                },
            }
            for index in range(40)
        ]
    }


def _inspect(activation: dict) -> list[dict]:
    return [
        {
            "Id": record["container"]["container_id"],
            "Name": f"/{record['container']['container_name']}",
            "Image": record["container"]["image_id"],
            "State": {"Status": "created", "Running": False},
        }
        for record in activation["containers"]
    ]


def test_inventory_inspects_only_activation_container_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activation = _activation()
    inspected = _inspect(activation)
    captured: list[str] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(inspected), "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert activation_inventory(activation) == {
        "participant_container_count": 40,
        "created_count": 40,
        "running_count": 0,
    }
    assert captured[:3] == ["docker", "container", "inspect"]
    assert set(captured[3:]) == {
        record["container"]["container_id"] for record in activation["containers"]
    }
    assert "civitas-j1q-runner-old-revision" not in captured


def test_inventory_rejects_missing_or_drifted_activation_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activation = _activation()
    inspected = _inspect(activation)
    inspected[0]["Name"] = "/replacement-with-same-family-prefix"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **_: subprocess.CompletedProcess(
            command, 0, json.dumps(inspected), ""
        ),
    )

    with pytest.raises(ValueError, match="projection drifted"):
        activation_inventory(activation)

    missing = copy.deepcopy(activation)
    missing["containers"].pop()
    with pytest.raises(ValueError, match="exactly 40"):
        activation_inventory(missing)
