"""Read the current container state for one frozen J1-D activation."""

from __future__ import annotations

import json
import subprocess
from typing import Any


def activation_inventory(activation: dict[str, Any]) -> dict[str, int]:
    records = activation.get("containers")
    if not isinstance(records, list) or len(records) != 40:
        raise ValueError("r4 activation must bind exactly 40 containers")

    expected: dict[str, dict[str, Any]] = {}
    participant_ids: set[str] = set()
    for record in records:
        container = record.get("container") if isinstance(record, dict) else None
        container_id = (
            container.get("container_id") if isinstance(container, dict) else None
        )
        participant_id = record.get("participant_id") if isinstance(record, dict) else None
        if not (
            isinstance(container_id, str)
            and len(container_id) == 64
            and all(char in "0123456789abcdef" for char in container_id.lower())
            and isinstance(participant_id, str)
            and participant_id
            and container_id not in expected
            and participant_id not in participant_ids
        ):
            raise ValueError("r4 activation container identity set is invalid")
        expected[container_id] = container
        participant_ids.add(participant_id)

    result = subprocess.run(
        ["docker", "container", "inspect", *expected],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError("r4 activation container set is unavailable")
    try:
        inspected = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("r4 activation container inspection is invalid") from error
    if not isinstance(inspected, list) or len(inspected) != len(expected):
        raise ValueError("r4 activation container inspection is incomplete")

    current: dict[str, dict[str, Any]] = {}
    for item in inspected:
        container_id = item.get("Id") if isinstance(item, dict) else None
        if not (
            isinstance(container_id, str)
            and container_id in expected
            and container_id not in current
        ):
            raise ValueError("r4 activation container inspection identity mismatch")
        current[container_id] = item

    created_count = 0
    running_count = 0
    for container_id, expected_container in expected.items():
        item = current[container_id]
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        name = str(item.get("Name", "")).removeprefix("/")
        if not (
            name == expected_container.get("container_name")
            and item.get("Image") == expected_container.get("image_id")
        ):
            raise ValueError("r4 activation container projection drifted")
        created_count += state.get("Status") == "created"
        running_count += state.get("Running") is True

    return {
        "participant_container_count": len(current),
        "created_count": created_count,
        "running_count": running_count,
    }
