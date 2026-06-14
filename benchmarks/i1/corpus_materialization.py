"""Materialize I.1 positive cases and fail-closed negative controls."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.i1.data import as_object, strings


def materialize_cases(
    *,
    cases: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    output_root: Path,
) -> list[dict[str, Any]]:
    output_root.mkdir(parents=True, exist_ok=True)
    by_id = {str(item["case_id"]): item for item in cases}
    manifest = []
    for case in cases:
        artifact = copy.deepcopy(as_object(case["artifact"]))
        manifest.append(
            _write_case(
                output_root=output_root,
                case_id=str(case["case_id"]),
                case_class="positive",
                expected_verdict="accept",
                expected_failure_reason=None,
                artifact=artifact,
                metadata={},
            )
        )
    for control in controls:
        base = copy.deepcopy(
            as_object(by_id[str(control["base_case_id"])]["artifact"])
        )
        mutation = as_object(control.get("mutation"))
        for path in strings(mutation.get("delete_paths")):
            _delete_path(base, path)
        for path, value in as_object(mutation.get("set_values")).items():
            _set_path(base, path, value)
        metadata = {
            key: value
            for key, value in mutation.items()
            if key not in {"delete_paths", "set_values"}
        }
        manifest.append(
            _write_case(
                output_root=output_root,
                case_id=str(control["control_id"]),
                case_class="negative_control",
                expected_verdict="reject",
                expected_failure_reason=str(control["expected_failure_reason"]),
                artifact=base,
                metadata=metadata,
            )
        )
    return manifest


def negative_controls_effective(
    *,
    materialized_cases: list[dict[str, Any]],
    identities: list[dict[str, Any]],
    proposer_alias: str,
) -> bool:
    controls = {
        str(item["case_id"]).removeprefix("negative-"): item
        for item in materialized_cases
        if item.get("case_class") == "negative_control"
    }
    identity_runtime = {
        str(item.get("identity_alias")): str(item.get("runtime_family"))
        for item in identities
    }
    try:
        schema_artifact = _read_artifact(controls["schema-error"])
        semantic_artifact = _read_artifact(controls["semantic-error"])
        side_effect_artifact = _read_artifact(controls["side-effect-request"])
        hash_case = controls["hash-mismatch"]
        identity_selection = _metadata_strings(
            controls["identity-conflict"], "verifier_selection"
        )
        replay_ref = str(
            as_object(controls["response-replay"].get("control_metadata")).get(
                "replay_of_control_id"
            )
            or ""
        )
        homogeneous_selection = _metadata_strings(
            controls["provider-homogeneity"], "verifier_selection"
        )
    except (KeyError, OSError, json.JSONDecodeError):
        return False
    homogeneous_runtimes = {
        identity_runtime.get(alias, "") for alias in homogeneous_selection
    }
    semantic_checks = as_object(
        as_object(semantic_artifact.get("result")).get("checks")
    )
    return (
        "schema_version" not in schema_artifact
        and any(value is False for value in semantic_checks.values())
        and hash_case.get("claimed_sha256") != hash_case.get("artifact_sha256")
        and as_object(side_effect_artifact.get("boundary")).get(
            "external_side_effect_allowed"
        )
        is True
        and proposer_alias in identity_selection
        and bool(replay_ref)
        and len(homogeneous_selection) >= 3
        and homogeneous_runtimes == {"cli-agent"}
    )


def _metadata_strings(case: dict[str, Any], key: str) -> list[str]:
    return strings(as_object(case.get("control_metadata")).get(key))


def _write_case(
    *,
    output_root: Path,
    case_id: str,
    case_class: str,
    expected_verdict: str,
    expected_failure_reason: str | None,
    artifact: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    path = output_root / f"{case_id}.json"
    path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "case_id": case_id,
        "case_class": case_class,
        "artifact_path": str(path.resolve()),
        "artifact_sha256": actual_sha256,
        "claimed_sha256": metadata.get("claimed_sha256", actual_sha256),
        "expected_verdict": expected_verdict,
        "expected_failure_reason": expected_failure_reason,
        "control_metadata": metadata,
    }


def _read_artifact(case: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(Path(str(case["artifact_path"])).read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def _delete_path(value: dict[str, Any], dotted_path: str) -> None:
    parts = dotted_path.split(".")
    parent = value
    for part in parts[:-1]:
        parent = as_object(parent.get(part))
    parent.pop(parts[-1], None)


def _set_path(value: dict[str, Any], dotted_path: str, replacement: Any) -> None:
    parts = dotted_path.split(".")
    parent = value
    for part in parts[:-1]:
        child = parent.get(part)
        if not isinstance(child, dict):
            child = {}
            parent[part] = child
        parent = child
    parent[parts[-1]] = replacement
