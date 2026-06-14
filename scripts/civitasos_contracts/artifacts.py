"""Canonical task/review/approval/receipt envelope and artifact references."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping


ARTIFACT_ENVELOPE_SCHEMA = "civitasos-artifact-envelope:v1"
ARTIFACT_KINDS = frozenset({"task", "review", "approval", "receipt"})
ARTIFACT_PLANES = frozenset({"runtime", "governance", "release"})


def build_artifact_envelope(
    *,
    artifact_kind: str,
    plane: str,
    schema_version: str,
    artifact_id: str,
    subject_id: str,
    producer: str,
    source_refs: Iterable[Mapping[str, Any]] = (),
    scope: str,
) -> dict[str, Any]:
    envelope = {
        "schema_version": ARTIFACT_ENVELOPE_SCHEMA,
        "artifact_kind": artifact_kind,
        "plane": plane,
        "payload_schema_version": _required_text(schema_version, "schema_version"),
        "artifact_id": _required_text(artifact_id, "artifact_id"),
        "subject_id": _required_text(subject_id, "subject_id"),
        "producer": _required_text(producer, "producer"),
        "scope": _required_text(scope, "scope"),
        "source_refs": [dict(ref) for ref in source_refs if ref],
    }
    failures = validate_artifact_envelope(envelope)
    if failures:
        raise ValueError("; ".join(failures))
    return envelope


def validate_artifact_envelope(value: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return ["artifact envelope must be an object"]
    if value.get("schema_version") != ARTIFACT_ENVELOPE_SCHEMA:
        failures.append(f"schema_version must be {ARTIFACT_ENVELOPE_SCHEMA}")
    if value.get("artifact_kind") not in ARTIFACT_KINDS:
        failures.append(f"artifact_kind must be one of {sorted(ARTIFACT_KINDS)}")
    if value.get("plane") not in ARTIFACT_PLANES:
        failures.append(f"plane must be one of {sorted(ARTIFACT_PLANES)}")
    for field in ("payload_schema_version", "artifact_id", "subject_id", "producer", "scope"):
        if not str(value.get(field) or "").strip():
            failures.append(f"{field} must be non-empty")
    source_refs = value.get("source_refs")
    if not isinstance(source_refs, list):
        failures.append("source_refs must be a list")
    else:
        for index, ref in enumerate(source_refs):
            if not isinstance(ref, dict):
                failures.append(f"source_refs[{index}] must be an object")
                continue
            if not str(ref.get("path") or "").strip():
                failures.append(f"source_refs[{index}].path must be non-empty")
            digest = str(ref.get("sha256") or "")
            if len(digest) != 64:
                failures.append(f"source_refs[{index}].sha256 must be a SHA-256 digest")
    return failures


def artifact_ref(path: Path) -> dict[str, str | None]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "sha256": _sha256(resolved) if resolved.is_file() else None,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} must be non-empty")
    return text
