"""Canonical compatibility contracts for CivitasOS operator tooling."""

from .artifacts import (
    ARTIFACT_ENVELOPE_SCHEMA,
    artifact_ref,
    build_artifact_envelope,
    validate_artifact_envelope,
)
from .auth import CivitasHttpClient, resolve_auth_session
from .provenance import (
    build_governance_evidence,
    build_git_release_provenance,
    build_runtime_evidence,
)

__all__ = [
    "ARTIFACT_ENVELOPE_SCHEMA",
    "CivitasHttpClient",
    "artifact_ref",
    "build_artifact_envelope",
    "build_git_release_provenance",
    "build_governance_evidence",
    "build_runtime_evidence",
    "resolve_auth_session",
    "validate_artifact_envelope",
]
