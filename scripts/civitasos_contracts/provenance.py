"""Separate runtime evidence, governance records, and Git release provenance."""

from __future__ import annotations

from typing import Any, Mapping


RUNTIME_EVIDENCE_SCHEMA = "civitasos-runtime-evidence-bundle:v1"
GOVERNANCE_EVIDENCE_SCHEMA = "civitasos-governance-evidence-bundle:v1"
GIT_RELEASE_PROVENANCE_SCHEMA = "civitasos-git-release-provenance:v1"


def build_runtime_evidence(
    refs: Mapping[str, Any],
    *,
    assertions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": RUNTIME_EVIDENCE_SCHEMA,
        "refs": _refs(refs),
        "assertions": dict(assertions or {}),
        "excludes": [
            "git_commit_push_pr_merge_history",
            "operator_authorization_decisions",
        ],
    }


def build_governance_evidence(
    refs: Mapping[str, Any],
    *,
    assertions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": GOVERNANCE_EVIDENCE_SCHEMA,
        "refs": _refs(refs),
        "assertions": dict(assertions or {}),
        "excludes": [
            "agent_runtime_behavior",
            "git_provider_state_as_runtime_truth",
        ],
    }


def build_git_release_provenance(
    refs: Mapping[str, Any],
    *,
    actions_observed: Mapping[str, bool] | None = None,
    actions_performed_by_current_step: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    actions = ("commit", "push", "pr", "merge")
    return {
        "schema_version": GIT_RELEASE_PROVENANCE_SCHEMA,
        "provider": "git",
        "refs": _refs(refs),
        "actions_observed": {
            action: bool((actions_observed or {}).get(action, False))
            for action in actions
        },
        "actions_performed_by_current_step": {
            action: bool((actions_performed_by_current_step or {}).get(action, False))
            for action in actions
        },
        "runtime_evidence": False,
    }


def _refs(refs: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in refs.items() if value is not None}
