"""Build the non-executable I.1 preparation report."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "i1-verifier-preparation-report:v1"


def build_report(
    *,
    passed: bool,
    failures: list[str],
    checks: dict[str, bool],
    roster: dict[str, Any],
    prepared_identities: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    control_records: list[dict[str, Any]],
    materialized_cases: list[dict[str, Any]],
    roster_path: Path,
    corpus_path: Path,
    negative_controls_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "identity_roster": _artifact_ref(roster_path),
            "fixed_corpus": _artifact_ref(corpus_path),
            "negative_controls": _artifact_ref(negative_controls_path),
        },
        "identity_manifest": {
            "identity_count": len(prepared_identities),
            "identities": prepared_identities,
            "proposer_identity_alias": roster.get("proposer_identity_alias"),
            "default_verifier_allowlist": roster.get(
                "default_verifier_allowlist", []
            ),
        },
        "corpus_manifest": {
            "positive_case_count": len(cases),
            "negative_control_count": len(control_records),
            "control_types": sorted(
                {str(item.get("control_type")) for item in control_records}
            ),
            "cases": materialized_cases,
        },
        "readiness": {
            "preparation_complete": passed,
            "state": (
                "i1_assets_prepared_not_started"
                if passed
                else "blocked_i1_asset_preparation"
            ),
            "h3_qualification_still_required": True,
            "identity_registration_still_required": True,
            "signature_control_proof_still_required": True,
            "i1_execution_allowed": False,
        },
        "boundary": {
            "fixture_and_local_test_identity_only": True,
            "verifier_dispatch_allowed": False,
            "consensus_claim_allowed": False,
            "external_side_effect_allowed": False,
            "state_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "preparation_does_not_start_i1",
            "local_identity_keys_are_not_registered_agent_proof",
            "fixture_results_are_not_verifier_consensus",
            "h3_qualification_cannot_be_bypassed",
        ],
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
