#!/usr/bin/env python3
"""Write a bounded Beta preview operator handoff artifact.

The handoff consumes an existing Beta preview chain summary and its referenced
artifacts. It is a read-only operator surface: it does not execute merge,
deploy, task delivery, provider calls, production runtime execution, or receipt
writes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_preview_evidence import (
        artifact_ref as _preview_artifact_ref,
        boundary as _preview_boundary,
        expect_h3_blocked as _preview_expect_h3_blocked,
        h3_boundary as _preview_h3_boundary,
        sha256 as _preview_sha256,
        write_json as _preview_write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_preview_evidence import (
        artifact_ref as _preview_artifact_ref,
        boundary as _preview_boundary,
        expect_h3_blocked as _preview_expect_h3_blocked,
        h3_boundary as _preview_h3_boundary,
        sha256 as _preview_sha256,
        write_json as _preview_write_json,
    )

HANDOFF_SCHEMA = "beta-preview-operator-handoff:v1"
CHAIN_SCHEMA = "beta-preview-chain-run-summary:v1"
READINESS_SCHEMA = "beta-deployment-preview-readiness-report:v1"
PROVIDER_PREFLIGHT_SCHEMA = "beta-external-provider-env-preflight:v1"
PREVIEW_SCHEMA = "beta5-repeatable-preview-nightly-artifact:v1"
OWNER_INDEX_SCHEMA = "beta5-owner-feedback-evidence-index:v1"
MULTI_REVIEW_SCHEMA = "beta-multi-external-review-reconciliation:v1"

NON_CLAIMS = (
    "beta_preview_operator_handoff_is_read_only",
    "beta_preview_operator_handoff_does_not_execute_merge",
    "beta_preview_operator_handoff_does_not_execute_deploy",
    "beta_preview_operator_handoff_does_not_authorize_production_runtime_execution",
    "beta_preview_operator_handoff_does_not_write_production_receipts",
    "beta_preview_operator_handoff_does_not_claim_h3_production_readiness",
)

DEFAULT_ROLES = {
    "operator": "local-operator-cc",
    "preview_owner": "local-owner-cc",
    "monitoring_owner": "observability_owner",
    "audit_owner": "audit_owner",
    "external_agent_registrar": "external_agent_registrar",
    "external_agent_observer": "external_agent_observer",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain-summary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--operator-id", default=DEFAULT_ROLES["operator"])
    parser.add_argument("--preview-owner", default=DEFAULT_ROLES["preview_owner"])
    parser.add_argument("--monitoring-owner", default=DEFAULT_ROLES["monitoring_owner"])
    parser.add_argument("--audit-owner", default=DEFAULT_ROLES["audit_owner"])
    parser.add_argument("--external-agent-registrar", default=DEFAULT_ROLES["external_agent_registrar"])
    parser.add_argument("--external-agent-observer", default=DEFAULT_ROLES["external_agent_observer"])
    args = parser.parse_args(argv)

    report = write_beta_preview_operator_handoff(
        chain_summary_path=Path(args.chain_summary),
        output_path=Path(args.output),
        roles={
            "operator": args.operator_id,
            "preview_owner": args.preview_owner,
            "monitoring_owner": args.monitoring_owner,
            "audit_owner": args.audit_owner,
            "external_agent_registrar": args.external_agent_registrar,
            "external_agent_observer": args.external_agent_observer,
        },
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def write_beta_preview_operator_handoff(
    *,
    chain_summary_path: Path,
    output_path: Path,
    roles: dict[str, str] | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    normalized_roles = {**DEFAULT_ROLES, **(roles or {})}
    _validate_roles(normalized_roles, failures)

    chain = _read_json(chain_summary_path, failures, "chain_summary")
    readiness = _read_ref(chain, "readiness", failures, "readiness")
    provider = _read_ref(chain, "provider_env_preflight", failures, "provider_env_preflight")
    preview = _read_ref(chain, "preview_summary", failures, "preview_summary")
    owner_index = _read_ref(chain, "owner_feedback_index", failures, "owner_feedback_index")
    multi_review = _read_ref(chain, "multi_external_review", failures, "multi_external_review", required=False)

    _validate_chain(chain, failures)
    _validate_readiness(readiness, failures)
    _validate_provider(provider, chain, failures)
    _validate_preview(preview, failures)
    _validate_owner_index(owner_index, failures)
    if chain.get("multi_external_review_observed") is True:
        _validate_multi_review(multi_review, failures)

    passed = not failures
    metrics = _handoff_metrics(chain, readiness, provider, preview, owner_index, multi_review)
    report = {
        "schema_version": HANDOFF_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_preview_operator_handoff_ready" if passed else "blocked",
        "failure_reasons": failures,
        "chain_summary": _artifact_ref(chain_summary_path),
        "roles": normalized_roles,
        "handoff_metrics": metrics,
        "required_operator_checks": _operator_checks(metrics),
        "handoff_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "next_operator_actions": [
            "review beta_preview_chain_summary.json and referenced hashes",
            "confirm provider preflight passed without recording API keys",
            "confirm preview smoke and rollback receipt before any repeat run",
            "record owner feedback or audit follow-up if behavior is not accepted",
            "do not treat this handoff as merge, deploy, or production authorization",
        ],
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _validate_roles(roles: dict[str, str], failures: list[str]) -> None:
    for key in DEFAULT_ROLES:
        value = str(roles.get(key) or "").strip()
        if not value:
            failures.append(f"roles.{key} must be non-empty")
        roles[key] = value


def _validate_chain(chain: dict[str, Any], failures: list[str]) -> None:
    if not chain:
        return
    _expect(chain, "schema_version", CHAIN_SCHEMA, failures, "chain_summary")
    _expect_true(chain, "passed", failures, "chain_summary")
    _expect(chain, "decision", "beta_preview_chain_passed", failures, "chain_summary")
    _expect(chain, "readiness_decision", "beta_preview_ready", failures, "chain_summary")
    _expect_false(chain, "production_deploy_allowed", failures, "chain_summary")
    _expect_false(chain, "production_runtime_execution_allowed", failures, "chain_summary")
    _expect_false(chain, "production_receipt_write_allowed", failures, "chain_summary")
    _expect_h3_blocked(chain, failures, "chain_summary")


def _validate_readiness(readiness: dict[str, Any], failures: list[str]) -> None:
    if not readiness:
        return
    _expect(readiness, "schema_version", READINESS_SCHEMA, failures, "readiness")
    _expect_true(readiness, "passed", failures, "readiness")
    _expect(readiness, "decision", "beta_preview_ready", failures, "readiness")
    surface = readiness.get("readiness") if isinstance(readiness.get("readiness"), dict) else {}
    if surface.get("beta_preview_repeat_ready") is not True:
        failures.append("readiness.readiness.beta_preview_repeat_ready must be true")
    for key in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed", "h3_production_readiness_claimed"):
        if surface.get(key) is not False:
            failures.append(f"readiness.readiness.{key} must be false")
    _expect_h3_blocked(readiness, failures, "readiness")


def _validate_provider(provider: dict[str, Any], chain: dict[str, Any], failures: list[str]) -> None:
    if not provider:
        return
    _expect(provider, "schema_version", PROVIDER_PREFLIGHT_SCHEMA, failures, "provider_env_preflight")
    _expect_true(provider, "passed", failures, "provider_env_preflight")
    _expect(provider, "decision", "provider_env_ready", failures, "provider_env_preflight")
    _expect_false(provider, "api_key_recorded", failures, "provider_env_preflight")
    if chain.get("require_distinct_providers") is True and int(provider.get("unique_provider_identity_count") or 0) < 2:
        failures.append("provider_env_preflight.unique_provider_identity_count must be >= 2 for distinct-provider handoff")
    for key in ("production_deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        _expect_false(provider, key, failures, "provider_env_preflight")
    _expect_h3_blocked(provider, failures, "provider_env_preflight")


def _validate_preview(preview: dict[str, Any], failures: list[str]) -> None:
    if not preview:
        return
    _expect(preview, "schema_version", PREVIEW_SCHEMA, failures, "preview_summary")
    _expect_true(preview, "passed", failures, "preview_summary")
    if int(preview.get("smoke_total_checks") or 0) < 1:
        failures.append("preview_summary.smoke_total_checks must be >= 1")
    rollback = str(preview.get("rollback_receipt") or "").strip()
    if not rollback:
        failures.append("preview_summary.rollback_receipt must be present")
    _expect_false(preview, "production_deploy_allowed", failures, "preview_summary")
    _expect_false(preview, "production_runtime_execution_allowed", failures, "preview_summary")
    _expect_false(preview, "production_receipt_write_allowed", failures, "preview_summary")
    _expect_false(preview, "h3_production_readiness_claimed", failures, "preview_summary")


def _validate_owner_index(owner_index: dict[str, Any], failures: list[str]) -> None:
    if not owner_index:
        return
    _expect(owner_index, "schema_version", OWNER_INDEX_SCHEMA, failures, "owner_feedback_index")
    _expect_true(owner_index, "passed", failures, "owner_feedback_index")
    if int(owner_index.get("packet_count") or 0) < 1:
        failures.append("owner_feedback_index.packet_count must be >= 1")
    verdict_counts = owner_index.get("verdict_counts") if isinstance(owner_index.get("verdict_counts"), dict) else {}
    if int(verdict_counts.get("rejected") or 0) != 0:
        failures.append("owner_feedback_index.verdict_counts.rejected must be 0")
    _expect_false(owner_index, "production_deploy_allowed", failures, "owner_feedback_index")
    _expect_false(owner_index, "production_runtime_execution_allowed", failures, "owner_feedback_index")
    _expect_false(owner_index, "production_receipt_write_allowed", failures, "owner_feedback_index")
    _expect_false(owner_index, "h3_production_readiness_claimed", failures, "owner_feedback_index")
    _expect_h3_blocked(owner_index, failures, "owner_feedback_index")


def _validate_multi_review(multi_review: dict[str, Any], failures: list[str]) -> None:
    if not multi_review:
        failures.append("chain_summary.multi_external_review_observed requires multi_external_review artifact")
        return
    _expect(multi_review, "schema_version", MULTI_REVIEW_SCHEMA, failures, "multi_external_review")
    _expect_true(multi_review, "passed", failures, "multi_external_review")
    _expect(multi_review, "decision", "multi_external_review_ready", failures, "multi_external_review")
    _expect_true(multi_review, "all_external_verdicts_approved", failures, "multi_external_review")
    if int(multi_review.get("unique_external_agent_count") or 0) < 2:
        failures.append("multi_external_review.unique_external_agent_count must be >= 2")
    _expect_h3_blocked(multi_review, failures, "multi_external_review")


def _handoff_metrics(
    chain: dict[str, Any],
    readiness: dict[str, Any],
    provider: dict[str, Any],
    preview: dict[str, Any],
    owner_index: dict[str, Any],
    multi_review: dict[str, Any],
) -> dict[str, Any]:
    return {
        "readiness_decision": readiness.get("decision") or chain.get("readiness_decision"),
        "provider_identity_count": provider.get("unique_provider_identity_count") or chain.get("provider_identity_count"),
        "provider_identities": provider.get("unique_provider_identities") or [],
        "external_agent_review_count": multi_review.get("unique_external_agent_count") or chain.get("review_summary_count"),
        "distinct_provider_required": bool(chain.get("require_distinct_providers")),
        "preview_smoke_total_checks": preview.get("smoke_total_checks"),
        "rollback_receipt": preview.get("rollback_receipt"),
        "owner_feedback_packet_count": owner_index.get("packet_count"),
        "owner_feedback_accepted_ratio": owner_index.get("accepted_ratio"),
        "owner_feedback_verdict_counts": owner_index.get("verdict_counts") if isinstance(owner_index.get("verdict_counts"), dict) else {},
    }


def _operator_checks(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    verdict_counts = metrics.get("owner_feedback_verdict_counts") if isinstance(metrics.get("owner_feedback_verdict_counts"), dict) else {}
    return [
        {"check": "readiness_ready", "passed": metrics.get("readiness_decision") == "beta_preview_ready"},
        {"check": "provider_identity_observed", "passed": int(metrics.get("provider_identity_count") or 0) >= 1},
        {"check": "multi_external_agent_review_observed", "passed": int(metrics.get("external_agent_review_count") or 0) >= 2},
        {"check": "rollback_receipt_present", "passed": bool(metrics.get("rollback_receipt"))},
        {"check": "owner_feedback_not_rejected", "passed": int(verdict_counts.get("rejected") or 0) == 0},
    ]


def _read_ref(
    chain: dict[str, Any],
    key: str,
    failures: list[str],
    label: str,
    *,
    required: bool = True,
) -> dict[str, Any]:
    ref = chain.get(key) if isinstance(chain.get(key), dict) else None
    path_text = str(ref.get("path") or "").strip() if ref else ""
    if not path_text:
        if required:
            failures.append(f"chain_summary.{key}.path must be present")
        return {}
    return _read_json(Path(path_text), failures, label)


def _read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - operator-facing report preserves parser error.
        failures.append(f"invalid {label} JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return value


def _expect(payload: dict[str, Any], key: str, expected: Any, failures: list[str], label: str) -> None:
    if payload.get(key) != expected:
        failures.append(f"{label}.{key} must be {expected!r}")


def _expect_true(payload: dict[str, Any], key: str, failures: list[str], label: str) -> None:
    if payload.get(key) is not True:
        failures.append(f"{label}.{key} must be true")


def _expect_false(payload: dict[str, Any], key: str, failures: list[str], label: str) -> None:
    if payload.get(key) is not False:
        failures.append(f"{label}.{key} must be false")


def _expect_h3_blocked(payload: dict[str, Any], failures: list[str], label: str) -> None:
    _preview_expect_h3_blocked(payload, failures, label)


def _boundary() -> dict[str, bool]:
    return _preview_boundary()


def _h3_boundary() -> dict[str, bool]:
    return _preview_h3_boundary()


def _artifact_ref(path: Path) -> dict[str, str | None]:
    return _preview_artifact_ref(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _preview_write_json(path, payload)


def _sha256(path: Path) -> str:
    return _preview_sha256(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
