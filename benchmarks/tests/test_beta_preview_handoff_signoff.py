from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_preview_handoff_signoff", SCRIPTS / "beta_preview_handoff_signoff.py")


def test_record_signoffs_and_cumulative_index(tmp_path: Path) -> None:
    handoff = _write_handoff(tmp_path / "handoff.json")
    monitoring = module.record_handoff_signoff(
        handoff_path=handoff,
        output_path=tmp_path / "monitoring_signoff.json",
        role="monitoring_owner",
        actor_id="observability_owner",
        verdict="accepted",
        evidence_ref="monitoring:green:preview-smoke",
    )
    audit = module.record_handoff_signoff(
        handoff_path=handoff,
        output_path=tmp_path / "audit_signoff.json",
        role="audit_owner",
        actor_id="audit_owner",
        verdict="accepted",
        evidence_ref="audit:handoff-reviewed",
    )

    index = module.write_beta_preview_evidence_index(
        handoff_paths=[handoff],
        handoff_globs=[],
        signoff_paths=[Path(monitoring["packet_path"]), Path(audit["packet_path"])],
        signoff_globs=[],
        output_path=tmp_path / "index.json",
        min_handoffs=1,
        require_monitoring_signoff=True,
        require_audit_signoff=True,
    )

    assert index["passed"] is True
    assert index["decision"] == "beta_preview_evidence_index_ready"
    assert index["handoff_count"] == 1
    assert index["signoff_count"] == 2
    assert index["accepted_signoff_count"] == 2
    assert index["total_preview_smoke_checks"] == 15
    assert index["min_provider_identity_count"] == 2
    assert index["index_boundary"]["production_runtime_execution_allowed"] is False
    assert index["h3_boundary"]["h3_remains_blocked"] is True


def test_index_blocks_missing_required_audit_signoff(tmp_path: Path) -> None:
    handoff = _write_handoff(tmp_path / "handoff.json")
    monitoring = module.record_handoff_signoff(
        handoff_path=handoff,
        output_path=tmp_path / "monitoring_signoff.json",
        role="monitoring_owner",
        actor_id="observability_owner",
        verdict="accepted",
        evidence_ref="monitoring:green:preview-smoke",
    )

    index = module.write_beta_preview_evidence_index(
        handoff_paths=[handoff],
        handoff_globs=[],
        signoff_paths=[Path(monitoring["packet_path"])],
        signoff_globs=[],
        output_path=tmp_path / "index.json",
        min_handoffs=1,
        require_monitoring_signoff=True,
        require_audit_signoff=True,
    )

    assert index["passed"] is False
    assert index["decision"] == "blocked"
    assert any("missing accepted audit_owner signoff" in reason for reason in index["failure_reasons"])


def _write_handoff(path: Path) -> Path:
    chain = _write_json(path.parent / "chain.json", {"schema_version": "beta-preview-chain-run-summary:v1"})
    _write_json(
        path,
        {
            "schema_version": "beta-preview-operator-handoff:v1",
            "checked_at": "2026-06-01T00:00:00+00:00",
            "passed": True,
            "decision": "beta_preview_operator_handoff_ready",
            "failure_reasons": [],
            "chain_summary": {"path": str(chain), "sha256": module._sha256(chain)},
            "roles": {
                "operator": "local-operator-cc",
                "preview_owner": "local-owner-cc",
                "monitoring_owner": "observability_owner",
                "audit_owner": "audit_owner",
                "external_agent_registrar": "external_agent_registrar",
                "external_agent_observer": "external_agent_observer",
            },
            "handoff_metrics": {
                "readiness_decision": "beta_preview_ready",
                "provider_identity_count": 2,
                "provider_identities": ["provider-a", "provider-b"],
                "external_agent_review_count": 2,
                "distinct_provider_required": True,
                "preview_smoke_total_checks": 15,
                "rollback_receipt": "/tmp/rollback.json",
                "owner_feedback_packet_count": 4,
                "owner_feedback_accepted_ratio": 0.75,
                "owner_feedback_verdict_counts": {"accepted": 3, "needs_followup": 1, "rejected": 0},
            },
            "required_operator_checks": [
                {"check": "readiness_ready", "passed": True},
                {"check": "provider_identity_observed", "passed": True},
                {"check": "multi_external_agent_review_observed", "passed": True},
                {"check": "rollback_receipt_present", "passed": True},
                {"check": "owner_feedback_not_rejected", "passed": True},
            ],
            "handoff_boundary": module._boundary(),
            "h3_boundary": module._h3_boundary(),
            "non_claims": [
                "beta_preview_operator_handoff_is_read_only",
                "beta_preview_operator_handoff_does_not_execute_merge",
                "beta_preview_operator_handoff_does_not_execute_deploy",
                "beta_preview_operator_handoff_does_not_authorize_production_runtime_execution",
                "beta_preview_operator_handoff_does_not_write_production_receipts",
                "beta_preview_operator_handoff_does_not_claim_h3_production_readiness",
            ],
        },
    )
    return path


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
