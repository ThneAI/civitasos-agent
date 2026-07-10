from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


module = _load("private_beta_vm_preview_readiness", SCRIPTS / "private_beta_vm_preview_readiness.py")


def test_readiness_index_accepts_complete_preview_without_vm_contact(tmp_path: Path) -> None:
    summary = _write_preview_artifacts(tmp_path)

    report = module.build_readiness_index(
        summary_paths=[summary],
        output_path=tmp_path / "readiness.json",
        min_previews=1,
    )

    assert report["passed"] is True
    assert report["preview_count"] == 1
    assert report["total_checks"] == 15
    assert report["boundary"]["artifact_only"] is True
    assert report["boundary"]["vm_contact_performed"] is False
    assert report["readiness"]["production_transition_allowed"] is False


def test_readiness_index_fails_when_rollback_boundary_is_missing(tmp_path: Path) -> None:
    summary_path = _write_preview_artifacts(tmp_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["readiness"]["rollback_health_passed"] = False
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    report = module.build_readiness_index(
        summary_paths=[summary_path],
        output_path=tmp_path / "readiness.json",
        min_previews=1,
    )

    assert report["passed"] is False
    assert any("rollback_health_passed" in reason for reason in report["failure_reasons"])
    assert report["readiness"]["production_transition_allowed"] is False


def _write_preview_artifacts(tmp_path: Path) -> Path:
    authorization_id = "private-beta-deploy-ops-auth:test"
    execution_path = _write_json(
        tmp_path / "execution.json",
        {
            "schema_version": module.EXECUTION_SCHEMA,
            "passed": True,
            "authorization_id": authorization_id,
        },
    )
    rollback_path = _write_json(
        tmp_path / "rollback.json",
        {"schema_version": module.ROLLBACK_SCHEMA, "passed": True},
    )
    monitoring_path = _write_json(
        tmp_path / "monitoring.json",
        {
            "schema_version": module.MONITORING_SCHEMA,
            "passed": True,
            "authorization_id": authorization_id,
            "latency_summary": {"total_checks": 15, "latency_ms_median": 9.845},
        },
    )
    return _write_json(
        tmp_path / "summary.json",
        {
            "schema_version": module.SUMMARY_SCHEMA,
            "passed": True,
            "decision": "private_beta_vm_preview_passed",
            "authorization_id": authorization_id,
            "vm_target_ids": ["vm1", "vm2", "vm3"],
            "artifacts": {
                "execution_receipt": module.artifact_ref(execution_path),
                "rollback_receipt": module.artifact_ref(rollback_path),
                "monitoring_receipt": module.artifact_ref(monitoring_path),
            },
            "readiness": {
                **{key: True for key in module.REQUIRED_READY},
                "production_transition_allowed": False,
            },
            "boundary": {
                **{key: True for key in module.REQUIRED_BOUNDARY_TRUE},
                **{key: False for key in module.REQUIRED_BOUNDARY_FALSE},
            },
        },
    )


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
