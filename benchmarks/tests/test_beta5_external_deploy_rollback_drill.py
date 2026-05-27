from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
external_tests = _load(
    "beta5_external_deploy_fixture_for_rollback_drill",
    ROOT / "benchmarks" / "tests" / "test_beta5_external_deploy_evidence_executor.py",
)
module = _load(
    "beta5_external_deploy_rollback_drill",
    ROOT / "scripts" / "beta5_external_deploy_rollback_drill.py",
)


def test_rollback_drill_consumes_external_receipt_and_writes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_receipt = _write_external_deploy_receipt(tmp_path, monkeypatch)
    authorization_path = tmp_path / "rollback_authorization.json"

    report = module.record_rollback_authorization(
        external_deploy_receipt_path=external_receipt,
        rollback_command=f"{sys.executable} -c \"print('rollback')\"",
        rollback_smoke_command=f"{sys.executable} -c \"print('rollback-smoke')\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="prove controlled external preview rollback path",
        ack_rollback_drill=True,
    )
    execution = module.run_rollback_drill(
        authorization_path=authorization_path,
        output_root=tmp_path / "rollback-run",
    )

    assert report["validation"]["passed"] is True
    assert execution["passed"] is True
    assert execution["receipt_validation"]["passed"] is True
    assert execution["rollback_performed"] is True
    assert execution["rollback_smoke_performed"] is True
    receipt = json.loads(Path(execution["rollback_receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["source_beta5_external_deploy_receipt"]["sha256"] == _sha256(external_receipt)
    assert receipt["production_deploy_allowed"] is False
    assert receipt["production_runtime_execution_allowed"] is False
    assert receipt["production_receipt_write_allowed"] is False


def test_rollback_drill_requires_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_receipt = _write_external_deploy_receipt(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="explicit acknowledgement"):
        module.record_rollback_authorization(
            external_deploy_receipt_path=external_receipt,
            rollback_command=f"{sys.executable} -c \"print('rollback')\"",
            rollback_smoke_command=f"{sys.executable} -c \"print('smoke')\"",
            working_directory=tmp_path,
            output_path=tmp_path / "blocked.json",
            operator_id="operator-001",
            reason="missing ack fixture",
            ack_rollback_drill=False,
        )


def test_rollback_drill_blocks_failed_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_receipt = _write_external_deploy_receipt(tmp_path, monkeypatch)
    authorization_path = tmp_path / "rollback_authorization.json"
    module.record_rollback_authorization(
        external_deploy_receipt_path=external_receipt,
        rollback_command=f"{sys.executable} -c \"print('rollback')\"",
        rollback_smoke_command=f"{sys.executable} -c \"raise SystemExit(5)\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="failed smoke fixture",
        ack_rollback_drill=True,
    )

    execution = module.run_rollback_drill(
        authorization_path=authorization_path,
        output_root=tmp_path / "rollback-run",
    )

    assert execution["passed"] is False
    assert "rollback_smoke_failed" in execution["failure_codes"]
    assert execution["rollback_receipt_path"] is None


def test_rollback_drill_cli_failed_smoke_returns_nonzero_without_receipt_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_receipt = _write_external_deploy_receipt(tmp_path, monkeypatch)
    authorization_path = tmp_path / "rollback_authorization.json"
    module.record_rollback_authorization(
        external_deploy_receipt_path=external_receipt,
        rollback_command=f"{sys.executable} -c \"print('rollback')\"",
        rollback_smoke_command=f"{sys.executable} -c \"raise SystemExit(5)\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="failed smoke CLI fixture",
        ack_rollback_drill=True,
    )

    rc = module.main(
        [
            "execute",
            "--authorization",
            str(authorization_path),
            "--output-root",
            str(tmp_path / "rollback-run"),
        ]
    )

    assert rc == 1


def test_rollback_receipt_rejects_production_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_receipt = _write_external_deploy_receipt(tmp_path, monkeypatch)
    authorization_path = tmp_path / "rollback_authorization.json"
    module.record_rollback_authorization(
        external_deploy_receipt_path=external_receipt,
        rollback_command=f"{sys.executable} -c \"print('rollback')\"",
        rollback_smoke_command=f"{sys.executable} -c \"print('rollback-smoke')\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="receipt drift fixture",
        ack_rollback_drill=True,
    )
    execution = module.run_rollback_drill(
        authorization_path=authorization_path,
        output_root=tmp_path / "rollback-run",
    )
    receipt_path = Path(execution["rollback_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["production_deploy_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_rollback_receipt(receipt_path)

    assert validation["passed"] is False
    assert "production_deploy_allowed must be false" in validation["failure_reasons"]


def _write_external_deploy_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    local_receipt = external_tests._write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = external_tests._write_environment_proof(tmp_path / "environment_proof.json")
    authorization_path = tmp_path / "external_authorization.json"
    external_tests.module.record_external_deploy_authorization(
        local_deploy_receipt_path=local_receipt,
        environment_proof_path=environment_proof,
        deploy_target="external-preview-fixture",
        deploy_command=f"{sys.executable} -c \"print('external-deploy')\"",
        external_smoke_command=f"{sys.executable} -c \"print('external-smoke')\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="external deploy fixture for rollback drill",
        rollback_evidence_ref="rollback:external-preview-fixture",
        ack_external_controlled_deploy=True,
    )
    execution = external_tests.module.run_external_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "external-run",
    )
    assert execution["receipt_validation"]["passed"] is True
    return Path(execution["deploy_receipt_path"])


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
