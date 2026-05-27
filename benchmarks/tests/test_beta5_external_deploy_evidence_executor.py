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
local_tests = _load(
    "beta5_local_controlled_deploy_fixture_for_external_deploy",
    ROOT / "benchmarks" / "tests" / "test_beta5_local_controlled_deploy_executor.py",
)
module = _load(
    "beta5_external_deploy_evidence_executor",
    ROOT / "scripts" / "beta5_external_deploy_evidence_executor.py",
)


def test_external_deploy_consumes_local_receipt_and_writes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_receipt = _write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = _write_environment_proof(tmp_path / "environment_proof.json")
    authorization_path = tmp_path / "external_deploy_authorization.json"

    report = module.record_external_deploy_authorization(
        local_deploy_receipt_path=local_receipt,
        environment_proof_path=environment_proof,
        deploy_target="external-preview-fixture",
        deploy_command=f"{sys.executable} -c \"print('external-deploy')\"",
        external_smoke_command=f"{sys.executable} -c \"print('external-smoke')\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="run controlled external preview after local deploy receipt",
        rollback_evidence_ref="rollback:close-external-preview-fixture",
        ack_external_controlled_deploy=True,
    )
    execution = module.run_external_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "external-run",
    )

    assert report["validation"]["passed"] is True
    assert execution["passed"] is True
    assert execution["receipt_validation"]["passed"] is True
    assert execution["external_deploy_performed"] is True
    assert execution["external_smoke_performed"] is True
    receipt = json.loads(Path(execution["deploy_receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["source_beta5_local_deploy_receipt"]["sha256"] == _sha256(local_receipt)
    assert receipt["external_environment"]["environment_classification"] == "external_preview"
    assert receipt["production_deploy_allowed"] is False
    assert receipt["production_runtime_execution_allowed"] is False
    assert receipt["production_receipt_write_allowed"] is False
    assert receipt["h3_boundary"]["h3_remains_blocked"] is True


def test_external_deploy_rejects_production_environment_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_receipt = _write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = _write_environment_proof(tmp_path / "environment_proof.json")
    proof = json.loads(environment_proof.read_text(encoding="utf-8"))
    proof["production_environment"] = True
    environment_proof.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_environment_proof(environment_proof)
    assert validation["passed"] is False
    assert "production_environment must be false" in validation["failure_reasons"]
    with pytest.raises(ValueError, match="production_environment"):
        module.record_external_deploy_authorization(
            local_deploy_receipt_path=local_receipt,
            environment_proof_path=environment_proof,
            deploy_target="external-preview-fixture",
            deploy_command=f"{sys.executable} -c \"print('deploy')\"",
            external_smoke_command=f"{sys.executable} -c \"print('smoke')\"",
            working_directory=tmp_path,
            output_path=tmp_path / "blocked.json",
            operator_id="operator-001",
            reason="production proof fixture",
            rollback_evidence_ref="rollback:production-proof-fixture",
            ack_external_controlled_deploy=True,
        )


def test_external_deploy_blocks_failed_external_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_receipt = _write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = _write_environment_proof(tmp_path / "environment_proof.json")
    authorization_path = tmp_path / "external_deploy_authorization.json"
    module.record_external_deploy_authorization(
        local_deploy_receipt_path=local_receipt,
        environment_proof_path=environment_proof,
        deploy_target="external-preview-fixture",
        deploy_command=f"{sys.executable} -c \"print('deploy')\"",
        external_smoke_command=f"{sys.executable} -c \"raise SystemExit(9)\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="failed smoke fixture",
        rollback_evidence_ref="rollback:failed-external-smoke-fixture",
        ack_external_controlled_deploy=True,
    )

    execution = module.run_external_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "external-run",
    )

    assert execution["passed"] is False
    assert "external_deploy_smoke_failed" in execution["failure_codes"]
    assert execution["deploy_receipt_path"] is None


def test_external_deploy_cli_failed_smoke_returns_nonzero_without_receipt_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_receipt = _write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = _write_environment_proof(tmp_path / "environment_proof.json")
    authorization_path = tmp_path / "external_deploy_authorization.json"
    module.record_external_deploy_authorization(
        local_deploy_receipt_path=local_receipt,
        environment_proof_path=environment_proof,
        deploy_target="external-preview-fixture",
        deploy_command=f"{sys.executable} -c \"print('deploy')\"",
        external_smoke_command=f"{sys.executable} -c \"raise SystemExit(9)\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="failed smoke CLI fixture",
        rollback_evidence_ref="rollback:failed-external-smoke-cli-fixture",
        ack_external_controlled_deploy=True,
    )

    rc = module.main(
        [
            "deploy",
            "--authorization",
            str(authorization_path),
            "--output-root",
            str(tmp_path / "external-run"),
        ]
    )

    assert rc == 1


def test_external_deploy_receipt_rejects_production_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_receipt = _write_local_deploy_receipt(tmp_path, monkeypatch)
    environment_proof = _write_environment_proof(tmp_path / "environment_proof.json")
    authorization_path = tmp_path / "external_deploy_authorization.json"
    module.record_external_deploy_authorization(
        local_deploy_receipt_path=local_receipt,
        environment_proof_path=environment_proof,
        deploy_target="external-preview-fixture",
        deploy_command=f"{sys.executable} -c \"print('deploy')\"",
        external_smoke_command=f"{sys.executable} -c \"print('smoke')\"",
        working_directory=tmp_path,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="receipt drift fixture",
        rollback_evidence_ref="rollback:receipt-drift-fixture",
        ack_external_controlled_deploy=True,
    )
    execution = module.run_external_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "external-run",
    )
    receipt_path = Path(execution["deploy_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["production_runtime_execution_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_external_deploy_receipt(receipt_path)

    assert validation["passed"] is False
    assert "production_runtime_execution_allowed must be false" in validation["failure_reasons"]


def _write_local_deploy_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = local_tests._init_repo(tmp_path / "repo")
    merge_receipt = local_tests._write_merge_receipt(tmp_path, repo, monkeypatch)
    authorization_path = tmp_path / "local_deploy_authorization.json"
    local_tests.module.record_deploy_authorization(
        github_merge_receipt_path=merge_receipt,
        target_repo=repo,
        deploy_target="local-staging-fixture",
        deploy_command=f"{sys.executable} -c \"print('local-deploy')\"",
        smoke_command=f"{sys.executable} -c \"print('local-smoke')\"",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="local staging fixture for external deploy",
        rollback_evidence_ref="rollback:local-staging-fixture",
        ack_local_controlled_deploy=True,
    )
    execution = local_tests.module.run_local_controlled_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "local-run",
    )
    assert execution["receipt_validation"]["passed"] is True
    return Path(execution["deploy_receipt_path"])


def _write_environment_proof(path: Path) -> Path:
    proof = {
        "schema_version": module.ENVIRONMENT_PROOF_SCHEMA,
        "recorded_at": "2026-05-27T00:00:00+00:00",
        "environment_id": "external-preview-fixture-001",
        "environment_kind": "preview",
        "environment_classification": "external_preview",
        "environment_url": "https://preview.example.invalid/civitasos-fixture",
        "owner": "operator-001",
        "proof_ref": "proof:external-preview-fixture",
        "production_environment": False,
        "customer_traffic_allowed": False,
        "production_data_allowed": False,
        "destructive_action_allowed": False,
        "secret_material_included": False,
        "no_production_flags": module._no_production_flags(),
        "non_claims": list(module.NON_CLAIMS),
    }
    path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert module.validate_environment_proof(path)["passed"] is True
    return path


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
