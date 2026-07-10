from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


module = _load("private_beta_vm_preview_execution", SCRIPTS / "private_beta_vm_preview_execution.py")


def test_private_beta_vm_preview_execution_consumes_authorization(tmp_path: Path) -> None:
    authorization = _write_authorization(tmp_path)
    prepared = _write_prepared_run(tmp_path)

    summary = module.run_gate(
        authorization_path=authorization,
        output_root=tmp_path / "out",
        backend_bin=tmp_path / "missing-api-only",
        frontend_build_dir=tmp_path / "missing-build",
        nodes=[
            module.PreviewNode("vm1", "vm1", "192.168.56.4"),
            module.PreviewNode("vm2", "vm2", "192.168.56.5"),
            module.PreviewNode("vm3", "vm3", "192.168.56.6"),
        ],
        remote_root="/tmp/private-beta-preview",
        backend_port=18181,
        frontend_port=18182,
        prepared_run_root=prepared,
        operator_id="operator-cc",
        ack_private_beta_vm_preview_execution=True,
    )

    assert summary["passed"] is True
    assert summary["readiness"]["authorization_consumed"] is True
    assert summary["readiness"]["deploy_executed"] is True
    assert summary["readiness"]["rollback_executed"] is True
    assert summary["boundary"]["public_ingress_allowed"] is False
    assert summary["boundary"]["production_runtime_execution_allowed"] is False
    assert (tmp_path / "out" / "private_beta_vm_preview_execution_receipt.json").is_file()
    assert (tmp_path / "out" / "private_beta_vm_preview_rollback_receipt.json").is_file()
    assert (tmp_path / "out" / "private_beta_vm_preview_monitoring_receipt.json").is_file()


def test_private_beta_vm_preview_execution_requires_ack(tmp_path: Path) -> None:
    authorization = _write_authorization(tmp_path)
    prepared = _write_prepared_run(tmp_path)
    summary = module.run_gate(
        authorization_path=authorization,
        output_root=tmp_path / "out",
        backend_bin=tmp_path / "missing-api-only",
        frontend_build_dir=tmp_path / "missing-build",
        nodes=[
            module.PreviewNode("vm1", "vm1", "192.168.56.4"),
            module.PreviewNode("vm2", "vm2", "192.168.56.5"),
            module.PreviewNode("vm3", "vm3", "192.168.56.6"),
        ],
        remote_root="/tmp/private-beta-preview",
        backend_port=18181,
        frontend_port=18182,
        prepared_run_root=prepared,
        operator_id="operator-cc",
        ack_private_beta_vm_preview_execution=False,
    )
    assert summary["passed"] is False
    assert any("acknowledgement" in reason for reason in summary["failure_reasons"])
    assert summary["readiness"]["deploy_executed"] is False


def _write_authorization(tmp_path: Path) -> Path:
    path = tmp_path / "authorization.json"
    payload = {
        "schema_version": module.AUTHORIZATION_SCHEMA,
        "passed": True,
        "decision": "private_beta_deploy_ops_authorized_once",
        "authorization_id": "private-beta-deploy-ops-auth:test",
        "single_use": True,
        "consumed": False,
        "authorized_scope": {
            "target_scope": "private_vm_preview",
            "deploy_target": "vm1-vm2-vm3-private-preview",
            "service_token_scopes": ["pool:read", "audit:read"],
            "public_ingress_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "roles": {
            "deploy_owner": "deploy_owner",
            "rollback_owner": "rollback_owner",
            "monitoring_owner": "observability_owner",
            "audit_owner": "audit_owner",
        },
        "boundary": {
            "deploy_execution_authorized_once": True,
            "rollback_or_abort_authorized_once": True,
            "deploy_executed": False,
            "rollback_executed": False,
            "public_ingress_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_prepared_run(tmp_path: Path) -> Path:
    root = tmp_path / "prepared"
    root.mkdir()
    (root / "prepare_report.json").write_text(
        json.dumps({"prepared": True, "production_deploy_allowed": False, "environment_proof": str(root / "environment_proof.json")}),
        encoding="utf-8",
    )
    (root / "environment_proof.json").write_text("{}", encoding="utf-8")
    _write_script(root / "deploy_multivm_real_service.sh", "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'deployed\\n'\n")
    _write_script(
        root / "smoke_multivm_real_service.py",
        f"""#!/usr/bin/env python3
import json
from pathlib import Path
summary = {{
  "schema_version": "{module.SMOKE_SCHEMA}",
  "passed": True,
  "cycles": 1,
  "nodes": ["vm1", "vm2", "vm3"],
  "total_checks": 3,
  "latency_ms_min": 1.0,
  "latency_ms_median": 2.0,
  "latency_ms_max": 3.0,
  "production_deploy_allowed": False,
  "production_runtime_execution_allowed": False,
  "production_receipt_write_allowed": False,
  "h3_production_readiness_claimed": False
}}
Path("multivm_real_service_smoke_summary.json").write_text(json.dumps(summary), encoding="utf-8")
print(json.dumps(summary))
""",
    )
    _write_script(root / "rollback_multivm_real_service.sh", "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'rolled back\\n'\n")
    _write_script(root / "smoke_rollback_multivm_real_service.sh", "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'rollback healthy\\n'\n")
    return root


def _write_script(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o755)
