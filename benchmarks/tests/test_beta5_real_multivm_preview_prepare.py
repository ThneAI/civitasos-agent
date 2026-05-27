from __future__ import annotations

import importlib.util
import json
import os
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


module = _load("beta5_real_multivm_preview_prepare", SCRIPTS / "beta5_real_multivm_preview_prepare.py")
external = _load("beta5_external_deploy_evidence_executor", SCRIPTS / "beta5_external_deploy_evidence_executor.py")


def test_prepare_writes_fail_closed_multivm_preview_run_root(tmp_path: Path) -> None:
    backend = tmp_path / "api_only"
    backend.write_text("#!/usr/bin/env bash\necho api\n", encoding="utf-8")
    backend.chmod(0o755)
    frontend = tmp_path / "build"
    frontend.mkdir()
    (frontend / "index.html").write_text("<!doctype html><div id=\"root\"></div>\n", encoding="utf-8")

    report = module.write_real_multivm_preview_run(
        run_root=tmp_path / "run",
        backend_bin=backend,
        frontend_build_dir=frontend,
        nodes=[
            module.PreviewNode("vm1", "vm1", "192.168.56.4"),
            module.PreviewNode("vm2", "vm2", "192.168.56.5"),
            module.PreviewNode("vm3", "vm3", "192.168.56.6"),
        ],
        remote_root="/home/cal/civitasos_beta5_real_multivm_preview",
    )

    run_root = Path(report["run_root"])
    assert report["prepared"] is True
    assert report["production_deploy_allowed"] is False
    assert (run_root / "artifacts" / "civitasos_frontend_build.tgz").is_file()

    environment_proof = json.loads((run_root / "environment_proof.json").read_text(encoding="utf-8"))
    validation = external.validate_environment_proof(run_root / "environment_proof.json")
    assert validation["passed"] is True
    assert environment_proof["no_production_flags"] == module._no_production_flags()
    assert environment_proof["production_environment"] is False
    assert environment_proof["customer_traffic_allowed"] is False
    assert environment_proof["production_data_allowed"] is False

    deploy = (run_root / "deploy_multivm_real_service.sh").read_text(encoding="utf-8")
    assert 'ssh -n "$SSH_HOST"' in deploy
    assert "api_only.next" in deploy
    assert "mv \"$REMOTE_ROOT/backend/api_only.next\" \"$REMOTE_ROOT/backend/api_only\"" in deploy
    assert os.access(run_root / "deploy_multivm_real_service.sh", os.X_OK)
    assert os.access(run_root / "operator_commands.sh", os.X_OK)


def test_parse_node_rejects_invalid_tuple() -> None:
    try:
        module.parse_node("vm1,192.168.56.4")
    except ValueError as exc:
        assert "ssh_host,node_id,node_ip" in str(exc)
    else:
        raise AssertionError("invalid node tuple must be rejected")
