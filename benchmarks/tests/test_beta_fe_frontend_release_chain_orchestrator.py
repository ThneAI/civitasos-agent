from __future__ import annotations

import importlib.util
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


module = _load("beta_fe_frontend_release_chain_orchestrator", SCRIPTS / "beta_fe_frontend_release_chain_orchestrator.py")


def test_release_chain_summary_writes_fail_closed_boundary(tmp_path: Path) -> None:
    report = module._summary(tmp_path, ["blocked for test"], {})

    assert report["schema_version"] == module.SUMMARY_SCHEMA
    assert report["passed"] is False
    assert report["decision"] == "blocked"
    assert report["boundary"]["deploy_allowed"] is False
    assert report["boundary"]["production_runtime_execution_allowed"] is False
    assert report["h3_boundary"]["h3_remains_blocked"] is True
    assert (tmp_path / "frontend_release_chain_summary.json").is_file()
