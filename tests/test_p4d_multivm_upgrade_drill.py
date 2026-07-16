import json
from pathlib import Path

import pytest

from scripts.p4d_multivm_upgrade_drill import main


def assets(tmp_path: Path) -> tuple[Path, Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    frontend = tmp_path / "frontend"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    frontend.mkdir()
    (frontend / "index.html").write_text("ready", encoding="utf-8")
    return baseline, candidate, frontend


def test_authorization_binds_release_hashes_and_nonproduction_boundary(tmp_path, monkeypatch):
    baseline, candidate, frontend = assets(tmp_path)
    output = tmp_path / "authorization.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "p4d_multivm_upgrade_drill.py",
            "authorize",
            "--baseline-bin", str(baseline),
            "--candidate-bin", str(candidate),
            "--frontend-build-dir", str(frontend),
            "--output", str(output),
            "--ack-private-beta-upgrade-drill",
        ],
    )

    assert main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["single_use"] is True
    assert report["nodes"] == ["vm1", "vm2", "vm3"]
    assert report["baseline_sha256"] != report["candidate_sha256"]
    assert report["production_runtime_allowed"] is False


def test_authorization_requires_explicit_acknowledgement(tmp_path, monkeypatch):
    baseline, candidate, frontend = assets(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "p4d_multivm_upgrade_drill.py",
            "authorize",
            "--baseline-bin", str(baseline),
            "--candidate-bin", str(candidate),
            "--frontend-build-dir", str(frontend),
            "--output", str(tmp_path / "authorization.json"),
        ],
    )

    with pytest.raises(SystemExit, match="explicit"):
        main()
