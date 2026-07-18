from __future__ import annotations

import json

import pytest

from scripts.p5b4_multivm_materials import generate_materials, validate_materials


def test_generate_and_validate_isolated_material_manifest(tmp_path) -> None:
    root = tmp_path / "materials"
    payload = generate_materials(root, created_at=123)

    validated = validate_materials(root / "manifest.json")
    assert validated == payload
    assert payload["isolated_gate_only"] is True
    assert payload["production_identity"] is False
    assert set(payload["nodes"]) == {"vm1", "vm2", "vm3"}
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())


def test_material_tampering_and_overwrite_are_refused(tmp_path) -> None:
    root = tmp_path / "materials"
    generate_materials(root, created_at=123)
    (root / "service.secret").write_text("tampered\n")

    with pytest.raises(ValueError, match="sha256:service.secret"):
        validate_materials(root / "manifest.json")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        generate_materials(root)


def test_manifest_tampering_is_refused(tmp_path) -> None:
    root = tmp_path / "materials"
    generate_materials(root, created_at=123)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["production_identity"] = True
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o600)

    with pytest.raises(ValueError, match="materials_id"):
        validate_materials(manifest_path)
