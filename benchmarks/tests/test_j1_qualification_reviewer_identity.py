from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest

from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_reviewer_identity import (
    provision_reviewer_identity,
)


MODULE = "/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL = "civitas-j1-reviewer-beta"
USER_PIN = "39172845"


@pytest.fixture(scope="module")
def softhsm_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("j1-reviewer-softhsm")
    token_dir = root / "tokens"
    token_dir.mkdir()
    config = root / "softhsm2.conf"
    config.write_text(
        f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n",
        encoding="utf-8",
    )
    environment = os.environ | {"SOFTHSM2_CONF": str(config)}
    subprocess.run(
        [
            "softhsm2-util",
            "--init-token",
            "--free",
            "--label",
            TOKEN_LABEL,
            "--so-pin",
            "82946173",
            "--pin",
            USER_PIN,
        ],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    previous = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(config)
    try:
        yield root
    finally:
        if previous is None:
            os.environ.pop("SOFTHSM2_CONF", None)
        else:
            os.environ["SOFTHSM2_CONF"] = previous


def _provision(
    root: Path, *, key_label: str, key_id_hex: str, output_name: str
) -> tuple[dict, Path]:
    output_path = root / "evidence" / output_name
    report = provision_reviewer_identity(
        module_path=MODULE,
        token_label=TOKEN_LABEL,
        key_label=key_label,
        key_id_hex=key_id_hex,
        credential_version=1,
        pin=USER_PIN,
        output_path=output_path,
        limitations_acknowledged=True,
        created_at="2026-07-20T10:00:00+08:00",
    )
    return report, output_path


def test_provisions_non_extractable_controlled_beta_identity(
    softhsm_root: Path,
) -> None:
    report, output_path = _provision(
        softhsm_root,
        key_label="j1-reviewer-ed25519-primary",
        key_id_hex="41",
        output_name="reviewer-identity-primary.json",
    )
    profile = json.loads(output_path.read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert validate_reviewer_identity_profile(profile) == []
    assert profile["reviewer"]["did"].startswith("did:civ:testnet:z")
    assert profile["pkcs11_key"]["key_type"] == "CKK_EC_EDWARDS"
    assert profile["pkcs11_key"]["mechanism"] == "CKM_EDDSA"
    assert profile["custody_boundary"] == {
        "provider": "SoftHSM v2",
        "physical_hsm_claimed": False,
        "production_custody_claimed": False,
        "token_store_copyable": True,
        "private_key_sensitive": True,
        "private_key_extractable": False,
        "seed_exported": False,
        "pin_recorded": False,
    }
    assert all(value is False for value in profile["authorization_boundary"].values())
    assert output_path.parent.stat().st_mode & 0o777 == 0o700
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert USER_PIN not in output_path.read_text(encoding="utf-8")


def test_requires_explicit_soft_token_acknowledgement(
    softhsm_root: Path,
) -> None:
    with pytest.raises(ValueError, match="explicitly acknowledged"):
        provision_reviewer_identity(
            module_path=MODULE,
            token_label=TOKEN_LABEL,
            key_label="j1-reviewer-ed25519-unacknowledged",
            key_id_hex="42",
            credential_version=1,
            pin=USER_PIN,
            output_path=softhsm_root / "identity-unacknowledged.json",
            limitations_acknowledged=False,
        )


def test_rejects_duplicate_key_label_without_overwrite(
    softhsm_root: Path,
) -> None:
    _provision(
        softhsm_root,
        key_label="j1-reviewer-ed25519-duplicate",
        key_id_hex="43",
        output_name="reviewer-identity-duplicate.json",
    )

    with pytest.raises(ValueError, match="key label already exists"):
        provision_reviewer_identity(
            module_path=MODULE,
            token_label=TOKEN_LABEL,
            key_label="j1-reviewer-ed25519-duplicate",
            key_id_hex="44",
            credential_version=1,
            pin=USER_PIN,
            output_path=softhsm_root / "second-identity.json",
            limitations_acknowledged=True,
        )


def test_profile_rejects_tampered_possession_signature(
    softhsm_root: Path,
) -> None:
    _, output_path = _provision(
        softhsm_root,
        key_label="j1-reviewer-ed25519-tamper",
        key_id_hex="45",
        output_name="reviewer-identity-tamper.json",
    )
    profile = json.loads(output_path.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(profile)
    tampered["possession_proof"]["signature_hex"] = "00" * 64

    failures = validate_reviewer_identity_profile(tampered)

    assert "reviewer_profile_signature_verification_failed" in failures
