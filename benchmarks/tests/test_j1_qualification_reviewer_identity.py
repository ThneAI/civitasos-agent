from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import pkcs11

from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_reviewer_identity import (
    inspect_token_pin_state,
    provision_reviewer_identity,
)
from benchmarks.j1_reviewer_soft_token_pin import reset_user_pin


MODULE = "/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL = "civitas-j1-reviewer-beta"
USER_PIN = "39172845"
SO_PIN = "82946173"
RESET_TOKEN_LABEL = "civitas-j1-reviewer-reset"


@pytest.fixture(scope="module")
def softhsm_environment(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Any]:
    root = tmp_path_factory.mktemp("j1-reviewer-softhsm")
    token_dir = root / "tokens"
    token_dir.mkdir()
    config = root / "softhsm2.conf"
    config.write_text(
        f"directories.tokendir = {token_dir}\nobjectstore.backend = file\n",
        encoding="utf-8",
    )
    environment = os.environ | {"SOFTHSM2_CONF": str(config)}
    for token_label in (TOKEN_LABEL, RESET_TOKEN_LABEL):
        subprocess.run(
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                token_label,
                "--so-pin",
                SO_PIN,
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
    library = pkcs11.lib(str(Path(MODULE).resolve()))
    try:
        yield root, library
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
    softhsm_environment: tuple[Path, Any],
) -> None:
    softhsm_root, _ = softhsm_environment
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
    softhsm_environment: tuple[Path, Any],
) -> None:
    softhsm_root, _ = softhsm_environment
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
    softhsm_environment: tuple[Path, Any],
) -> None:
    softhsm_root, _ = softhsm_environment
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
    softhsm_environment: tuple[Path, Any],
) -> None:
    softhsm_root, _ = softhsm_environment
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


def test_pin_risk_blocks_retry_and_so_reset_restores_provisioning(
    softhsm_environment: tuple[Path, Any],
) -> None:
    softhsm_root, library = softhsm_environment
    token = library.get_token(token_label=RESET_TOKEN_LABEL)
    with pytest.raises(pkcs11.exceptions.PinIncorrect):
        token.open(user_pin="incorrect-user-pin", rw=True)
    risky = inspect_token_pin_state(module_path=MODULE, token_label=RESET_TOKEN_LABEL)
    assert risky["safe_to_attempt_user_login"] is False
    assert "USER_PIN_COUNT_LOW" in risky["user_pin_risk_flags"]

    with pytest.raises(ValueError, match="SO PIN reset required"):
        provision_reviewer_identity(
            module_path=MODULE,
            token_label=RESET_TOKEN_LABEL,
            key_label="must-not-be-created",
            key_id_hex="51",
            credential_version=1,
            pin=USER_PIN,
            output_path=softhsm_root / "must-not-exist.json",
            limitations_acknowledged=True,
        )

    new_user_pin = "58419372"
    reset = reset_user_pin(
        module_path=MODULE,
        token_label=RESET_TOKEN_LABEL,
        so_pin=SO_PIN,
        new_user_pin=new_user_pin,
        reset_acknowledged=True,
    )
    assert reset["passed"] is True
    assert reset["after"]["safe_to_attempt_user_login"] is True
    assert reset["so_pin_recorded"] is False
    assert reset["user_pin_recorded"] is False

    output_path = softhsm_root / "reset-reviewer-identity.json"
    provision = provision_reviewer_identity(
        module_path=MODULE,
        token_label=RESET_TOKEN_LABEL,
        key_label="j1-reviewer-after-reset",
        key_id_hex="52",
        credential_version=1,
        pin=new_user_pin,
        output_path=output_path,
        limitations_acknowledged=True,
        created_at="2026-07-20T11:00:00+08:00",
    )
    assert provision["passed"] is True
    assert output_path.exists()
