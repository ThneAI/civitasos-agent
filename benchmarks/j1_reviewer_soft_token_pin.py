"""Safely reset a SoftHSM reviewer token user PIN through an SO session."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
from typing import Any

import pkcs11

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1_qualification_reviewer_identity import (
    inspect_token_pin_state,
)
from scripts.pkcs11_identity_probe import DEFAULT_MODULE


def reset_user_pin(
    *,
    module_path: str,
    token_label: str,
    so_pin: str,
    new_user_pin: str,
    reset_acknowledged: bool,
) -> dict[str, Any]:
    if not reset_acknowledged:
        raise ValueError("user PIN reset must be explicitly acknowledged")
    if not so_pin:
        raise ValueError("SO PIN is empty")
    if len(new_user_pin) < 8:
        raise ValueError("new user PIN must contain at least 8 characters")
    before = inspect_token_pin_state(module_path=module_path, token_label=token_label)
    if not before["safe_to_attempt_so_login"]:
        raise ValueError(
            "token SO PIN retry risk; stop and recover token administration: "
            f"{before['so_pin_risk_flags']}"
        )
    module = Path(module_path).resolve()
    library = pkcs11.lib(str(module))
    token = library.get_token(token_label=token_label)
    if token.model != "SoftHSM v2":
        raise ValueError(f"token is not SoftHSM v2: {token.model}")
    with token.open(
        rw=True,
        user_pin=so_pin,
        user_type=pkcs11.UserType.SO,
    ) as session:
        session.init_pin(new_user_pin)
    after = inspect_token_pin_state(module_path=module_path, token_label=token_label)
    if not after["safe_to_attempt_user_login"]:
        raise RuntimeError("user PIN risk flags remained after reset")
    return {
        "schema_version": "j1-soft-token-user-pin-reset:v1",
        "passed": True,
        "state": "soft_token_user_pin_reset_reviewer_provisioning_ready",
        "token_label": token.label,
        "token_serial": _decode(token.serial),
        "before": before,
        "after": after,
        "so_pin_recorded": False,
        "user_pin_recorded": False,
        "reviewer_key_created": False,
        "review_decision_created": False,
    }


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii").strip()
    return str(value).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--acknowledge-user-pin-reset",
        action="store_true",
        help="acknowledge that the token user PIN will be replaced",
    )
    args = parser.parse_args()
    if not args.acknowledge_user_pin_reset:
        parser.error("--acknowledge-user-pin-reset is required")
    state = inspect_token_pin_state(
        module_path=args.module, token_label=args.token_label
    )
    if not state["safe_to_attempt_so_login"]:
        print(
            json.dumps(
                {
                    "schema_version": "j1-soft-token-user-pin-reset:v1",
                    "passed": False,
                    "state": "blocked_so_pin_retry_risk",
                    "token_pin_state": state,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    so_pin = getpass.getpass("SoftHSM SO PIN: ")
    new_user_pin = getpass.getpass("New PKCS#11 user PIN: ")
    confirmation = getpass.getpass("Confirm new PKCS#11 user PIN: ")
    if new_user_pin != confirmation:
        print(
            json.dumps(
                {
                    "schema_version": "j1-soft-token-user-pin-reset:v1",
                    "passed": False,
                    "state": "blocked_new_user_pin_confirmation_mismatch",
                    "so_login_attempted": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    try:
        try:
            report = reset_user_pin(
                module_path=args.module,
                token_label=args.token_label,
                so_pin=so_pin,
                new_user_pin=new_user_pin,
                reset_acknowledged=True,
            )
        except pkcs11.exceptions.PinIncorrect:
            report = {
                "schema_version": "j1-soft-token-user-pin-reset:v1",
                "passed": False,
                "state": "blocked_so_pin_incorrect_stop_retrying",
                "error_class": "PinIncorrect",
                "so_pin_recorded": False,
                "user_pin_recorded": False,
            }
    finally:
        so_pin = ""
        new_user_pin = ""
        confirmation = ""
    if args.output is not None:
        write_private_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
