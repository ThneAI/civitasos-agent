from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.post_h3_external_user_identity_consent_gate import SIGNATURE_NAMESPACE, run_gate
from benchmarks.post_h3_external_user_usage_review_gate import run_gate as run_post_h3t
from benchmarks.tests.test_post_h3_external_user_usage_review_gate import _write_post_h3s_fixture


def test_post_h3u_binds_external_user_identity_and_consent(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t = _write_post_h3t_fixture(tmp_path, monkeypatch)
    package = _write_signed_consent_package(tmp_path, handle="external-user")

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=tmp_path / "post_h3u",
        external_user_handle="external-user",
    )

    assert summary["passed"] is True
    assert summary["external_user_identity_consent_id"]
    assert summary["readiness"]["external_user_identity_and_consent_bound"] is True
    assert summary["readiness"]["external_user_usage_review_rerun_ready"] is True
    assert summary["readiness"]["external_user_usage_allowed"] is False
    assert "real_external_user_identity_and_consent_not_bound" not in summary["remaining_requirements"]
    assert "production_grade_public_ingress_not_authorized" in summary["remaining_requirements"]


def test_post_h3u_blocks_missing_signature(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t = _write_post_h3t_fixture(tmp_path, monkeypatch)
    package = _write_signed_consent_package(tmp_path, handle="external-user")
    package["signature"].unlink()

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=tmp_path / "post_h3u",
        external_user_handle="external-user",
    )

    assert summary["passed"] is False
    assert "signature_verified" in summary["failure_reasons"]
    assert summary["readiness"]["external_user_identity_and_consent_bound"] is False


def test_post_h3u_blocks_identity_provider_key_mismatch(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t = _write_post_h3t_fixture(tmp_path, monkeypatch)
    package = _write_signed_consent_package(tmp_path, handle="external-user")
    package["identity_provider_keys"].write_text(json.dumps([{"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMismatch"}]), encoding="utf-8")

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=tmp_path / "post_h3u",
        external_user_handle="external-user",
    )

    assert summary["passed"] is False
    assert "allowed_key_in_identity_provider_keys" in summary["failure_reasons"]


def test_post_h3u_blocks_consent_that_allows_production_data(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3t = _write_post_h3t_fixture(tmp_path, monkeypatch)
    package = _write_signed_consent_package(tmp_path, handle="external-user", production_data_access_allowed="true")

    summary = run_gate(
        post_h3t_summary_path=post_h3t,
        consent_path=package["consent"],
        signature_path=package["signature"],
        allowed_signers_path=package["allowed_signers"],
        identity_provider_keys_path=package["identity_provider_keys"],
        output_root=tmp_path / "post_h3u",
        external_user_handle="external-user",
    )

    assert summary["passed"] is False
    assert "production_data_access_allowed_false" in summary["failure_reasons"]


def _write_post_h3t_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3s = _write_post_h3s_fixture(tmp_path, monkeypatch)
    post_h3t_root = tmp_path / "post_h3t"
    run_post_h3t(
        post_h3s_summary_path=post_h3s,
        output_root=post_h3t_root,
        ack_external_user_usage_review=True,
    )
    return post_h3t_root / "post_h3t_external_user_usage_review_summary.json"


def _write_signed_consent_package(tmp_path: Path, *, handle: str, production_data_access_allowed: str = "false") -> dict[str, Path]:
    key_path = tmp_path / f"{handle}_key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-q"], check=True)
    public_key = " ".join((key_path.with_suffix(".pub")).read_text(encoding="utf-8").split()[:2])
    consent = tmp_path / "external_user_consent.md"
    valid_until = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    consent.write_text(
        f"""# CivitasOS Limited External User Usage Consent

external_user_provider: github
external_user_handle: {handle}
consent_scope: invite-only limited external user usage trial
allowed_usage_scope: status/read-only task only
max_external_users: 1
max_runtime_tasks: 1
production_data_access_allowed: {production_data_access_allowed}
source_write_allowed: false
git_write_allowed: false
deploy_allowed: false
valid_until_utc: {valid_until}
withdrawal_path: user may request abort via operator; operator must stop usage and write abort receipt
rollback_owner: rollback_owner
monitoring_owner: monitoring_owner
audit_owner: audit_owner

I confirm
""",
        encoding="utf-8",
    )
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", SIGNATURE_NAMESPACE, str(consent)], check=True, capture_output=True)
    allowed_signers = tmp_path / "allowed_signers"
    allowed_signers.write_text(f"{handle} {public_key}\n", encoding="utf-8")
    identity_provider_keys = tmp_path / "identity_provider_keys.json"
    identity_provider_keys.write_text(json.dumps([{"key": public_key}], indent=2), encoding="utf-8")
    return {
        "consent": consent,
        "signature": consent.with_suffix(".md.sig"),
        "allowed_signers": allowed_signers,
        "identity_provider_keys": identity_provider_keys,
    }
