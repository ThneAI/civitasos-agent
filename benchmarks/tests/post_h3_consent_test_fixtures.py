from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.post_h3_external_user_identity_consent_gate import SIGNATURE_NAMESPACE


def write_signed_consent_package(
    tmp_path: Path,
    *,
    handle: str,
    production_data_access_allowed: str = "false",
) -> dict[str, Path]:
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
