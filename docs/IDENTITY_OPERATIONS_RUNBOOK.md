# Identity Operations Runbook

This runbook covers the current file-backed Ed25519 identity path for Private
Beta. Exportable seeds are transitional; hardware-backed signing or WebAuthn is
required before broader production use.

## Preconditions

- Use the repository `.venv/bin/python` interpreter.
- Keep identities and backups outside repositories and synchronized folders.
- Inject secrets interactively or through a protected environment mechanism.
- Require file mode `0600` and keep one encrypted backup offline.

## Create And Back Up

```bash
.venv/bin/python scripts/identity_ops.py create \
  --identity "$IDENTITY_PATH" --agent-id "$AGENT_ID"
.venv/bin/python scripts/identity_ops.py backup \
  --identity "$IDENTITY_PATH" --output "$OFFLINE_BACKUP_PATH"
.venv/bin/python scripts/identity_ops.py verify-backup \
  --backup "$OFFLINE_BACKUP_PATH"
```

Record only the agent ID, public key, media identifier, operator, and verification
time. Move the verified backup offline after verification.

## Restore Drill

Restore to a new temporary path, never over the active identity:

```bash
.venv/bin/python scripts/identity_ops.py restore \
  --backup "$OFFLINE_BACKUP_PATH" --output "$TEMP_RESTORE_PATH"
.venv/bin/python scripts/identity_ops.py inspect --identity "$TEMP_RESTORE_PATH"
```

Compare agent ID and public key with inventory, then securely remove the temporary
plaintext identity. Successful decryption does not authorize credential activation.

## Credential Rotation

1. Generate a new identity at a staged path, back it up, and verify the backup.
2. Obtain `/api/v1/auth/challenge` for the current agent.
3. Sign the exact challenge with both current and staged keys.
4. Submit `/api/v1/auth/credential/rotate` with the current bearer token.
5. Require `rotated=true` and a non-empty `fact_id`.
6. Verify the old token returns HTTP 401 and authenticate with the new key.
7. Atomically activate the staged identity and retain the old encrypted backup
   only for the approved rollback period.

The executable regression gate is `scripts/beta_runtime_identity_task_smoke.py`.

## Signed Revocation

Sign a fresh challenge with the current key and submit
`/api/v1/auth/credential/revoke`. Require `revoked=true`, a non-empty `fact_id`,
and HTTP 401 from the previously valid token.

## Emergency Revocation

Use this only when the signing key is unavailable or suspected compromised. The
operator service token must have `agents:write` and must be injected as a protected
secret. Submit the affected agent ID and a specific incident reason to
`/api/v1/auth/credential/emergency-revoke`.

Acceptance requires HTTP 200, a non-empty Fact ID, HTTP 401 for old tokens, an
unbroken audit stream, and an incident record linking operator, reason, time, and
Fact ID. Recovery must create or rotate to a new key, never re-enable the suspected
credential. The Private Beta soak executes and verifies this path every round.

## Private Beta Gate

```bash
.venv/bin/python scripts/beta_runtime_identity_task_smoke.py
```

Use `scripts/private_beta_soak.py` for repeated restart recovery, challenge expiry,
retry, rotation, signed revocation, emergency revocation, Fact integrity, and audit
continuity coverage.
