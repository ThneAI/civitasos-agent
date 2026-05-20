#!/usr/bin/env bash
# Lightweight Beta-1 proposal-only packet and operator receipt check.
#
# This does not call an LLM or mutate a real repository. It verifies the local
# packet/receipt safety boundary that a real Beta-1 repo review run must pass.
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if [ -x "./.venv/bin/python" ]; then
    PYTHON="./.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
  else
    PYTHON="python"
  fi
fi

RUN_ROOT="${BETA1_REPO_REVIEW_PACKET_CHECK_ROOT:-}"
if [ -z "$RUN_ROOT" ]; then
  RUN_ROOT="$(mktemp -d)"
  CLEANUP_RUN_ROOT=1
else
  CLEANUP_RUN_ROOT=0
fi
trap 'if [ "${CLEANUP_RUN_ROOT:-0}" = "1" ]; then rm -rf "$RUN_ROOT"; fi' EXIT

REPO="$RUN_ROOT/repo"
PACKET="$RUN_ROOT/packet"
mkdir -p "$REPO" "$PACKET"

git -C "$REPO" init >/dev/null
git -C "$REPO" config user.email "beta1@example.com"
git -C "$REPO" config user.name "Beta1 Packet Check"
printf 'initial\n' > "$REPO/README.md"
git -C "$REPO" add README.md
git -C "$REPO" commit -m "initial" >/dev/null
printf 'initial\nchanged\n' > "$REPO/README.md"

"$PYTHON" scripts/beta1_repo_review_proposal.py prepare \
  --repo "$REPO" \
  --output-root "$PACKET" \
  --request-id beta1-packet-check \
  --request-text "Review this repository state and produce a proposal only." \
  --operator-id l1-controlled-pilot-operator \
  --target-agent external-model-reviewer >/dev/null

cat > "$PACKET/proposal.md" <<'EOF'
# Proposal

## Scope
Proposal-only repository review.

## Repository Evidence
README.md has a controlled dirty change in the packet-check repository.

## Findings
No repository mutation was performed by the reviewer.

## Proposal
Keep the proposed follow-up as a manual operator decision candidate.

## Risks
The proposal must not be treated as merge, push, deploy, or production authorization.

## Operator Decision Required
An operator receipt is required before any manual follow-up.

## H3 Boundary
H.3 remains blocked; no production runtime execution; no production receipt writes.
EOF

"$PYTHON" scripts/beta1_repo_review_proposal.py receipt \
  --request "$PACKET/beta1_repo_review_proposal_request.json" \
  --proposal "$PACKET/proposal.md" \
  --output "$PACKET/operator_decision_receipt.json" \
  --decision deferred \
  --operator-id l1-controlled-pilot-operator \
  --reason "packet check only" \
  --audit-output "$PACKET/sinks/audit-events.jsonl" >/dev/null

"$PYTHON" scripts/beta1_repo_review_proposal.py validate \
  --receipt "$PACKET/operator_decision_receipt.json" \
  --output "$PACKET/operator_decision_receipt_validation.json" >/dev/null

"$PYTHON" - "$PACKET" <<'PY'
import json
import sys
from pathlib import Path

packet = Path(sys.argv[1])
validation = json.loads((packet / "operator_decision_receipt_validation.json").read_text(encoding="utf-8"))
receipt = json.loads((packet / "operator_decision_receipt.json").read_text(encoding="utf-8"))
if validation.get("passed") is not True:
    raise SystemExit(f"Beta-1 receipt validation failed: {validation}")
for flag in (
    "merge_allowed",
    "push_allowed",
    "deploy_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
):
    if receipt.get(flag) is not False:
        raise SystemExit(f"unsafe receipt flag: {flag}={receipt.get(flag)!r}")
print(json.dumps({
    "schema_version": "beta1-repo-review-packet-check-summary:v1",
    "packet_root": str(packet),
    "receipt_validation_passed": True,
    "audit_record_count": len((packet / "sinks/audit-events.jsonl").read_text(encoding="utf-8").splitlines()),
    "boundary": "proposal_only; H.3 remains blocked",
}, indent=2, sort_keys=True))
PY

echo "Beta-1 repo review packet check passed: $PACKET"
