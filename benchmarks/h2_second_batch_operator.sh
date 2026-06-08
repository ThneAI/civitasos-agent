#!/usr/bin/env bash
set -euo pipefail

AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$AGENT_ROOT"

PYTHON="${CIVITASOS_AGENT_PYTHON:-$AGENT_ROOT/.venv/bin/python}"
FIRST_REPORT="${H2_FIRST_SOURCE_REPORT:-runs/H2_delayed_semantic_observability_owner_20260607/h2_multi_agent_backend_continuity_gate.json}"
SECOND_RUN_ROOT="${H2_SECOND_RUN_ROOT:-runs/H2_delayed_semantic_audit_owner_20260608}"
SECOND_OWNER_ID="${H2_SECOND_OWNER_ID:-audit_owner}"
AGGREGATE_ROOT="${H2_AGGREGATE_ROOT:-runs/H2_h3_readiness_20260608_round2}"
BACKEND_BINARY="${H2_BACKEND_BINARY:-$AGENT_ROOT/../civitasos-backend/target/debug/api_only}"

SECOND_REPORT="$SECOND_RUN_ROOT/h2_multi_agent_backend_continuity_gate.json"
H2_REPORT="$AGGREGATE_ROOT/h2_delayed_consequence_evidence_check.json"
H3_REPORT="$AGGREGATE_ROOT/h3_read_only_goal_proposal_gate.json"
READINESS_REPORT="$AGGREGATE_ROOT/h2_h3_readiness_summary.json"

usage() {
  cat <<'EOF'
Usage: ./benchmarks/h2_second_batch_operator.sh <status|preflight|run|verify>

Environment overrides:
  H2_FIRST_SOURCE_REPORT
  H2_SECOND_RUN_ROOT
  H2_SECOND_OWNER_ID
  H2_AGGREGATE_ROOT
  H2_BACKEND_BINARY
  CIVITASOS_AGENT_PYTHON

The run command refuses to start until 86400 seconds after the earliest
observed_at timestamp in the first source report.
EOF
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -s "$path" ]]; then
    echo "missing $label: $path" >&2
    exit 2
  fi
}

time_status() {
  local enforce="${1:-false}"
  "$PYTHON" - "$FIRST_REPORT" "$SECOND_OWNER_ID" "$enforce" <<'PY'
import json
import re
import sys
from datetime import datetime, timedelta, timezone

report_path, second_owner, enforce = sys.argv[1:]
report = json.load(open(report_path, encoding="utf-8"))

def parse(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    value = re.sub(r"(\.\d{6})\d+(?=[+-]\d\d:\d\d$)", r"\1", value)
    return datetime.fromisoformat(value).astimezone(timezone.utc)

timestamps = [
    parse(str(item["observed_at"]))
    for item in report.get("worker_summaries", {}).values()
    if item.get("observed_at")
]
if not timestamps:
    raise SystemExit("first source report has no observed_at timestamps")

first_owner = str(report.get("owner_id") or "").strip()
if not first_owner:
    raise SystemExit("first source report has no owner_id")
if not second_owner.strip():
    raise SystemExit("second owner id must not be blank")
if first_owner == second_owner:
    raise SystemExit(f"second owner must differ from first owner: {first_owner}")

earliest = min(timestamps)
not_before = earliest + timedelta(seconds=86400)
now = datetime.now(timezone.utc)
remaining = max(0.0, (not_before - now).total_seconds())
state = "READY" if remaining == 0 else "WAITING"

print(f"time_state={state}")
print(f"first_owner={first_owner}")
print(f"second_owner={second_owner}")
print(f"first_observed_at_utc={earliest.isoformat()}")
print(f"not_before_utc={not_before.isoformat()}")
print(f"not_before_asia_shanghai={not_before.astimezone(timezone(timedelta(hours=8))).isoformat()}")
print(f"now_utc={now.isoformat()}")
print(f"remaining_seconds={remaining:.3f}")

if enforce == "true" and remaining > 0:
    raise SystemExit(4)
PY
}

validate_first_report() {
  "$PYTHON" - "$FIRST_REPORT" <<'PY'
import json
import sys

path = sys.argv[1]
report = json.load(open(path, encoding="utf-8"))
if report.get("schema_version") != "h2-multi-agent-backend-continuity-gate:v1":
    raise SystemExit("unexpected first source report schema")
if report.get("evidence_class") != "controlled_pilot_backend":
    raise SystemExit("first source report is not controlled-pilot backend evidence")
if report.get("passed") is not True:
    raise SystemExit("first source report did not pass")
summaries = report.get("worker_summaries", {})
tasks = {str(item.get("task_id") or "") for item in summaries.values()}
if len(summaries) != 3 or "" in tasks or len(tasks) != 3:
    raise SystemExit("first source report must contain three distinct tasks")
print("first_source_report=valid")
PY
}

status() {
  require_file "$FIRST_REPORT" "first H.2 source report"
  time_status false
  "$PYTHON" - "$SECOND_REPORT" "$H2_REPORT" "$H3_REPORT" "$READINESS_REPORT" <<'PY'
import json
import os
import sys

labels = ("second_source", "h2_aggregate", "h3_proposals", "readiness")
for label, path in zip(labels, sys.argv[1:]):
    if not os.path.isfile(path):
        print(f"{label}=missing ({path})")
        continue
    report = json.load(open(path, encoding="utf-8"))
    details = [f"passed={report.get('passed')}"]
    if label == "h2_aggregate":
        metrics = report.get("metrics", {})
        details.extend(
            [
                f"owners={metrics.get('owner_count')}",
                f"tasks={metrics.get('task_count')}",
                f"days={metrics.get('observation_day_count')}",
                f"span_seconds={metrics.get('observation_span_seconds')}",
                f"failure_class={report.get('failure_class')}",
            ]
        )
    elif label == "h3_proposals":
        details.append(
            f"proposal_count={report.get('proposal_surface', {}).get('proposal_count')}"
        )
    elif label == "readiness":
        details.append(f"status={report.get('status')}")
    print(f"{label}=present " + " ".join(details) + f" ({path})")
PY
}

preflight() {
  require_file "$FIRST_REPORT" "first H.2 source report"
  if [[ ! -x "$PYTHON" ]]; then
    echo "python is not executable: $PYTHON" >&2
    exit 2
  fi
  if [[ ! -x "$BACKEND_BINARY" ]]; then
    echo "backend binary is not executable: $BACKEND_BINARY" >&2
    exit 2
  fi
  if [[ -d "$SECOND_RUN_ROOT" ]] && [[ -n "$(find "$SECOND_RUN_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "second run root is non-empty; choose a new H2_SECOND_RUN_ROOT: $SECOND_RUN_ROOT" >&2
    exit 2
  fi
  validate_first_report
  "$PYTHON" -m benchmarks.h2_multi_agent_backend_continuity_gate --help >/dev/null
  "$PYTHON" -m benchmarks.h2_delayed_consequence_evidence_check --help >/dev/null
  "$PYTHON" -m benchmarks.h3_read_only_goal_proposal_gate --help >/dev/null
  "$PYTHON" -m benchmarks.h2_h3_readiness_summary --help >/dev/null
  time_status true
  echo "preflight=passed"
}

print_result() {
  "$PYTHON" - "$H2_REPORT" "$H3_REPORT" "$READINESS_REPORT" <<'PY'
import json
import os
import sys

h2 = json.load(open(sys.argv[1], encoding="utf-8"))
h3 = json.load(open(sys.argv[2], encoding="utf-8")) if os.path.isfile(sys.argv[2]) else {}
ready = json.load(open(sys.argv[3], encoding="utf-8"))
metrics = h2.get("metrics", {})
print("H.2/H.3 result")
print(f"  h2_passed={h2.get('passed')}")
print(f"  integrity_passed={h2.get('integrity_passed')}")
print(f"  maturity_passed={h2.get('maturity_passed')}")
print(f"  failure_class={h2.get('failure_class')}")
print(f"  owners={metrics.get('owner_count')}")
print(f"  tasks={metrics.get('task_count')}")
print(f"  observation_days={metrics.get('observation_day_count')}")
print(f"  observation_span_seconds={metrics.get('observation_span_seconds')}")
print(f"  h3_passed={h3.get('passed')}")
print(f"  h3_proposal_count={h3.get('proposal_surface', {}).get('proposal_count')}")
print(f"  readiness_status={ready.get('status')}")
PY
}

verify() {
  require_file "$FIRST_REPORT" "first H.2 source report"
  require_file "$SECOND_REPORT" "second H.2 source report"
  mkdir -p "$AGGREGATE_ROOT"
  rm -f "$H3_REPORT"

  local h2_status=0
  "$PYTHON" -m benchmarks.h2_delayed_consequence_evidence_check \
    --source-report "$FIRST_REPORT" \
    --source-report "$SECOND_REPORT" \
    --output "$H2_REPORT" \
    >"$AGGREGATE_ROOT/h2_delayed_consequence_evidence_check.stdout.json" || h2_status=$?

  local h3_status=0
  if [[ "$h2_status" -eq 0 ]]; then
    "$PYTHON" -m benchmarks.h3_read_only_goal_proposal_gate \
      --h2-evidence-report "$H2_REPORT" \
      --output "$H3_REPORT" \
      >"$AGGREGATE_ROOT/h3_read_only_goal_proposal_gate.stdout.json" || h3_status=$?
  fi

  local readiness_args=(
    --h2-evidence-report "$H2_REPORT"
    --output "$READINESS_REPORT"
  )
  if [[ -s "$H3_REPORT" ]]; then
    readiness_args+=(--h3-proposal-report "$H3_REPORT")
  fi
  "$PYTHON" -m benchmarks.h2_h3_readiness_summary "${readiness_args[@]}" \
    >"$AGGREGATE_ROOT/h2_h3_readiness_summary.stdout.json"

  print_result
  if [[ "$h2_status" -ne 0 ]]; then
    return "$h2_status"
  fi
  return "$h3_status"
}

run() {
  preflight
  mkdir -p "$AGGREGATE_ROOT"
  "$PYTHON" -m benchmarks.h2_multi_agent_backend_continuity_gate \
    --run-root "$SECOND_RUN_ROOT" \
    --backend-binary "$BACKEND_BINARY" \
    --owner-id "$SECOND_OWNER_ID" \
    >"$AGGREGATE_ROOT/second_batch.stdout.json"
  verify
}

case "${1:-}" in
  status)
    status
    ;;
  preflight)
    preflight
    ;;
  run)
    run
    ;;
  verify)
    verify
    ;;
  *)
    usage
    exit 2
    ;;
esac
