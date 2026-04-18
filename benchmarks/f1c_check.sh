#!/usr/bin/env bash
# benchmarks/f1c_check.sh — F.1.c pre-flight readiness checks (R3 §7).
#
# Validates everything F.1.c needs before launching the ~9h overnight run.
# Exits non-zero on first failure with a remediation hint.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

PYTHON="${PYTHON:-./.venv/bin/python}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8099}"
LLM_BASE_URL="${LLM_BASE_URL:-http://localhost:11434}"
LLM_MODEL="${LLM_MODEL:-qwen3:latest}"
RUNS_ROOT="${RUNS_ROOT:-runs/F1c}"

ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
hint()  { printf '    → %s\n' "$*"; }

failures=0

echo "F.1.c readiness check"
echo "──────────────────────"

# 1. python venv
if [ -x "$PYTHON" ]; then
    ok "python venv: $PYTHON ($($PYTHON --version))"
else
    fail "python venv not found at $PYTHON"
    hint "create with: python3 -m venv .venv && ./.venv/bin/pip install -e ."
    failures=$((failures + 1))
fi

# 2. unit tests still passing
if $PYTHON -m pytest -q --no-header 2>&1 | tail -1 | grep -q "passed"; then
    ok "unit tests pass"
else
    fail "unit tests not passing"
    hint "run: $PYTHON -m pytest -q"
    failures=$((failures + 1))
fi

# 3. backend healthz
if curl -sf -m 3 "$BACKEND_URL/healthz" >/dev/null 2>&1; then
    ok "backend healthz OK at $BACKEND_URL"
else
    fail "backend not reachable at $BACKEND_URL"
    hint "start: cd ../civitasos-backend && ./target/debug/civitasos-backend &"
    hint "  or:  ./target/release/civitasos-backend &"
    failures=$((failures + 1))
fi

# 4. backend cluster peers (R9-related; for serial mode we still want quorum)
if PEERS=$(curl -sf -m 3 "$BACKEND_URL/cluster/peers" 2>/dev/null); then
    n=$(echo "$PEERS" | $PYTHON -c "import sys, json; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else len(d.get('peers', [])))" 2>/dev/null || echo 0)
    if [ "$n" -ge 0 ]; then
        ok "backend cluster: $n peer(s) (single-node OK for benchmark)"
    fi
else
    ok "backend cluster query skipped (endpoint optional)"
fi

# 5. ollama up + qwen3 pulled
if curl -sf -m 3 "$LLM_BASE_URL/api/tags" 2>/dev/null | grep -q "$LLM_MODEL"; then
    ok "ollama serving $LLM_MODEL"
else
    fail "ollama not serving $LLM_MODEL at $LLM_BASE_URL"
    hint "start ollama and: ollama pull $LLM_MODEL"
    failures=$((failures + 1))
fi

# 6. ollama warm (first inference is slow, do a tiny warmup)
if curl -sf -m 60 -X POST "$LLM_BASE_URL/api/generate" \
        -d "{\"model\":\"$LLM_MODEL\",\"prompt\":\"hi\",\"stream\":false}" \
        >/dev/null 2>&1; then
    ok "ollama responded to warmup prompt"
else
    fail "ollama warmup failed"
    hint "verify: curl -X POST $LLM_BASE_URL/api/generate -d '{\"model\":\"$LLM_MODEL\",\"prompt\":\"hi\",\"stream\":false}'"
    failures=$((failures + 1))
fi

# 7. manifest present
MANIFEST="benchmarks/v1/manifest.yaml"
if [ -f "$MANIFEST" ]; then
    n_tasks=$($PYTHON -c "from benchmarks.task_loader import load_manifest; print(len(load_manifest('$MANIFEST').tasks))" 2>/dev/null || echo 0)
    if [ "$n_tasks" -ge 60 ]; then
        ok "manifest loads $n_tasks tasks"
    else
        fail "manifest only has $n_tasks tasks (need ≥60)"
        failures=$((failures + 1))
    fi
else
    fail "manifest missing: $MANIFEST"
    failures=$((failures + 1))
fi

# 8. agent_ids.json present
AGENT_IDS="$RUNS_ROOT/agent_ids.json"
if [ -f "$AGENT_IDS" ]; then
    n_agents=$($PYTHON -c "import json; print(len(json.load(open('$AGENT_IDS'))))" 2>/dev/null || echo 0)
    ok "agent_ids.json: $n_agents agents registered"
else
    fail "agent_ids.json missing"
    hint "run: $PYTHON -m benchmarks.f1c_preflight --backend-url $BACKEND_URL --runs-root $RUNS_ROOT"
    failures=$((failures + 1))
fi

# 9. disk space (60 task × 3 agent × ~5MB raw_ticks ~ 1GB)
free_gb=$(df -BG "$ROOT" | awk 'NR==2 {gsub("G",""); print $4}')
if [ "$free_gb" -ge 5 ]; then
    ok "disk free: ${free_gb}GB (need ~1GB)"
else
    fail "disk free: ${free_gb}GB (need ≥5GB)"
    failures=$((failures + 1))
fi

echo
if [ $failures -eq 0 ]; then
    echo "═══ All checks passed. Ready for: ./benchmarks/run_f1c.sh ═══"
    exit 0
else
    echo "═══ $failures check(s) failed. Resolve the hints above before launching. ═══"
    exit 1
fi
