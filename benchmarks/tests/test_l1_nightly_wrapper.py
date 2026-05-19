from __future__ import annotations

from pathlib import Path


def test_nightly_wrapper_wires_l1_pilot_contract_chain() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_L1_PILOT_001_CONTRACT_CHAIN="${RUN_L1_PILOT_001_CONTRACT_CHAIN:-0}"' in text
    assert 'L1_PILOT_001_CONTRACT_ROOT="${L1_PILOT_001_CONTRACT_ROOT:-$RUNS_ROOT/l1_pilot_001_contract_runner}"' in text
    assert 'L1_PILOT_001_WAKE_MODE="event"' in text
    assert 'L1_PILOT_001_WAKE_MODE="${L1_PILOT_001_WAKE_MODE:-auto}"' in text
    assert 'L1_PILOT_001_REQUIRE_SIGNED_WAKE="${L1_PILOT_001_REQUIRE_SIGNED_WAKE:-$RUN_L1_PILOT_001_CONTRACT_CHAIN}"' in text
    assert 'L1_PILOT_001_REQUIRE_SERVICE_TOKEN="${L1_PILOT_001_REQUIRE_SERVICE_TOKEN:-$RUN_L1_PILOT_001_CONTRACT_CHAIN}"' in text
    assert 'L1_PILOT_001_WAKE_CALLBACK_SECRET="${L1_PILOT_001_WAKE_CALLBACK_SECRET:-${CIVITASOS_WAKE_CALLBACK_SECRET:-}}"' in text
    assert 'L1_PILOT_001_SERVICE_TOKEN_SECRET="${L1_PILOT_001_SERVICE_TOKEN_SECRET:-${CIVITASOS_SERVICE_TOKEN_SECRET:-}}"' in text
    assert 'L1_PILOT_001_SERVICE_SCOPES="${L1_PILOT_001_SERVICE_SCOPES:-agents:read,agents:write,pool:post,pool:read,pool:claim,pool:write,webhooks:write}"' in text
    assert "l1_service_scope_present()" in text
    assert 'if [ "$RUN_L1_PILOT_001_CONTRACT_CHAIN" = "1" ]; then' in text
    assert 'if [ "$L1_PILOT_001_REQUIRE_SERVICE_TOKEN" = "1" ]; then' in text
    assert "for required_scope in agents:read agents:write pool:post pool:read pool:claim pool:write webhooks:write; do" in text
    assert '"$PYTHON" scripts/l1_pilot_001_contract_runner.py \\' in text
    assert '--wake-mode "$L1_PILOT_001_WAKE_MODE"' in text
    assert '--event-wake-grace "$L1_PILOT_001_EVENT_WAKE_GRACE"' in text
    assert 'L1_REQUIRE_SIGNED_WAKE="$L1_PILOT_001_REQUIRE_SIGNED_WAKE"' in text
    assert 'L1_REQUIRE_SERVICE_TOKEN="$L1_PILOT_001_REQUIRE_SERVICE_TOKEN"' in text
    assert 'CIVITASOS_WAKE_CALLBACK_SECRET="$L1_PILOT_001_WAKE_CALLBACK_SECRET"' in text
    assert 'L1_SERVICE_TOKEN_SECRET="$L1_PILOT_001_SERVICE_TOKEN_SECRET"' in text
    assert 'L1_SERVICE_TOKEN_SCOPES="$L1_PILOT_001_SERVICE_SCOPES"' in text
    assert '--require-signed-wake' in text
    assert 'L1_ENABLE_EVENT_WAKE="$L1_PILOT_001_ENABLE_EVENT_WAKE"' in text


def test_l1_contract_smoke_is_strict_service_token_signed_wake() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_l1_contract_smoke.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'L1_PILOT_001_WAKE_MODE="${L1_PILOT_001_WAKE_MODE:-event}"' in text
    assert 'L1_PILOT_001_REQUIRE_SIGNED_WAKE="${L1_PILOT_001_REQUIRE_SIGNED_WAKE:-1}"' in text
    assert 'L1_PILOT_001_REQUIRE_SERVICE_TOKEN="${L1_PILOT_001_REQUIRE_SERVICE_TOKEN:-1}"' in text
    assert 'for required_scope in agents:read agents:write pool:post pool:read pool:claim pool:write webhooks:write; do' in text
    assert 'L1_REQUIRE_SERVICE_TOKEN="$L1_PILOT_001_REQUIRE_SERVICE_TOKEN"' in text
    assert 'auth.get("auth_method") != "service_token"' in text
    assert 'wake.get("require_signed_wake") is not True' in text
    assert '"Demo-login token bootstrapped" in logs' in text
    assert '"Service-token bootstrap token acquired"' in text
    assert '"DID auth token bootstrapped"' in text
    assert '"$PYTHON" scripts/l1_pilot_001_contract_runner.py "${RUNNER_ARGS[@]}"' in text


def test_l1_contract_smoke_ci_check_protects_fail_fast_surface() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_l1_contract_smoke_ci_check.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "benchmarks/run_l1_contract_smoke.sh" in text
    assert "benchmarks/run_l1_contract_smoke_scheduled.sh" in text
    assert "benchmarks/run_nightly_regression.sh" in text
    assert "-u L1_PILOT_001_WAKE_CALLBACK_SECRET" in text
    assert "-u CIVITASOS_WAKE_CALLBACK_SECRET" in text
    assert "requires signed wake" in text
    assert "L1_PILOT_001_SERVICE_SCOPES=pool:read" in text
    assert "missing required scope: agents:read" in text
    assert "benchmarks/tests/test_l1_nightly_wrapper.py" in text
    assert "benchmarks/tests/test_l1_pilot_contract_runner.py" in text
    assert "benchmarks/tests/test_l1_pilot_contract_tasks.py" in text


def test_l1_contract_smoke_scheduled_indexes_evidence() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_l1_contract_smoke_scheduled.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "curl -fsS \"$BACKEND_URL/healthz\"" in text
    assert "curl -fsS \"$LLM_BASE_URL/models\"" in text
    assert "benchmarks/run_l1_contract_smoke.sh" in text
    assert "l1_contract_smoke_index.jsonl" in text
    assert "l1_contract_smoke_latest.json" in text
    assert "wake_event_counts" in text
    assert "rule_pool_claim_count" in text
    assert "service_token_bootstrap_count" in text
    assert "did_auth_bootstrap_count" in text
    assert "scheduled_smoke_does_not_claim_h3_production_readiness" in text


def test_l1_contract_smoke_workflow_wires_lightweight_and_full_paths() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "l1-contract-smoke.yml"
    )
    text = workflow.read_text(encoding="utf-8")

    assert "benchmarks/run_l1_contract_smoke_ci_check.sh" in text
    assert "benchmarks/run_l1_contract_smoke_scheduled.sh" in text
    assert "runs-on: [self-hosted, civitasos-l1]" in text
    assert "github.event_name == 'schedule'" in text
    assert "CIVITASOS_SERVICE_TOKEN_SECRET" in text
    assert "CIVITASOS_WAKE_CALLBACK_SECRET" in text
