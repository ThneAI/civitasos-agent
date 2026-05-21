from __future__ import annotations

from pathlib import Path


def test_nightly_wrapper_wires_l1_pilot_contract_chain() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_nightly_regression.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert 'RUN_L1_PILOT_001_CONTRACT_CHAIN="${RUN_L1_PILOT_001_CONTRACT_CHAIN:-0}"' in text
    assert 'L1_PILOT_001_CONTRACT_ROOT="${L1_PILOT_001_CONTRACT_ROOT:-$RUNS_ROOT/l1_pilot_001_contract_runner}"' in text
    assert 'RUN_L1_REPAIR_AUDIT_PACKET_CHECK="${RUN_L1_REPAIR_AUDIT_PACKET_CHECK:-$RUN_L1_PILOT_001_CONTRACT_CHAIN}"' in text
    assert 'L1_REPAIR_AUDIT_PACKET_CHECK_ROOT="${L1_REPAIR_AUDIT_PACKET_CHECK_ROOT:-$RUNS_ROOT/l1_repair_audit_packet_check}"' in text
    assert 'RUN_BETA2_PATCH_REVIEW_OUTCOME_INDEX="${RUN_BETA2_PATCH_REVIEW_OUTCOME_INDEX:-0}"' in text
    assert 'BETA2_PATCH_REVIEW_OUTCOME_SUMMARY="${BETA2_PATCH_REVIEW_OUTCOME_SUMMARY:-$RUNS_ROOT/beta2_patch_review_outcome_summary.json}"' in text
    assert 'BETA2_PATCH_REVIEW_OUTCOME_INDEX_FILE="${BETA2_PATCH_REVIEW_OUTCOME_INDEX_FILE:-runs/beta2_patch_review_outcome_index.jsonl}"' in text
    assert 'BETA2_PATCH_REVIEW_OUTCOME_LATEST="${BETA2_PATCH_REVIEW_OUTCOME_LATEST:-runs/beta2_patch_review_outcome_latest.json}"' in text
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
    assert "wake_action_bias_pool_claim_count" in text
    assert "L1 nightly event wake hard gate requires wake action bias pool_claim" in text
    assert 'if [ "$RUN_L1_REPAIR_AUDIT_PACKET_CHECK" = "1" ]; then' in text
    assert "benchmarks/run_l1_repair_audit_packet_check.sh" in text
    assert 'if [ "$RUN_BETA2_PATCH_REVIEW_OUTCOME_INDEX" = "1" ]; then' in text
    assert "requires BETA2_PATCH_REVIEW_OUTCOME_RUN_ROOTS" in text
    assert 'scripts/beta2_patch_review_outcome.py "${BETA2_REVIEW_INDEX_ARGS[@]}"' in text


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


def test_l1_local_agent_check_supports_authenticated_llm_models_probe() -> None:
    wrapper = Path(__file__).resolve().parents[2] / "scripts" / "l1_pilot_001_local_agents.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "llm-openai-compatible-models" in text
    assert 'headers["Authorization"] = f"Bearer {bearer_token}"' in text
    assert '${LLM_API_KEY:-}' in text


def test_l1_contract_smoke_ci_check_protects_fail_fast_surface() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_l1_contract_smoke_ci_check.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "benchmarks/run_l1_contract_smoke.sh" in text
    assert "benchmarks/run_beta0_real_model_pilot.sh" in text
    assert "benchmarks/run_l1_contract_smoke_scheduled.sh" in text
    assert "benchmarks/run_l1_repair_audit_packet_check.sh" in text
    assert "benchmarks/run_nightly_regression.sh" in text
    assert "-u L1_PILOT_001_WAKE_CALLBACK_SECRET" in text
    assert "-u CIVITASOS_WAKE_CALLBACK_SECRET" in text
    assert "requires signed wake" in text
    assert "L1_PILOT_001_SERVICE_SCOPES=pool:read" in text
    assert "missing required scope: agents:read" in text
    assert "benchmarks/tests/test_l1_nightly_wrapper.py" in text
    assert "benchmarks/tests/test_l1_export_contract_audit_refs.py" in text
    assert "benchmarks/tests/test_l1_pilot_contract_runner.py" in text
    assert "benchmarks/tests/test_l1_pilot_contract_tasks.py" in text
    assert "RUN_L1_REPAIR_AUDIT_PACKET_CHECK" in text


def test_beta0_real_model_pilot_wrapper_enforces_external_model_and_strict_boundary() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_beta0_real_model_pilot.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "Beta-0 requires AGENT_LLM" in text
    assert "Beta-0 requires LLM_API_KEY" in text
    assert 'BETA0_REQUIRE_EXTERNAL_MODEL="${BETA0_REQUIRE_EXTERNAL_MODEL:-1}"' in text
    assert '[[ "$AGENT_LLM" == ollama:* ]]' in text
    assert 'LLM_BASE_URL must not point to local Ollama' in text
    assert "Beta-0 requires signed wake" in text
    assert "Beta-0 requires service-token auth" in text
    assert "benchmarks/run_l1_contract_smoke.sh" in text
    assert "benchmarks/run_l1_repair_audit_packet_check.sh" in text
    assert "beta0-real-model-pilot-summary:v1" in text
    assert "agent_llm" in text
    assert "beta0_real_model_pilot_does_not_claim_h3_production_readiness" in text


def test_l1_contract_smoke_scheduled_indexes_evidence() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "run_l1_contract_smoke_scheduled.sh"
    text = wrapper.read_text(encoding="utf-8")

    assert "curl -fsS \"$BACKEND_URL/healthz\"" in text
    assert "curl -fsS \"$LLM_BASE_URL/models\"" in text
    assert "Authorization: Bearer $LLM_API_KEY" in text
    assert "benchmarks/run_l1_contract_smoke.sh" in text
    assert "l1_contract_smoke_index.jsonl" in text
    assert "l1_contract_smoke_latest.json" in text
    assert "wake_event_counts" in text
    assert "rule_pool_claim_count" in text
    assert "wake_action_bias_pool_claim_count" in text
    assert "cannot index L1 event wake smoke without wake action bias evidence" in text
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
