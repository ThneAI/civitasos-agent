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
    assert 'RUN_BETA3_CONTROLLED_APPLY_CANDIDATE_CHECK="${RUN_BETA3_CONTROLLED_APPLY_CANDIDATE_CHECK:-0}"' in text
    assert 'BETA3_CONTROLLED_APPLY_CANDIDATE_REPORT="${BETA3_CONTROLLED_APPLY_CANDIDATE_REPORT:-$RUNS_ROOT/beta3_controlled_apply_candidate.json}"' in text
    assert 'RUN_BETA3_CONTROLLED_APPLY_SANDBOX_CHECK="${RUN_BETA3_CONTROLLED_APPLY_SANDBOX_CHECK:-0}"' in text
    assert 'BETA3_CONTROLLED_APPLY_SANDBOX_OUTPUT_ROOT="${BETA3_CONTROLLED_APPLY_SANDBOX_OUTPUT_ROOT:-$RUNS_ROOT/beta3_controlled_apply_sandbox}"' in text
    assert 'RUN_BETA3_POST_SANDBOX_RECEIPT_CHECK="${RUN_BETA3_POST_SANDBOX_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA3_MULTI_AGENT_REVIEW_PACKET_CHECK="${RUN_BETA3_MULTI_AGENT_REVIEW_PACKET_CHECK:-0}"' in text
    assert 'RUN_BETA3_SOURCE_APPLY_AUTHORIZATION_CHECK="${RUN_BETA3_SOURCE_APPLY_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA3_POST_SOURCE_APPLY_RECEIPT_CHECK="${RUN_BETA3_POST_SOURCE_APPLY_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA3_SOURCE_APPLY_OUTCOME_INDEX="${RUN_BETA3_SOURCE_APPLY_OUTCOME_INDEX:-0}"' in text
    assert 'BETA3_SOURCE_APPLY_OUTCOME_SUMMARY="${BETA3_SOURCE_APPLY_OUTCOME_SUMMARY:-$RUNS_ROOT/beta3_source_apply_outcome_summary.json}"' in text
    assert 'RUN_BETA3_GIT_PUBLICATION_AUTHORIZATION_CHECK="${RUN_BETA3_GIT_PUBLICATION_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA3_GIT_COMMIT_RECEIPT_CHECK="${RUN_BETA3_GIT_COMMIT_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA3_GIT_PUSH_AUTHORIZATION_CHECK="${RUN_BETA3_GIT_PUSH_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA3_GIT_PUSH_RECEIPT_CHECK="${RUN_BETA3_GIT_PUSH_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA3_GIT_MERGE_AUTHORIZATION_CHECK="${RUN_BETA3_GIT_MERGE_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA3_GIT_MERGE_RECEIPT_CHECK="${RUN_BETA3_GIT_MERGE_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA3_LOCAL_DEPLOY_AUTHORIZATION_CHECK="${RUN_BETA3_LOCAL_DEPLOY_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA3_LOCAL_DEPLOY_RECEIPT_CHECK="${RUN_BETA3_LOCAL_DEPLOY_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA4_DRAFT_PR_AUTHORIZATION_CHECK="${RUN_BETA4_DRAFT_PR_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA4_DRAFT_PR_RECEIPT_CHECK="${RUN_BETA4_DRAFT_PR_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA4_READY_PR_TRANSITION_AUTHORIZATION_CHECK="${RUN_BETA4_READY_PR_TRANSITION_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA4_READY_PR_TRANSITION_RECEIPT_CHECK="${RUN_BETA4_READY_PR_TRANSITION_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA4_PR_REVIEW_EVIDENCE_CHECK="${RUN_BETA4_PR_REVIEW_EVIDENCE_CHECK:-0}"' in text
    assert 'RUN_BETA4_READY_PR_REVIEW_EVIDENCE_CHECK="${RUN_BETA4_READY_PR_REVIEW_EVIDENCE_CHECK:-0}"' in text
    assert 'RUN_BETA5_POST_REVIEW_MERGE_AUTHORIZATION_CHECK="${RUN_BETA5_POST_REVIEW_MERGE_AUTHORIZATION_CHECK:-0}"' in text
    assert 'BETA5_POST_REVIEW_MERGE_RECONCILIATION_PATH="${BETA5_POST_REVIEW_MERGE_RECONCILIATION_PATH:-}"' in text
    assert 'RUN_BETA5_GITHUB_MERGE_PREFLIGHT_CHECK="${RUN_BETA5_GITHUB_MERGE_PREFLIGHT_CHECK:-0}"' in text
    assert 'RUN_BETA5_GITHUB_MERGE_RECEIPT_CHECK="${RUN_BETA5_GITHUB_MERGE_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA5_LOCAL_DEPLOY_AUTHORIZATION_CHECK="${RUN_BETA5_LOCAL_DEPLOY_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA5_LOCAL_DEPLOY_RECEIPT_CHECK="${RUN_BETA5_LOCAL_DEPLOY_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA5_EXTERNAL_DEPLOY_ENVIRONMENT_PROOF_CHECK="${RUN_BETA5_EXTERNAL_DEPLOY_ENVIRONMENT_PROOF_CHECK:-0}"' in text
    assert 'RUN_BETA5_EXTERNAL_DEPLOY_AUTHORIZATION_CHECK="${RUN_BETA5_EXTERNAL_DEPLOY_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA5_EXTERNAL_DEPLOY_RECEIPT_CHECK="${RUN_BETA5_EXTERNAL_DEPLOY_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA5_EXTERNAL_ROLLBACK_AUTHORIZATION_CHECK="${RUN_BETA5_EXTERNAL_ROLLBACK_AUTHORIZATION_CHECK:-0}"' in text
    assert 'RUN_BETA5_EXTERNAL_ROLLBACK_RECEIPT_CHECK="${RUN_BETA5_EXTERNAL_ROLLBACK_RECEIPT_CHECK:-0}"' in text
    assert 'RUN_BETA5_REPEATABLE_PREVIEW_ARTIFACT="${RUN_BETA5_REPEATABLE_PREVIEW_ARTIFACT:-0}"' in text
    assert 'BETA5_REPEATABLE_PREVIEW_RUN_ROOT="${BETA5_REPEATABLE_PREVIEW_RUN_ROOT:-$RUNS_ROOT/beta5_repeatable_preview}"' in text
    assert 'BETA5_REPEATABLE_PREVIEW_LOCAL_DEPLOY_RECEIPT_PATH="${BETA5_REPEATABLE_PREVIEW_LOCAL_DEPLOY_RECEIPT_PATH:-$BETA5_LOCAL_DEPLOY_RECEIPT_PATH}"' in text
    assert 'BETA5_REPEATABLE_PREVIEW_NODES="${BETA5_REPEATABLE_PREVIEW_NODES:-vm1,vm1,192.168.56.4 vm2,vm2,192.168.56.5 vm3,vm3,192.168.56.6}"' in text
    assert 'BETA5_REPEATABLE_PREVIEW_SUMMARY="${BETA5_REPEATABLE_PREVIEW_SUMMARY:-$RUNS_ROOT/beta5_repeatable_preview_summary.json}"' in text
    assert 'RUN_BETA5_OWNER_FEEDBACK_PACKET_CHECK="${RUN_BETA5_OWNER_FEEDBACK_PACKET_CHECK:-0}"' in text
    assert 'BETA5_OWNER_FEEDBACK_PACKET_VALIDATION_OUTPUT="${BETA5_OWNER_FEEDBACK_PACKET_VALIDATION_OUTPUT:-$RUNS_ROOT/beta5_owner_feedback_packet_validation.json}"' in text
    assert 'RUN_BETA5_OWNER_FEEDBACK_INDEX="${RUN_BETA5_OWNER_FEEDBACK_INDEX:-0}"' in text
    assert 'BETA5_OWNER_FEEDBACK_INDEX_PACKET_PATHS="${BETA5_OWNER_FEEDBACK_INDEX_PACKET_PATHS:-$BETA5_OWNER_FEEDBACK_PACKET_PATH}"' in text
    assert 'BETA5_OWNER_FEEDBACK_INDEX_OUTPUT="${BETA5_OWNER_FEEDBACK_INDEX_OUTPUT:-$RUNS_ROOT/beta5_owner_feedback_index.json}"' in text
    assert 'RUN_BETA6_EXTERNAL_AGENT_READINESS_CHECK="${RUN_BETA6_EXTERNAL_AGENT_READINESS_CHECK:-0}"' in text
    assert 'BETA6_EXTERNAL_AGENT_READINESS_FEEDBACK_INDEX="${BETA6_EXTERNAL_AGENT_READINESS_FEEDBACK_INDEX:-$BETA5_OWNER_FEEDBACK_INDEX_OUTPUT}"' in text
    assert 'BETA6_EXTERNAL_AGENT_READINESS_MIN_ACCEPTED_RATIO="${BETA6_EXTERNAL_AGENT_READINESS_MIN_ACCEPTED_RATIO:-0.5}"' in text
    assert 'RUN_BETA6_EXTERNAL_AGENT_INVITATION_CHECK="${RUN_BETA6_EXTERNAL_AGENT_INVITATION_CHECK:-0}"' in text
    assert 'RUN_BETA6_EXTERNAL_AGENT_REGISTRATION_CHECK="${RUN_BETA6_EXTERNAL_AGENT_REGISTRATION_CHECK:-0}"' in text
    assert 'RUN_BETA7_EXTERNAL_AGENT_TASK_INVITATION_CHECK="${RUN_BETA7_EXTERNAL_AGENT_TASK_INVITATION_CHECK:-0}"' in text
    assert 'RUN_BETA8_EXTERNAL_AGENT_REVIEW_RESPONSE_CHECK="${RUN_BETA8_EXTERNAL_AGENT_REVIEW_RESPONSE_CHECK:-0}"' in text
    assert 'RUN_BETA9_REVIEW_RECONCILIATION_CHECK="${RUN_BETA9_REVIEW_RECONCILIATION_CHECK:-0}"' in text
    assert 'RUN_BETA6_9_REAL_API_REVIEW_RUNNER="${RUN_BETA6_9_REAL_API_REVIEW_RUNNER:-0}"' in text
    assert 'BETA6_9_REAL_API_REVIEW_RUN_ROOT="${BETA6_9_REAL_API_REVIEW_RUN_ROOT:-$RUNS_ROOT/beta6_9_real_api_review}"' in text
    assert 'BETA6_9_REAL_API_REVIEW_ENV_FILE="${BETA6_9_REAL_API_REVIEW_ENV_FILE:-.env.beta6.external.local}"' in text
    assert 'BETA6_9_REAL_API_REVIEW_FEEDBACK_INDEX="${BETA6_9_REAL_API_REVIEW_FEEDBACK_INDEX:-$BETA6_EXTERNAL_AGENT_READINESS_FEEDBACK_INDEX}"' in text
    assert 'BETA6_9_REAL_API_REVIEW_PR_REVIEW_EVIDENCE="${BETA6_9_REAL_API_REVIEW_PR_REVIEW_EVIDENCE:-$BETA4_READY_PR_REVIEW_EVIDENCE_PATH}"' in text
    assert 'BETA6_9_REAL_API_REVIEW_PREVIEW_SUMMARY="${BETA6_9_REAL_API_REVIEW_PREVIEW_SUMMARY:-$BETA5_REPEATABLE_PREVIEW_SUMMARY}"' in text
    assert 'RUN_BETA_PREVIEW_CHAIN_RUNNER="${RUN_BETA_PREVIEW_CHAIN_RUNNER:-0}"' in text
    assert 'BETA_PREVIEW_CHAIN_RUN_ROOT="${BETA_PREVIEW_CHAIN_RUN_ROOT:-$RUNS_ROOT/beta_preview_chain}"' in text
    assert 'BETA_PREVIEW_CHAIN_ADDITIONAL_ENV_FILES="${BETA_PREVIEW_CHAIN_ADDITIONAL_ENV_FILES:-}"' in text
    assert 'BETA_PREVIEW_CHAIN_LOCAL_DEPLOY_RECEIPT="${BETA_PREVIEW_CHAIN_LOCAL_DEPLOY_RECEIPT:-$BETA5_REPEATABLE_PREVIEW_LOCAL_DEPLOY_RECEIPT_PATH}"' in text
    assert 'RUN_BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT="${RUN_BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT:-0}"' in text
    assert 'BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT_MIN_PROVIDERS="${BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT_MIN_PROVIDERS:-2}"' in text
    assert 'BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT_REQUIRE_DISTINCT_PROVIDERS="${BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT_REQUIRE_DISTINCT_PROVIDERS:-1}"' in text
    assert 'RUN_BETA_DEPLOYMENT_PREVIEW_READINESS_CHECK="${RUN_BETA_DEPLOYMENT_PREVIEW_READINESS_CHECK:-0}"' in text
    assert 'BETA_DEPLOYMENT_PREVIEW_READINESS_BETA6_9_SUMMARY="${BETA_DEPLOYMENT_PREVIEW_READINESS_BETA6_9_SUMMARY:-$BETA6_9_REAL_API_REVIEW_RUN_ROOT/beta6_9_real_api_review_summary.json}"' in text
    assert 'BETA_DEPLOYMENT_PREVIEW_READINESS_OWNER_FEEDBACK_INDEX="${BETA_DEPLOYMENT_PREVIEW_READINESS_OWNER_FEEDBACK_INDEX:-$BETA6_9_REAL_API_REVIEW_FEEDBACK_INDEX}"' in text
    assert 'BETA_DEPLOYMENT_PREVIEW_READINESS_MULTI_EXTERNAL_REVIEW="${BETA_DEPLOYMENT_PREVIEW_READINESS_MULTI_EXTERNAL_REVIEW:-}"' in text
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
    assert 'if [ "$RUN_BETA3_CONTROLLED_APPLY_CANDIDATE_CHECK" = "1" ]; then' in text
    assert "requires BETA3_CONTROLLED_APPLY_RUN_ROOT" in text
    assert "requires BETA3_CONTROLLED_APPLY_SELECTION_REASON" in text
    assert 'scripts/beta3_controlled_apply_candidate.py "${BETA3_CANDIDATE_ARGS[@]}"' in text
    assert 'if [ "$RUN_BETA3_CONTROLLED_APPLY_SANDBOX_CHECK" = "1" ]; then' in text
    assert "requires BETA3_CONTROLLED_APPLY_SANDBOX_CANDIDATE_REPORT" in text
    assert "scripts/beta3_controlled_apply_sandbox.py" in text
    assert 'if [ "$RUN_BETA3_POST_SANDBOX_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_POST_SANDBOX_RECEIPT_PATH" in text
    assert "scripts/beta3_post_sandbox_operator_receipt.py validate" in text
    assert 'if [ "$RUN_BETA3_MULTI_AGENT_REVIEW_PACKET_CHECK" = "1" ]; then' in text
    assert "requires BETA3_MULTI_AGENT_REVIEW_PACKET_PATH" in text
    assert "scripts/beta3_multi_agent_review_packet.py validate" in text
    assert 'if [ "$RUN_BETA3_SOURCE_APPLY_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA3_SOURCE_APPLY_AUTHORIZATION_PATH" in text
    assert "scripts/beta3_source_apply_authorization.py validate" in text
    assert 'if [ "$RUN_BETA3_POST_SOURCE_APPLY_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_POST_SOURCE_APPLY_RECEIPT_PATH" in text
    assert "scripts/beta3_source_apply_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA3_SOURCE_APPLY_OUTCOME_INDEX" = "1" ]; then' in text
    assert "requires BETA3_SOURCE_APPLY_EXECUTION_REPORTS" in text
    assert 'scripts/beta3_source_apply_outcome.py "${BETA3_SOURCE_APPLY_OUTCOME_ARGS[@]}"' in text
    assert 'if [ "$RUN_BETA3_GIT_PUBLICATION_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_PUBLICATION_AUTHORIZATION_PATH" in text
    assert "scripts/beta3_git_publication_authorization.py validate" in text
    assert 'if [ "$RUN_BETA3_GIT_COMMIT_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_COMMIT_RECEIPT_PATH" in text
    assert "scripts/beta3_git_commit_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA3_GIT_PUSH_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_PUSH_AUTHORIZATION_PATH" in text
    assert "scripts/beta3_git_push_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA3_GIT_PUSH_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_PUSH_RECEIPT_PATH" in text
    assert "scripts/beta3_git_push_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA3_GIT_MERGE_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_MERGE_AUTHORIZATION_PATH" in text
    assert "scripts/beta3_git_merge_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA3_GIT_MERGE_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_GIT_MERGE_RECEIPT_PATH" in text
    assert "scripts/beta3_git_merge_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA3_LOCAL_DEPLOY_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA3_LOCAL_DEPLOY_AUTHORIZATION_PATH" in text
    assert "scripts/beta3_local_deploy_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA3_LOCAL_DEPLOY_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA3_LOCAL_DEPLOY_RECEIPT_PATH" in text
    assert "scripts/beta3_local_deploy_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA4_DRAFT_PR_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA4_DRAFT_PR_AUTHORIZATION_PATH" in text
    assert "scripts/beta4_draft_pr_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA4_DRAFT_PR_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA4_DRAFT_PR_RECEIPT_PATH" in text
    assert "scripts/beta4_draft_pr_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA4_READY_PR_TRANSITION_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA4_READY_PR_TRANSITION_AUTHORIZATION_PATH" in text
    assert "scripts/beta4_ready_pr_transition_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA4_READY_PR_TRANSITION_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA4_READY_PR_TRANSITION_RECEIPT_PATH" in text
    assert "scripts/beta4_ready_pr_transition_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA4_PR_REVIEW_EVIDENCE_CHECK" = "1" ]; then' in text
    assert "requires BETA4_PR_REVIEW_EVIDENCE_PATH" in text
    assert "scripts/beta4_pr_review_evidence.py validate" in text
    assert 'if [ "$RUN_BETA4_READY_PR_REVIEW_EVIDENCE_CHECK" = "1" ]; then' in text
    assert "requires BETA4_READY_PR_REVIEW_EVIDENCE_PATH" in text
    assert "scripts/beta4_ready_pr_review_evidence.py validate" in text
    assert 'if [ "$RUN_BETA5_POST_REVIEW_MERGE_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA5_POST_REVIEW_MERGE_AUTHORIZATION_PATH" in text
    assert "scripts/beta5_post_review_merge_authorization.py validate" in text
    assert "BETA5_POST_REVIEW_MERGE_RECONCILIATION_PATH does not match" in text
    assert "authorization.source_review_reconciliation" in text
    assert 'if [ "$RUN_BETA5_GITHUB_MERGE_PREFLIGHT_CHECK" = "1" ]; then' in text
    assert "requires BETA5_GITHUB_MERGE_AUTHORIZATION_PATH" in text
    assert "scripts/beta5_github_merge_executor.py preflight" in text
    assert 'if [ "$RUN_BETA5_GITHUB_MERGE_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA5_GITHUB_MERGE_RECEIPT_PATH" in text
    assert "scripts/beta5_github_merge_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA5_LOCAL_DEPLOY_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA5_LOCAL_DEPLOY_AUTHORIZATION_PATH" in text
    assert "scripts/beta5_local_controlled_deploy_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA5_LOCAL_DEPLOY_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA5_LOCAL_DEPLOY_RECEIPT_PATH" in text
    assert "scripts/beta5_local_controlled_deploy_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA5_EXTERNAL_DEPLOY_ENVIRONMENT_PROOF_CHECK" = "1" ]; then' in text
    assert "requires BETA5_EXTERNAL_DEPLOY_ENVIRONMENT_PROOF_PATH" in text
    assert "scripts/beta5_external_deploy_evidence_executor.py validate-environment-proof" in text
    assert 'if [ "$RUN_BETA5_EXTERNAL_DEPLOY_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA5_EXTERNAL_DEPLOY_AUTHORIZATION_PATH" in text
    assert "scripts/beta5_external_deploy_evidence_executor.py validate-authorization" in text
    assert 'if [ "$RUN_BETA5_EXTERNAL_DEPLOY_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA5_EXTERNAL_DEPLOY_RECEIPT_PATH" in text
    assert "scripts/beta5_external_deploy_evidence_executor.py validate-receipt" in text
    assert 'if [ "$RUN_BETA5_EXTERNAL_ROLLBACK_AUTHORIZATION_CHECK" = "1" ]; then' in text
    assert "requires BETA5_EXTERNAL_ROLLBACK_AUTHORIZATION_PATH" in text
    assert "scripts/beta5_external_deploy_rollback_drill.py validate-authorization" in text
    assert 'if [ "$RUN_BETA5_EXTERNAL_ROLLBACK_RECEIPT_CHECK" = "1" ]; then' in text
    assert "requires BETA5_EXTERNAL_ROLLBACK_RECEIPT_PATH" in text
    assert "scripts/beta5_external_deploy_rollback_drill.py validate-receipt" in text
    assert 'if [ "$RUN_BETA5_REPEATABLE_PREVIEW_ARTIFACT" = "1" ]; then' in text
    assert "requires BETA5_REPEATABLE_PREVIEW_LOCAL_DEPLOY_RECEIPT_PATH or BETA5_LOCAL_DEPLOY_RECEIPT_PATH" in text
    assert 'scripts/beta5_real_multivm_preview_prepare.py "${BETA5_REPEATABLE_PREVIEW_PREPARE_ARGS[@]}"' in text
    assert '"$BETA5_REPEATABLE_PREVIEW_RUN_ROOT/operator_commands.sh"' in text
    assert '"schema_version": "beta5-repeatable-preview-nightly-artifact:v1"' in text
    assert '"external_environment_provider": "virtualbox"' in text
    assert 'if [ "$RUN_BETA5_OWNER_FEEDBACK_PACKET_CHECK" = "1" ]; then' in text
    assert "requires BETA5_OWNER_FEEDBACK_PACKET_PATH" in text
    assert "scripts/beta5_owner_feedback_packet.py validate" in text
    assert '--output "$BETA5_OWNER_FEEDBACK_PACKET_VALIDATION_OUTPUT"' in text
    assert 'if [ "$RUN_BETA5_OWNER_FEEDBACK_INDEX" = "1" ]; then' in text
    assert '--min-packets "$BETA5_OWNER_FEEDBACK_INDEX_MIN_PACKETS"' in text
    assert "scripts/beta5_owner_feedback_packet.py index" in text
    assert 'if [ "$RUN_BETA6_EXTERNAL_AGENT_READINESS_CHECK" = "1" ]; then' in text
    assert "scripts/beta6_external_agent_onboarding.py validate-readiness" in text
    assert '--feedback-index "$BETA6_EXTERNAL_AGENT_READINESS_FEEDBACK_INDEX"' in text
    assert '--min-accepted-ratio "$BETA6_EXTERNAL_AGENT_READINESS_MIN_ACCEPTED_RATIO"' in text
    assert 'if [ "$RUN_BETA6_EXTERNAL_AGENT_INVITATION_CHECK" = "1" ]; then' in text
    assert "requires BETA6_EXTERNAL_AGENT_INVITATION_PATH" in text
    assert "scripts/beta6_external_agent_onboarding.py validate-invitation" in text
    assert 'if [ "$RUN_BETA6_EXTERNAL_AGENT_REGISTRATION_CHECK" = "1" ]; then' in text
    assert "requires BETA6_EXTERNAL_AGENT_REGISTRATION_PATH" in text
    assert "scripts/beta6_external_agent_onboarding.py validate-registration" in text
    assert 'if [ "$RUN_BETA7_EXTERNAL_AGENT_TASK_INVITATION_CHECK" = "1" ]; then' in text
    assert "requires BETA7_EXTERNAL_AGENT_TASK_INVITATION_PATH" in text
    assert "scripts/beta7_external_agent_task_invitation.py validate" in text
    assert 'if [ "$RUN_BETA8_EXTERNAL_AGENT_REVIEW_RESPONSE_CHECK" = "1" ]; then' in text
    assert "requires BETA8_EXTERNAL_AGENT_REVIEW_RESPONSE_PATH" in text
    assert "scripts/beta8_external_agent_review_response.py validate" in text
    assert 'if [ "$RUN_BETA9_REVIEW_RECONCILIATION_CHECK" = "1" ]; then' in text
    assert "requires BETA9_REVIEW_RECONCILIATION_PATH" in text
    assert "scripts/beta9_review_reconciliation.py validate" in text
    assert 'if [ "$RUN_BETA6_9_REAL_API_REVIEW_RUNNER" = "1" ]; then' in text
    assert "requires BETA6_9_REAL_API_REVIEW_PR_REVIEW_EVIDENCE" in text
    assert "scripts/beta6_9_real_api_review_runner.py" in text
    assert '--model-max-tokens "$BETA6_9_REAL_API_REVIEW_MODEL_MAX_TOKENS"' in text
    assert 'if [ "$RUN_BETA_EXTERNAL_PROVIDER_ENV_PREFLIGHT" = "1" ]; then' in text
    assert "scripts/beta_external_provider_env_preflight.py" in text
    assert '--env-file "$provider_env_file"' in text
    assert 'if [ "$RUN_BETA_PREVIEW_CHAIN_RUNNER" = "1" ]; then' in text
    assert "requires BETA_PREVIEW_CHAIN_LOCAL_DEPLOY_RECEIPT" in text
    assert "scripts/beta_preview_chain_runner.py" in text
    assert '--additional-env-file "$additional_env_file"' in text
    assert '--previous-owner-feedback-packet "$previous_packet"' in text
    assert 'if [ "$RUN_BETA_DEPLOYMENT_PREVIEW_READINESS_CHECK" = "1" ]; then' in text
    assert "scripts/beta_deployment_preview_readiness.py" in text
    assert '--multi-external-review "$BETA_DEPLOYMENT_PREVIEW_READINESS_MULTI_EXTERNAL_REVIEW"' in text
    assert '--min-owner-feedback-packets "$BETA_DEPLOYMENT_PREVIEW_READINESS_MIN_OWNER_FEEDBACK_PACKETS"' in text


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
    assert "benchmarks/tests/test_beta_deployment_preview_readiness.py" in text
    assert "benchmarks/tests/test_beta_external_provider_env_preflight.py" in text
    assert "benchmarks/tests/test_beta_multi_external_review_reconciliation.py" in text
    assert "benchmarks/tests/test_beta_preview_chain_runner.py" in text
    assert "benchmarks/tests/test_beta6_9_real_api_review_runner.py" in text
    assert "benchmarks/run_l1_contract_smoke_scheduled.sh" in text
    assert "benchmarks/run_l1_repair_audit_packet_check.sh" in text
    assert "benchmarks/run_nightly_regression.sh" in text
    assert "-u L1_PILOT_001_WAKE_CALLBACK_SECRET" in text
    assert "-u CIVITASOS_WAKE_CALLBACK_SECRET" in text
    assert "requires signed wake" in text
    assert "L1_PILOT_001_SERVICE_SCOPES=pool:read" in text
    assert "missing required scope: agents:read" in text
    assert "benchmarks/tests/test_l1_nightly_wrapper.py" in text
    assert "benchmarks/tests/test_beta3_controlled_apply_candidate.py" in text
    assert "benchmarks/tests/test_beta3_controlled_apply_sandbox.py" in text
    assert "benchmarks/tests/test_beta3_git_commit_executor.py" in text
    assert "benchmarks/tests/test_beta3_git_merge_executor.py" in text
    assert "benchmarks/tests/test_beta3_git_push_executor.py" in text
    assert "benchmarks/tests/test_beta3_git_publication_authorization.py" in text
    assert "benchmarks/tests/test_beta3_local_deploy_executor.py" in text
    assert "benchmarks/tests/test_beta3_multi_agent_review_packet.py" in text
    assert "benchmarks/tests/test_beta3_post_sandbox_operator_receipt.py" in text
    assert "benchmarks/tests/test_beta3_real_multi_agent_review_runner.py" in text
    assert "benchmarks/tests/test_beta3_source_apply_authorization.py" in text
    assert "benchmarks/tests/test_beta3_source_apply_executor.py" in text
    assert "benchmarks/tests/test_beta3_source_apply_outcome.py" in text
    assert "benchmarks/tests/test_beta4_draft_pr_executor.py" in text
    assert "benchmarks/tests/test_beta4_pr_review_evidence.py" in text
    assert "benchmarks/tests/test_beta4_ready_pr_transition_executor.py" in text
    assert "benchmarks/tests/test_beta4_ready_pr_review_evidence.py" in text
    assert "benchmarks/tests/test_beta5_post_review_merge_authorization.py" in text
    assert "benchmarks/tests/test_beta5_github_merge_executor.py" in text
    assert "benchmarks/tests/test_beta5_local_controlled_deploy_executor.py" in text
    assert "benchmarks/tests/test_beta5_external_deploy_evidence_executor.py" in text
    assert "benchmarks/tests/test_beta5_owner_feedback_packet.py" in text
    assert "benchmarks/tests/test_beta5_external_deploy_rollback_drill.py" in text
    assert "benchmarks/tests/test_beta6_external_agent_onboarding.py" in text
    assert "benchmarks/tests/test_beta7_external_agent_task_invitation.py" in text
    assert "benchmarks/tests/test_beta8_external_agent_review_response.py" in text
    assert "benchmarks/tests/test_beta9_review_reconciliation.py" in text
    assert "benchmarks/tests/test_beta_approval_sandbox_observation.py" in text
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
