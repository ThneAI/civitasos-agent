"""Live adapter for strict outcome-sensitive participant decisions."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1_qualification_outcome_sensitive_participant_runner import (
    INPUT_SCHEMA,
    validate_output_envelope,
)

from .controlled_comparison import canonical_sha256
from .qualification_container_runner_v4 import ParticipantContainerClient
from .qualification_live_adapter_v4 import (
    LiveExecutionAdapter,
    PrivateEvidenceStore,
)


@dataclass(frozen=True)
class OutcomeLiveMaterials:
    run_id: str
    authorization_id: str
    authorization_sha256: str
    fixtures: dict[str, dict[str, Any]]
    signed_advice: dict[str, dict[str, Any]]
    assignment_commitments: dict[str, str]
    reviewed_assignment: dict[str, Any]
    reviewed_assignment_raw_sha256: str


class OutcomeSensitiveLiveExecutionAdapter(LiveExecutionAdapter):
    """Join reviewed IPC, provider, PKCS#11, and direct-observation boundaries."""

    materials: OutcomeLiveMaterials

    def __init__(
        self,
        *,
        materials: OutcomeLiveMaterials,
        containers: ParticipantContainerClient,
        provider: Any,
        signer: Any,
        evidence_root: Path,
    ) -> None:
        super().__init__(
            materials=materials,
            containers=containers,
            provider=provider,
            signer=signer,
            evidence_root=evidence_root,
        )
        self.evidence = PrivateEvidenceStore(evidence_root)

    def finalize_decision(
        self,
        task: dict[str, Any],
        response: dict[str, Any],
    ) -> dict[str, Any]:
        task_id = task["task_execution_id"]
        receipt = response["provider_receipt"]
        decision_content = response["content"]
        envelope = self._envelope(
            task,
            operation="finalize_provider_response",
            provider_response={
                "provider_request_sha256": response[
                    "provider_request_sha256"
                ],
                "provider_receipt_sha256": receipt["receipt_sha256"],
                "decision": decision_content,
                "decision_sha256": hashlib.sha256(
                    decision_content.encode()
                ).hexdigest(),
            },
        )
        output = self.containers.exchange(task, envelope)
        self._validate_runner_output(output, envelope)
        self._runner_outputs[task_id].append(output)
        participant_decision = output["participant_decision"]
        return {
            "schema_version": "j1-qualification-structured-decision:v1",
            "run_id": self.materials.run_id,
            "task_execution_id": task_id,
            "call_id": task["call_id"],
            "participant_id": task["participant_id"],
            "participant_did": task["execution_did"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "task_id": task["task"]["task_id"],
            "task_ordinal": task["task"]["task_ordinal"],
            "phase": task["task"]["phase"],
            "selected_action_id": participant_decision[
                "selected_action_id"
            ],
            "predicted_pattern_ids": participant_decision[
                "predicted_pattern_ids"
            ],
            "provider_receipt_sha256": participant_decision[
                "provider_receipt_sha256"
            ],
            "decision_content_sha256": participant_decision[
                "decision_sha256"
            ],
            "first_process_instance_id": response[
                "host_process_instance_id"
            ],
            "final_process_instance_id": output["process_instance_id"],
            "fixture_ground_truth_available": False,
            "verifier_assertions": None,
        }

    def sign_decision(
        self,
        task: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "run_id": self.materials.run_id,
            "execution_authorization_sha256": (
                self.materials.authorization_sha256
            ),
            "task_execution_id": task["task_execution_id"],
            "call_id": task["call_id"],
            "participant_id": task["participant_id"],
            "execution_did": task["execution_did"],
            "credential_version": task["credential_version"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "task_id": task["task"]["task_id"],
            "task_ordinal": task["task"]["task_ordinal"],
            "prompt_sha256": task["task"]["prompt_sha256"],
            "ground_truth_commitment_sha256": task["task"][
                "ground_truth_commitment_sha256"
            ],
            "signed_advice_canonical_sha256_or_null": (
                task["advice"]["canonical_sha256"]
                if task["advice"]["mode"] == "mentor_signed"
                else None
            ),
            "provider_receipt_sha256": decision[
                "provider_receipt_sha256"
            ],
            "structured_decision_sha256": canonical_sha256(decision),
        }
        encoded = _canonical_bytes(payload)
        signature = self.signer.sign(
            participant_id=task["participant_id"],
            payload=encoded,
        )
        if not self.signer.verify(
            participant_id=task["participant_id"],
            payload=encoded,
            signature=signature,
        ):
            raise ValueError(
                "outcome participant decision signature verification failed"
            )
        value = {
            "schema_version": (
                "j1-qualification-outcome-sensitive-decision-signature:v1"
            ),
            "algorithm": "ed25519",
            "participant_id": task["participant_id"],
            "execution_did": task["execution_did"],
            "signed_payload": payload,
            "signed_payload_sha256": hashlib.sha256(encoded).hexdigest(),
            "signature_hex": signature.hex(),
            "signature_verified": True,
        }
        value["signature_receipt_sha256"] = canonical_sha256(value)
        self._signatures[task["task_execution_id"]] = value
        self.participant_signatures += 1
        return value

    def verify_event_trace(
        self,
        task: dict[str, Any],
        decision: dict[str, Any],
        signature: dict[str, Any],
    ) -> dict[str, Any]:
        if not (
            decision["selected_action_id"]
            in task["task"]["allowed_action_ids"]
            and len(decision["predicted_pattern_ids"])
            == len(set(decision["predicted_pattern_ids"]))
            and all(
                item in task["task"]["allowed_pattern_ids"]
                for item in decision["predicted_pattern_ids"]
            )
            and signature["signature_verified"] is True
        ):
            raise ValueError(
                "outcome direct behavior observation validation failed"
            )
        observation = {
            "schema_version": (
                "j1-qualification-direct-behavior-observation:v1"
            ),
            "run_id": self.materials.run_id,
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "task_id": task["task"]["task_id"],
            "task_ordinal": task["task"]["task_ordinal"],
            "phase": task["task"]["phase"],
            "prompt_sha256": task["task"]["prompt_sha256"],
            "ground_truth_commitment_sha256": task["task"][
                "ground_truth_commitment_sha256"
            ],
            "selected_action_id": decision["selected_action_id"],
            "predicted_pattern_ids": decision["predicted_pattern_ids"],
            "provider_receipt_sha256": decision[
                "provider_receipt_sha256"
            ],
            "participant_signature_sha256": signature[
                "signature_receipt_sha256"
            ],
            "first_process_instance_id": decision[
                "first_process_instance_id"
            ],
            "final_process_instance_id": decision[
                "final_process_instance_id"
            ],
            "deterministic_verifier": task["task"][
                "deterministic_verifier"
            ],
            "ground_truth_revealed": False,
            "effectiveness_scored": False,
            "verified": True,
        }
        receipt = {
            "schema_version": (
                "j1-qualification-direct-observation-receipt-projection:v1"
            ),
            "task_execution_id": task["task_execution_id"],
            "observation_sha256": canonical_sha256(observation),
            "fixture_commitment_sha256": task["task"][
                "ground_truth_commitment_sha256"
            ],
            "raw_ground_truth_persisted": False,
            "backend_fact_appended": False,
            "ledger_appended": False,
        }
        receipt["receipt_sha256"] = canonical_sha256(receipt)
        self._event_receipts[task["task_execution_id"]] = [receipt]
        return observation

    def commit_task_evidence(
        self,
        task: dict[str, Any],
        artifacts: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        provider_receipt = artifacts["response"]["provider_receipt"]
        values: dict[str, Any] = {
            "provider-receipt": provider_receipt,
            "structured-decision": artifacts["decision"],
            "participant-signature": artifacts["signature"],
            "direct-observation": artifacts["event_trace"],
            "observation-receipts": artifacts["event_receipts"]["receipts"],
            "task-verification": {
                "schema_version": (
                    "j1-qualification-outcome-sensitive-task-verification:v1"
                ),
                "task_execution_id": task["task_execution_id"],
                "passed": True,
                "failure_reasons": [],
                "strict_decision_verified": True,
                "direct_observation_verified": True,
                "ground_truth_revealed": False,
                "effectiveness_scored": False,
            },
        }
        if _contains_ground_truth(values):
            raise ValueError(
                "outcome terminal Evidence contains fixture ground truth"
            )
        return self.evidence.commit(task["task_execution_id"], values)

    def execution_boundary(self) -> dict[str, Any]:
        return {
            **super().execution_boundary(),
            "strict_structured_decision_enforced": True,
            "direct_behavior_observation_recorded": (
                self.participant_signatures > 0
            ),
            "fixture_ground_truth_revealed": False,
            "effectiveness_scored_during_execution": False,
            "si13_maturity_upgrade_authorized": False,
        }

    def _envelope(
        self,
        task: dict[str, Any],
        *,
        operation: str,
        provider_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        fixture = self._fixture(task)
        advice = self._advice(task)
        return {
            "schema_version": INPUT_SCHEMA,
            "operation": operation,
            "run_id": self.materials.run_id,
            "participant": {
                "participant_id": task["participant_id"],
                "execution_did": task["execution_did"],
                "credential_version": task["credential_version"],
                "pair_id": task["pair_id"],
                "cohort": task["cohort"],
                "assignment_commitment_sha256": (
                    self.materials.assignment_commitments[
                        task["participant_id"]
                    ]
                ),
            },
            "task": {
                "task_id": fixture["task_id"],
                "task_ordinal": fixture["task_ordinal"],
                "phase": fixture["phase"],
                "prompt": fixture["prompt"],
                "prompt_sha256": fixture["prompt_sha256"],
                "ground_truth_commitment_sha256": fixture[
                    "ground_truth_commitment_sha256"
                ],
                "allowed_action_ids": fixture["allowed_action_ids"],
                "allowed_pattern_ids": fixture["allowed_pattern_ids"],
                "advice_mode": task["advice"]["mode"],
            },
            "advice_projection": advice,
            "authorization": {
                "authorization_id": self.materials.authorization_id,
                "artifact_sha256": self.materials.authorization_sha256,
            },
            "ipc": {
                "request_id": (
                    f"{task['task_execution_id']}:{operation}"
                ),
                "nonce": secrets.token_hex(32),
                "created_at": datetime.now(UTC).isoformat(),
            },
            "provider_response": provider_response,
        }

    def _advice(self, task: dict[str, Any]) -> dict[str, Any] | None:
        if task["advice"]["mode"] != "mentor_signed":
            return None
        source = self.materials.signed_advice[
            task["advice"]["advice_id"]
        ]
        value = source["value"]
        advice = value["advice"]
        if not (
            source["raw_sha256"] == task["advice"]["sha256"]
            and value["signed_advice_sha256"]
            == task["advice"]["canonical_sha256"]
            and value["recipient"]["participant_id"]
            == task["participant_id"]
            and value["task"]["task_id"] == task["task"]["task_id"]
            and value["task"]["task_ordinal"]
            == task["task"]["task_ordinal"]
        ):
            raise ValueError(
                "outcome signed advice artifact binding mismatch"
            )
        return {
            "advice_id": task["advice"]["advice_id"],
            "artifact_sha256": source["raw_sha256"],
            "canonical_sha256": value["signed_advice_sha256"],
            "text": advice["text"],
            "visibility": advice["visibility"],
            "authority": advice["authority"],
            "may_execute_for_participant": advice[
                "may_execute_for_participant"
            ],
            "may_override_constitution": advice[
                "may_override_constitution"
            ],
        }

    def _fixture(self, task: dict[str, Any]) -> dict[str, Any]:
        fixture = self.materials.fixtures[task["task"]["task_id"]]
        if not (
            fixture["task_ordinal"] == task["task"]["task_ordinal"]
            and fixture["phase"] == task["task"]["phase"]
            and fixture["prompt_sha256"] == task["task"]["prompt_sha256"]
            and fixture["ground_truth_commitment_sha256"]
            == task["task"]["ground_truth_commitment_sha256"]
            and fixture["allowed_action_ids"]
            == task["task"]["allowed_action_ids"]
            and fixture["allowed_pattern_ids"]
            == task["task"]["allowed_pattern_ids"]
        ):
            raise ValueError("outcome task fixture binding mismatch")
        return fixture

    @staticmethod
    def _validate_runner_output(
        output: dict[str, Any],
        envelope: dict[str, Any],
    ) -> None:
        failures = validate_output_envelope(output, source=envelope)
        if failures:
            raise ValueError(
                f"outcome participant runner output invalid: {failures}"
            )


def load_outcome_live_materials(
    *,
    run_id: str,
    authorization_id: str,
    authorization_path: Path,
    task_fixture_path: Path,
    signed_advice_root: Path,
    reviewed_assignment_path: Path,
) -> OutcomeLiveMaterials:
    authorization_sha256 = hashlib.sha256(
        authorization_path.read_bytes()
    ).hexdigest()
    fixture_manifest = _read(task_fixture_path)
    fixtures = {
        item["task_id"]: item
        for item in fixture_manifest.get("fixtures", [])
    }
    if len(fixtures) != 12:
        raise ValueError("outcome fixture inventory must contain 12 tasks")
    advice: dict[str, dict[str, Any]] = {}
    for path in sorted(signed_advice_root.glob("*.json")):
        raw = path.read_bytes()
        value = json.loads(raw)
        advice[value["advice_id"]] = {
            "value": value,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }
    if len(advice) != 180:
        raise ValueError("outcome signed advice inventory must contain 180 items")
    assignment_raw = reviewed_assignment_path.read_bytes()
    assignment = json.loads(assignment_raw)
    commitments = {
        member["participant_id"]: pair["rebind_commitment_sha256"]
        for pair in assignment["assignments"]
        for member in (pair["mentor"], pair["control"])
    }
    if len(commitments) != 40:
        raise ValueError("outcome assignment must bind 40 participants")
    return OutcomeLiveMaterials(
        run_id=run_id,
        authorization_id=authorization_id,
        authorization_sha256=authorization_sha256,
        fixtures=fixtures,
        signed_advice=advice,
        assignment_commitments=commitments,
        reviewed_assignment=assignment,
        reviewed_assignment_raw_sha256=hashlib.sha256(
            assignment_raw
        ).hexdigest(),
    )


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"outcome live material is not an object: {path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _contains_ground_truth(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            key == "ground_truth" or _contains_ground_truth(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_ground_truth(item) for item in value)
    return False
