"""Live J1-D adapter joining container IPC, provider, signer, and Evidence."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from benchmarks.j1_qualification_participant_runner import (
    INPUT_SCHEMA,
    validate_output_envelope,
)

from .controlled_comparison import canonical_sha256
from .qualification_container_runner_v4 import ParticipantContainerClient
from .qualification_live_evidence_v4 import build_live_trace, build_task_evidence
from .qualification_provider_broker import sanitized_provider_failure
from .qualification_verifier import verify_task


class Provider(Protocol):
    def call(
        self, *, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]: ...


class ParticipantSigner(Protocol):
    def sign(self, *, participant_id: str, payload: bytes) -> bytes: ...

    def verify(
        self, *, participant_id: str, payload: bytes, signature: bytes
    ) -> bool: ...


@dataclass(frozen=True)
class LiveMaterials:
    run_id: str
    authorization_id: str
    authorization_sha256: str
    task_inputs: dict[str, dict[str, Any]]
    signed_advice: dict[str, dict[str, Any]]
    assignment_commitments: dict[str, str]
    reviewed_assignment: dict[str, Any]
    reviewed_assignment_raw: bytes

    @property
    def reviewed_assignment_sha256(self) -> str:
        return str(
            self.reviewed_assignment.get("reviewed_rebound_assignment_sha256")
            or self.reviewed_assignment["reviewed_assignment_sha256"]
        )

    @property
    def reviewed_assignment_raw_sha256(self) -> str:
        return hashlib.sha256(self.reviewed_assignment_raw).hexdigest()


class LiveExecutionAdapter:
    def __init__(
        self,
        *,
        materials: LiveMaterials,
        containers: ParticipantContainerClient,
        provider: Provider,
        signer: ParticipantSigner,
        evidence_root: Path,
    ) -> None:
        self.materials = materials
        self.containers = containers
        self.provider = provider
        self.signer = signer
        self.evidence = PrivateEvidenceStore(evidence_root)
        self.provider_calls = 0
        self.participant_signatures = 0
        self._envelopes: dict[str, dict[str, Any]] = {}
        self._runner_outputs: dict[str, list[dict[str, Any]]] = {}
        self._provider_results: dict[str, dict[str, Any]] = {}
        self._signatures: dict[str, dict[str, Any]] = {}
        self._event_receipts: dict[str, list[dict[str, Any]]] = {}

    @property
    def container_starts(self) -> int:
        return self.containers.start_count

    @property
    def container_stops(self) -> int:
        return self.containers.stop_count

    def start_container(self, task: dict[str, Any]) -> dict[str, Any]:
        envelope = self._envelope(task, operation="prepare_provider_request")
        output = self.containers.start(task, envelope)
        self._validate_runner_output(output, envelope)
        task_id = task["task_execution_id"]
        self._envelopes[task_id] = envelope
        self._runner_outputs[task_id] = [output]
        return {
            "container_name": task["container"]["container_name"],
            "process_instance_id": output["process_instance_id"],
            "real_container_started": True,
        }

    def stop_container(self, task: dict[str, Any]) -> None:
        self.containers.stop(task)

    def prepare_request(self, task: dict[str, Any]) -> dict[str, Any]:
        output = self._runner_outputs[task["task_execution_id"]][0]
        return {
            **output["provider_request"],
            "host_process_instance_id": output["process_instance_id"],
        }

    def provider_call(
        self, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]:
        self.provider_calls += 1
        result = self.provider.call(task=task, request=request)
        if not (
            isinstance(result.get("decision"), str)
            and result["decision"]
            and isinstance(result.get("receipt"), dict)
            and isinstance(result.get("usage"), dict)
            and result["receipt"].get("receipt_sha256")
            == canonical_sha256(
                {
                    key: item
                    for key, item in result["receipt"].items()
                    if key != "receipt_sha256"
                }
            )
        ):
            raise sanitized_provider_failure(
                category="schema",
                stage="broker_result_shape",
                source_exception_type="LiveProviderResultValidationError",
            )
        self._provider_results[task["task_execution_id"]] = result
        return {
            "content": result["decision"],
            "provider_receipt": result["receipt"],
            "usage": result["usage"],
            "host_process_instance_id": request["host_process_instance_id"],
            "provider_request_sha256": canonical_sha256(
                {
                    key: item
                    for key, item in request.items()
                    if key != "host_process_instance_id"
                }
            ),
        }

    def finalize_decision(
        self, task: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        task_id = task["task_execution_id"]
        receipt = response["provider_receipt"]
        decision = response["content"]
        envelope = self._envelope(
            task,
            operation="finalize_provider_response",
            provider_response={
                "provider_request_sha256": response["provider_request_sha256"],
                "provider_receipt_sha256": receipt["receipt_sha256"],
                "decision": decision,
                "decision_sha256": hashlib.sha256(decision.encode()).hexdigest(),
            },
        )
        if "runtime_restarted" in task["task"]["event_script"]:
            output = self.containers.restart(task, envelope)
        else:
            output = self.containers.exchange(task, envelope)
        self._validate_runner_output(output, envelope)
        self._runner_outputs[task_id].append(output)
        participant_decision = output["participant_decision"]
        return {
            "schema_version": "j1-qualification-participant-decision:v2",
            "run_id": self.materials.run_id,
            "task_execution_id": task_id,
            "call_id": task["call_id"],
            "participant_id": task["participant_id"],
            "participant_did": task["execution_did"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "first_process_instance_id": response["host_process_instance_id"],
            "final_process_instance_id": output["process_instance_id"],
            **participant_decision,
        }

    def sign_decision(
        self, task: dict[str, Any], decision: dict[str, Any]
    ) -> dict[str, Any]:
        task_id = task["task_execution_id"]
        payload = {
            "run_id": self.materials.run_id,
            "execution_authorization_sha256": self.materials.authorization_sha256,
            "task_execution_id": task_id,
            "call_id": task["call_id"],
            "participant_id": task["participant_id"],
            "execution_did": task["execution_did"],
            "credential_version": task["credential_version"],
            "pair_id": task["pair_id"],
            "cohort": task["cohort"],
            "task_id": task["task"]["task_id"],
            "task_input_sha256": task["task"]["task_input_sha256"],
            "signed_advice_canonical_sha256_or_null": (
                task["advice"]["canonical_sha256"]
                if task["advice"]["mode"] == "mentor_signed"
                else None
            ),
            "provider_receipt_sha256": decision["provider_receipt_sha256"],
            "decision_sha256": decision["decision_sha256"],
        }
        encoded = _canonical_bytes(payload)
        signature = self.signer.sign(
            participant_id=task["participant_id"], payload=encoded
        )
        if not self.signer.verify(
            participant_id=task["participant_id"],
            payload=encoded,
            signature=signature,
        ):
            raise ValueError("participant decision signature verification failed")
        value = {
            "schema_version": "j1-qualification-participant-decision-signature:v2",
            "algorithm": "ed25519",
            "participant_id": task["participant_id"],
            "execution_did": task["execution_did"],
            "signed_payload": payload,
            "signed_payload_sha256": hashlib.sha256(encoded).hexdigest(),
            "signature_hex": signature.hex(),
            "signature_verified": True,
        }
        value["signature_receipt_sha256"] = canonical_sha256(value)
        self._signatures[task_id] = value
        self.participant_signatures += 1
        return value

    def verify_event_trace(
        self,
        task: dict[str, Any],
        decision: dict[str, Any],
        signature: dict[str, Any],
    ) -> dict[str, Any]:
        task_id = task["task_execution_id"]
        receipts, trace = build_live_trace(
            run_id=self.materials.run_id,
            authorization_sha256=self.materials.authorization_sha256,
            task=task,
            decision_sha256=canonical_sha256(decision),
            signature_sha256=signature["signature_receipt_sha256"],
            provider_receipt_sha256=decision["provider_receipt_sha256"],
            first_process_instance_id=decision["first_process_instance_id"],
            final_process_instance_id=decision["final_process_instance_id"],
        )
        self._event_receipts[task_id] = receipts
        return trace

    def event_receipts(self, task: dict[str, Any]) -> dict[str, Any]:
        return {"receipts": self._event_receipts[task["task_execution_id"]]}

    def commit_task_evidence(
        self, task: dict[str, Any], artifacts: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        task_id = task["task_execution_id"]
        provider = artifacts["response"]["provider_receipt"]
        signature = artifacts["signature"]
        receipts = artifacts["event_receipts"]["receipts"]
        trace = artifacts["event_trace"]
        task_evidence = build_task_evidence(
            task=task,
            authorization_sha256=self.materials.authorization_sha256,
            reviewed_assignment_raw_sha256=(
                self.materials.reviewed_assignment_raw_sha256
            ),
            assignment_commitment_sha256=self.materials.assignment_commitments[
                task["participant_id"]
            ],
            provider_receipt_sha256=provider["receipt_sha256"],
            decision_sha256=canonical_sha256(artifacts["decision"]),
            signature_sha256=signature["signature_receipt_sha256"],
            receipts=receipts,
            trace=trace,
        )
        verification = verify_task(
            task_evidence,
            reviewed_assignment_bytes=self.materials.reviewed_assignment_raw,
            expected_reviewed_assignment_sha256=(
                self.materials.reviewed_assignment_sha256
            ),
        )
        if not verification["passed"]:
            raise ValueError(
                f"live task Evidence rejected: {verification['failure_reasons']}"
            )
        values: dict[str, Any] = {
            "provider-receipt": provider,
            "participant-decision": artifacts["decision"],
            "participant-signature": signature,
            "event-receipts": receipts,
            "event-trace": trace,
            "task-evidence": task_evidence,
            "task-verification": verification,
        }
        return self.evidence.commit(task_id, values)

    def execution_boundary(self) -> dict[str, Any]:
        return {
            "offline_adapter_only": False,
            "real_container_started": self.container_starts > 0,
            "provider_credential_read": self.provider_calls > 0,
            "provider_api_call_performed": self.provider_calls > 0,
            "model_invocation_performed": self.provider_calls > 0,
            "pkcs11_signature_performed": self.participant_signatures > 0,
            "raw_provider_response_persisted": False,
            "credential_value_or_hash_persisted": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        }

    def _envelope(
        self,
        task: dict[str, Any],
        *,
        operation: str,
        provider_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        source_task = self.materials.task_inputs[task["task"]["task_id"]]
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
                    self.materials.assignment_commitments[task["participant_id"]]
                ),
            },
            "task": {
                "task_id": task["task"]["task_id"],
                "input": source_task["input"],
                "input_sha256": source_task["input_sha256"],
                "verifier_case": task["task"]["verifier_case"],
                "event_script": task["task"]["event_script"],
            },
            "advice_projection": advice,
            "authorization": {
                "authorization_id": self.materials.authorization_id,
                "artifact_sha256": self.materials.authorization_sha256,
            },
            "ipc": {
                "request_id": f"{task['task_execution_id']}:{operation}",
                "nonce": secrets.token_hex(32),
                "created_at": datetime.now(UTC).isoformat(),
            },
            "provider_response": provider_response,
        }

    def _advice(self, task: dict[str, Any]) -> dict[str, Any] | None:
        if task["cohort"] == "control":
            return None
        source = self.materials.signed_advice[task["advice"]["advice_id"]]
        advice = source["value"]["advice"]
        if not (
            source["raw_sha256"] == task["advice"]["sha256"]
            and source["value"]["signed_advice_sha256"]
            == task["advice"]["canonical_sha256"]
        ):
            raise ValueError("signed advice artifact binding mismatch")
        return {
            "advice_id": task["advice"]["advice_id"],
            "artifact_sha256": source["raw_sha256"],
            "canonical_sha256": source["value"]["signed_advice_sha256"],
            "template": advice["template"],
            "visibility": advice["visibility"],
            "authority": advice["authority"],
            "may_execute_for_participant": advice["may_execute_for_participant"],
            "may_override_constitution": advice["may_override_constitution"],
        }

    @staticmethod
    def _validate_runner_output(
        output: dict[str, Any], envelope: dict[str, Any]
    ) -> None:
        failures = validate_output_envelope(output, source=envelope)
        if failures:
            raise ValueError(f"participant runner output invalid: {failures}")


class PrivateEvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def commit(self, task_id: str, values: dict[str, Any]) -> dict[str, Any]:
        task_root = self.root / task_id
        task_root.mkdir(mode=0o700, exist_ok=True)
        refs = {}
        for name, value in sorted(values.items()):
            path = task_root / f"{name}.json"
            payload = (
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode()
            if path.exists():
                if path.read_bytes() != payload:
                    raise ValueError(f"task Evidence replay drift: {name}")
            else:
                temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
                descriptor = os.open(
                    temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            refs[name] = {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        return refs


def load_live_materials(
    *,
    run_id: str,
    authorization_id: str,
    authorization_path: Path,
    task_source_path: Path,
    signed_advice_root: Path,
    reviewed_assignment_path: Path,
) -> LiveMaterials:
    authorization_raw = authorization_path.read_bytes()
    task_source = _read(task_source_path)
    assignment_raw = reviewed_assignment_path.read_bytes()
    assignment = json.loads(assignment_raw)
    advice = {}
    for path in sorted(signed_advice_root.glob("*.signed.json")):
        raw = path.read_bytes()
        value = json.loads(raw)
        advice[value["advice_id"]] = {
            "value": value,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }
    commitments = {
        member["participant_id"]: pair["rebind_commitment_sha256"]
        for pair in assignment["assignments"]
        for member in (pair["mentor"], pair["control"])
    }
    return LiveMaterials(
        run_id=run_id,
        authorization_id=authorization_id,
        authorization_sha256=hashlib.sha256(authorization_raw).hexdigest(),
        task_inputs={item["task_id"]: item for item in task_source["tasks"]},
        signed_advice=advice,
        assignment_commitments=commitments,
        reviewed_assignment=assignment,
        reviewed_assignment_raw=assignment_raw,
    )


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact is not an object: {path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
