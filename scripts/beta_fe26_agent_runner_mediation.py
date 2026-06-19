#!/usr/bin/env python3
"""Run Beta-FE-2 prompts through CivitasOS-mediated Agent runners.

Beta-FE-2.6 is stricter than FE-2.5. FE-2.5 delivered already-collected
Agent responses through the task pool. FE-2.6 posts tasks first, lets worker
identities claim those tasks, then invokes the configured external/local runner
only after the task is claimed. The generated response is delivered back through
CivitasOS task-pool state.

This does not modify civitasos-frontend and does not authorize apply, commit,
push, merge, deploy, production runtime execution, or production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

try:
    from civitasos_contracts.artifacts import build_artifact_envelope
    from civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope
    from scripts.civitasos_contracts.auth import CivitasHttpClient

try:
    from beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        read_json_any_or_empty,
        sha256_file,
        write_json,
    )
except ModuleNotFoundError:
    from scripts.beta_evidence import (
        artifact_ref as _evidence_artifact_ref,
        read_json_any_or_empty,
        sha256_file,
        write_json,
    )

try:
    from beta_fe26_contracts import (
        FE2_PACKET_SCHEMA,
        NON_CLAIMS,
        boundary as _boundary,
        delivery_output as _delivery_output,
        h3_boundary as _h3_boundary,
        participant_ids as _participant_ids,
        run_alias_suffix as _run_alias_suffix,
        runner_prompt as _runner_prompt,
        safe_alias as _safe_alias,
        select_participants as _select_participants,
        task_payload as _task_payload,
        task_summary as _task_summary,
        validate_fe2_packet as _validate_fe2_packet,
    )
except ModuleNotFoundError:
    from scripts.beta_fe26_contracts import (
        FE2_PACKET_SCHEMA,
        NON_CLAIMS,
        boundary as _boundary,
        delivery_output as _delivery_output,
        h3_boundary as _h3_boundary,
        participant_ids as _participant_ids,
        run_alias_suffix as _run_alias_suffix,
        runner_prompt as _runner_prompt,
        safe_alias as _safe_alias,
        select_participants as _select_participants,
        task_payload as _task_payload,
        task_summary as _task_summary,
        validate_fe2_packet as _validate_fe2_packet,
    )

try:
    from beta_fe_ollama_native_reviewer import OllamaNativeReviewer, OllamaReviewResult, patch_review_as_text
except ModuleNotFoundError:
    from scripts.beta_fe_ollama_native_reviewer import OllamaNativeReviewer, OllamaReviewResult, patch_review_as_text

SUMMARY_SCHEMA = "beta-fe26-agent-runner-mediation-summary:v1"
TASK_RECEIPT_SCHEMA = "beta-fe26-agent-runner-task-receipt:v1"
GENERATION_SCHEMA = "beta-fe26-agent-runner-generation:v1"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_REQUESTER_ALIAS = "beta_fe26_frontend_operator"
PARTICIPANT_ALIASES = {
    "deepseek-api-agent": "beta_fe26_deepseek_runner",
    "hermes-cli-agent": "beta_fe26_hermes_runner",
    "local-gpu-agent": "beta_fe26_local_gpu_runner",
    "claude-cli-agent": "beta_fe26_claude_runner",
}


class HttpJsonClient(CivitasHttpClient):
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        demo_login_agent_id: str = "beta_fe26_runner_mediation",
        service_token_secret: str | None = None,
        service_id: str = "beta_fe26_runner_mediation",
        service_scopes: list[str] | None = None,
        require_service_token: bool = False,
    ) -> None:
        super().__init__(
            base_url,
            bearer_token=bearer_token or os.getenv("CIVITASOS_BEARER_TOKEN"),
            service_token_secret=(
                service_token_secret
                or os.getenv("CIVITASOS_FE_MEDIATION_SERVICE_TOKEN_SECRET")
                or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET")
            ),
            service_id=service_id,
            service_scopes=service_scopes or _default_service_scopes(),
            require_service_token=require_service_token,
            demo_login_agent_id=demo_login_agent_id,
            required_service_token_error=(
                "FE mediation strict auth requires --service-token-secret "
                "or CIVITASOS_SERVICE_TOKEN_SECRET"
            ),
            timeout=60,
        )

    def healthz(self) -> None:
        request = urllib.request.Request(self._url("/healthz"), method="GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()


@dataclass(frozen=True)
class GenerationResult:
    participant_id: str
    runner_kind: str
    content: str
    raw_report: dict[str, Any]


class AgentResponseGenerator(Protocol):
    def generate(
        self,
        *,
        participant_id: str,
        prompt: str,
        task_id: str,
        claimed_task: dict[str, Any],
        worker: dict[str, Any],
    ) -> GenerationResult:
        ...


class OpenAiCompatibleGenerator:
    def __init__(self, *, env_file: Path, timeout_secs: int = 180) -> None:
        env = _read_env_file(env_file)
        self.env_file = env_file
        self.base_url = _first_env(env, "BETA6_EXTERNAL_AGENT_API_BASE_URL", "LLM_BASE_URL")
        self.model = _normalize_model(_first_env(env, "BETA6_EXTERNAL_AGENT_MODEL", "AGENT_LLM"))
        self.api_key = _first_env(env, "BETA6_EXTERNAL_AGENT_API_KEY", "LLM_API_KEY")
        self.timeout_secs = timeout_secs
        if not self.base_url:
            raise RuntimeError(f"OpenAI-compatible runner env missing base URL: {env_file}")
        if not self.model:
            raise RuntimeError(f"OpenAI-compatible runner env missing model: {env_file}")

    def generate(
        self,
        *,
        participant_id: str,
        prompt: str,
        task_id: str,
        claimed_task: dict[str, Any],
        worker: dict[str, Any],
    ) -> GenerationResult:
        endpoint = _chat_endpoint(self.base_url)
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a CivitasOS-controlled frontend collaboration Agent. "
                        "Generate the response only for the claimed task. Preserve all boundaries."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1800,
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        status = None
        payload: dict[str, Any] = {}
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_secs) as response:
                status = response.status
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{participant_id} OpenAI-compatible runner HTTP {exc.code}: {detail}") from exc
        content = _extract_openai_content(payload).strip()
        if not content:
            raise RuntimeError(f"{participant_id} OpenAI-compatible runner returned empty content")
        return GenerationResult(
            participant_id=participant_id,
            runner_kind="openai_compatible",
            content=content,
            raw_report={
                "schema_version": GENERATION_SCHEMA,
                "participant_id": participant_id,
                "runner_kind": "openai_compatible",
                "task_id": task_id,
                "claimed_task_status": claimed_task.get("status"),
                "claimed_by": claimed_task.get("claimed_by"),
                "worker_did": worker.get("did"),
                "status": status,
                "model": self.model,
                "env_file": str(self.env_file.resolve()),
                "api_key_recorded": False,
                "content_chars": len(content),
                "generated_after_claim": True,
                "boundary": _boundary(),
                "h3_boundary": _h3_boundary(),
                "non_claims": list(NON_CLAIMS),
            },
        )


class OllamaNativeGenerator:
    def __init__(
        self,
        *,
        model: str,
        base_url: str | None = None,
        reviewer: OllamaNativeReviewer | None = None,
    ) -> None:
        self.reviewer = reviewer or OllamaNativeReviewer(model=model, base_url=base_url)

    def generate(
        self,
        *,
        participant_id: str,
        prompt: str,
        task_id: str,
        claimed_task: dict[str, Any],
        worker: dict[str, Any],
    ) -> GenerationResult:
        result = self.reviewer.review_patch_proposal(prompt)
        content = patch_review_as_text(result.payload)
        return GenerationResult(
            participant_id=participant_id,
            runner_kind="ollama_native_reviewer",
            content=content,
            raw_report={
                "schema_version": GENERATION_SCHEMA,
                "participant_id": participant_id,
                "runner_kind": "ollama_native_reviewer",
                "task_id": task_id,
                "claimed_task_status": claimed_task.get("status"),
                "claimed_by": claimed_task.get("claimed_by"),
                "worker_did": worker.get("did"),
                "model": self.reviewer.model,
                "content_chars": len(content),
                "generated_after_claim": True,
                "review_payload": result.payload,
                "review_report": result.report,
                "boundary": _boundary(),
                "h3_boundary": _h3_boundary(),
                "non_claims": list(NON_CLAIMS),
            },
        )


class CommandGenerator:
    def __init__(self, *, command: str, timeout_secs: int = 180) -> None:
        self.command = command
        self.timeout_secs = timeout_secs

    def generate(
        self,
        *,
        participant_id: str,
        prompt: str,
        task_id: str,
        claimed_task: dict[str, Any],
        worker: dict[str, Any],
    ) -> GenerationResult:
        env = os.environ.copy()
        env.setdefault("CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS", "0")
        argv = [prompt if part == "{prompt}" else part for part in shlex.split(self.command)]
        stdin = None if "{prompt}" in self.command else prompt
        result = subprocess.run(
            argv,
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
            timeout=self.timeout_secs,
            env=env,
        )
        content = result.stdout.strip()
        if not content:
            raise RuntimeError(f"{participant_id} command runner returned empty stdout; stderr={result.stderr[:500]}")
        if result.returncode != 0:
            raise RuntimeError(f"{participant_id} command runner exited {result.returncode}; stderr={result.stderr[:500]}")
        return GenerationResult(
            participant_id=participant_id,
            runner_kind="command",
            content=content,
            raw_report={
                "schema_version": GENERATION_SCHEMA,
                "participant_id": participant_id,
                "runner_kind": "command",
                "task_id": task_id,
                "claimed_task_status": claimed_task.get("status"),
                "claimed_by": claimed_task.get("claimed_by"),
                "worker_did": worker.get("did"),
                "command": argv,
                "returncode": result.returncode,
                "stderr_excerpt": result.stderr[:1000],
                "content_chars": len(content),
                "generated_after_claim": True,
                "boundary": _boundary(),
                "h3_boundary": _h3_boundary(),
                "non_claims": list(NON_CLAIMS),
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--fe2-packet-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument(
        "--runner-spec",
        action="append",
        default=[],
        help="participant=openai-env:/path, participant=ollama-native:model, or participant=command:argv",
    )
    parser.add_argument("--participant", action="append", default=[], help="optional participant allowlist; defaults to all FE-2 packet participants")
    parser.add_argument("--confirm-deliveries", action="store_true")
    parser.add_argument("--demo-login-agent-id", default="beta_fe26_runner_mediation")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default="beta_fe26_runner_mediation")
    parser.add_argument("--service-token-scope", action="append", default=[])
    parser.add_argument("--require-service-token", action="store_true")
    parser.add_argument("--expected-patch-slice-id", default="task_read_adapter_extraction")
    args = parser.parse_args(argv)

    generators = _parse_runner_specs(args.runner_spec)
    client = HttpJsonClient(
        args.backend_url,
        demo_login_agent_id=args.demo_login_agent_id,
        service_token_secret=args.service_token_secret,
        service_id=args.service_id,
        service_scopes=args.service_token_scope or None,
        require_service_token=bool(args.require_service_token),
    )
    summary = run_mediation(
        client=client,
        fe2_packet_summary_path=Path(args.fe2_packet_summary),
        output_root=Path(args.output_root),
        generators=generators,
        participant_allowlist=args.participant or None,
        backend_url=args.backend_url,
        confirm_deliveries=bool(args.confirm_deliveries),
        expected_patch_slice_id=args.expected_patch_slice_id,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


def _default_service_scopes() -> list[str]:
    raw = os.getenv(
        "CIVITASOS_FE_MEDIATION_SERVICE_TOKEN_SCOPES",
        "agents:read,agents:write,pool:post,pool:read,pool:claim,pool:write",
    )
    return [scope.strip() for scope in raw.split(",") if scope.strip()]


def run_mediation(
    *,
    client: HttpJsonClient,
    fe2_packet_summary_path: Path,
    output_root: Path,
    generators: dict[str, AgentResponseGenerator],
    participant_allowlist: list[str] | None = None,
    backend_url: str = DEFAULT_BACKEND_URL,
    confirm_deliveries: bool = False,
    expected_patch_slice_id: str = "task_read_adapter_extraction",
) -> dict[str, Any]:
    failures: list[str] = []
    output_root.mkdir(parents=True, exist_ok=True)
    fe2_packet = _read_json(fe2_packet_summary_path, failures, "FE-2 packet summary")
    _validate_fe2_packet(fe2_packet, failures, expected_patch_slice_id)
    if not generators:
        failures.append("at least one Agent runner generator must be configured")
    selected_participant_ids: list[str] = []
    excluded_participant_ids: list[str] = []
    if isinstance(fe2_packet, dict):
        packet_participant_ids = _participant_ids(fe2_packet)
        selected_participant_ids = _select_participants(packet_participant_ids, participant_allowlist, failures)
        excluded_participant_ids = [participant_id for participant_id in packet_participant_ids if participant_id not in set(selected_participant_ids)]
        missing = sorted(set(selected_participant_ids) - set(generators))
        if missing:
            failures.append(f"missing runner generator for participant(s): {', '.join(missing)}")
        if len(selected_participant_ids) < 3:
            failures.append("FE-2.6 runner mediation requires at least 3 selected participants")
    if failures:
        raise ValueError(f"Beta-FE-2.6 runner mediation blocked: {failures}")

    client.healthz()
    alias_suffix = _run_alias_suffix(output_root)
    requester = _quickstart_agent(
        client,
        alias=f"{DEFAULT_REQUESTER_ALIAS}_{alias_suffix}",
        name="Beta FE2.6 Frontend Operator",
        description="Requester identity for CivitasOS Agent-runner-mediated frontend collaboration tasks",
        output_path=output_root / "requester_quickstart.json",
    )

    receipts: list[dict[str, Any]] = []
    for participant in fe2_packet.get("participants", []):
        participant_id = str(participant.get("participant_id") or "")
        if participant_id not in set(selected_participant_ids):
            continue
        prompt_ref = fe2_packet.get("agent_prompt_refs", {}).get(participant_id)
        prompt_path = Path(str((prompt_ref or {}).get("path") or ""))
        base_alias = PARTICIPANT_ALIASES.get(participant_id, _safe_alias(f"beta_fe26_{participant_id}"))
        worker = _quickstart_agent(
            client,
            alias=f"{base_alias}_{alias_suffix}",
            name=f"Beta FE2.6 Runner {participant_id}",
            description=f"CivitasOS Agent runner identity for {participant_id}",
            output_path=output_root / f"{participant_id}.quickstart.json",
        )
        receipt = _post_claim_generate_deliver(
            client=client,
            requester=requester,
            worker=worker,
            participant=participant,
            fe2_packet=fe2_packet,
            fe2_packet_summary_path=fe2_packet_summary_path,
            prompt_path=prompt_path,
            generator=generators[participant_id],
            output_root=output_root,
            confirm_delivery=confirm_deliveries,
        )
        receipts.append(receipt)
        _write_json(output_root / f"{participant_id}.task_receipt.json", receipt)

    statuses = [str(receipt.get("final_task", {}).get("status") or "") for receipt in receipts]
    passed = bool(receipts) and all(status in {"Delivered", "Completed"} for status in statuses)
    if not all(receipt.get("generation_observed_after_claim") is True for receipt in receipts):
        passed = False
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe26_agent_runner_mediation_passed" if passed else "blocked",
        "failure_reasons": [] if passed else ["all task receipts must be generated-after-claim and end in Delivered or Completed"],
        "backend_url": backend_url,
        "mediation_level": "civitasos_agent_runner_claim_generate_deliver",
        "agent_runner_mediation_observed": True,
        "source_fe2_packet_summary": _artifact_ref(fe2_packet_summary_path),
        "requester": requester,
        "task_receipt_count": len(receipts),
        "task_receipts": [_artifact_ref(output_root / f"{receipt['participant_id']}.task_receipt.json") for receipt in receipts],
        "task_ids": [receipt.get("task_id") for receipt in receipts],
        "runner_participant_ids": [receipt.get("participant_id") for receipt in receipts],
        "excluded_participant_ids": excluded_participant_ids,
        "participant_allowlist": selected_participant_ids,
        "final_statuses": statuses,
        "claim_observed_count": sum(1 for receipt in receipts if receipt.get("claim_observed") is True),
        "generation_after_claim_observed_count": sum(1 for receipt in receipts if receipt.get("generation_observed_after_claim") is True),
        "delivery_observed_count": sum(1 for receipt in receipts if receipt.get("delivery_observed") is True),
        "challenge_window_observed_count": sum(1 for receipt in receipts if receipt.get("challenge_window_observed") is True),
        "confirm_deliveries": confirm_deliveries,
        "expected_patch_slice_id": expected_patch_slice_id,
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe26_agent_runner_mediation_summary.json", summary)
    return summary


def _post_claim_generate_deliver(
    *,
    client: HttpJsonClient,
    requester: dict[str, Any],
    worker: dict[str, Any],
    participant: dict[str, Any],
    fe2_packet: dict[str, Any],
    fe2_packet_summary_path: Path,
    prompt_path: Path,
    generator: AgentResponseGenerator,
    output_root: Path,
    confirm_delivery: bool,
) -> dict[str, Any]:
    participant_id = str(participant.get("participant_id") or "unknown")
    prompt = prompt_path.read_text(encoding="utf-8")
    post = client.post("/api/v1/a2a/pool/post", _task_payload(requester, worker, participant, fe2_packet, fe2_packet_summary_path, prompt_path))
    task_id = str((post or {}).get("task_id") or "")
    if not task_id:
        raise RuntimeError(f"pool post missing task_id for {participant_id}: {post}")
    claim = client.post("/api/v1/a2a/pool/claim", {"agent_id": worker["did"], "task_id": task_id, "stake_amount": 0})
    claimed_task = _task_from_claim_or_readback(client, task_id, claim)
    runner_prompt = _runner_prompt(prompt=prompt, task_id=task_id, participant=participant, worker=worker, claimed_task=claimed_task)
    generation = generator.generate(
        participant_id=participant_id,
        prompt=runner_prompt,
        task_id=task_id,
        claimed_task=claimed_task,
        worker=worker,
    )
    generation_path = output_root / f"{participant_id}.generation.md"
    generation_report_path = output_root / f"{participant_id}.generation_report.json"
    generation_path.write_text(generation.content + "\n", encoding="utf-8")
    generation_report = dict(generation.raw_report)
    generation_report.update({"response_file": _artifact_ref(generation_path)})
    _write_json(generation_report_path, generation_report)
    execute = client.post(
        "/api/v1/a2a/task/execute",
        {
            "agent_id": worker["did"],
            "task_id": task_id,
            "output": _delivery_output(participant_id, fe2_packet, prompt_path, generation_path, generation_report_path),
            "success": True,
            "metadata": {
                "runner": "beta_fe26_agent_runner_mediation",
                "participant_id": participant_id,
                "generated_after_claim": "true",
                "runner_kind": str(generation.runner_kind),
            },
        },
    )
    delivered_task = _get_task(client, task_id)
    confirm = None
    final_task = delivered_task
    if confirm_delivery and delivered_task.get("status") == "Delivered":
        try:
            confirm = client.post(f"/api/v1/a2a/pool/confirm/{task_id}", {})
            final_task = _get_task(client, task_id)
        except RuntimeError as exc:
            confirm = {"blocked": True, "reason": "confirm_blocked_or_unavailable", "error": str(exc)}
    prompt_ref = _artifact_ref(prompt_path)
    generation_ref = _artifact_ref(generation_path)
    generation_report_ref = _artifact_ref(generation_report_path)
    return {
        "schema_version": TASK_RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="task",
            plane="runtime",
            schema_version=TASK_RECEIPT_SCHEMA,
            artifact_id=f"fe26-task:{task_id}",
            subject_id=f"pool-task:{task_id}",
            producer="beta_fe26_agent_runner_mediation",
            source_refs=[prompt_ref, generation_ref, generation_report_ref],
            scope="agent_runner_claim_generate_deliver",
        ),
        "checked_at": _now(),
        "participant_id": participant_id,
        "task_id": task_id,
        "requester": requester,
        "worker": worker,
        "post_response": post,
        "claim_response": claim,
        "execute_response": execute,
        "confirm_response": confirm,
        "final_task": _task_summary(final_task),
        "runner_kind": generation.runner_kind,
        "prompt_ref": prompt_ref,
        "generation_response": generation_ref,
        "generation_report": generation_report_ref,
        "claim_observed": bool(final_task.get("claimed_by") or delivered_task.get("claimed_by") or claimed_task.get("claimed_by")),
        "generation_observed_after_claim": True,
        "delivery_observed": final_task.get("status") in {"Delivered", "Completed"} or delivered_task.get("status") == "Delivered",
        "challenge_window_observed": bool(delivered_task.get("challenge_deadline_at") or delivered_task.get("challenge_window_secs")),
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _quickstart_agent(client: HttpJsonClient, *, alias: str, name: str, description: str, output_path: Path) -> dict[str, Any]:
    result = client.post(
        "/api/v1/a2a/quickstart",
        {
            "public_key": _generate_public_key_hex(),
            "alias": alias,
            "name": name,
            "endpoint": f"http://127.0.0.1:65535/{alias}",
            "description": description,
        },
    )
    _write_json(output_path, result if isinstance(result, dict) else {"result": result})
    agent = result.get("agent", {}) if isinstance(result, dict) else {}
    did = str(agent.get("did") or "")
    if not did:
        raise RuntimeError(f"quickstart response missing DID for {alias}: {result}")
    return {"did": did, "alias": agent.get("alias") or alias, "name": agent.get("name") or name, "quickstart_ref": _artifact_ref(output_path)}


def _generate_public_key_hex() -> str:
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a valid Ed25519 public key") from exc
    agent = CivitasAgent(auto_discover=False)
    return str(agent.generate_keys())


def _task_from_claim_or_readback(client: HttpJsonClient, task_id: str, claim: Any) -> dict[str, Any]:
    if isinstance(claim, dict) and isinstance(claim.get("task"), dict):
        return claim["task"]
    return _get_task(client, task_id)


def _get_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id"),
        "requester": task.get("requester"),
        "required_capability": task.get("required_capability"),
        "status": task.get("status"),
        "claimed_by": task.get("claimed_by"),
        "posted_at": task.get("posted_at"),
        "claimed_at": task.get("claimed_at"),
        "delivered_at": task.get("delivered_at"),
        "challenge_deadline_at": task.get("challenge_deadline_at"),
        "challenge_window_secs": task.get("challenge_window_secs"),
        "has_output": task.get("output") not in (None, "", {}, []),
    }


def _parse_runner_specs(values: list[str]) -> dict[str, AgentResponseGenerator]:
    generators: dict[str, AgentResponseGenerator] = {}
    for value in values:
        participant_id, sep, spec = value.partition("=")
        if not sep or not participant_id.strip() or not spec.strip():
            raise ValueError(
                "runner spec must be participant_id=openai-env:/path, "
                "participant_id=ollama-native:model, or participant_id=command:argv"
            )
        mode, mode_sep, arg = spec.partition(":")
        if not mode_sep or not arg.strip():
            raise ValueError(f"runner spec missing mode argument: {value}")
        if mode == "openai-env":
            generators[participant_id.strip()] = OpenAiCompatibleGenerator(env_file=Path(arg.strip()))
        elif mode == "ollama-native":
            generators[participant_id.strip()] = OllamaNativeGenerator(model=arg.strip())
        elif mode == "command":
            generators[participant_id.strip()] = CommandGenerator(command=arg.strip())
        else:
            raise ValueError(
                f"unsupported runner spec mode {mode!r}; expected openai-env, ollama-native, or command"
            )
    return generators


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"env file not found: {path}")
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _first_env(env: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = env.get(key, "").strip()
        if value and not value.startswith("REPLACE_WITH"):
            return value
    return ""


def _normalize_model(model: str) -> str:
    model = model.strip()
    for prefix in ("openai:", "anthropic:", "litellm:"):
        if model.startswith(prefix):
            return model.split(":", 1)[1]
    return model


def _chat_endpoint(base_url: str) -> str:
    base_url = base_url.strip().rstrip("/")
    if base_url.endswith("/chat/completions"):
        return base_url
    return f"{base_url}/chat/completions"


def _extract_openai_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if isinstance(message, dict):
        return str(message.get("content") or "")
    return str(first.get("text") or "")


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    return read_json_any_or_empty(path, failures, label)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)


def _artifact_ref(path: Path) -> dict[str, str]:
    return _evidence_artifact_ref(path)


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
