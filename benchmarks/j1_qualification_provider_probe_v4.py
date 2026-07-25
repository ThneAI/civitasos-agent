"""Consume one authorization for one J1-D r4 live-provider admission probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_admission import _load_private_env
from benchmarks.j1.qualification_provider_admission_v4 import (
    authorization_statement,
    validate_admission_plan,
)
from benchmarks.j1.qualification_provider_probe_v4 import (
    PROBE_BOUNDARY,
    build_claim,
    build_receipt,
    normalize_response,
)
from benchmarks.j1_qualification_provider_admission_probe import _https_post_once


DOMAIN_SOURCE = Path(__file__).parent / "j1" / "qualification_provider_probe_v4.py"
OPERATION_SOURCE = Path(__file__)


def execute_probe(
    *,
    probe_id: str,
    claimed_at: str,
    authorization_statement_value: str,
    plan_path: Path,
    preflight_path: Path,
    provider_env_path: Path,
    claim_root: Path,
    output_root: Path,
    repository_root: Path,
) -> dict[str, Any]:
    plan, plan_raw = _read_private(plan_path)
    preflight, preflight_raw = _read_private(preflight_path)
    failures = validate_admission_plan(plan)
    expected_statement = authorization_statement(
        plan_raw_sha256=hashlib.sha256(plan_raw).hexdigest(), plan=plan
    )
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    if failures or not (
        preflight.get("preflight_sha256") == canonical_sha256(preflight_body)
        and preflight.get("plan", {}).get("sha256")
        == hashlib.sha256(plan_raw).hexdigest()
        and preflight.get("plan", {}).get("canonical_sha256")
        == plan.get("plan_sha256")
        and preflight.get("owner_authorization", {}).get(
            "required_exact_statement"
        )
        == expected_statement
        and preflight.get("owner_authorization", {}).get("statement_sha256")
        == hashlib.sha256(expected_statement.encode()).hexdigest()
        and authorization_statement_value == expected_statement
    ):
        raise ValueError("r4 provider authorization source mismatch")
    _replay_sources(plan)
    inventory_before = _inventory()
    implementation = _implementation(repository_root)
    if output_root.exists():
        raise FileExistsError(f"r4 provider probe output exists: {output_root}")
    authorization_sha256 = hashlib.sha256(expected_statement.encode()).hexdigest()
    claim_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    claim_root.chmod(0o700)
    claim_path = claim_root / f"{authorization_sha256}.claim.json"
    if claim_path.exists():
        raise ValueError("r4 provider authorization already claimed")
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    plan_ref = _ref(plan_path, plan["plan_sha256"])
    preflight_ref = _ref(preflight_path, preflight["preflight_sha256"])
    claim = build_claim(
        probe_id=probe_id,
        claimed_at=claimed_at,
        authorization_statement_sha256=authorization_sha256,
        plan_ref=plan_ref,
        preflight_ref=preflight_ref,
        output_root_sha256=hashlib.sha256(
            str(output_root.resolve()).encode()
        ).hexdigest(),
        plan=plan,
    )
    _write_exclusive(claim_path, claim)
    claim_ref = _ref(claim_path, claim["claim_sha256"])
    journal_path = output_root / "r4-provider-probe-journal.json"
    journal = {
        "schema_version": "j1-qualification-r4-provider-probe-journal:v1",
        "probe_id": probe_id,
        "state": "authorization_claimed_call_reserved",
        "authorization_statement_sha256": authorization_sha256,
        "claim": claim_ref,
        "provider_env_read_count": 0,
        "provider_call_count": 0,
        "reservation": claim["reservation"],
    }
    write_private_json(journal_path, journal)
    try:
        api_key = _read_provider_env(provider_env_path, plan)
        journal["provider_env_read_count"] = 1
        journal["state"] = "credential_validated_call_reserved"
        write_private_json(journal_path, journal)
        journal["provider_call_count"] = 1
        journal["state"] = "provider_call_dispatched_no_retry"
        write_private_json(journal_path, journal)
        provider = plan["provider"]
        status, body = _https_post_once(
            f"{provider['base_url']}{plan['probe_contract']['path']}",
            api_key,
            plan["probe_contract"]["request_body"],
        )
        api_key = ""
        result = normalize_response(status=status, body=body, plan=plan)
        inventory_after = _inventory()
        receipt = build_receipt(
            probe_id=probe_id,
            completed_at=datetime.now(UTC).isoformat(),
            authorization_statement_sha256=authorization_sha256,
            claim_ref=claim_ref,
            plan_ref=plan_ref,
            preflight_ref=preflight_ref,
            plan=plan,
            provider_result=result,
            inventory_before=inventory_before,
            inventory_after=inventory_after,
            credential_basename=provider_env_path.name,
            implementation=implementation,
        )
        receipt_path = output_root / "r4-provider-admission-receipt.json"
        write_private_json(receipt_path, receipt)
        journal["state"] = "probe_admitted_authorization_consumed"
        write_private_json(journal_path, journal)
        gate = {
            "schema_version": "j1-qualification-r4-provider-admission-gate:v1",
            "passed": True,
            "failure_reasons": [],
            "state": "r4_provider_admission_refreshed_execution_preflight_required",
            "authorization": {
                "statement_sha256": authorization_sha256,
                "claim": claim_ref,
                "consumed": True,
                "reusable": False,
            },
            "receipt": _ref(receipt_path, receipt["receipt_sha256"]),
            "journal": _ref(journal_path, canonical_sha256(journal)),
            "readiness": {
                "r4_provider_admission_refreshed": True,
                "execution_preflight_allowed": True,
                "execution_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": PROBE_BOUNDARY,
        }
        gate["report_sha256"] = canonical_sha256(gate)
        write_private_json(output_root / "r4-provider-admission-gate-report.json", gate)
        return gate
    except Exception as error:
        journal["state"] = "probe_failed_authorization_consumed_no_retry"
        journal["failure_type"] = type(error).__name__
        write_private_json(journal_path, journal)
        gate = {
            "schema_version": "j1-qualification-r4-provider-admission-gate:v1",
            "passed": False,
            "failure_reasons": ["r4_provider_probe_failed"],
            "state": "r4_provider_admission_failed_authorization_consumed",
            "authorization": {
                "statement_sha256": authorization_sha256,
                "claim": claim_ref,
                "consumed": True,
                "reusable": False,
            },
            "journal": _ref(journal_path, canonical_sha256(journal)),
            "failure_type": type(error).__name__,
            "readiness": {
                "r4_provider_admission_refreshed": False,
                "execution_preflight_allowed": False,
                "execution_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": {
                **PROBE_BOUNDARY,
                "provider_admission_refreshed": False,
                "provider_credential_read_count": journal[
                    "provider_env_read_count"
                ],
                "credential_value_or_hash_persisted": False,
                "provider_api_call_count": journal["provider_call_count"],
                "model_invocation_count": journal["provider_call_count"],
            },
        }
        gate["report_sha256"] = canonical_sha256(gate)
        write_private_json(output_root / "r4-provider-admission-gate-report.json", gate)
        return gate


def _read_provider_env(path: Path, plan: dict[str, Any]) -> str:
    failures: list[str] = []
    values = _load_private_env(path, failures)
    if failures:
        raise ValueError(f"r4 provider environment invalid: {failures}")
    expected = {
        "BETA6_EXTERNAL_AGENT_PROVIDER": plan["provider"]["provider_id"],
        "BETA6_EXTERNAL_AGENT_API_BASE_URL": plan["provider"]["base_url"],
        "BETA6_EXTERNAL_AGENT_MODEL": plan["provider"]["model_id"],
    }
    for name, expected_value in expected.items():
        if values.get(name, "").rstrip("/") != expected_value:
            raise ValueError(f"r4 provider configuration mismatch: {name}")
    api_key = values.get("BETA6_EXTERNAL_AGENT_API_KEY", "")
    if not api_key:
        raise ValueError("r4 provider API key missing")
    return api_key


def _replay_sources(plan: dict[str, Any]) -> None:
    for name, reference in plan["source_artifacts"].items():
        path = Path(reference["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
            raise ValueError(f"r4 provider source drift: {name}")


def _inventory() -> dict[str, int]:
    statuses = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "name=civitas-j1q-runner",
            "--format",
            "{{.Status}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {
        "participant_container_count": len(statuses),
        "created_count": sum(item.startswith("Created") for item in statuses),
        "running_count": sum(item.startswith("Up ") for item in statuses),
    }


def _implementation(root: Path) -> dict[str, str]:
    if _git(root, "status", "--porcelain"):
        raise ValueError("repository must be clean before r4 provider probe")
    return {
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "domain_source_sha256": hashlib.sha256(DOMAIN_SOURCE.read_bytes()).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file() or resolved.stat().st_mode & 0o077:
        raise ValueError(f"private artifact invalid: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {resolved}")
    return value, raw


def _write_exclusive(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _ref(path: Path, canonical_digest: str) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "canonical_sha256": canonical_digest,
    }


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--claimed-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--provider-env", type=Path, required=True)
    parser.add_argument("--claim-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    args = parser.parse_args()
    datetime.fromisoformat(args.claimed_at.replace("Z", "+00:00"))
    gate = execute_probe(
        probe_id=args.probe_id,
        claimed_at=args.claimed_at,
        authorization_statement_value=args.authorization_statement,
        plan_path=args.plan,
        preflight_path=args.preflight,
        provider_env_path=args.provider_env,
        claim_root=args.claim_root,
        output_root=args.output_root,
        repository_root=args.repository_root,
    )
    print(json.dumps(gate, ensure_ascii=False, sort_keys=True))
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
