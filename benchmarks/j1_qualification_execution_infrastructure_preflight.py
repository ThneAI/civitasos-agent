"""Generate the offline J1-D execution-infrastructure plan and evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_event_harness import (
    build_event_receipt,
    build_event_trace,
    validate_event_trace,
)
from benchmarks.j1.qualification_execution_infrastructure import (
    REQUIRED_BLOCKERS,
    build_execution_infrastructure_plan,
    verifier_contract_conflicts,
)
from benchmarks.j1.qualification_participant_provisioning import (
    validate_participant_profile,
)
from benchmarks.j1.qualification_provider_broker import (
    QualificationBudgetStore,
    execute_provider_call,
)


REPORT_SCHEMA = "j1-qualification-execution-infrastructure-preflight:v1"
DEFAULT_ROOT = Path(
    "/home/cc/.local/state/civitasos/j1d-qualification-materials-20260719-r1"
)


def prepare_preflight(
    *,
    plan_id: str,
    created_at: str,
    reviewed_design_path: Path,
    design_gate_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    signed_advice_manifest_path: Path,
    signed_advice_gate_path: Path,
    provisioning_report_path: Path,
    profiles_root: Path,
    provider_admission_report_path: Path,
    repository_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"preflight output already exists: {output_root}")
    sources = {
        "reviewed_design": _read_private(reviewed_design_path),
        "design_gate": _read_private(design_gate_path),
        "reviewed_assignment": _read_private(reviewed_assignment_path),
        "assignment_gate": _read_private(assignment_gate_path),
        "signed_advice_manifest": _read_private(signed_advice_manifest_path),
        "signed_advice_gate": _read_private(signed_advice_gate_path),
        "provisioning_report": _read_private(provisioning_report_path),
        "provider_admission_report": _read_private(provider_admission_report_path),
    }
    profiles = _load_profiles(profiles_root)
    _validate_sources(sources, profiles)
    conflicts = verifier_contract_conflicts(sources["reviewed_design"][0])
    if len(conflicts) != 2:
        raise ValueError(f"unexpected cohort/verifier conflict inventory: {conflicts}")
    isolation = inspect_existing_isolation(profiles)
    implementation = _implementation(repository_root)

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        fault_matrix = _run_offline_fault_matrix(
            design=sources["reviewed_design"][0],
            budget_path=output_root / "synthetic-budget.sqlite3",
        )
        offline_readiness = {
            "event_harness_dry_run_passed": fault_matrix["event_harness_passed"],
            "provider_broker_dry_run_passed": fault_matrix["provider_broker_passed"],
        }
        source_binding = {
            f"{name}_artifact_sha256": hashlib.sha256(raw).hexdigest()
            for name, (_, raw) in sources.items()
        }
        source_binding["participant_profile_set_sha256"] = canonical_sha256(
            sorted(profile["profile_sha256"] for profile in profiles)
        )
        plan = build_execution_infrastructure_plan(
            plan_id=plan_id,
            created_at=created_at,
            source_binding=source_binding,
            reviewed_design=sources["reviewed_design"][0],
            reviewed_assignment=sources["reviewed_assignment"][0],
            signed_advice_manifest=sources["signed_advice_manifest"][0],
            participant_profiles=profiles,
            blockers=sorted(REQUIRED_BLOCKERS),
            implementation=implementation,
            offline_readiness=offline_readiness,
        )
        plan_path = output_root / "execution-infrastructure-plan.json"
        write_private_json(plan_path, plan)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "offline_preflight_passed_execution_blocked",
            "created_at": created_at,
            "plan": {
                **_artifact(plan_path),
                "canonical_sha256": plan["plan_sha256"],
            },
            "source_artifacts": {
                name: _artifact_bytes(path, raw)
                for name, path in {
                    "reviewed_design": reviewed_design_path,
                    "design_gate": design_gate_path,
                    "reviewed_assignment": reviewed_assignment_path,
                    "assignment_gate": assignment_gate_path,
                    "signed_advice_manifest": signed_advice_manifest_path,
                    "signed_advice_gate": signed_advice_gate_path,
                    "provisioning_report": provisioning_report_path,
                    "provider_admission_report": provider_admission_report_path,
                }.items()
                for raw in [sources[name][1]]
            },
            "inventory": plan["inventory"],
            "existing_isolation": isolation,
            "verifier_contract_conflicts": conflicts,
            "offline_fault_matrix": fault_matrix,
            "blockers": sorted(REQUIRED_BLOCKERS),
            "readiness": plan["readiness"],
            "implementation": implementation,
            "execution_boundary": plan["execution_boundary"],
        }
        report["report_sha256"] = canonical_sha256(report)
        write_private_json(
            output_root / "execution-infrastructure-preflight.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def inspect_existing_isolation(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    names = [profile["isolation"]["container_name"] for profile in profiles]
    result = subprocess.run(
        ["docker", "inspect", *names],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Docker inspect failed: {result.stderr.strip()}")
    inspected = json.loads(result.stdout)
    if not isinstance(inspected, list) or len(inspected) != 40:
        raise ValueError("Docker inspect did not return exactly 40 containers")
    by_name = {
        str(item.get("Name", "")).removeprefix("/"): item
        for item in inspected
        if isinstance(item, dict)
    }
    failures: list[str] = []
    states: dict[str, int] = {}
    placeholder_count = 0
    for profile in profiles:
        expected = profile["isolation"]
        item = by_name.get(expected["container_name"])
        if item is None:
            failures.append(f"container_missing:{expected['container_name']}")
            continue
        host = item.get("HostConfig", {})
        state = item.get("State", {})
        status = str(state.get("Status", "unknown"))
        states[status] = states.get(status, 0) + 1
        config_hash = canonical_sha256(
            {"Config": item.get("Config"), "HostConfig": host}
        )
        checks = (
            item.get("Id") == expected["isolation_id"],
            config_hash == expected["container_config_sha256"],
            state.get("Running") is False,
            host.get("NetworkMode") == "none",
            host.get("ReadonlyRootfs") is True,
            host.get("CapDrop") == ["ALL"],
            "no-new-privileges:true" in host.get("SecurityOpt", []),
            host.get("PidsLimit") == 64,
            host.get("Memory") == 268_435_456,
            host.get("NanoCpus") == 250_000_000,
        )
        if not all(checks):
            failures.append(f"container_boundary_invalid:{expected['container_name']}")
        if item.get("Config", {}).get("Cmd") == [
            "python",
            "-c",
            "raise SystemExit('J1-D execution authorization required')",
        ]:
            placeholder_count += 1
    if failures:
        raise ValueError(f"existing participant isolation invalid: {failures}")
    if placeholder_count != 40:
        raise ValueError("existing isolation placeholder inventory drifted")
    return {
        "inspected": True,
        "container_count": 40,
        "state_counts": states,
        "hardening_matches_profiles": True,
        "placeholder_runner_count": placeholder_count,
        "runner_replacement_required": True,
        "container_created": False,
        "container_started": False,
    }


def _run_offline_fault_matrix(
    *, design: dict[str, Any], budget_path: Path
) -> dict[str, Any]:
    auth_hash = "a" * 64
    source_hash = "b" * 64
    receipts: list[dict[str, Any]] = []
    for event_type, payload in (
        ("advice_issued", {"issued": True}),
        ("relation_revoked", {"revoked": True}),
        ("stale_advice_read_attempt", {"read_succeeded": False, "advice_used": False}),
    ):
        receipts.append(
            build_event_receipt(
                run_id="offline-dry-run",
                participant_id="synthetic-participant",
                participant_did="did:civ:qualification:synthetic-participant",
                cohort="mentor",
                task_id="synthetic-revocation-task",
                sequence=len(receipts),
                event_type=event_type,
                observed_at="2026-07-22T00:00:00+00:00",
                process_instance_id="synthetic-process",
                credential_version=1,
                payload=payload,
                source_refs=[source_hash],
                execution_authorization_sha256=auth_hash,
                previous_event_sha256=(
                    receipts[-1]["event_sha256"] if receipts else None
                ),
            )
        )
    script = [item["event_type"] for item in receipts]
    trace = build_event_trace(receipts=receipts, expected_script=script)
    broken = [dict(item) for item in receipts]
    broken[-1] = {**broken[-1], "previous_event_sha256": "c" * 64}
    event_failures = validate_event_trace(broken, expected_script=script)
    event_passed = (
        trace["assertions"]["stale_advice_rejected"]["value"] is True
        and "harness_trace_hash_chain_invalid" in event_failures
    )

    store = QualificationBudgetStore(budget_path)
    success = execute_provider_call(
        call_id="synthetic-success",
        run_id="offline-dry-run",
        participant_id="synthetic-participant",
        task_id="synthetic-task",
        prompt="synthetic prompt",
        api_key="synthetic-non-provider-key",
        execution_authorization_sha256=auth_hash,
        reviewed_design=design,
        budget_store=store,
        provider_call=lambda **_: {
            "content": "synthetic decision",
            "usage": {"input_cache_miss": 200, "output": 100},
        },
    )
    overrun_rejected = False
    try:
        execute_provider_call(
            call_id="synthetic-overrun",
            run_id="offline-dry-run",
            participant_id="synthetic-participant-2",
            task_id="synthetic-task",
            prompt="synthetic prompt",
            api_key="synthetic-non-provider-key",
            execution_authorization_sha256=auth_hash,
            reviewed_design=design,
            budget_store=store,
            provider_call=lambda **_: {
                "content": "synthetic decision",
                "usage": {"input_cache_miss": 500, "output": 2000},
            },
        )
    except ValueError:
        overrun_rejected = store.status("synthetic-overrun") == "overrun"
    provider_passed = (
        store.status("synthetic-success") == "reconciled"
        and success["receipt"]["execution_boundary"]["raw_response_recorded"] is False
        and overrun_rejected
    )
    if not event_passed or not provider_passed:
        raise ValueError("offline execution-infrastructure fault matrix failed")
    return {
        "event_harness_passed": event_passed,
        "hash_chain_tamper_rejected": True,
        "revocation_fail_closed": True,
        "provider_broker_passed": provider_passed,
        "synthetic_transport_only": True,
        "budget_reservation_reconciled": True,
        "budget_overrun_persisted_and_rejected": overrun_rejected,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
    }


def _validate_sources(
    sources: dict[str, tuple[dict[str, Any], bytes]], profiles: list[dict[str, Any]]
) -> None:
    design, design_raw = sources["reviewed_design"]
    design_gate = sources["design_gate"][0]
    assignment, assignment_raw = sources["reviewed_assignment"]
    assignment_gate = sources["assignment_gate"][0]
    advice, advice_raw = sources["signed_advice_manifest"]
    advice_gate = sources["signed_advice_gate"][0]
    provisioning = sources["provisioning_report"][0]
    admission = sources["provider_admission_report"][0]
    failures = []
    if not (
        design_gate.get("passed") is True
        and design_gate.get("failure_reasons") == []
        and design_gate.get("reviewed_design_sha256")
        == design.get("reviewed_design_sha256")
        and design_gate.get("artifacts", {}).get("reviewed_design", {}).get("sha256")
        == hashlib.sha256(design_raw).hexdigest()
    ):
        failures.append("reviewed_design_gate_invalid")
    if not (
        assignment_gate.get("passed") is True
        and assignment_gate.get("failure_reasons") == []
        and assignment_gate.get("reviewed_assignment_sha256")
        == assignment.get("reviewed_assignment_sha256")
        and assignment_gate.get("artifacts", {})
        .get("reviewed_assignment", {})
        .get("sha256")
        == hashlib.sha256(assignment_raw).hexdigest()
    ):
        failures.append("reviewed_assignment_gate_invalid")
    if not (
        advice_gate.get("passed") is True
        and advice_gate.get("failure_reasons") == []
        and advice_gate.get("signed_manifest_sha256") == advice.get("manifest_sha256")
        and advice_gate.get("artifacts", {}).get("signed_manifest", {}).get("sha256")
        == hashlib.sha256(advice_raw).hexdigest()
        and advice_gate.get("inventory", {}).get("signed_advice_count") == 160
        and advice_gate.get("inventory", {}).get("control_advice_count") == 0
        and advice_gate.get("inventory", {}).get("all_signatures_verified") is True
    ):
        failures.append("signed_advice_gate_invalid")
    profile_hashes = sorted(profile.get("profile_sha256") for profile in profiles)
    if not (
        provisioning.get("passed") is True
        and provisioning.get("participant_count") == 40
        and sorted(provisioning.get("participant_profile_sha256", [])) == profile_hashes
    ):
        failures.append("participant_provisioning_invalid")
    if not (
        admission.get("passed") is True
        and admission.get("readiness", {}).get("provider_configuration_admitted")
        is True
        and admission.get("readiness", {}).get("qualification_protocol_frozen") is False
        and admission.get("readiness", {}).get("real_participant_roster_bound") is False
    ):
        failures.append("expected_stale_provider_admission_not_observed")
    if failures:
        raise ValueError(f"execution infrastructure sources invalid: {failures}")


def _load_profiles(root: Path) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("participant profiles root must be a real directory")
    paths = sorted(root.glob("*.json"))
    if len(paths) != 40:
        raise ValueError("participant profile inventory must contain exactly 40 files")
    profiles = []
    for path in paths:
        profile, _ = _read_private(path)
        failures = validate_participant_profile(profile)
        if failures:
            raise ValueError(f"participant profile invalid ({path.name}): {failures}")
        profiles.append(profile)
    if len({item["participant"]["participant_id"] for item in profiles}) != 40:
        raise ValueError("participant profile identities are not unique")
    return profiles


def _implementation(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve()
    status = _git(root, "status", "--porcelain")
    if status.strip():
        raise ValueError("repository must be clean before freezing preflight evidence")
    revision = _git(root, "rev-parse", "HEAD").strip()
    paths = [
        "benchmarks/j1/qualification_event_harness.py",
        "benchmarks/j1/qualification_execution_infrastructure.py",
        "benchmarks/j1/qualification_provider_broker.py",
        "benchmarks/j1_qualification_execution_infrastructure_preflight.py",
    ]
    source_hashes = {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths
    }
    return {
        "source_revision": revision,
        "source_sha256": canonical_sha256(source_hashes),
    }


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    )
    return result.stdout


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file():
        raise ValueError(f"artifact must be a regular non-symlink file: {path}")
    if resolved.stat().st_mode & 0o077:
        raise PermissionError(f"artifact permissions must be private: {resolved}")
    raw = resolved.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"artifact must contain a JSON object: {resolved}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _artifact_bytes(path: Path, raw: bytes) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_ROOT / "execution-infrastructure-preflight-20260722-r1",
    )
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).parents[1]
    )
    args = parser.parse_args()
    report = prepare_preflight(
        plan_id="j1d-execution-infrastructure-20260722-r1",
        created_at=datetime.now(timezone.utc).isoformat(),
        reviewed_design_path=DEFAULT_ROOT
        / "execution-design-review-20260722-r1/execution-design.operator-reviewed.json",
        design_gate_path=DEFAULT_ROOT
        / "execution-design-review-20260722-r1/execution-design-review-gate-report.json",
        reviewed_assignment_path=DEFAULT_ROOT
        / "cohort-assignment-review-20260722-r1/cohort-assignment.operator-reviewed.json",
        assignment_gate_path=DEFAULT_ROOT
        / "cohort-assignment-review-20260722-r1/cohort-assignment-gate-report.json",
        signed_advice_manifest_path=DEFAULT_ROOT
        / "treatment-advice-signing-20260722-r1/treatment-advice-manifest.signed.json",
        signed_advice_gate_path=DEFAULT_ROOT
        / "treatment-advice-signing-20260722-r1/treatment-advice-gate-report.json",
        provisioning_report_path=DEFAULT_ROOT
        / "participant-provisioning-20260721-r1/provisioning-report.json",
        profiles_root=DEFAULT_ROOT / "participant-provisioning-20260721-r1/profiles",
        provider_admission_report_path=Path(
            "/home/cc/.local/state/civitasos/"
            "j1d-qualification-admission-20260719-r1/report.json"
        ),
        repository_root=args.repository_root,
        output_root=args.output_root,
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
