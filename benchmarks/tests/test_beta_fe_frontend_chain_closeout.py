from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location(
    "beta_fe_frontend_chain_closeout",
    SCRIPTS / "beta_fe_frontend_chain_closeout.py",
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_closeout_writes_hash_bound_summary_and_handoff(tmp_path: Path) -> None:
    mediation, stages = _chain_artifacts(tmp_path / "chain", "chain-a", pr_number=4)

    handoff = module.closeout_frontend_chain(
        chain_id="chain-a",
        mediation_summary=mediation,
        stage_paths=stages,
        output_root=tmp_path / "out",
        roles={"operator": "operator", "monitoring_owner": "monitor", "audit_owner": "audit"},
    )

    assert handoff["passed"] is True
    assert handoff["decision"] == "beta_fe_frontend_operator_handoff_ready"
    assert handoff["handoff_metrics"]["pool_task_count"] == 4
    assert handoff["handoff_metrics"]["passed_gate_count"] == 8
    assert handoff["handoff_metrics"]["preview_check_count"] == 3
    assert handoff["handoff_boundary"]["merge_allowed"] is False
    assert (tmp_path / "out" / "frontend_release_chain_summary.json").is_file()


def test_closeout_blocks_broken_stage_hash_chain(tmp_path: Path) -> None:
    mediation, stages = _chain_artifacts(tmp_path / "chain", "chain-a", pr_number=4)
    fe5 = json.loads(stages["fe5"].read_text(encoding="utf-8"))
    fe5["source_fe4_receipt"]["sha256"] = "0" * 64
    stages["fe5"].write_text(json.dumps(fe5), encoding="utf-8")

    handoff = module.closeout_frontend_chain(
        chain_id="chain-a",
        mediation_summary=mediation,
        stage_paths=stages,
        output_root=tmp_path / "out",
        roles={"operator": "operator", "monitoring_owner": "monitor", "audit_owner": "audit"},
    )

    assert handoff["passed"] is False
    assert any("fe5.source_fe4_receipt sha256 mismatch" in item for item in handoff["failure_reasons"])


def test_cumulative_index_aggregates_two_chains(tmp_path: Path) -> None:
    handoffs = []
    for index, chain_id in enumerate(("chain-a", "chain-b"), start=1):
        mediation, stages = _chain_artifacts(tmp_path / chain_id, chain_id, pr_number=index)
        output = tmp_path / f"out-{chain_id}"
        module.closeout_frontend_chain(
            chain_id=chain_id,
            mediation_summary=mediation,
            stage_paths=stages,
            output_root=output,
            roles={"operator": "operator", "monitoring_owner": "monitor", "audit_owner": "audit"},
        )
        handoffs.append(output / "frontend_release_operator_handoff.json")

    report = module.write_cumulative_index(
        handoff_paths=handoffs,
        output_path=tmp_path / "index.json",
        min_chains=2,
    )

    assert report["passed"] is True
    assert report["chain_count"] == 2
    assert report["total_gate_receipt_count"] == 16
    assert report["total_pool_task_count"] == 8
    assert report["unique_participant_count"] == 4
    assert report["index_boundary"]["deploy_allowed"] is False


def _chain_artifacts(root: Path, chain_id: str, pr_number: int) -> tuple[Path, dict[str, Path]]:
    root.mkdir(parents=True)
    mediation = root / "mediation.json"
    inner = _write(root / "inner.json", {"passed": True})
    reconciliation = _write(root / "reconciliation.json", {"passed": True})
    _write(
        mediation,
        {
            "schema_version": "test-mediation:v1",
            "passed": True,
            "decision": "passed",
            "participants": ["deepseek", "claude", "hermes", "ollama"],
            "task_receipt_count": 4,
            "claim_observed_count": 4,
            "generation_after_claim_observed_count": 4,
            "delivery_observed_count": 4,
            "mediation_summary": _ref(inner),
            "reconciliation": _ref(reconciliation),
            "boundary": _safe_stage_boundary(),
            "h3_boundary": _h3(),
        },
    )
    commit_id = f"{pr_number}" * 40
    merge_commit = f"{pr_number + 1}" * 40
    stages: dict[str, Path] = {}
    common = {"passed": True, "h3_boundary": _h3()}
    stages["fe3"] = _write_stage(
        root,
        "fe3",
        {**common, "source_fe26_summary": _ref(mediation), "changed_files": ["src/App.tsx"], "boundary": _safe_stage_boundary()},
    )
    stages["fe4"] = _write_stage(
        root,
        "fe4",
        {**common, "source_fe3_receipt": _ref(stages["fe3"]), "commit_id": commit_id, "boundary": _safe_stage_boundary()},
    )
    stages["fe5"] = _write_stage(
        root,
        "fe5",
        {
            **common,
            "source_fe4_receipt": _ref(stages["fe4"]),
            "commit_id": commit_id,
            "remote_branch_after_head": commit_id,
            "boundary": _safe_stage_boundary(),
        },
    )
    draft_pr = {
        "number": pr_number,
        "url": f"https://example.test/pr/{pr_number}",
        "headRefOid": commit_id,
        "headRefName": f"feature/{chain_id}",
        "baseRefName": "main",
    }
    stages["fe6"] = _write_stage(
        root,
        "fe6",
        {**common, "source_fe5_receipt": _ref(stages["fe5"]), "draft_pr": draft_pr, "boundary": _safe_stage_boundary()},
    )
    stages["fe7"] = _write_stage(
        root,
        "fe7",
        {
            **common,
            "source_fe6_receipt": _ref(stages["fe6"]),
            "pr": draft_pr,
            "review_reconciliation": {
                "merge_ready": True,
                "all_agent_verdicts": {"a": "approved", "b": "approved"},
            },
            "boundary": _safe_stage_boundary(),
        },
    )
    stages["fe8"] = _write_stage(
        root,
        "fe8",
        {
            **common,
            "source_fe7_reconciliation": _ref(stages["fe7"]),
            "base_branch_after_head": merge_commit,
            "pr": {
                "number": pr_number,
                "state": "MERGED",
                "mergeCommit": {"oid": merge_commit},
            },
            "boundary": _safe_stage_boundary(),
        },
    )
    stages["fe9"] = _write_stage(
        root,
        "fe9",
        {
            **common,
            "source_fe8_receipt": _ref(stages["fe8"]),
            "merge_commit": merge_commit,
            "remote_head": merge_commit,
            "local_head": merge_commit,
            "verification_commands": [{"returncode": 0}],
            "boundary": _safe_stage_boundary(),
        },
    )
    stages["fe10"] = _write_stage(
        root,
        "fe10",
        {
            **common,
            "source_fe9_receipt": _ref(stages["fe9"]),
            "frontend_checks": [{"status_code": 200}],
            "backend_read_model_checks": [{"status_code": 200}, {"status_code": 200}],
            "backend_auth": {"auth_method": "service_token"},
            "boundary": _safe_stage_boundary(),
        },
    )
    return mediation, stages


def _write_stage(root: Path, stage: str, extra: dict) -> Path:
    schema, decision = module.STAGES[stage]
    return _write(root / f"{stage}.json", {"schema_version": schema, "decision": decision, **extra})


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": module._sha256(path)}


def _safe_stage_boundary() -> dict[str, bool]:
    return {
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _h3() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}
