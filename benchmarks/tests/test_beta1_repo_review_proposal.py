from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta1_repo_review_proposal.py"
spec = importlib.util.spec_from_file_location("beta1_repo_review_proposal", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

EXPORT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta1_export_l1_packet.py"
export_spec = importlib.util.spec_from_file_location("beta1_export_l1_packet", EXPORT_SCRIPT)
assert export_spec and export_spec.loader
export_module = importlib.util.module_from_spec(export_spec)
sys.modules[export_spec.name] = export_module
export_spec.loader.exec_module(export_module)

BETA2_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta2_patch_proposal.py"
beta2_spec = importlib.util.spec_from_file_location("beta2_patch_proposal", BETA2_SCRIPT)
assert beta2_spec and beta2_spec.loader
beta2_module = importlib.util.module_from_spec(beta2_spec)
sys.modules[beta2_spec.name] = beta2_module
beta2_spec.loader.exec_module(beta2_module)

RUNNER_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta1_real_repo_review_runner.py"
runner_spec = importlib.util.spec_from_file_location("beta1_real_repo_review_runner", RUNNER_SCRIPT)
assert runner_spec and runner_spec.loader
runner_module = importlib.util.module_from_spec(runner_spec)
sys.modules[runner_spec.name] = runner_module
runner_spec.loader.exec_module(runner_module)


def test_prepare_writes_proposal_only_request_and_task_payload(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    out = tmp_path / "beta1"

    report = module.prepare_request(
        repo=repo,
        output_root=out,
        request_id="beta1-test-001",
        request_text="Review this repo state and produce a proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-reviewer",
    )

    request = json.loads(Path(report["request_path"]).read_text(encoding="utf-8"))
    task = json.loads(Path(report["task_payload_path"]).read_text(encoding="utf-8"))
    assert report["prepared"] is True
    assert request["schema_version"] == module.REQUEST_SCHEMA
    assert request["mode"] == "proposal_only"
    assert request["operator_decision_required"] is True
    assert request["repo_snapshot"]["status_short"]
    assert "merge" in request["forbidden_actions"]
    assert request["h3_boundary"]["h3_remains_blocked"] is True
    assert request["h3_boundary"]["production_runtime_execution_allowed"] is False
    assert task["schema_version"] == module.TASK_SCHEMA
    assert task["proposal_request_sha256"] == module._sha256(Path(report["request_path"]))
    assert "Operator Decision Required" in task["required_sections"]


def test_receipt_writes_hash_bound_decision_and_audit_record(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    out = tmp_path / "beta1"
    report = module.prepare_request(
        repo=repo,
        output_root=out,
        request_id="beta1-test-002",
        request_text="Review this repo state and produce a proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-reviewer",
    )
    proposal = _write_proposal(out / "proposal.md")
    audit_output = out / "packet" / "sinks" / "audit-events.jsonl"
    receipt_path = out / "operator_decision_receipt.json"

    receipt_report = module.write_operator_receipt(
        request_path=Path(report["request_path"]),
        proposal_path=proposal,
        output_path=receipt_path,
        decision="approved",
        operator_id="operator-001",
        reason="proposal accepted for manual follow-up only",
        audit_output_path=audit_output,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    validation = module.validate_receipt(receipt_path=receipt_path)

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    audit_rows = [json.loads(line) for line in audit_output.read_text(encoding="utf-8").splitlines()]
    assert receipt_report["receipt_written"] is True
    assert validation["passed"] is True
    assert receipt["decision_scope"] == "proposal_review_only"
    assert receipt["merge_allowed"] is False
    assert receipt["push_allowed"] is False
    assert receipt["deploy_allowed"] is False
    assert receipt["production_runtime_execution_allowed"] is False
    assert receipt["production_receipt_write_allowed"] is False
    assert audit_rows == [
        {
            "type": "audit_event_recorded",
            "actor_id": "audit-owner-001",
            "status": "recorded",
            "audit_event_ref": "beta1-operator-decision:beta1-test-002",
            "audit_ref_kind": "beta1_repo_review_operator_decision_receipt",
            "recorded_at": audit_rows[0]["recorded_at"],
            "source_evidence_ref": str(receipt_path.resolve()),
            "request_id": "beta1-test-002",
            "decision": "approved",
            "decision_scope": "proposal_review_only",
            "merge_allowed": False,
            "push_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "non_claims": list(module.NON_CLAIMS),
        }
    ]


def test_validate_receipt_fails_closed_on_dangerous_flag(tmp_path: Path) -> None:
    receipt_path = _write_valid_receipt(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["merge_allowed"] = True
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    validation = module.validate_receipt(receipt_path=receipt_path)

    assert validation["passed"] is False
    assert "merge_allowed must be false" in validation["failure_reasons"]


def test_validate_receipt_fails_closed_on_proposal_hash_mismatch(tmp_path: Path) -> None:
    receipt_path = _write_valid_receipt(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    proposal = Path(receipt["proposal_artifact"]["path"])
    proposal.write_text(proposal.read_text(encoding="utf-8") + "\nmutated\n", encoding="utf-8")

    validation = module.validate_receipt(receipt_path=receipt_path)

    assert validation["passed"] is False
    assert "proposal_artifact.sha256 does not match file bytes" in validation["failure_reasons"]


def test_export_beta1_l1_packet_writes_importable_packet_shape(tmp_path: Path) -> None:
    receipt_path = _write_valid_receipt(tmp_path)
    run_root = receipt_path.parent
    (run_root / "external_model_summary.json").write_text(
        json.dumps({
            "schema_version": "beta1-external-model-proposal-run-summary:v1",
            "model": "deepseek-test",
            "boundary": "proposal_only; H.3 remains blocked",
        }),
        encoding="utf-8",
    )
    packet_root = tmp_path / "packet"

    report = export_module.export_beta1_l1_packet(
        run_root=run_root,
        packet_root=packet_root,
        operator_id="operator-001",
        observer_actor_id="observer-001",
        registrar_actor_id="agent-registrar-001",
        agent_observer_actor_id="agent-observer-001",
        audit_actor_id="audit-owner-001",
        external_agent_id="deepseek-reviewer",
        overwrite=False,
    )

    assert report["exported"] is True
    assert report["requires_packet_manifest_refresh"] is True
    audit_rows = [
        json.loads(line)
        for line in (packet_root / "sinks" / "audit-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    external_rows = [
        json.loads(line)
        for line in (packet_root / "sinks" / "external-agent-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    receipt_rows = [
        json.loads(line)
        for line in (packet_root / "sinks" / "receipt-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {row["type"] for row in audit_rows} == {"audit_event_recorded"}
    assert [row["type"] for row in external_rows] == [
        "external_agent_registered",
        "external_agent_message_observed",
    ]
    assert receipt_rows[0]["type"] == "receipt_sink_ready"
    assert receipt_rows[0]["source_evidence_ref"] == str(run_root / "operator_decision_receipt.json")


def test_runner_helpers_normalize_model_endpoint_and_reject_ignored_untracked(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    (repo / ".gitignore").write_text("secret.txt\n", encoding="utf-8")
    (repo / "secret.txt").write_text("do-not-send\n", encoding="utf-8")

    assert runner_module.normalize_model_name("openai:deepseek-v4-flash") == "deepseek-v4-flash"
    assert runner_module.chat_completions_endpoint("https://api.example.com/v1") == (
        "https://api.example.com/v1/chat/completions"
    )
    try:
        runner_module.build_review_context(
            repo=repo,
            base_ref=None,
            include_untracked_paths=[Path("secret.txt")],
            max_chars=10_000,
        )
    except ValueError as exc:
        assert "refusing to include ignored path" in str(exc)
    else:
        raise AssertionError("ignored untracked paths must not be included in model context")


def _write_valid_receipt(tmp_path: Path) -> Path:
    repo = _write_git_repo(tmp_path)
    out = tmp_path / "beta1"
    report = module.prepare_request(
        repo=repo,
        output_root=out,
        request_id="beta1-test-valid",
        request_text="Review this repo state and produce a proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-reviewer",
    )
    proposal = _write_proposal(out / "proposal.md")
    receipt_path = out / "operator_decision_receipt.json"
    module.write_operator_receipt(
        request_path=Path(report["request_path"]),
        proposal_path=proposal,
        output_path=receipt_path,
        decision="deferred",
        operator_id="operator-001",
        reason="needs another human review",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    return receipt_path


def _write_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")
    (repo / "README.md").write_text("initial\nchanged\n", encoding="utf-8")
    return repo


def _write_proposal(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                "# Proposal",
                "## Scope",
                "Proposal-only repository review.",
                "## Repository Evidence",
                "Dirty README.md change observed.",
                "## Findings",
                "No code mutation performed.",
                "## Proposal",
                "Keep this as a manual follow-up candidate.",
                "## Risks",
                "Requires operator review.",
                "## Operator Decision Required",
                "Do not merge without explicit operator decision.",
                "## H3 Boundary",
                "H.3 remains blocked; no production runtime execution; no production receipt writes.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
