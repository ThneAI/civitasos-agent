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
