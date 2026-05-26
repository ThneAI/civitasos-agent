from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
_load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
_load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
_load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
_load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
_load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
_load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
_load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")
_load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
_load("beta3_git_publication_authorization", ROOT / "scripts" / "beta3_git_publication_authorization.py")
_load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")
_load("beta3_git_push_executor", ROOT / "scripts" / "beta3_git_push_executor.py")
push_tests = _load(
    "beta3_git_merge_executor_fixture_for_ready_pr_transition",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_merge_executor.py",
)
draft = _load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")
module = _load("beta4_ready_pr_transition_executor", ROOT / "scripts" / "beta4_ready_pr_transition_executor.py")


def test_ready_pr_transition_marks_draft_pr_ready_with_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    draft_receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(draft_receipt.read_text(encoding="utf-8"))
    fake_gh = _fake_gh(receipt_payload)
    monkeypatch.setattr(module, "_gh", fake_gh)
    authorization_path = _write_authorization(tmp_path, draft_receipt)

    report = module.run_ready_pr_transition(
        authorization_path=authorization_path,
        output_root=tmp_path / "ready-pr-transition",
    )
    receipt = json.loads(Path(report["ready_pr_transition_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["ready_transition_performed"] is True
    assert report["ready_pr"]["isDraft"] is False
    assert report["github_review_approval_observed"] is False
    assert report["merge_authorized"] is False
    assert report["merge_performed"] is False
    assert receipt["receipt_scope"] == "github_ready_pr_transition_only"
    assert receipt["ready_pr"]["headRefOid"] == receipt_payload["source_commit_id"]
    assert receipt["deploy_allowed"] is False


def test_ready_pr_transition_authorization_rejects_already_ready_pr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(draft_receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(receipt_payload, initially_ready=True))

    with pytest.raises(ValueError, match="draft PR isDraft must match draft PR receipt"):
        _write_authorization(tmp_path, draft_receipt)


def test_ready_pr_transition_refuses_draft_receipt_as_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    draft_receipt = _write_draft_receipt(tmp_path, monkeypatch)

    report = module.run_ready_pr_transition(
        authorization_path=draft_receipt,
        output_root=tmp_path / "draft-receipt-is-not-transition-authorization",
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["ready_pr_transition_authorization_refused"]
    assert report["ready_transition_performed"] is False
    assert any(
        "schema_version must be beta4-ready-pr-transition-authorization:v1" in reason
        for reason in report["failure_reasons"]
    )


def test_ready_pr_transition_receipt_validation_rejects_merge_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft_receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(draft_receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_gh(receipt_payload))
    authorization_path = _write_authorization(tmp_path, draft_receipt)
    report = module.run_ready_pr_transition(authorization_path=authorization_path, output_root=tmp_path / "ready-pr")
    receipt_path = Path(report["ready_pr_transition_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["merge_performed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_ready_pr_transition_receipt(receipt_path)

    assert validation["passed"] is False
    assert "merge_performed must be false" in validation["failure_reasons"]


def _write_draft_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    authorization_path = tmp_path / "draft_pr_authorization.json"
    draft.record_draft_pr_authorization(
        push_receipt_path=push_receipt,
        github_repo="fixture/repo",
        base_branch="main",
        title="Beta-4 fixture draft PR",
        body_file=_write_body(tmp_path),
        output_path=authorization_path,
        operator_id="operator-001",
        reason="open a bounded draft PR for ready transition evidence",
        rollback_evidence_ref="rollback:close-fixture-pr",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(draft, "_gh", _fake_draft_create_gh(authorization))
    report = draft.run_draft_pr_create(authorization_path=authorization_path, output_root=tmp_path / "draft-pr")
    assert report["passed"] is True
    return Path(report["draft_pr_receipt_path"])


def _write_authorization(tmp_path: Path, draft_receipt: Path) -> Path:
    authorization_path = tmp_path / "ready_pr_transition_authorization.json"
    module.record_ready_pr_transition_authorization(
        draft_pr_receipt_path=draft_receipt,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="mark controlled draft PR ready for review after operator approval",
        rollback_evidence_ref="rollback:convert-ready-pr-back-to-draft-or-close",
    )
    return authorization_path


def _write_body(tmp_path: Path) -> Path:
    body = tmp_path / "draft_pr_body.md"
    body.write_text("Draft review only. Merge and deploy remain separately authorized.\n", encoding="utf-8")
    return body


def _fake_draft_create_gh(authorization: dict[str, object]):
    def run(_repo: Path, _failures: list[str], *args: str, input_text: str | None = None) -> dict[str, object]:
        command = " ".join(["gh", *args])
        if args[:2] == ("pr", "create"):
            assert "--draft" in args
            assert input_text == authorization["body"]["text"]
            return {
                "command": command,
                "returncode": 0,
                "stdout": "https://example.invalid/fixture/repo/pull/17\n",
                "stderr": "",
            }
        assert args[:2] == ("pr", "view")
        return {
            "command": command,
            "returncode": 0,
            "stdout": json.dumps(_pr_metadata(authorization, is_draft=True)),
            "stderr": "",
        }

    return run


def _fake_gh(draft_receipt: dict[str, object], *, initially_ready: bool = False):
    state = {"ready": initially_ready}

    def run(_failures: list[str], *args: str, input_text: str | None = None) -> dict[str, object]:
        command = " ".join(["gh", *args])
        if args[:2] == ("pr", "ready"):
            state["ready"] = True
            return {"command": command, "returncode": 0, "stdout": "", "stderr": ""}
        assert args[:2] == ("pr", "view")
        return {
            "command": command,
            "returncode": 0,
            "stdout": json.dumps(_pr_metadata(draft_receipt, is_draft=not state["ready"])),
            "stderr": "",
        }

    return run


def _pr_metadata(source: dict[str, object], *, is_draft: bool) -> dict[str, object]:
    pr = source.get("draft_pr")
    if not isinstance(pr, dict):
        pr = {
            "number": 17,
            "url": "https://example.invalid/fixture/repo/pull/17",
            "title": source["title"],
        }
    return {
        "number": pr["number"],
        "url": pr["url"],
        "isDraft": is_draft,
        "state": "OPEN",
        "headRefName": source["source_branch"],
        "headRefOid": source["source_commit_id"],
        "baseRefName": source["base_branch"],
        "title": pr["title"],
    }
