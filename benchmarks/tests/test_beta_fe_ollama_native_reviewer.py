from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_fe_ollama_native_reviewer", SCRIPTS / "beta_fe_ollama_native_reviewer.py")


def test_patch_review_uses_native_json_and_disables_thinking() -> None:
    requests = []

    def transport(url, payload, timeout):
        requests.append((url, payload, timeout))
        content = {
            "verdict": "proceed",
            "allowed_files_only": True,
            "reviewed_files": ["src/App.tsx"],
            "findings": [],
            "tests": ["npm test"],
            "summary": "bounded",
        }
        return 200, {"message": {"content": json.dumps(content)}}

    reviewer = module.OllamaNativeReviewer(model="qwen3.6:latest", transport=transport)
    result = reviewer.review_patch_proposal("review this slice")

    assert result.payload["verdict"] == "proceed"
    assert result.report["repair_attempted"] is False
    assert requests[0][0].endswith("/api/chat")
    assert requests[0][1]["think"] is False
    assert requests[0][1]["format"] == "json"
    assert requests[0][1]["options"]["temperature"] == 0


def test_patch_review_repairs_invalid_first_response_once() -> None:
    responses = iter([
        {"message": {"content": "not json"}},
        {
            "message": {
                "content": json.dumps({
                    "verdict": "revise",
                    "allowed_files_only": True,
                    "reviewed_files": ["src/App.tsx"],
                    "findings": ["add rollback assertion"],
                    "tests": ["npm test"],
                    "summary": "repair required",
                })
            }
        },
    ])

    reviewer = module.OllamaNativeReviewer(
        model="qwen3:latest",
        transport=lambda _url, _payload, _timeout: (200, next(responses)),
    )
    result = reviewer.review_patch_proposal("review")

    assert result.payload["verdict"] == "revise"
    assert result.report["attempt_count"] == 2
    assert result.report["repair_attempted"] is True
    assert result.report["attempts"][0]["validation_errors"]


def test_release_review_rejects_unsafe_approval() -> None:
    reviewer = module.OllamaNativeReviewer(
        model="qwen3:latest",
        max_repair_attempts=0,
        transport=lambda _url, _payload, _timeout: (
            200,
            {
                "message": {
                    "content": json.dumps({
                        "verdict": "approved",
                        "risk_level": "low",
                        "allowed_files_only": False,
                        "production_boundary_preserved": True,
                        "reviewed_files": ["src/App.tsx"],
                        "findings": [],
                        "summary": "unsafe approval",
                    })
                }
            },
        ),
    )

    try:
        reviewer.review_release("review")
    except RuntimeError as exc:
        assert "approved requires allowed_files_only=true" in str(exc)
    else:
        raise AssertionError("unsafe approval must fail closed")
