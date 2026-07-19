from __future__ import annotations

import copy
import json
from pathlib import Path

from benchmarks.j1.qualification_admission import (
    REPORT_SCHEMA,
    evaluate_admission,
    validate_request,
)
from benchmarks.j1_qualification_admission_gate import (
    DEFAULT_REQUEST,
    GATE_SCHEMA,
    run_gate,
)


def _request() -> dict:
    return json.loads(DEFAULT_REQUEST.read_text(encoding="utf-8"))


def _env(path: Path, *, api_key: str = "qualification-secret-key") -> Path:
    path.write_text(
        "\n".join(
            (
                "BETA6_EXTERNAL_AGENT_PROVIDER=openai_compatible",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://api.deepseek.com",
                "BETA6_EXTERNAL_AGENT_MODEL=deepseek-v4-pro",
                f"BETA6_EXTERNAL_AGENT_API_KEY={api_key}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_admission_request_is_valid() -> None:
    assert validate_request(_request()) == []


def test_provider_admission_records_metadata_without_secret(tmp_path: Path) -> None:
    env = _env(tmp_path / ".env.private")

    report = evaluate_admission(_request(), env_file=env)

    assert report["schema_version"] == REPORT_SCHEMA
    assert report["passed"] is True
    assert report["provider_admission"]["host"] == "api.deepseek.com"
    assert report["provider_admission"]["api_key_present"] is True
    assert report["provider_admission"]["api_key_recorded"] is False
    assert "qualification-secret-key" not in json.dumps(report)
    assert report["readiness"]["qualification_protocol_frozen"] is False
    assert report["readiness"]["controlled_experiment_execution_ready"] is False


def test_gate_rejects_all_fault_controls_and_remains_nonexecuting(
    tmp_path: Path,
) -> None:
    env = _env(tmp_path / ".env.private")
    output = tmp_path / "report.json"

    report = run_gate(
        request_path=DEFAULT_REQUEST,
        env_file=env,
        output_path=output,
    )

    assert report["schema_version"] == GATE_SCHEMA
    assert report["passed"] is True
    assert len(report["negative_controls"]) == 6
    assert all(item["rejected"] for item in report["negative_controls"])
    assert report["checks"]["no_network_or_model_invocation"] is True
    assert report["readiness"]["real_participant_roster_bound"] is False
    assert output.stat().st_mode & 0o777 == 0o600
    assert "qualification-secret-key" not in output.read_text(encoding="utf-8")


def test_admission_rejects_public_env_permissions_and_missing_key(
    tmp_path: Path,
) -> None:
    env = _env(tmp_path / ".env.public", api_key="")
    env.chmod(0o644)

    report = evaluate_admission(_request(), env_file=env)

    assert report["passed"] is False
    assert "provider_env_permissions_not_private" in report["failure_reasons"]
    assert "provider_api_key_missing" in report["failure_reasons"]


def test_admission_rejects_provider_drift(tmp_path: Path) -> None:
    env = _env(tmp_path / ".env.private")
    request = copy.deepcopy(_request())
    request["provider"]["model"] = "deepseek-other"

    report = evaluate_admission(request, env_file=env)

    assert report["passed"] is False
    assert "configured_provider_model_mismatch" in report["failure_reasons"]


def test_gate_rejects_development_protocol_binding_drift(tmp_path: Path) -> None:
    request = _request()
    request["source_development_protocol_sha256"] = "0" * 64
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    report = run_gate(
        request_path=request_path,
        env_file=_env(tmp_path / ".env.private"),
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert report["checks"]["source_development_protocol_bound"] is False


def test_gate_fails_closed_for_missing_request(tmp_path: Path) -> None:
    report = run_gate(
        request_path=tmp_path / "missing.json",
        env_file=_env(tmp_path / ".env.private"),
        output_path=tmp_path / "report.json",
    )

    assert report["passed"] is False
    assert "admission_request_unreadable" in report["failure_reasons"]
    assert report["readiness"]["controlled_experiment_execution_ready"] is False
