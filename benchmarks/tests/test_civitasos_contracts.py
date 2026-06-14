from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from civitasos_contracts.artifacts import (  # noqa: E402
    ARTIFACT_ENVELOPE_SCHEMA,
    artifact_ref,
    build_artifact_envelope,
    validate_artifact_envelope,
)
from civitasos_contracts.auth import CivitasHttpClient  # noqa: E402
from civitasos_contracts.provenance import (  # noqa: E402
    build_git_release_provenance,
    build_governance_evidence,
    build_runtime_evidence,
)


@pytest.mark.parametrize("kind", ["task", "review", "approval", "receipt"])
def test_canonical_artifact_envelope_supports_all_contract_kinds(
    tmp_path: Path,
    kind: str,
) -> None:
    source = tmp_path / "source.json"
    source.write_text("{}\n", encoding="utf-8")

    envelope = build_artifact_envelope(
        artifact_kind=kind,
        plane="governance" if kind in {"review", "approval"} else "runtime",
        schema_version=f"legacy-{kind}:v1",
        artifact_id=f"{kind}:1",
        subject_id="subject:1",
        producer="test",
        source_refs=[artifact_ref(source)],
        scope="bounded_test",
    )

    assert envelope["schema_version"] == ARTIFACT_ENVELOPE_SCHEMA
    assert envelope["artifact_kind"] == kind
    assert envelope["payload_schema_version"] == f"legacy-{kind}:v1"
    assert validate_artifact_envelope(envelope) == []


def test_provenance_planes_do_not_promote_git_to_runtime_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_text("{}\n", encoding="utf-8")
    ref = artifact_ref(source)

    runtime = build_runtime_evidence({"task_receipt": ref})
    governance = build_governance_evidence({"operator_approval": ref})
    release = build_git_release_provenance(
        {"merge_receipt": ref},
        actions_observed={"merge": True},
    )

    assert runtime["refs"] == {"task_receipt": ref}
    assert governance["refs"] == {"operator_approval": ref}
    assert release["runtime_evidence"] is False
    assert release["actions_observed"]["merge"] is True
    assert release["actions_performed_by_current_step"]["merge"] is False


def test_canonical_auth_client_fails_closed_without_required_service_secret() -> None:
    client = CivitasHttpClient(
        "http://backend",
        require_service_token=True,
        required_service_token_error="strict auth secret missing",
    )

    with pytest.raises(RuntimeError, match="strict auth secret missing"):
        client.get("/api/v1/a2a/agents")
    assert client.auth_context()["auth_method"] == "missing_required_service_token"
