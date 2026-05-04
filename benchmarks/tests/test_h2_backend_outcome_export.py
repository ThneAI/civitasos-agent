from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from benchmarks import h2_backend_outcome_export as exporter


class _Response:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_export_backend_outcome_events_writes_complete_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = _payload([_event("task_backend_1")])
    seen: dict[str, object] = {}

    def fake_urlopen(request: object, timeout: float) -> _Response:
        seen["url"] = request.full_url  # type: ignore[attr-defined]
        seen["headers"] = dict(request.header_items())  # type: ignore[attr-defined]
        seen["timeout"] = timeout
        return _Response(payload)

    monkeypatch.setattr(exporter, "urlopen", fake_urlopen)
    output = tmp_path / "backend_outcome_events.json"

    result = exporter.export_backend_outcome_events(
        backend_url="http://backend/",
        output_path=output,
        agent_id="did:alpha",
        requester_id="benchmark-suite",
        event_kind="post_delivery_dispute",
        timeout_s=7.5,
    )

    assert result == payload
    assert json.loads(output.read_text(encoding="utf-8")) == payload
    parsed = urlparse(str(seen["url"]))
    assert parsed.scheme == "http"
    assert parsed.netloc == "backend"
    assert parsed.path == "/api/v1/a2a/outcomes/events"
    query = parse_qs(parsed.query)
    assert query["agent_id"] == ["did:alpha"]
    assert query["requester"] == ["benchmark-suite"]
    assert query["event_kind"] == ["post_delivery_dispute"]
    assert query["limit"] == ["500"]
    assert seen["headers"]["Accept"] == "application/json"
    assert seen["timeout"] == 7.5


def test_export_backend_outcome_events_fails_closed_when_truncated(tmp_path: Path) -> None:
    payload = _payload([_event("task_backend_1")], total=2, returned=1)

    with pytest.raises(exporter.BackendOutcomeExportError, match="truncated"):
        exporter.validate_backend_outcome_events_payload(payload)

    exporter.validate_backend_outcome_events_payload(payload, allow_truncated=True)


def test_export_backend_outcome_events_rejects_invalid_schema(tmp_path: Path) -> None:
    payload = _payload([_event("task_backend_1")])
    payload["schema_version"] = "wrong"

    with pytest.raises(exporter.BackendOutcomeExportError, match="schema_version"):
        exporter.validate_backend_outcome_events_payload(payload)


def test_export_backend_outcome_events_rejects_malformed_event(tmp_path: Path) -> None:
    payload = _payload([{"event_id": "missing-fields"}])

    with pytest.raises(exporter.BackendOutcomeExportError, match="missing"):
        exporter.validate_backend_outcome_events_payload(payload)


def _payload(
    events: list[dict],
    *,
    total: int | None = None,
    returned: int | None = None,
) -> dict:
    event_count = len(events)
    return {
        "schema_version": "h2-delayed-outcome-events:v1",
        "source": "backend_task_pool_read_model",
        "events": events,
        "total": event_count if total is None else total,
        "returned": event_count if returned is None else returned,
        "limit": 500,
        "filters": {},
    }


def _event(task_id: str) -> dict:
    return {
        "event_id": f"backend-task-outcome:{task_id}:disputed",
        "agent_alias": "did:alpha",
        "agent_id": "did:alpha",
        "requester": "benchmark-suite",
        "task_id": task_id,
        "event_kind": "post_delivery_dispute",
        "observed_at": "2026-05-04T02:00:00+00:00",
        "source": "backend_task_pool_read_model",
        "subject": "did:alpha",
        "evidence_ref": {
            "ref_id": f"task_pool:{task_id}:disputed",
            "source": "backend_task_pool_read_model",
            "task_status": "Disputed",
        },
        "verifier_or_settlement_read": True,
        "outcome_status": "disputed",
        "dispute_ref": f"task_failure:{task_id}",
    }