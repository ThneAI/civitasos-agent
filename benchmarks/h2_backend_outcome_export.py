"""Export H.2 backend delayed outcome events as a release artifact.

The exporter is intentionally read-only: it calls the backend
``/api/v1/a2a/outcomes/events`` read model once, validates the returned schema,
and writes the JSON artifact consumed by ``h2_outcome_report.py``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


SCHEMA_VERSION = "h2-delayed-outcome-events:v1"
DEFAULT_BACKEND_URL = "http://localhost:8099"
DEFAULT_LIMIT = 500


class BackendOutcomeExportError(RuntimeError):
    """Raised when backend outcome export cannot produce a valid artifact."""


def export_backend_outcome_events(
    *,
    backend_url: str,
    output_path: Path,
    agent_id: str | None = None,
    requester_id: str | None = None,
    relation_id: str | None = None,
    task_id: str | None = None,
    event_kind: str | None = None,
    since: str | None = None,
    limit: int | None = DEFAULT_LIMIT,
    timeout_s: float = 20.0,
    allow_truncated: bool = False,
) -> dict[str, Any]:
    payload = fetch_backend_outcome_events(
        backend_url=backend_url,
        agent_id=agent_id,
        requester_id=requester_id,
        relation_id=relation_id,
        task_id=task_id,
        event_kind=event_kind,
        since=since,
        limit=limit,
        timeout_s=timeout_s,
    )
    validate_backend_outcome_events_payload(payload, allow_truncated=allow_truncated)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def fetch_backend_outcome_events(
    *,
    backend_url: str,
    agent_id: str | None = None,
    requester_id: str | None = None,
    relation_id: str | None = None,
    task_id: str | None = None,
    event_kind: str | None = None,
    since: str | None = None,
    limit: int | None = DEFAULT_LIMIT,
    timeout_s: float = 20.0,
) -> dict[str, Any]:
    url = build_outcome_events_url(
        backend_url=backend_url,
        agent_id=agent_id,
        requester_id=requester_id,
        relation_id=relation_id,
        task_id=task_id,
        event_kind=event_kind,
        since=since,
        limit=limit,
    )
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise BackendOutcomeExportError(
            f"backend outcome export HTTP {exc.code} from {url}: {body}"
        ) from exc
    except URLError as exc:
        raise BackendOutcomeExportError(
            f"backend outcome export failed to reach {url}: {exc.reason}"
        ) from exc
    except OSError as exc:
        raise BackendOutcomeExportError(
            f"backend outcome export failed to read {url}: {exc}"
        ) from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BackendOutcomeExportError(
            f"backend outcome export returned invalid JSON from {url}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise BackendOutcomeExportError(
            f"backend outcome export payload must be a JSON object from {url}"
        )
    return payload


def build_outcome_events_url(
    *,
    backend_url: str,
    agent_id: str | None = None,
    requester_id: str | None = None,
    relation_id: str | None = None,
    task_id: str | None = None,
    event_kind: str | None = None,
    since: str | None = None,
    limit: int | None = DEFAULT_LIMIT,
) -> str:
    base = backend_url.strip().rstrip("/")
    if not base:
        raise BackendOutcomeExportError("backend_url must not be empty")
    params = _query_params(
        agent_id=agent_id,
        requester_id=requester_id,
        relation_id=relation_id,
        task_id=task_id,
        event_kind=event_kind,
        since=since,
        limit=limit,
    )
    query = urlencode(params)
    url = f"{base}/api/v1/a2a/outcomes/events"
    return f"{url}?{query}" if query else url


def validate_backend_outcome_events_payload(
    payload: dict[str, Any],
    *,
    allow_truncated: bool = False,
) -> None:
    failures: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        failures.append(
            "schema_version mismatch: "
            f"{payload.get('schema_version')!r} != {SCHEMA_VERSION!r}"
        )
    events = payload.get("events")
    if not isinstance(events, list):
        failures.append("events must be an array")
        events = []
    total = _json_int(payload.get("total"), "total", failures)
    returned = _json_int(payload.get("returned"), "returned", failures)
    if returned is not None and returned != len(events):
        failures.append(f"returned={returned} does not match len(events)={len(events)}")
    if total is not None and returned is not None:
        if total < returned:
            failures.append(f"total={total} is smaller than returned={returned}")
        if returned < total and not allow_truncated:
            failures.append(
                f"outcome events artifact is truncated: returned={returned}, total={total}"
            )
    for index, event in enumerate(events, start=1):
        _validate_event(event, index=index, failures=failures)
    if failures:
        raise BackendOutcomeExportError("; ".join(failures))


def _query_params(
    *,
    agent_id: str | None,
    requester_id: str | None,
    relation_id: str | None,
    task_id: str | None,
    event_kind: str | None,
    since: str | None,
    limit: int | None,
) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in (
        ("agent_id", agent_id),
        ("requester", requester_id),
        ("relation_id", relation_id),
        ("task_id", task_id),
        ("event_kind", event_kind),
        ("since", since),
    ):
        if value is not None and str(value).strip():
            params[key] = str(value).strip()
    if limit is not None:
        if limit <= 0:
            raise BackendOutcomeExportError("limit must be greater than zero")
        params["limit"] = str(limit)
    return params


def _validate_event(event: object, *, index: int, failures: list[str]) -> None:
    if not isinstance(event, dict):
        failures.append(f"events[{index}] must be an object")
        return
    required = (
        "event_id",
        "agent_alias",
        "task_id",
        "event_kind",
        "observed_at",
        "source",
        "subject",
        "evidence_ref",
        "verifier_or_settlement_read",
    )
    missing = [key for key in required if event.get(key) in (None, "")]
    if missing:
        failures.append(f"events[{index}] missing {missing}")
    evidence_ref = event.get("evidence_ref")
    if isinstance(evidence_ref, str):
        return
    if not isinstance(evidence_ref, dict) or not evidence_ref.get("ref_id"):
        failures.append(f"events[{index}].evidence_ref must include ref_id")


def _json_int(value: object, name: str, failures: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        failures.append(f"{name} must be an integer")
        return None
    return value


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main(argv: list[str] | None = None) -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend-url",
        default=os.environ.get("BACKEND_URL", DEFAULT_BACKEND_URL),
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--requester", default="")
    parser.add_argument("--relation-id", default="")
    parser.add_argument("--task-id", default="")
    parser.add_argument("--event-kind", default="")
    parser.add_argument("--since", default="")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--timeout-s", type=float, default=20.0)
    parser.add_argument("--allow-truncated", action="store_true")
    args = parser.parse_args(argv)
    output = _resolve_path(Path(args.output), agent_root)
    try:
        payload = export_backend_outcome_events(
            backend_url=args.backend_url,
            output_path=output,
            agent_id=args.agent_id or None,
            requester_id=args.requester or None,
            relation_id=args.relation_id or None,
            task_id=args.task_id or None,
            event_kind=args.event_kind or None,
            since=args.since or None,
            limit=args.limit,
            timeout_s=args.timeout_s,
            allow_truncated=args.allow_truncated,
        )
    except BackendOutcomeExportError as exc:
        print(f"H2 backend outcome export failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())