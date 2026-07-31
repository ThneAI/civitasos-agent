"""Recoverable offline orchestrator primitives for the J1-D r4 contract."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .controlled_comparison import canonical_sha256
from .qualification_execution_contract_v4 import (
    ALLOWED_TRANSITIONS,
    TASK_TERMINAL_STATES,
)
from .qualification_provider_broker import PROVIDER_FAILURE_STAGES


REPORT_SCHEMA = "j1-qualification-r4-offline-orchestrator-report:v1"
LIVE_REPORT_SCHEMA = "j1-qualification-r4-live-orchestrator-report:v1"
PROGRESS_TRANSITIONS = {source: target for source, target in ALLOWED_TRANSITIONS}
BEFORE_DISPATCH_STATES = {
    "planned",
    "input_staged",
    "container_started",
    "request_prepared",
    "budget_reserved",
}
AFTER_RESPONSE_STATES = {
    "provider_response_committed",
    "budget_reconciled",
    "response_staged",
    "decision_finalized",
    "decision_signed",
    "event_trace_verified",
}


class InjectedCrash(RuntimeError):
    """A deterministic process-crash simulation used by the fault matrix."""


@dataclass
class OfflineAdapter:
    """Deterministic adapter with no container, credential, network, or HSM access."""

    provider_calls: int = 0
    participant_signatures: int = 0
    container_starts: int = 0
    container_stops: int = 0

    def start_container(self, task: dict[str, Any]) -> dict[str, Any]:
        self.container_starts += 1
        return {
            "container_name": task["container"]["container_name"],
            "offline_simulated": True,
        }

    def stop_container(self, task: dict[str, Any]) -> None:
        del task
        self.container_stops += 1

    def prepare_request(self, task: dict[str, Any]) -> dict[str, Any]:
        return {
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "task_id": task["task"]["task_id"],
            "advice_mode": task["advice"]["mode"],
            "offline_synthetic": True,
        }

    def prepare_provider(self, task: dict[str, Any]) -> None:
        del task

    def provider_call(
        self, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]:
        self.provider_calls += 1
        return {
            "content": f"offline-decision:{task['task_execution_id']}",
            "request_sha256": canonical_sha256(request),
            "usage": {
                "input_cache_hit": 0,
                "input_cache_miss": 32,
                "output": 16,
                "cost_microunits": 28,
            },
            "offline_synthetic": True,
        }

    def finalize_decision(
        self, task: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "task_execution_id": task["task_execution_id"],
            "participant_id": task["participant_id"],
            "decision_sha256": hashlib.sha256(
                response["content"].encode("utf-8")
            ).hexdigest(),
            "provider_response_sha256": canonical_sha256(response),
            "offline_synthetic": True,
        }

    def sign_decision(
        self, task: dict[str, Any], decision: dict[str, Any]
    ) -> dict[str, Any]:
        self.participant_signatures += 1
        payload = {
            "task_execution_id": task["task_execution_id"],
            "execution_did": task["execution_did"],
            "decision_sha256": canonical_sha256(decision),
        }
        return {
            "algorithm": "offline-test-sha256-not-a-signature",
            "payload_sha256": canonical_sha256(payload),
            "offline_synthetic": True,
        }

    def verify_event_trace(
        self,
        task: dict[str, Any],
        decision: dict[str, Any],
        signature: dict[str, Any],
    ) -> dict[str, Any]:
        del signature
        return {
            "task_execution_id": task["task_execution_id"],
            "event_script": task["task"]["event_script"],
            "decision_sha256": canonical_sha256(decision),
            "verified": True,
            "offline_synthetic": True,
        }

    def event_receipts(self, task: dict[str, Any]) -> dict[str, Any]:
        del task
        return {"receipts": [], "offline_synthetic": True}

    def commit_task_evidence(
        self, task: dict[str, Any], artifacts: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        del task
        return {
            "artifact_sha256": {
                name: canonical_sha256(value)
                for name, value in sorted(artifacts.items())
            },
            "offline_synthetic": True,
        }


class PrivateWorkspace:
    """Mode-0700 run workspace with mode-0600 participant intermediates."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def write(self, task_id: str, name: str, value: dict[str, Any]) -> str:
        path = self._path(task_id, name)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        payload = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        with temporary.open("xb") as stream:
            os.chmod(temporary, 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        return hashlib.sha256(payload).hexdigest()

    def read(self, task_id: str, name: str) -> dict[str, Any]:
        path = self._path(task_id, name)
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"workspace artifact is not an object: {path}")
        return value

    def hash(self, task_id: str, name: str) -> str:
        return hashlib.sha256(self._path(task_id, name).read_bytes()).hexdigest()

    def clear(self, task_id: str) -> None:
        path = self.root / task_id
        if path.exists():
            shutil.rmtree(path)
            _fsync_directory(self.root)

    def _path(self, task_id: str, name: str) -> Path:
        if (
            not task_id
            or "/" in task_id
            or name
            not in {
                "request",
                "response",
                "decision",
                "signature",
                "event_receipts",
                "event_trace",
            }
        ):
            raise ValueError("invalid private workspace key")
        return self.root / task_id / f"{name}.json"


class ExecutionJournal:
    """SQLite WAL journal and budget ledger for one r4 contract."""

    def __init__(self, path: Path, contract_sha256: str) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_states (
                task_execution_id TEXT PRIMARY KEY,
                call_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                task_execution_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                previous_event_sha256 TEXT,
                event_sha256 TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS reservations (
                call_id TEXT PRIMARY KEY,
                task_execution_id TEXT NOT NULL UNIQUE,
                reserved_tokens INTEGER NOT NULL,
                reserved_cost_microunits INTEGER NOT NULL,
                actual_tokens INTEGER,
                actual_cost_microunits INTEGER,
                status TEXT NOT NULL
            );
            """
        )
        existing = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'contract_sha256'"
        ).fetchone()
        if existing is None:
            self.connection.execute(
                "INSERT INTO metadata(key, value) VALUES('contract_sha256', ?)",
                (contract_sha256,),
            )
            self.connection.commit()
        elif existing["value"] != contract_sha256:
            raise ValueError("journal contract binding mismatch")
        self.path.chmod(0o600)

    def initialize_tasks(self, tasks: list[dict[str, Any]]) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for task in tasks:
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO task_states(
                        task_execution_id, call_id, state
                    ) VALUES(?, ?, 'planned')
                    """,
                    (task["task_execution_id"], task["call_id"]),
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def state(self, task_execution_id: str) -> str:
        row = self.connection.execute(
            "SELECT state FROM task_states WHERE task_execution_id = ?",
            (task_execution_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"task is not journaled: {task_execution_id}")
        return str(row["state"])

    def failure_diagnostic(self, task_execution_id: str) -> dict[str, str] | None:
        row = self.connection.execute(
            """
            SELECT to_state, payload_json
            FROM events
            WHERE task_execution_id = ?
              AND to_state IN (
                'task_failed_before_dispatch',
                'task_failed_after_response',
                'provider_outcome_unknown'
              )
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (task_execution_id,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        reason = payload.get("reason")
        category = payload.get("failure_category")
        stage = payload.get("failure_stage")
        source = payload.get("source_exception_type")
        if (
            isinstance(reason, str)
            and isinstance(category, str)
            and isinstance(stage, str)
            and stage in PROVIDER_FAILURE_STAGES.get(category, set())
            and isinstance(source, str)
        ):
            return {
                "reason": reason,
                "failure_category": category,
                "failure_stage": stage,
                "source_exception_type": source,
            }
        if isinstance(reason, str):
            return {
                "reason": reason,
                "failure_category": "internal",
                "failure_stage": (
                    "pre_dispatch_unclassified"
                    if row["to_state"] == "task_failed_before_dispatch"
                    else "legacy_unclassified_post_dispatch"
                ),
                "source_exception_type": reason,
            }
        return None

    def transition(
        self,
        task: dict[str, Any],
        target: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> str:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.state(task["task_execution_id"])
            if not _transition_allowed(current, target):
                raise ValueError(f"invalid r4 task transition: {current} -> {target}")
            previous = self.connection.execute(
                "SELECT event_sha256 FROM events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence_row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS value FROM events"
            ).fetchone()
            sequence = int(sequence_row["value"])
            occurred_at = datetime.now(UTC).isoformat()
            payload_json = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            )
            payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            event_body = {
                "sequence": sequence,
                "task_execution_id": task["task_execution_id"],
                "call_id": task["call_id"],
                "from_state": current,
                "to_state": target,
                "event_type": event_type,
                "occurred_at": occurred_at,
                "payload_sha256": payload_sha256,
                "previous_event_sha256": (
                    str(previous["event_sha256"]) if previous else None
                ),
            }
            event_sha256 = canonical_sha256(event_body)
            event_id = f"r4-event-{event_sha256[:32]}"
            self.connection.execute(
                """
                INSERT INTO events(
                    sequence, event_id, task_execution_id, call_id,
                    from_state, to_state, event_type, occurred_at,
                    payload_json, payload_sha256, previous_event_sha256,
                    event_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    event_id,
                    task["task_execution_id"],
                    task["call_id"],
                    current,
                    target,
                    event_type,
                    occurred_at,
                    payload_json,
                    payload_sha256,
                    event_body["previous_event_sha256"],
                    event_sha256,
                ),
            )
            self.connection.execute(
                "UPDATE task_states SET state = ? WHERE task_execution_id = ?",
                (target, task["task_execution_id"]),
            )
            self.connection.commit()
            return event_sha256
        except Exception:
            self.connection.rollback()
            raise

    def reserve(self, task: dict[str, Any]) -> None:
        reservation = task["reservation"]
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute(
                "SELECT * FROM reservations WHERE call_id = ?", (task["call_id"],)
            ).fetchone()
            expected = (
                task["task_execution_id"],
                reservation["tokens"],
                reservation["cost_microunits"],
            )
            if existing is None:
                self.connection.execute(
                    """
                    INSERT INTO reservations(
                        call_id, task_execution_id, reserved_tokens,
                        reserved_cost_microunits, status
                    ) VALUES(?, ?, ?, ?, 'reserved')
                    """,
                    (task["call_id"], *expected),
                )
            elif (
                existing["task_execution_id"],
                existing["reserved_tokens"],
                existing["reserved_cost_microunits"],
            ) != expected:
                raise ValueError("reservation replay binding mismatch")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def reconcile(self, task: dict[str, Any], usage: dict[str, Any]) -> None:
        actual_tokens = sum(
            int(usage.get(name, 0))
            for name in ("input_cache_hit", "input_cache_miss", "output")
        )
        actual_cost = int(usage.get("cost_microunits", 0))
        reservation = task["reservation"]
        status = (
            "overrun"
            if actual_tokens > reservation["tokens"]
            or actual_cost > reservation["cost_microunits"]
            else "reconciled"
        )
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT status FROM reservations WHERE call_id = ?", (task["call_id"],)
            ).fetchone()
            if row is None:
                raise ValueError("budget reconciliation without reservation")
            if row["status"] not in {"reserved", status}:
                raise ValueError("budget reconciliation replay mismatch")
            self.connection.execute(
                """
                UPDATE reservations
                SET actual_tokens = ?, actual_cost_microunits = ?, status = ?
                WHERE call_id = ?
                """,
                (actual_tokens, actual_cost, status, task["call_id"]),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        if status == "overrun":
            raise ValueError("offline provider usage exceeded reservation")

    def mark_unknown(self, task: dict[str, Any]) -> None:
        self.connection.execute(
            """
            UPDATE reservations
            SET status = 'provider_outcome_unknown'
            WHERE call_id = ? AND status = 'reserved'
            """,
            (task["call_id"],),
        )
        self.connection.commit()

    def mark_failed_before_dispatch(self, task: dict[str, Any]) -> None:
        self.connection.execute(
            """
            UPDATE reservations
            SET status = 'failed_before_dispatch'
            WHERE call_id = ? AND status = 'reserved'
            """,
            (task["call_id"],),
        )
        self.connection.commit()

    def expected_artifact_hash(
        self, task: dict[str, Any], state: str, field: str
    ) -> str:
        row = self.connection.execute(
            """
            SELECT payload_json
            FROM events
            WHERE task_execution_id = ? AND to_state = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (task["task_execution_id"], state),
        ).fetchone()
        if row is None:
            raise ValueError(f"journal commitment missing for state: {state}")
        payload = json.loads(row["payload_json"])
        digest = payload.get(field) if isinstance(payload, dict) else None
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"journal artifact commitment missing: {field}")
        return digest

    def validate(self) -> list[str]:
        failures: list[str] = []
        rows = self.connection.execute(
            "SELECT * FROM events ORDER BY sequence"
        ).fetchall()
        previous: str | None = None
        for expected_sequence, row in enumerate(rows, 1):
            payload_sha256 = hashlib.sha256(
                row["payload_json"].encode("utf-8")
            ).hexdigest()
            body = {
                "sequence": row["sequence"],
                "task_execution_id": row["task_execution_id"],
                "call_id": row["call_id"],
                "from_state": row["from_state"],
                "to_state": row["to_state"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "payload_sha256": row["payload_sha256"],
                "previous_event_sha256": row["previous_event_sha256"],
            }
            if (
                row["sequence"] != expected_sequence
                or row["payload_sha256"] != payload_sha256
                or row["previous_event_sha256"] != previous
                or row["event_sha256"] != canonical_sha256(body)
                or not _transition_allowed(row["from_state"], row["to_state"])
            ):
                failures.append("r4_journal_hash_chain_or_transition_invalid")
                break
            previous = str(row["event_sha256"])
        return failures

    def summary(self) -> dict[str, Any]:
        states = {
            row["state"]: row["count"]
            for row in self.connection.execute(
                "SELECT state, COUNT(*) AS count FROM task_states GROUP BY state"
            )
        }
        budgets = {
            row["status"]: row["count"]
            for row in self.connection.execute(
                "SELECT status, COUNT(*) AS count FROM reservations GROUP BY status"
            )
        }
        event_count = self.connection.execute(
            "SELECT COUNT(*) AS count FROM events"
        ).fetchone()["count"]
        last_event = self.connection.execute(
            "SELECT event_sha256 FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        logical = {
            "task_states": states,
            "budget_states": budgets,
            "event_count": event_count,
            "last_event_sha256": (
                str(last_event["event_sha256"]) if last_event else None
            ),
        }
        logical["journal_sha256"] = canonical_sha256(logical)
        return logical

    def close(self) -> None:
        self.connection.close()


def run_offline_orchestrator(
    *,
    contract: dict[str, Any],
    run_id: str,
    root: Path,
    adapter: OfflineAdapter | None = None,
    checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
    task_limit: int | None = None,
) -> dict[str, Any]:
    """Execute or resume the r4 manifest using only deterministic offline adapters."""
    return _run_orchestrator(
        contract=contract,
        run_id=run_id,
        root=root,
        adapter=adapter or OfflineAdapter(),
        checkpoint=checkpoint,
        task_limit=task_limit,
        live=False,
    )


def run_live_orchestrator(
    *,
    contract: dict[str, Any],
    run_id: str,
    root: Path,
    adapter: Any,
    checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
    task_limit: int | None = None,
) -> dict[str, Any]:
    """Execute or resume a claimed r4 manifest through reviewed live adapters."""
    return _run_orchestrator(
        contract=contract,
        run_id=run_id,
        root=root,
        adapter=adapter,
        checkpoint=checkpoint,
        task_limit=task_limit,
        live=True,
    )


def _run_orchestrator(
    *,
    contract: dict[str, Any],
    run_id: str,
    root: Path,
    adapter: Any,
    checkpoint: Callable[[str, dict[str, Any]], None] | None,
    task_limit: int | None,
    live: bool,
) -> dict[str, Any]:
    actual_adapter = adapter
    journal = ExecutionJournal(
        root / "execution-journal.sqlite3", contract["contract_sha256"]
    )
    workspace = PrivateWorkspace(root / "workspace")
    tasks = contract["task_executions"]
    tasks = tasks[:task_limit] if task_limit is not None else tasks
    journal.initialize_tasks(tasks)
    run_failure: str | None = None
    failure_diagnostic: dict[str, str] | None = None
    try:
        for task in tasks:
            state = journal.state(task["task_execution_id"])
            if state == "dispatch_intent_committed":
                failure_diagnostic = {
                    "reason": "ProcessRecovery",
                    "failure_category": "internal",
                    "failure_stage": "recovery_after_dispatch_intent",
                    "source_exception_type": "ProcessRecovery",
                }
                journal.mark_unknown(task)
                journal.transition(
                    task,
                    "provider_outcome_unknown",
                    "recovery_provider_outcome_unknown",
                    {
                        **failure_diagnostic,
                        "provider_call_performed": True,
                        "provider_retry_performed": False,
                    },
                )
                run_failure = "provider_outcome_unknown"
                break
            if state in TASK_TERMINAL_STATES:
                if state != "task_committed":
                    run_failure = state
                    failure_diagnostic = journal.failure_diagnostic(
                        task["task_execution_id"]
                    )
                    break
                continue
            try:
                _drive_task(
                    task=task,
                    journal=journal,
                    workspace=workspace,
                    adapter=actual_adapter,
                    checkpoint=checkpoint,
                )
            except InjectedCrash:
                raise
            except Exception as error:
                state = journal.state(task["task_execution_id"])
                failure_diagnostic = _sanitized_failure_diagnostic(
                    error,
                    fallback_stage=(
                        "pre_dispatch_unclassified"
                        if state in BEFORE_DISPATCH_STATES
                        else "post_dispatch_unclassified"
                    ),
                )
                if state in BEFORE_DISPATCH_STATES:
                    journal.mark_failed_before_dispatch(task)
                    journal.transition(
                        task,
                        "task_failed_before_dispatch",
                        "task_failed_before_dispatch",
                        {
                            **failure_diagnostic,
                            "provider_call_performed": False,
                        },
                    )
                    run_failure = "task_failed_before_dispatch"
                elif state == "dispatch_intent_committed":
                    journal.mark_unknown(task)
                    journal.transition(
                        task,
                        "provider_outcome_unknown",
                        "provider_outcome_unknown",
                        {
                            **failure_diagnostic,
                            "provider_call_performed": True,
                            "provider_retry_performed": False,
                        },
                    )
                    run_failure = "provider_outcome_unknown"
                elif state in AFTER_RESPONSE_STATES:
                    journal.transition(
                        task,
                        "task_failed_after_response",
                        "task_failed_after_response",
                        {
                            **failure_diagnostic,
                            "provider_call_performed": True,
                            "provider_retry_performed": False,
                        },
                    )
                    run_failure = "task_failed_after_response"
                else:
                    run_failure = "orchestrator_error"
                if state not in TASK_TERMINAL_STATES:
                    actual_adapter.stop_container(task)
                break
    except InjectedCrash:
        raise
    finally:
        journal_failures = journal.validate()
        summary = journal.summary()
        journal.close()
        summary["journal_artifact_sha256"] = hashlib.sha256(
            (root / "execution-journal.sqlite3").read_bytes()
        ).hexdigest()
    state_counts = summary["task_states"]
    committed = int(state_counts.get("task_committed", 0))
    complete = committed == len(tasks) and run_failure is None and not journal_failures
    scope = {
        "task_execution_count": len(tasks),
        "provider_call_count": actual_adapter.provider_calls,
        "participant_signature_count": actual_adapter.participant_signatures,
        "container_start_count": actual_adapter.container_starts,
        "container_stop_count": actual_adapter.container_stops,
    }
    report = {
        "schema_version": LIVE_REPORT_SCHEMA if live else REPORT_SCHEMA,
        "run_id": run_id,
        "status": "complete" if complete else "failed",
        "contract_sha256": contract["contract_sha256"],
        "execution_scope" if live else "offline_scope": scope,
        "journal": summary,
        "failure_reason": run_failure,
        "failure_diagnostic": failure_diagnostic,
        "validation_failures": journal_failures,
        "execution_boundary": (
            actual_adapter.execution_boundary()
            if live
            else {
                "offline_adapter_only": True,
                "real_container_started": False,
                "provider_credential_read": False,
                "provider_api_call_performed": False,
                "model_invocation_performed": False,
                "pkcs11_signature_performed": False,
                "backend_fact_append_performed": False,
                "ledger_append_performed": False,
            }
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _drive_task(
    *,
    task: dict[str, Any],
    journal: ExecutionJournal,
    workspace: PrivateWorkspace,
    adapter: Any,
    checkpoint: Callable[[str, dict[str, Any]], None] | None,
) -> None:
    task_id = task["task_execution_id"]
    state = journal.state(task_id)
    if state == "planned":
        input_digest = workspace.write(task_id, "request", {"task": task})
        journal.transition(
            task, "input_staged", "input_staged", {"input_sha256": input_digest}
        )
        _checkpoint(checkpoint, "after_input_staged", task)
        state = "input_staged"
    if state == "input_staged":
        container = adapter.start_container(task)
        journal.transition(
            task,
            "container_started",
            "offline_container_start_simulated",
            {"container": container},
        )
        _checkpoint(checkpoint, "after_container_started", task)
        state = "container_started"
    if state == "container_started":
        request = adapter.prepare_request(task)
        request_digest = workspace.write(task_id, "request", request)
        journal.transition(
            task,
            "request_prepared",
            "provider_request_prepared",
            {"request_sha256": request_digest},
        )
        _checkpoint(checkpoint, "after_request_prepared", task)
        state = "request_prepared"
    if state == "request_prepared":
        _verify_workspace(
            journal, workspace, task, "request_prepared", "request", "request_sha256"
        )
        adapter.prepare_provider(task)
        journal.reserve(task)
        journal.transition(
            task,
            "budget_reserved",
            "budget_reserved",
            {"reservation": task["reservation"]},
        )
        _checkpoint(checkpoint, "after_budget_reserved", task)
        state = "budget_reserved"
    if state == "budget_reserved":
        _verify_workspace(
            journal, workspace, task, "request_prepared", "request", "request_sha256"
        )
        journal.transition(
            task,
            "dispatch_intent_committed",
            "provider_dispatch_intent_committed",
            {"automatic_retry_allowed": False},
        )
        _checkpoint(checkpoint, "after_dispatch_intent_committed", task)
        state = "dispatch_intent_committed"
    if state == "dispatch_intent_committed":
        _verify_workspace(
            journal, workspace, task, "request_prepared", "request", "request_sha256"
        )
        request = workspace.read(task_id, "request")
        response = adapter.provider_call(task, request)
        _checkpoint(checkpoint, "after_provider_return_before_commit", task)
        response_digest = workspace.write(task_id, "response", response)
        journal.transition(
            task,
            "provider_response_committed",
            "provider_response_committed",
            {"response_sha256": response_digest, "content_persisted_in_journal": False},
        )
        _checkpoint(checkpoint, "after_provider_response_committed", task)
        state = "provider_response_committed"
    if state == "provider_response_committed":
        _verify_workspace(
            journal,
            workspace,
            task,
            "provider_response_committed",
            "response",
            "response_sha256",
        )
        response = workspace.read(task_id, "response")
        journal.reconcile(task, response["usage"])
        journal.transition(
            task,
            "budget_reconciled",
            "budget_reconciled",
            {"usage_sha256": canonical_sha256(response["usage"])},
        )
        _checkpoint(checkpoint, "after_budget_reconciled", task)
        state = "budget_reconciled"
    if state == "budget_reconciled":
        _verify_workspace(
            journal,
            workspace,
            task,
            "provider_response_committed",
            "response",
            "response_sha256",
        )
        journal.transition(
            task,
            "response_staged",
            "response_staged",
            {"response_sha256": workspace.hash(task_id, "response")},
        )
        _checkpoint(checkpoint, "after_response_staged", task)
        state = "response_staged"
    if state == "response_staged":
        _verify_workspace(
            journal,
            workspace,
            task,
            "provider_response_committed",
            "response",
            "response_sha256",
        )
        response = workspace.read(task_id, "response")
        decision = adapter.finalize_decision(task, response)
        decision_digest = workspace.write(task_id, "decision", decision)
        journal.transition(
            task,
            "decision_finalized",
            "participant_decision_finalized",
            {"decision_sha256": decision_digest},
        )
        _checkpoint(checkpoint, "after_decision_finalized", task)
        state = "decision_finalized"
    if state == "decision_finalized":
        _verify_workspace(
            journal,
            workspace,
            task,
            "decision_finalized",
            "decision",
            "decision_sha256",
        )
        decision = workspace.read(task_id, "decision")
        signature = adapter.sign_decision(task, decision)
        signature_digest = workspace.write(task_id, "signature", signature)
        journal.transition(
            task,
            "decision_signed",
            "offline_participant_signature_simulated",
            {"signature_sha256": signature_digest},
        )
        _checkpoint(checkpoint, "after_decision_signed", task)
        state = "decision_signed"
    if state == "decision_signed":
        _verify_workspace(
            journal,
            workspace,
            task,
            "decision_finalized",
            "decision",
            "decision_sha256",
        )
        _verify_workspace(
            journal,
            workspace,
            task,
            "decision_signed",
            "signature",
            "signature_sha256",
        )
        decision = workspace.read(task_id, "decision")
        signature = workspace.read(task_id, "signature")
        try:
            trace = adapter.verify_event_trace(task, decision, signature)
        except ValueError as error:
            raise SanitizedExecutionFailure(
                stage="event_trace_validation",
                source_exception_type=type(error).__name__,
            ) from None
        receipt_digest = workspace.write(
            task_id, "event_receipts", adapter.event_receipts(task)
        )
        trace_digest = workspace.write(task_id, "event_trace", trace)
        journal.transition(
            task,
            "event_trace_verified",
            "event_trace_verified",
            {
                "event_receipts_sha256": receipt_digest,
                "event_trace_sha256": trace_digest,
            },
        )
        _checkpoint(checkpoint, "after_event_trace_verified", task)
        state = "event_trace_verified"
    if state == "event_trace_verified":
        _verify_workspace(
            journal,
            workspace,
            task,
            "decision_finalized",
            "decision",
            "decision_sha256",
        )
        _verify_workspace(
            journal,
            workspace,
            task,
            "decision_signed",
            "signature",
            "signature_sha256",
        )
        _verify_workspace(
            journal,
            workspace,
            task,
            "event_trace_verified",
            "event_receipts",
            "event_receipts_sha256",
        )
        _verify_workspace(
            journal,
            workspace,
            task,
            "event_trace_verified",
            "event_trace",
            "event_trace_sha256",
        )
        artifacts = {
            name: workspace.read(task_id, name)
            for name in (
                "request",
                "response",
                "decision",
                "signature",
                "event_receipts",
                "event_trace",
            )
        }
        evidence = adapter.commit_task_evidence(task, artifacts)
        adapter.stop_container(task)
        journal.transition(
            task,
            "task_committed",
            "task_committed",
            {
                "container_stopped": True,
                "decision_sha256": workspace.hash(task_id, "decision"),
                "signature_sha256": workspace.hash(task_id, "signature"),
                "event_trace_sha256": workspace.hash(task_id, "event_trace"),
                "evidence": evidence,
            },
        )
        workspace.clear(task_id)
        _checkpoint(checkpoint, "after_task_committed", task)


def _transition_allowed(source: str, target: str) -> bool:
    if PROGRESS_TRANSITIONS.get(source) == target:
        return True
    if source in BEFORE_DISPATCH_STATES and target in {
        "task_failed_before_dispatch",
        "task_aborted_before_dispatch",
    }:
        return True
    if source == "dispatch_intent_committed" and target == "provider_outcome_unknown":
        return True
    return source in AFTER_RESPONSE_STATES and target == "task_failed_after_response"


def _sanitized_failure_diagnostic(
    error: Exception, *, fallback_stage: str
) -> dict[str, str]:
    category = getattr(error, "failure_category", None)
    stage = getattr(error, "failure_stage", None)
    source_exception_type = getattr(error, "source_exception_type", None)
    if (
        isinstance(category, str)
        and isinstance(stage, str)
        and stage in PROVIDER_FAILURE_STAGES.get(category, set())
        and isinstance(source_exception_type, str)
        and source_exception_type.isidentifier()
    ):
        return {
            "reason": type(error).__name__,
            "failure_category": category,
            "failure_stage": stage,
            "source_exception_type": source_exception_type,
        }
    return {
        "reason": type(error).__name__,
        "failure_category": "internal",
        "failure_stage": fallback_stage,
        "source_exception_type": type(error).__name__,
    }


class SanitizedExecutionFailure(ValueError):
    """Execution failure carrying only reviewed, non-content diagnostics."""

    failure_category = "internal"

    def __init__(self, *, stage: str, source_exception_type: str) -> None:
        if stage not in PROVIDER_FAILURE_STAGES[self.failure_category]:
            raise ValueError("execution failure stage is not reviewed")
        self.failure_stage = stage
        self.source_exception_type = source_exception_type
        super().__init__(f"sanitized execution failure at {stage}")


def _checkpoint(
    callback: Callable[[str, dict[str, Any]], None] | None,
    name: str,
    task: dict[str, Any],
) -> None:
    if callback is not None:
        callback(name, task)


def _verify_workspace(
    journal: ExecutionJournal,
    workspace: PrivateWorkspace,
    task: dict[str, Any],
    state: str,
    name: str,
    field: str,
) -> None:
    expected = journal.expected_artifact_hash(task, state, field)
    if workspace.hash(task["task_execution_id"], name) != expected:
        raise ValueError(f"private workspace commitment mismatch: {name}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
