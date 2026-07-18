#!/usr/bin/env python3
"""Durable synthetic worker for the P5-B3e controller contract tests."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.p5b3e_checkpoint_fault_gate import (
    EVENT_SCHEMA,
    REJECTION_CASES,
    RESULT_SCHEMA,
)


MILESTONES = (
    "runtime_intent_durable",
    "backend_preflight_durable",
    "runtime_restore_journal_durable",
    "runtime_sqlite_committed",
    "runtime_applied_journal_durable",
    "backend_activation_durable",
    "runtime_activation_journal_durable",
    "runtime_intent_activated_durable",
    "runtime_tick_latch_released",
)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(payload, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def initial_state() -> dict[str, Any]:
    return {
        "checkpoint_id": "aic:v1:p5b3e-synthetic",
        "manifest_hash": "sha256:" + "a" * 64,
        "sequence": 7,
        "identity_id": "did:civ:p5b3e-synthetic",
        "completed": [],
        "activation_fact_id": None,
        "activation_fact_count": 0,
        "audit_events": [],
        "pre_activation_tick_count": 0,
    }


def emit(control: socket.socket, event: dict[str, Any]) -> None:
    control.sendall(json.dumps(event, sort_keys=True).encode() + b"\n")
    if control.recv(1) != b"C":
        raise RuntimeError("controller did not acknowledge milestone")


def main() -> int:
    case_root = Path(os.environ["CIVITASOS_P5B3E_CASE_ROOT"])
    case_id = os.environ["CIVITASOS_P5B3E_CASE_ID"]
    fault_point = os.environ["CIVITASOS_P5B3E_FAULT_POINT"]
    attempt = int(os.environ["CIVITASOS_P5B3E_ATTEMPT"])
    control_fd = int(os.environ["CIVITASOS_P5B3E_CONTROL_FD"])
    state_path = case_root / "synthetic-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else initial_state()
    control = socket.socket(fileno=control_fd)
    if fault_point in REJECTION_CASES:
        control.close()
        write_json(
            case_root / "result.json",
            {
                "schema_version": RESULT_SCHEMA,
                "case_id": case_id,
                "fault_point": fault_point,
                "status": "rejected",
                "fail_closed": True,
                "mutation_count": 0,
                "activation_fact_count": 0,
                "pre_activation_tick_count": 0,
                "failure_audit_recorded": True,
            },
        )
        return 0
    try:
        for milestone in MILESTONES:
            if milestone in state["completed"]:
                continue
            if milestone == "backend_activation_durable":
                state["activation_fact_id"] = "fact:p5b3e-synthetic-activation"
                state["activation_fact_count"] += 1
            state["completed"].append(milestone)
            state["audit_events"].append(
                {"sequence": len(state["audit_events"]) + 1, "milestone": milestone}
            )
            write_json(state_path, state)
            emit(
                control,
                {
                    "schema_version": EVENT_SCHEMA,
                    "case_id": case_id,
                    "attempt": attempt,
                    "milestone": milestone,
                    "checkpoint_id": state["checkpoint_id"],
                    "manifest_hash": state["manifest_hash"],
                    "sequence": state["sequence"],
                    "identity_id": state["identity_id"],
                },
            )
    finally:
        control.close()

    audit_sequences = [event["sequence"] for event in state["audit_events"]]
    result = {
        "schema_version": RESULT_SCHEMA,
        "case_id": case_id,
        "fault_point": fault_point,
        "checkpoint_id": state["checkpoint_id"],
        "manifest_hash": state["manifest_hash"],
        "sequence": state["sequence"],
        "identity_id": state["identity_id"],
        "status": "activated",
        "recovered": attempt > 1,
        "pre_activation_tick_count": state["pre_activation_tick_count"],
        "post_activation_tick_count": 1,
        "activation_fact_id": state["activation_fact_id"],
        "activation_fact_count": state["activation_fact_count"],
        "runtime_journal_status": "activated",
        "runtime_intent_status": "activated",
        "audit_sequence_contiguous": audit_sequences
        == list(range(1, len(audit_sequences) + 1)),
    }
    write_json(case_root / "result.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
