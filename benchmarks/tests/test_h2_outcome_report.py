from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_outcome_report import build_h2_outcome_report


def test_h2_outcome_report_builds_evidence_linked_records(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="V04_h1_verifier_before_delivery_01",
        raw_rows=[
            _raw_row(1, "pool_claim"),
            _raw_row(
                2,
                "address_diff",
                reasoning="benchmark mode: H1 verifier-before-delivery bridge",
                normative_blocked="true",
                governance_trigger="true",
            ),
            _raw_row(3, "task_execute", timestamp="2026-05-04T00:00:03+00:00"),
        ],
        terminal_output={"answer": "verified"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "V04_h1_verifier_before_delivery_01",
                "criterion_index": 0,
                "criterion_desc": "verifier before delivery",
                "passed": True,
                "score": 0.9,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["metrics"]["outcome_ledger_coverage_ratio"] == 1.0
    assert report["metrics"]["h1_evidence_ref_ratio"] == 1.0
    assert report["metrics"]["normative_local_update_blocked_ratio"] == 1.0
    assert report["metrics"]["delayed_verifier_coverage_ratio"] is None
    record = report["records"][0]
    assert record["record_id"] == "alpha:V04_h1_verifier_before_delivery_01"
    assert record["delivered_at"] == "2026-05-04T00:00:03+00:00"
    assert record["h1_judge_ref"][0]["prompt_hash"] == "sha256:test"
    assert record["verifier_evidence_ref"][0]["action"] == "address_diff"
    assert record["immediate_result"]["terminal_status"] == "Delivered"
    assert record["immediate_result"]["h1_judge_passed"] is True
    assert record["normative_update_blocked_or_governed"]["local_mutation_allowed"] is False
    assert record["iem_update_candidates"][0]["state"] == "Predicted"


def test_h2_outcome_report_allows_missing_default_judge_report_with_verifier_evidence(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="V04_h1_verifier_before_delivery_01",
        raw_rows=[
            _raw_row(1, "address_diff", reasoning="benchmark mode: H1 verifier-before-delivery bridge"),
            _raw_row(2, "task_execute"),
        ],
        terminal_output={"answer": "verified"},
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["metrics"]["h1_evidence_ref_ratio"] == 1.0
    assert report["records"][0]["h1_judge_ref"] == []
    assert report["records"][0]["verifier_evidence_ref"][0]["action"] == "address_diff"


def test_h2_outcome_report_requires_explicit_judge_report_path(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="V04_h1_verifier_before_delivery_01",
        raw_rows=[
            _raw_row(1, "address_diff", reasoning="benchmark mode: H1 verifier-before-delivery bridge"),
            _raw_row(2, "task_execute"),
        ],
        terminal_output={"answer": "verified"},
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=tmp_path / "missing_h1_judge_report.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert any("missing JSON artifact" in reason for reason in report["failure_reasons"])


def test_h2_outcome_report_fails_when_h1_judge_ref_missing(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="V04_h1_verifier_before_delivery_01",
        raw_rows=[_raw_row(1, "task_execute")],
        terminal_output={"answer": "done"},
    )
    _write_judge_report(run_root, [])

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["metrics"]["h1_evidence_ref_ratio"] == 0.0
    assert report["checks"]["h1_evidence_ref_ratio"] is False
    assert any("h1_evidence_ref_ratio" in reason for reason in report["failure_reasons"])


def test_h2_outcome_report_fails_on_unblocked_local_normative_update(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="G08_h0e_unapproved_local_revision_01",
        raw_rows=[
            _raw_row(1, "pool_claim"),
            _raw_row(
                2,
                "task_execute",
                governance_trigger="true",
                normative_blocked="false",
                governed_revision="false",
            ),
        ],
        terminal_output={"answer": "local normative update attempted"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "G08_h0e_unapproved_local_revision_01",
                "criterion_index": 0,
                "criterion_desc": "normative local update blocked",
                "passed": True,
                "score": 0.8,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["metrics"]["normative_record_count"] == 1
    assert report["metrics"]["normative_local_update_blocked_ratio"] == 0.0
    assert report["checks"]["normative_local_update_blocked_ratio"] is False
    assert report["records"][0]["normative_update_blocked_or_governed"]["blocked_or_governed"] is False


def test_h2_outcome_report_records_relation_feedback_ratio(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="G03_happy_01",
        raw_rows=[
            _raw_row(
                1,
                "task_execute",
                relation_context_id="relation:G03",
                relation_memory_refs="memory:failure-1;memory:repair-1",
            ),
        ],
        terminal_output={"answer": "relation repaired"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "G03_happy_01",
                "criterion_index": 0,
                "criterion_desc": "relation repair",
                "passed": True,
                "score": 1.0,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["metrics"]["relation_record_count"] == 1
    assert report["metrics"]["relation_outcome_feedback_ratio"] == 1.0
    record = report["records"][0]
    assert record["reuse_refs"] == ["memory:failure-1", "memory:repair-1"]
    assert record["relation_delta"]["feedback_recorded"] is True


def test_h2_outcome_report_ingests_delayed_outcome_seed(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="G03_happy_01",
        raw_rows=[_raw_row(1, "task_execute")],
        terminal_output={"answer": "relation repaired"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "G03_happy_01",
                "criterion_index": 0,
                "criterion_desc": "relation repair",
                "passed": True,
                "score": 1.0,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )
    seed = _write_delayed_seed(
        tmp_path,
        [
            {
                "event_id": "evt-reuse-1",
                "agent_alias": "alpha",
                "task_id": "G03_happy_01",
                "event_kind": "relation_repair_relapse",
                "observed_at": "2026-05-04T02:00:00+00:00",
                "source": "benchmark_seed",
                "subject": "did:alpha",
                "evidence_ref": {"ref_id": "seed:relation:relapse:1"},
                "verifier_or_settlement_read": True,
                "outcome_status": "relapse_detected",
                "dispute_ref": "dispute:relapse:1",
                "reuse_ref": "reuse:downstream:1",
                "relation_memory_ref": "memory:relapse:1",
            }
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        delayed_outcomes_path=seed,
        agent_root=tmp_path,
        min_delayed_verifier_coverage_ratio=1.0,
    )

    assert report["passed"] is True
    assert report["checks"]["delayed_verifier_coverage_ratio"] is True
    assert report["metrics"]["delayed_event_count"] == 1
    assert report["metrics"]["delayed_event_record_count"] == 1
    assert report["metrics"]["delayed_event_kind_counts"] == {"relation_repair_relapse": 1}
    assert report["metrics"]["delayed_verifier_coverage_ratio"] == 1.0
    record = report["records"][0]
    assert record["delayed_events"][0]["event_id"] == "evt-reuse-1"
    assert record["dispute_refs"] == ["dispute:relapse:1"]
    assert record["reuse_refs"] == ["reuse:downstream:1"]
    assert record["relation_delta"]["relation_memory_refs"] == ["memory:relapse:1"]
    assert any(
        item["update_kind"] == "delayed_outcome_observation"
        for item in record["iem_update_candidates"]
    )


def test_h2_outcome_report_ingests_backend_outcome_events_by_backend_task_id(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    task_ids = ["A01_adversarial_01", "A02_adversarial_01"]
    for task_id in task_ids:
        _write_task(
            run_root,
            alias="alpha",
            task_id=task_id,
            raw_rows=[_raw_row(1, "task_execute")],
            terminal_output={"answer": task_id},
        )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": task_id,
                "criterion_index": 0,
                "criterion_desc": "targeted action",
                "passed": True,
                "score": 1.0,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
            for task_id in task_ids
        ],
    )
    backend_events = _write_backend_outcome_events(
        tmp_path,
        [
            {
                "event_id": f"backend-task-outcome:backend-{task_id}:disputed",
                "agent_alias": "did:alpha",
                "agent_id": "did:alpha",
                "task_id": f"backend-{task_id}",
                "event_kind": "post_delivery_dispute",
                "observed_at": "2026-05-04T02:00:00+00:00",
                "source": "backend_task_pool_read_model",
                "subject": "did:alpha",
                "evidence_ref": {
                    "ref_id": f"backend-task-outcome:backend-{task_id}:disputed",
                    "task_status": "Disputed",
                },
                "verifier_or_settlement_read": True,
                "outcome_status": "disputed_after_delivery",
                "dispute_ref": f"task_failure:backend-{task_id}",
            }
            for task_id in task_ids
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        backend_outcome_events_path=backend_events,
        agent_root=tmp_path,
        min_delayed_verifier_coverage_ratio=1.0,
    )

    assert report["passed"] is True
    assert report["backend_outcome_events_path"] == str(backend_events)
    assert report["metrics"]["delayed_event_count"] == 2
    assert report["metrics"]["delayed_event_kind_counts"] == {"post_delivery_dispute": 2}
    records = {record["task_id"]: record for record in report["records"]}
    record = records["A01_adversarial_01"]
    event = record["delayed_events"][0]
    assert event["task_id"] == "A01_adversarial_01"
    assert event["backend_task_id"] == "backend-A01_adversarial_01"
    assert event["source"] == "backend_task_pool_read_model"
    assert record["dispute_refs"] == ["task_failure:backend-A01_adversarial_01"]
    repeated = [
        item for item in record["iem_update_candidates"]
        if item["update_kind"] == "delayed_repeated_pattern_slow_drift_candidate"
    ]
    assert repeated == [
        {
            "state": "Desired",
            "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
            "task_id": "A01_adversarial_01",
            "event_kind": "post_delivery_dispute",
            "pattern_count": 2,
            "source_refs": ["backend-task-outcome:backend-A01_adversarial_01:disputed"],
            "requires_repeated_pattern": True,
            "local_mutation_allowed": False,
        }
    ]


def test_h2_outcome_report_fails_on_invalid_backend_outcome_event_schema(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="A01_adversarial_01",
        raw_rows=[_raw_row(1, "task_execute")],
        terminal_output={"answer": "done"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "A01_adversarial_01",
                "criterion_index": 0,
                "criterion_desc": "targeted action",
                "passed": True,
                "score": 1.0,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )
    backend_events = tmp_path / "backend_outcome_events.json"
    backend_events.write_text(
        json.dumps({"schema_version": "wrong-schema", "events": []}),
        encoding="utf-8",
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        backend_outcome_events_path=backend_events,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert any("schema_version mismatch" in reason for reason in report["failure_reasons"])


def test_h2_outcome_report_fails_on_invalid_delayed_outcome_seed(tmp_path: Path) -> None:
    run_root = _write_run_root(tmp_path)
    _write_task(
        run_root,
        alias="alpha",
        task_id="A01_adversarial_01",
        raw_rows=[_raw_row(1, "task_execute")],
        terminal_output={"answer": "done"},
    )
    _write_judge_report(
        run_root,
        [
            {
                "agent_alias": "alpha",
                "task_id": "A01_adversarial_01",
                "criterion_index": 0,
                "criterion_desc": "targeted action",
                "passed": True,
                "score": 1.0,
                "model": "judge-test",
                "prompt_version": "h1-judge-v1",
                "prompt_hash": "sha256:test",
            }
        ],
    )
    seed = _write_delayed_seed(
        tmp_path,
        [
            {
                "event_id": "evt-bad-1",
                "agent_alias": "alpha",
                "task_id": "A01_adversarial_01",
                "event_kind": "dispute_opened",
                "observed_at": "2026-05-04T02:00:00+00:00",
                "source": "benchmark_seed",
                "subject": "did:alpha",
                "verifier_or_settlement_read": True,
            }
        ],
    )

    report = build_h2_outcome_report(
        run_root=run_root,
        judge_report_path=None,
        delayed_outcomes_path=seed,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert any("evidence_ref" in reason for reason in report["failure_reasons"])


def _write_run_root(tmp_path: Path) -> Path:
    run_root = tmp_path / "runs" / "H2A"
    run_dir = run_root / "baseline-alpha-20260504T000000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "raw_ticks").mkdir()
    (run_dir / "tasks").mkdir()
    return run_root


def _write_task(
    run_root: Path,
    *,
    alias: str,
    task_id: str,
    raw_rows: list[dict[str, str]],
    terminal_output: object,
) -> None:
    run_dir = run_root / f"baseline-{alias}-20260504T000000Z"
    task_dir = run_dir / "tasks" / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    tasks = []
    if summary_path.exists():
        tasks = json.loads(summary_path.read_text(encoding="utf-8"))["tasks"]
    tasks.append({
        "task_id": task_id,
        "agent_self_reported_success": True,
        "sentinel_kind": "done",
        "sentinel_reason": "backend status=Delivered",
        "final_output": json.dumps(terminal_output, sort_keys=True),
    })
    summary_path.write_text(
        json.dumps({
            "run_id": run_dir.name,
            "finished_at": "2026-05-04T00:01:00+00:00",
            "tasks": tasks,
        }),
        encoding="utf-8",
    )
    (task_dir / "backend_terminal_state.json").write_text(
        json.dumps({
            "task_id": f"backend-{task_id}",
            "status": "Delivered",
            "output": terminal_output,
            "failure_reason": None,
            "challenge_deadline_at": None,
        }),
        encoding="utf-8",
    )
    (task_dir / "backend_task_id.txt").write_text(f"backend-{task_id}\n", encoding="utf-8")
    _write_raw_ticks(run_dir / "raw_ticks" / f"{task_id}.csv", task_id, raw_rows)


def _write_raw_ticks(path: Path, task_id: str, rows: list[dict[str, str]]) -> None:
    fields = [
        "run_id",
        "agent_id",
        "task_id",
        "tick_seq",
        "tick_id",
        "timestamp",
        "decision_action",
        "decision_reasoning",
        "relation_context_id",
        "relation_memory_refs",
        "relation_pair_failure_ref_present",
        "h0_constitutional_surprise_present",
        "h0_normative_governance_trigger_present",
        "h0_governed_revision_present",
        "h0_normative_local_update_blocked",
        "h0_predicted_update_present",
        "h0_desired_slow_drift_present",
        "h0_reputation_surprise_present",
        "h0_economic_surprise_present",
        "h0_governance_surprise_present",
    ]
    lines = [",".join(fields)]
    for row in rows:
        values = {
            "run_id": "baseline-alpha-20260504T000000Z",
            "agent_id": "did:alpha",
            "task_id": task_id,
            "tick_id": f"tick-{row['tick_seq']}",
            "timestamp": row.get("timestamp", f"2026-05-04T00:00:0{row['tick_seq']}+00:00"),
            "relation_pair_failure_ref_present": "false",
            "h0_constitutional_surprise_present": "false",
            "h0_normative_governance_trigger_present": row.get("governance_trigger", "false"),
            "h0_governed_revision_present": row.get("governed_revision", "false"),
            "h0_normative_local_update_blocked": row.get("normative_blocked", "false"),
            "h0_predicted_update_present": "true",
            "h0_desired_slow_drift_present": "false",
            "h0_reputation_surprise_present": "false",
            "h0_economic_surprise_present": "false",
            "h0_governance_surprise_present": row.get("governance_trigger", "false"),
        }
        values.update(row)
        lines.append(",".join(str(values.get(field, "")) for field in fields))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _raw_row(
    tick_seq: int,
    action: str,
    *,
    reasoning: str = "",
    timestamp: str | None = None,
    relation_context_id: str = "",
    relation_memory_refs: str = "",
    governance_trigger: str = "false",
    normative_blocked: str = "false",
    governed_revision: str = "false",
) -> dict[str, str]:
    row = {
        "tick_seq": str(tick_seq),
        "decision_action": action,
        "decision_reasoning": reasoning,
        "relation_context_id": relation_context_id,
        "relation_memory_refs": relation_memory_refs,
        "governance_trigger": governance_trigger,
        "normative_blocked": normative_blocked,
        "governed_revision": governed_revision,
    }
    if timestamp is not None:
        row["timestamp"] = timestamp
    return row


def _write_judge_report(run_root: Path, rows: list[dict]) -> None:
    (run_root / "h1_llm_judge_report.json").write_text(
        json.dumps({
            "schema_version": "h1-llm-criteria-report:v1",
            "enabled": True,
            "passed": True,
            "total_criteria": len(rows),
            "judged_criteria": len(rows),
            "passed_criteria": len([row for row in rows if row.get("passed") is True]),
            "rows": rows,
        }),
        encoding="utf-8",
    )


def _write_delayed_seed(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "h2_delayed_outcomes.jsonl"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")
    return path


def _write_backend_outcome_events(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "backend_outcome_events.json"
    path.write_text(
        json.dumps({
            "schema_version": "h2-delayed-outcome-events:v1",
            "source": "backend_task_pool_read_model",
            "events": rows,
            "total": len(rows),
            "returned": len(rows),
        }),
        encoding="utf-8",
    )
    return path