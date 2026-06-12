"""Record an operator reconciliation over validated H.3 A8 pilot outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_controlled_pilot_post_run_review import (
    SCHEMA_VERSION as POST_RUN_REVIEW_SCHEMA_VERSION,
)


PACKET_SCHEMA_VERSION = "h3-controlled-pilot-operator-review-packet:v1"
RECONCILIATION_SCHEMA_VERSION = (
    "h3-controlled-pilot-operator-reconciliation:v1"
)
ALLOWED_FINDING_DECISIONS = {
    "retain_for_replication",
    "need_more_evidence",
    "reject",
}
ALLOWED_OPERATOR_DECISIONS = {
    "retain_bounded_hypotheses_for_replication",
    "close_without_followup",
}
def _boundary(profile: str) -> dict[str, bool]:
    return {
        "development_only": profile == "development",
        "qualification_controlled_only": profile == "qualification",
        "operator_reconciliation_recording_allowed": True,
        "replication_plan_review_input_ready": False,
        "controlled_pilot_execution_allowed": False,
        "qualification_evidence_allowed": False,
        "production_use_allowed": False,
        "trust_mutation_allowed": False,
        "iem_mutation_allowed": False,
        "relation_mutation_allowed": False,
        "authorization_mutation_allowed": False,
        "normative_mutation_allowed": False,
    }


BOUNDARY = _boundary("development")


def create_operator_review_packet(
    *,
    post_run_review_path: Path,
    output_path: Path,
    agent_root: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    review_path = _resolve(post_run_review_path, agent_root)
    output = _resolve(output_path, agent_root)
    if output.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite operator packet: {output}")

    failures: list[str] = []
    source = _read_json(review_path, failures, "post-run contract review")
    candidates = _validate_source_review(source, failures)
    if failures:
        raise ValueError(f"cannot create A9 operator packet: {failures}")

    profile = str(source.get("validation_profile") or "development")
    reconciliation = _object(source.get("reconciliation"))
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "state": "operator_input_required",
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "source_post_run_contract_review": _artifact_ref(review_path),
        "source_post_run_receipt": source.get("source_post_run_receipt"),
        "source_task": source.get("source_task"),
        "allowed_finding_decisions": sorted(ALLOWED_FINDING_DECISIONS),
        "allowed_operator_decisions": sorted(ALLOWED_OPERATOR_DECISIONS),
        "candidate_reviews": [
            {
                "candidate_id": _candidate_id(candidate),
                "candidate_sha256": _canonical_sha256(candidate),
                "condition": candidate["condition"],
                "support_count": candidate["support_count"],
                "decision": "pending",
                "reason": "",
            }
            for candidate in candidates
        ],
        "evidence_limitations": {
            "counterexample_count": len(
                _strings(reconciliation.get("counterexamples"))
            ),
            "counterexample_set_sha256": _canonical_sha256(
                _strings(reconciliation.get("counterexamples"))
            ),
            "counterexamples_acknowledged": False,
            "unresolved_assumption_count": len(
                _strings(reconciliation.get("unresolved_assumptions"))
            ),
            "unresolved_assumption_set_sha256": _canonical_sha256(
                _strings(reconciliation.get("unresolved_assumptions"))
            ),
            "unresolved_assumptions_acknowledged": False,
        },
        "operator_synthesis": {
            "decision": "pending",
            "provisional_findings": [],
            "deferred_questions": [],
            "reason": "",
            "operator_id": "",
            "operator_role": "",
            "reviewed_at": "",
        },
        "boundary": _boundary(profile),
        "non_claims": _non_claims(),
    }
    _write_json(output, packet)
    return packet


def reconcile_operator_review(
    *,
    post_run_review_path: Path,
    operator_packet_path: Path,
    output_path: Path,
    agent_root: Path,
    max_future_skew_seconds: float = 300.0,
) -> dict[str, Any]:
    review_path = _resolve(post_run_review_path, agent_root)
    packet_path = _resolve(operator_packet_path, agent_root)
    output = _resolve(output_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    source = _read_json(review_path, failures, "post-run contract review")
    packet = _read_json(packet_path, failures, "operator review packet")
    profile = str(_object(source).get("validation_profile") or "development")
    candidates = _validate_source_review(source, failures, checks)
    reviews = _validate_packet(
        packet,
        review_path=review_path,
        source=source,
        candidates=candidates,
        failures=failures,
        checks=checks,
        max_future_skew_seconds=max_future_skew_seconds,
    )

    retained = [
        review for review in reviews
        if review.get("decision") == "retain_for_replication"
    ]
    deferred = [
        review for review in reviews
        if review.get("decision") == "need_more_evidence"
    ]
    rejected = [
        review for review in reviews if review.get("decision") == "reject"
    ]
    synthesis = _object(_object(packet).get("operator_synthesis"))
    passed = not failures and all(checks.values())
    replication_ready = (
        passed
        and synthesis.get("decision")
        == "retain_bounded_hypotheses_for_replication"
        and bool(retained)
    )
    boundary = _boundary(profile)
    boundary["replication_plan_review_input_ready"] = replication_ready
    report = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "source_post_run_contract_review": (
            _artifact_ref(review_path) if review_path.is_file() else None
        ),
        "source_operator_review_packet": (
            _artifact_ref(packet_path) if packet_path.is_file() else None
        ),
        "review_summary": {
            "candidate_count": len(candidates),
            "retained_for_replication_count": len(retained),
            "need_more_evidence_count": len(deferred),
            "rejected_count": len(rejected),
        },
        "operator_reconciliation": {
            "decision": synthesis.get("decision") if passed else None,
            "provisional_findings": (
                _strings(synthesis.get("provisional_findings")) if passed else []
            ),
            "deferred_questions": (
                _strings(synthesis.get("deferred_questions")) if passed else []
            ),
            "reason": synthesis.get("reason") if passed else None,
            "operator_id": synthesis.get("operator_id") if passed else None,
            "operator_role": synthesis.get("operator_role") if passed else None,
            "reviewed_at": synthesis.get("reviewed_at") if passed else None,
            "retained_candidate_reviews": retained if passed else [],
            "deferred_candidate_reviews": deferred if passed else [],
            "rejected_candidate_reviews": rejected if passed else [],
            "counterexamples_acknowledged": (
                _object(_object(packet).get("evidence_limitations")).get(
                    "counterexamples_acknowledged"
                )
                is True
            ),
            "unresolved_assumptions_acknowledged": (
                _object(_object(packet).get("evidence_limitations")).get(
                    "unresolved_assumptions_acknowledged"
                )
                is True
            ),
        },
        "readiness": {
            "operator_reconciliation_complete": passed,
            "replication_plan_review_input_ready": replication_ready,
            "qualification_input_ready": False,
            "automatic_state_change_allowed": False,
            "decision": (
                "h3_a9_operator_reconciliation_complete"
                if passed
                else "blocked_h3_a9_operator_reconciliation"
            ),
            "next_action": (
                "prepare a separate bounded replication plan review"
                if replication_ready
                else f"close the {profile} hypothesis or repair the operator packet"
            ),
        },
        "boundary": boundary,
        "non_claims": _non_claims(),
    }
    _write_json(output, report)
    return report


def _validate_source_review(
    value: dict[str, Any] | None,
    failures: list[str],
    checks: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    checks = checks if checks is not None else {}
    if value is None:
        _require(checks, failures, "post_run_review_present", False)
        return []
    checks["post_run_review_present"] = True
    _require_equal(
        checks,
        failures,
        "post_run_review_schema",
        value.get("schema_version"),
        POST_RUN_REVIEW_SCHEMA_VERSION,
    )
    _require(checks, failures, "post_run_review_passed", value.get("passed") is True)
    profile = str(value.get("validation_profile") or "development")
    _require(
        checks,
        failures,
        "post_run_review_profile_supported",
        profile in {"development", "qualification"},
    )
    _require_equal(
        checks,
        failures,
        "post_run_review_development_flag",
        value.get("development_only", profile == "development"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "post_run_review_qualification_flag",
        value.get("valid_for_qualification", False),
        False,
    )
    readiness = _object(value.get("readiness"))
    _require(
        checks,
        failures,
        "outputs_ready_for_operator_review",
        readiness.get("controlled_pilot_outputs_valid_for_operator_review") is True,
    )
    _require(
        checks,
        failures,
        "automatic_state_change_blocked",
        readiness.get("automatic_state_change_allowed") is False,
    )
    reconciliation = _object(value.get("reconciliation"))
    _require_equal(
        checks,
        failures,
        "source_reconciliation_state",
        reconciliation.get("state"),
        "operator_review_required",
    )
    _require(
        checks,
        failures,
        "source_automatic_adoption_blocked",
        reconciliation.get("automatic_adoption_allowed") is False,
    )
    _require(
        checks,
        failures,
        "source_trust_authorization_change_blocked",
        reconciliation.get("trust_or_authorization_change_allowed") is False,
    )
    candidates = _objects(reconciliation.get("candidate_conditions"))
    _require(checks, failures, "candidate_conditions_present", bool(candidates))
    _require(
        checks,
        failures,
        "candidate_conditions_valid",
        all(
            bool(str(item.get("condition") or "").strip())
            and isinstance(item.get("support_count"), int)
            and item["support_count"] > 0
            for item in candidates
        ),
    )
    _require(
        checks,
        failures,
        "counterexamples_present",
        bool(_strings(reconciliation.get("counterexamples"))),
    )
    _require(
        checks,
        failures,
        "unresolved_assumptions_present",
        bool(_strings(reconciliation.get("unresolved_assumptions"))),
    )
    refs: dict[str, dict[str, Any]] = {}
    for name in ("source_post_run_receipt", "source_task"):
        ref = _object(value.get(name))
        refs[name] = ref
        path = Path(str(ref.get("path") or "/missing"))
        _require(
            checks,
            failures,
            f"{name}_hash_valid",
            path.is_file() and ref.get("sha256") == _sha256(path),
        )
    receipt_path = Path(
        str(refs.get("source_post_run_receipt", {}).get("path") or "/missing")
    )
    receipt = _read_json(receipt_path, failures, "source post-run receipt")
    _require_equal(
        checks,
        failures,
        "source_receipt_profile_binding",
        _object(receipt).get("validation_profile", profile),
        profile,
    )
    generation_refs = _objects(_object(receipt).get("generation_reports"))
    _require_equal(
        checks,
        failures,
        "generation_report_count_bound",
        len(generation_refs),
        value.get("generation_report_count"),
    )
    _require(
        checks,
        failures,
        "generation_report_hashes_valid",
        bool(generation_refs)
        and all(
            (
                path := Path(str(ref.get("path") or "/missing"))
            ).is_file()
            and ref.get("sha256") == _sha256(path)
            for ref in generation_refs
        ),
    )
    _require_equal(
        checks,
        failures,
        "receipt_task_binding",
        _object(receipt).get("task"),
        refs.get("source_task"),
    )
    side_effects = _object(_object(receipt).get("side_effects"))
    _require(
        checks,
        failures,
        "source_receipt_forbidden_mutations_absent",
        all(
            side_effects.get(field) is False
            for field in (
                "production_state_mutated",
                "iem_state_mutated",
                "relation_state_mutated",
                "authorization_state_mutated",
                "normative_state_mutated",
            )
        ),
    )
    return candidates


def _validate_packet(
    value: dict[str, Any] | None,
    *,
    review_path: Path,
    source: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
    max_future_skew_seconds: float,
) -> list[dict[str, Any]]:
    if value is None:
        _require(checks, failures, "operator_packet_present", False)
        return []
    checks["operator_packet_present"] = True
    _require_equal(
        checks, failures, "operator_packet_schema",
        value.get("schema_version"), PACKET_SCHEMA_VERSION,
    )
    _require_equal(
        checks, failures, "operator_packet_state",
        value.get("state"), "operator_input_required",
    )
    profile = str(_object(source).get("validation_profile") or "development")
    _require_equal(
        checks,
        failures,
        "operator_packet_profile",
        value.get("validation_profile"),
        profile,
    )
    _require_equal(
        checks,
        failures,
        "operator_packet_development_flag",
        value.get("development_only"),
        profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "operator_packet_qualification_flag",
        value.get("valid_for_qualification"),
        False,
    )
    _require_equal(
        checks, failures, "operator_packet_source_binding",
        value.get("source_post_run_contract_review"),
        _artifact_ref(review_path) if review_path.is_file() else None,
    )
    _require_equal(
        checks, failures, "operator_packet_receipt_binding",
        value.get("source_post_run_receipt"),
        _object(source).get("source_post_run_receipt"),
    )
    _require_equal(
        checks, failures, "operator_packet_task_binding",
        value.get("source_task"), _object(source).get("source_task"),
    )
    _require_equal(
        checks, failures, "operator_packet_finding_decisions",
        value.get("allowed_finding_decisions"),
        sorted(ALLOWED_FINDING_DECISIONS),
    )
    _require_equal(
        checks, failures, "operator_packet_decisions",
        value.get("allowed_operator_decisions"),
        sorted(ALLOWED_OPERATOR_DECISIONS),
    )
    _require_equal(
        checks, failures, "operator_packet_boundary",
        value.get("boundary"), _boundary(profile),
    )
    _require_equal(
        checks, failures, "operator_packet_non_claims",
        value.get("non_claims"), _non_claims(),
    )
    expected = {
        _candidate_id(item): {
            "sha256": _canonical_sha256(item),
            "condition": item["condition"],
            "support_count": item["support_count"],
        }
        for item in candidates
    }
    reviews = _objects(value.get("candidate_reviews"))
    review_ids = [str(item.get("candidate_id") or "") for item in reviews]
    _require(
        checks,
        failures,
        "candidate_reviews_complete",
        sorted(review_ids) == sorted(expected)
        and len(review_ids) == len(set(review_ids)),
    )
    review_fields_valid = True
    for review in reviews:
        candidate_id = str(review.get("candidate_id") or "")
        candidate = expected.get(candidate_id)
        valid = (
            candidate is not None
            and review.get("candidate_sha256") == candidate["sha256"]
            and review.get("condition") == candidate["condition"]
            and review.get("support_count") == candidate["support_count"]
            and review.get("decision") in ALLOWED_FINDING_DECISIONS
            and len(str(review.get("reason") or "").strip()) >= 12
        )
        if not valid:
            failures.append(f"candidate review invalid: {candidate_id or '<missing>'}")
            review_fields_valid = False
    _require(
        checks, failures, "candidate_review_fields_valid",
        bool(reviews) and review_fields_valid,
    )
    limitations = _object(value.get("evidence_limitations"))
    reconciliation = _object(_object(source).get("reconciliation"))
    counterexamples = _strings(reconciliation.get("counterexamples"))
    assumptions = _strings(reconciliation.get("unresolved_assumptions"))
    _require_equal(
        checks, failures, "counterexample_count_bound",
        limitations.get("counterexample_count"), len(counterexamples),
    )
    _require_equal(
        checks, failures, "counterexample_hash_bound",
        limitations.get("counterexample_set_sha256"),
        _canonical_sha256(counterexamples),
    )
    _require(
        checks, failures, "counterexamples_acknowledged",
        limitations.get("counterexamples_acknowledged") is True,
    )
    _require_equal(
        checks, failures, "assumption_count_bound",
        limitations.get("unresolved_assumption_count"), len(assumptions),
    )
    _require_equal(
        checks, failures, "assumption_hash_bound",
        limitations.get("unresolved_assumption_set_sha256"),
        _canonical_sha256(assumptions),
    )
    _require(
        checks, failures, "unresolved_assumptions_acknowledged",
        limitations.get("unresolved_assumptions_acknowledged") is True,
    )
    synthesis = _object(value.get("operator_synthesis"))
    reviewed_at = _timestamp(synthesis.get("reviewed_at"))
    now = datetime.now(timezone.utc)
    synthesis_valid = (
        synthesis.get("decision") in ALLOWED_OPERATOR_DECISIONS
        and len(str(synthesis.get("reason") or "").strip()) >= 20
        and bool(str(synthesis.get("operator_id") or "").strip())
        and bool(str(synthesis.get("operator_role") or "").strip())
        and reviewed_at is not None
        and max_future_skew_seconds >= 0
        and reviewed_at <= now + timedelta(seconds=max_future_skew_seconds)
    )
    if synthesis.get("decision") == "retain_bounded_hypotheses_for_replication":
        synthesis_valid = (
            synthesis_valid
            and bool(_strings(synthesis.get("provisional_findings")))
            and bool(_strings(synthesis.get("deferred_questions")))
            and any(
                item.get("decision") == "retain_for_replication"
                for item in reviews
            )
        )
    _require(checks, failures, "operator_synthesis_valid", synthesis_valid)
    return reviews


def _candidate_id(value: dict[str, Any]) -> str:
    return f"h3-a9-candidate:{_canonical_sha256(value)[:20]}"


def _non_claims() -> list[str]:
    return [
        "operator_reconciliation_does_not_rewrite_a8_receipt",
        "retained_findings_are_hypotheses_not_causal_facts",
        "operator_reconciliation_does_not_mutate_runtime_or_governance_state",
        "operator_reconciliation_does_not_authorize_another_pilot",
        "operator_reconciliation_is_not_qualification_or_production_evidence",
    ]


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("Z", "+00:00")
    normalized = re.sub(r"(\.\d{6})\d+(?=[+-]\d\d:\d\d$)", r"\1", normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _read_json(
    path: Path,
    failures: list[str],
    label: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    return value


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    condition: bool,
) -> None:
    checks[name] = bool(condition)
    if not condition:
        failures.append(name)


def _require_equal(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    actual: Any,
    expected: Any,
) -> None:
    _require(checks, failures, name, actual == expected)


def _resolve(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init", help="write a pending A9 operator packet")
    init.add_argument("--post-run-review", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--overwrite", action="store_true")
    reconcile = subparsers.add_parser(
        "reconcile", help="validate the completed A9 operator packet"
    )
    reconcile.add_argument("--post-run-review", type=Path, required=True)
    reconcile.add_argument("--operator-packet", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    reconcile.add_argument("--max-future-skew-seconds", type=float, default=300.0)
    return parser


def main() -> None:
    args = _parser().parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.command == "init":
        report = create_operator_review_packet(
            post_run_review_path=args.post_run_review,
            output_path=args.output,
            agent_root=root,
            overwrite=args.overwrite,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    report = reconcile_operator_review(
        post_run_review_path=args.post_run_review,
        operator_packet_path=args.operator_packet,
        output_path=args.output,
        agent_root=root,
        max_future_skew_seconds=args.max_future_skew_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
