"""Run the I.1 read-only verifier matrix over the fixed corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    artifact_ref,
    check,
    object_value,
    objects_value,
    read_json_object,
    sha256_file,
    sha256_text,
    write_json_object,
)
from nacl.signing import VerifyKey

SCHEMA_VERSION = "i1-read-only-verifier-matrix-gate:v1"
VERDICT_SCHEMA_VERSION = "i1-signed-verdict:v1"
MIN_QUORUM = 3


def run_gate(
    *,
    preparation_report_path: Path,
    identity_registration_path: Path,
    output: Path,
) -> dict[str, Any]:
    from civitasos import CivitasAgent

    failures: list[str] = []
    checks: dict[str, bool] = {}
    preparation = read_json_object(preparation_report_path)
    registration = read_json_object(identity_registration_path)

    identities = objects_value(object_value(preparation.get("identity_manifest")).get("identities"))
    cases = objects_value(object_value(preparation.get("corpus_manifest")).get("cases"))
    receipts = objects_value(registration.get("identity_receipts"))
    identities_by_alias = {str(item.get("identity_alias") or ""): item for item in identities}
    receipts_by_alias = {str(item.get("identity_alias") or ""): item for item in receipts}
    proposer = str(object_value(preparation.get("identity_manifest")).get("proposer_identity_alias") or "")
    allowlist = [
        str(item)
        for item in object_value(preparation.get("identity_manifest")).get("default_verifier_allowlist", [])
        if str(item)
    ]

    check(checks, failures, "preparation_report_passed", preparation.get("passed") is True)
    check(
        checks,
        failures,
        "identity_registration_prerequisites_complete",
        registration.get("schema_version") == "i1-identity-registration-gate:v1"
        and registration.get("passed") is True
        and object_value(registration.get("readiness")).get("i1_execution_preflight_input_ready") is True,
    )
    check(checks, failures, "five_identities_present", len(identities) == 5)
    check(checks, failures, "eleven_cases_present", len(cases) == 11)
    check(
        checks,
        failures,
        "default_quorum_excludes_proposer",
        bool(proposer) and proposer not in allowlist and len(set(allowlist)) >= MIN_QUORUM,
    )
    check(
        checks,
        failures,
        "registered_receipts_match_prepared_identities",
        set(identities_by_alias) == set(receipts_by_alias)
        and all(
            str(identities_by_alias[alias].get("did") or "") == str(receipts_by_alias[alias].get("did") or "")
            and receipts_by_alias[alias].get("signature_control_verified") is True
            for alias in identities_by_alias
        ),
    )

    verdicts: list[dict[str, Any]] = []
    if not failures:
        for case in cases:
            for identity in identities:
                verdicts.append(
                    _signed_verdict(
                        case=case,
                        identity=identity,
                        identities_by_alias=identities_by_alias,
                        proposer_alias=proposer,
                        agent=CivitasAgent(auto_discover=False),
                    )
                )

    quorum = _quorum_summary(cases=cases, verdicts=verdicts, allowlist=allowlist)
    check(
        checks,
        failures,
        "all_verdict_signatures_verified",
        bool(verdicts) and all(item.get("signature_verified") is True for item in verdicts),
    )
    check(
        checks,
        failures,
        "all_positive_cases_accepted_by_quorum",
        quorum.get("positive_cases_accepted") == 4,
    )
    check(
        checks,
        failures,
        "all_negative_controls_rejected_by_quorum",
        quorum.get("negative_controls_rejected") == 7,
    )
    check(
        checks,
        failures,
        "quorum_provider_independence_sufficient",
        _provider_independence(allowlist, identities_by_alias),
    )
    check(
        checks,
        failures,
        "proposer_excluded_from_all_quorums",
        bool(quorum.get("case_quorums"))
        and all(proposer not in item.get("counted_verifier_aliases", []) for item in quorum["case_quorums"]),
    )
    check(
        checks,
        failures,
        "hash_drift_negative_control_rejected",
        _case_quorum(quorum, "negative-hash-mismatch").get("quorum_decision") == "reject"
        and _case_quorum(quorum, "negative-hash-mismatch").get("failure_reason") == "artifact_hash_mismatch",
    )
    check(
        checks,
        failures,
        "replay_negative_control_rejected",
        _case_quorum(quorum, "negative-response-replay").get("quorum_decision") == "reject"
        and _case_quorum(quorum, "negative-response-replay").get("failure_reason") == "verdict_receipt_replay",
    )
    check(
        checks,
        failures,
        "provider_homogeneity_negative_control_rejected",
        _case_quorum(quorum, "negative-provider-homogeneity").get("quorum_decision") == "reject"
        and _case_quorum(quorum, "negative-provider-homogeneity").get("failure_reason")
        == "provider_runtime_independence_missing",
    )
    check(
        checks,
        failures,
        "identity_conflict_negative_control_rejected",
        _case_quorum(quorum, "negative-identity-conflict").get("quorum_decision") == "reject"
        and _case_quorum(quorum, "negative-identity-conflict").get("failure_reason")
        == "proposer_in_verifier_quorum",
    )

    passed = bool(checks) and all(checks.values()) and not failures
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "preparation_report": artifact_ref(preparation_report_path),
            "identity_registration": artifact_ref(identity_registration_path),
        },
        "matrix": {
            "verifier_count": len(identities),
            "case_count": len(cases),
            "signed_verdict_count": len(verdicts),
            "default_quorum": allowlist,
            "proposer_identity_alias": proposer,
            "quorum_threshold": MIN_QUORUM,
            "case_quorums": quorum.get("case_quorums", []),
            "verdicts": verdicts,
        },
        "metrics": {
            "positive_cases_accepted": quorum.get("positive_cases_accepted", 0),
            "negative_controls_rejected": quorum.get("negative_controls_rejected", 0),
            "signature_verified_count": sum(item.get("signature_verified") is True for item in verdicts),
            "provider_family_count": len({str(identities_by_alias[a].get("provider_family") or "") for a in allowlist}),
            "runtime_family_count": len({str(identities_by_alias[a].get("runtime_family") or "") for a in allowlist}),
        },
        "readiness": {
            "state": "i1_read_only_verifier_matrix_complete" if passed else "blocked_i1_verifier_matrix",
            "i1_a_matrix_complete": passed,
            "i1_b_c_reconciliation_input_ready": passed,
            "i1_execution_allowed": False,
        },
        "boundary": {
            "read_only_verification_allowed": True,
            "state_mutation_allowed": False,
            "external_side_effect_allowed": False,
            "verifier_consensus_recording_allowed": True,
            "i2_command_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "matrix_does_not_mutate_runtime_state",
            "matrix_does_not_execute_external_agent_commands",
            "matrix_does_not_authorize_i2",
            "fixture_corpus_is_not_production_evidence",
        ],
    }
    write_json_object(output, report)
    return report


def _signed_verdict(
    *,
    case: dict[str, Any],
    identity: dict[str, Any],
    identities_by_alias: dict[str, dict[str, Any]],
    proposer_alias: str,
    agent: Any,
) -> dict[str, Any]:
    alias = str(identity["identity_alias"])
    key_path = Path(str(identity["identity_key_path"]))
    mode = stat.S_IMODE(key_path.stat().st_mode)
    public_key = agent.load_identity(str(key_path))
    verdict, reason = _evaluate_case(case, identities_by_alias, proposer_alias)
    payload = {
        "schema_version": VERDICT_SCHEMA_VERSION,
        "verifier_alias": alias,
        "verifier_did": identity["did"],
        "case_id": case["case_id"],
        "case_class": case["case_class"],
        "artifact_sha256": case["artifact_sha256"],
        "claimed_sha256": case["claimed_sha256"],
        "expected_verdict": case["expected_verdict"],
        "verdict": verdict,
        "failure_reason": reason,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
    }
    message = _canonical(payload).encode("utf-8")
    signature = agent.sign(message)
    VerifyKey(bytes.fromhex(public_key)).verify(message, bytes.fromhex(signature))
    return {
        **payload,
        "identity_key_mode": f"{mode:04o}",
        "signature_hex": signature,
        "signature_verified": True,
        "signed_payload_sha256": hashlib.sha256(message).hexdigest(),
        "signature_sha256": sha256_text(signature),
    }


def _evaluate_case(
    case: dict[str, Any],
    identities_by_alias: dict[str, dict[str, Any]],
    proposer_alias: str,
) -> tuple[str, str | None]:
    artifact_path = Path(str(case.get("artifact_path") or ""))
    actual_sha = sha256_file(artifact_path)
    artifact = read_json_object(artifact_path)
    metadata = object_value(case.get("control_metadata"))
    if artifact.get("schema_version") != "i1-corpus-artifact:v1":
        return "reject", "schema_invalid"
    boundary = object_value(artifact.get("boundary"))
    if (
        boundary.get("read_only") is not True
        or boundary.get("external_side_effect_allowed") is not False
        or boundary.get("automatic_state_change_allowed") is not False
    ):
        return "reject", "boundary_violation"
    if actual_sha != str(case.get("artifact_sha256") or "") or actual_sha != str(case.get("claimed_sha256") or ""):
        return "reject", "artifact_hash_mismatch"
    result = object_value(artifact.get("result"))
    checks = object_value(result.get("checks"))
    if result.get("passed") is not True or any(value is not True for value in checks.values()):
        return "reject", "semantic_result_inconsistent"
    selection = [str(item) for item in metadata.get("verifier_selection", []) if str(item)]
    if proposer_alias and proposer_alias in selection:
        return "reject", "proposer_in_verifier_quorum"
    if selection and not _provider_independence(selection, identities_by_alias):
        return "reject", "provider_runtime_independence_missing"
    if metadata.get("replay_of_control_id"):
        return "reject", "verdict_receipt_replay"
    return "accept", None


def _quorum_summary(
    *,
    cases: list[dict[str, Any]],
    verdicts: list[dict[str, Any]],
    allowlist: list[str],
) -> dict[str, Any]:
    by_case: dict[str, list[dict[str, Any]]] = {}
    for verdict in verdicts:
        by_case.setdefault(str(verdict["case_id"]), []).append(verdict)
    case_quorums = []
    positive = 0
    negative = 0
    for case in cases:
        case_id = str(case["case_id"])
        counted = [item for item in by_case.get(case_id, []) if item["verifier_alias"] in allowlist]
        verdict_counts = Counter(str(item["verdict"]) for item in counted)
        reason_counts = Counter(str(item.get("failure_reason") or "") for item in counted if item.get("failure_reason"))
        expected = str(case["expected_verdict"])
        matching = verdict_counts.get(expected, 0)
        quorum_decision = expected if matching >= MIN_QUORUM else "no_quorum"
        reason = reason_counts.most_common(1)[0][0] if reason_counts else None
        if quorum_decision == "accept" and case.get("case_class") == "positive":
            positive += 1
        if quorum_decision == "reject" and case.get("case_class") == "negative_control":
            negative += 1
        case_quorums.append(
            {
                "case_id": case_id,
                "case_class": case.get("case_class"),
                "expected_verdict": expected,
                "expected_failure_reason": case.get("expected_failure_reason"),
                "counted_verifier_aliases": [str(item["verifier_alias"]) for item in counted],
                "matching_expected_count": matching,
                "quorum_decision": quorum_decision,
                "failure_reason": reason,
                "passed": quorum_decision == expected and (
                    expected == "accept" or reason == case.get("expected_failure_reason")
                ),
            }
        )
    return {
        "case_quorums": case_quorums,
        "positive_cases_accepted": positive,
        "negative_controls_rejected": negative,
    }


def _provider_independence(
    aliases: list[str],
    identities_by_alias: dict[str, dict[str, Any]],
) -> bool:
    unique_aliases = list(dict.fromkeys(aliases))
    provider_families = {
        str(identities_by_alias.get(alias, {}).get("provider_family") or "")
        for alias in unique_aliases
    }
    runtime_families = {
        str(identities_by_alias.get(alias, {}).get("runtime_family") or "")
        for alias in unique_aliases
    }
    return (
        len(unique_aliases) >= MIN_QUORUM
        and len(provider_families - {""}) >= MIN_QUORUM
        and len(runtime_families - {""}) >= 2
    )


def _case_quorum(quorum: dict[str, Any], case_id: str) -> dict[str, Any]:
    for item in quorum.get("case_quorums", []):
        if item.get("case_id") == case_id:
            return item
    return {}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation-report", required=True)
    parser.add_argument("--identity-registration", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        preparation_report_path=Path(args.preparation_report).resolve(),
        identity_registration_path=Path(args.identity_registration).resolve(),
        output=Path(args.output).resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
