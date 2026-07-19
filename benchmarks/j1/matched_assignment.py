"""Deterministic exact-strata assignment for J1-D cohorts."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .controlled_comparison import REQUIRED_STRATA, canonical_sha256, validate_protocol


ASSIGNMENT_SCHEMA = "j1-matched-assignment-manifest:v1"


def build_assignment(
    protocol: dict[str, Any], participants: list[dict[str, Any]]
) -> dict[str, Any]:
    failures = validate_protocol(protocol)
    participant_ids: set[str] = set()
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    ordered_strata = sorted(REQUIRED_STRATA)
    for participant in participants:
        participant_id = str(participant.get("participant_id") or "").strip()
        if not participant_id:
            failures.append("participant_id_missing")
            continue
        if participant_id in participant_ids:
            failures.append("participant_id_duplicate")
            continue
        participant_ids.add(participant_id)
        values = tuple(
            str(participant.get(field) or "").strip() for field in ordered_strata
        )
        if any(not value for value in values):
            failures.append("participant_stratum_missing")
            continue
        groups[values].append(participant)

    if any(len(group) != 2 for group in groups.values()):
        failures.append("each_exact_stratum_must_have_two_participants")
    minimum = int(protocol.get("assignment", {}).get("minimum_completed_pairs") or 0)
    if len(groups) < minimum:
        failures.append("matched_pair_sample_too_small")

    assignments: list[dict[str, Any]] = []
    if not failures:
        seed = protocol["assignment"]["seed"]
        for pair_index, (strata, group) in enumerate(sorted(groups.items()), start=1):
            pair_id = f"j1-pair:{pair_index:04d}:{canonical_sha256(strata)[:12]}"
            members = sorted(group, key=lambda item: item["participant_id"])
            bit = int(canonical_sha256([seed, pair_id]), 16) & 1
            mentor_index = bit
            for index, member in enumerate(members):
                assignments.append(
                    {
                        "participant_id": member["participant_id"],
                        "pair_id": pair_id,
                        "cohort": "mentor" if index == mentor_index else "control",
                        "strata_sha256": canonical_sha256(
                            dict(zip(ordered_strata, strata, strict=True))
                        ),
                    }
                )

    assignments.sort(key=lambda item: (item["pair_id"], item["participant_id"]))
    protocol_sha256 = canonical_sha256(protocol)
    manifest = {
        "schema_version": ASSIGNMENT_SCHEMA,
        "passed": not failures,
        "failure_reasons": list(dict.fromkeys(failures)),
        "protocol_sha256": protocol_sha256,
        "participant_count": len(participants),
        "matched_pair_count": len(assignments) // 2,
        "assignments": assignments,
        "assignment_sha256": canonical_sha256(
            {"protocol_sha256": protocol_sha256, "assignments": assignments}
        ),
        "synthetic_dry_run_only": protocol.get("validation_profile")
        == "development_dry_run",
    }
    return manifest
