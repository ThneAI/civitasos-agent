"""Write P1-R real source confirmation collection packet.

The packet is an operator-facing intake surface. It writes four confirmation
JSON templates and a runner script, but never creates production evidence.
"""

from __future__ import annotations

import argparse
import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, write_json_object
from benchmarks.p1r_real_source_confirmation_gate import CONFIRMATION_SCHEMA, EVENT_CATALOG, ROLE_CONFIRMATION_FILES

PACKET_SCHEMA = "p1r-real-source-confirmation-collection-packet:v1"
NON_CLAIMS = (
    "collection_packet_contains_templates_not_real_evidence",
    "operator_must_replace_all_placeholders_before_running_p1r",
    "collection_packet_does_not_mark_production_origin_confirmed",
    "collection_packet_does_not_authorize_runtime_execution_or_production_transition",
)


def write_collection_packet(
    *,
    output_root: Path,
    p0q_summary_path: Path,
    p1_summary_path: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    if output_root.exists() and any(output_root.iterdir()) and not overwrite:
        raise FileExistsError(f"Refusing to overwrite non-empty P1-R collection packet: {output_root}")
    inputs = output_root / "inputs"
    reports = output_root / "reports"
    inputs.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    template_paths = {
        role: inputs / f"{role}_confirmation.json"
        for role in ROLE_CONFIRMATION_FILES
    }
    for role, path in template_paths.items():
        write_json_object(path, _template_for_role(role))

    _write_inputs_readme(inputs / "README.md")
    _write_reports_readme(reports / "README.md")
    _write_packet_readme(output_root / "README.md")
    _write_runner(
        output_root / "run_p1r_gate.sh",
        p0q_summary_path=p0q_summary_path,
        p1_summary_path=p1_summary_path,
    )
    _write_pending_status(output_root / "PENDING_STATUS.json")

    summary = {
        "schema_version": PACKET_SCHEMA,
        "passed": True,
        "written_at": _now(),
        "output_root": str(output_root.resolve()),
        "source_artifacts": {
            "p0q_summary": artifact_ref(p0q_summary_path) if p0q_summary_path.is_file() else {"path": str(p0q_summary_path)},
            "p1_summary": artifact_ref(p1_summary_path) if p1_summary_path.is_file() else {"path": str(p1_summary_path)},
        },
        "template_artifacts": {role: artifact_ref(path) for role, path in template_paths.items()},
        "template_record_count": sum(len(_template_for_role(role)["records"]) for role in ROLE_CONFIRMATION_FILES),
        "required_record_count": len(EVENT_CATALOG),
        "ready_for_p1r_gate": False,
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output_root / "p1r_collection_packet_summary.json", summary)
    return summary


def _template_for_role(role: str) -> dict[str, Any]:
    return {
        "schema_version": CONFIRMATION_SCHEMA,
        "confirmation_role": role,
        "confirmed_by": f"TODO_REPLACE_REAL_{role.upper()}_REVIEWER",
        "production_origin_confirmed": False,
        "candidate_ref_promoted": False,
        "source": f"TODO_REPLACE_REAL_{role.upper()}_SOURCE_SYSTEM",
        "source_provider": f"TODO_REPLACE_REAL_{role.upper()}_SOURCE_PROVIDER",
        "source_uri": f"TODO_REPLACE_REAL_{role.upper()}_SOURCE_URI",
        "captured_at": "TODO_REPLACE_CAPTURED_AT_ISO8601",
        "records": [_record_template(role, event_kind, catalog) for event_kind, catalog in EVENT_CATALOG.items() if catalog["role"] == role],
        "collection_rules": {
            "must_be_real_production_origin": True,
            "must_not_use_candidate_refs_as_evidence": True,
            "must_not_use_local_test_mock_synthetic_demo_sources": True,
        },
        "non_claims": list(NON_CLAIMS),
    }


def _record_template(role: str, event_kind: str, catalog: dict[str, str]) -> dict[str, Any]:
    ref_field = catalog["ref_field"]
    return {
        "source_event_kind": event_kind,
        "reviewer": f"TODO_REPLACE_REAL_{role.upper()}_REVIEWER",
        "attestation_ref": f"TODO_REPLACE_REAL_{event_kind.upper()}_ATTESTATION_REF",
        ref_field: f"TODO_REPLACE_REAL_{ref_field.upper()}",
        "source_uri": f"TODO_REPLACE_REAL_{event_kind.upper()}_SOURCE_URI",
        "captured_at": "TODO_REPLACE_CAPTURED_AT_ISO8601",
        "evidence_summary": f"TODO_REPLACE_REAL_EVIDENCE_SUMMARY_FOR_{event_kind}",
        "risk_level": "low",
        "rollback_required": True,
    }


def _write_inputs_readme(path: Path) -> None:
    path.write_text(
        """# P1-R Confirmation Inputs\n\nFill these four files with real production-origin confirmations before running `../run_p1r_gate.sh`:\n\n- `owner_confirmation.json`\n- `audit_confirmation.json`\n- `monitoring_confirmation.json`\n- `rollback_confirmation.json`\n\nRequired edits:\n\n- Replace every `TODO_REPLACE_*` value.\n- Set `production_origin_confirmed=true` only after the source record is real.\n- Keep `candidate_ref_promoted=false`.\n- Use source/provider names that do not include local/test/mock/fixture/synthetic/demo/candidate.\n- Each record must point to a real source URI or ticket/log/monitoring/audit reference.\n""",
        encoding="utf-8",
    )


def _write_reports_readme(path: Path) -> None:
    path.write_text(
        """# P1-R Reports\n\n`run_p1r_gate.sh` writes gate outputs here. A successful run should include:\n\n- `p1r_real_source_confirmation_packet.json`\n- `round2_real_evidence_source_manifest.json`\n- `production_evidence_submission.json`\n- `h3_production_evidence_gap_map_after_p1r.json`\n- `p1r_real_source_confirmation_summary.json`\n""",
        encoding="utf-8",
    )


def _write_packet_readme(path: Path) -> None:
    path.write_text(
        """# P1-R Real Source Confirmation Collection Packet\n\nThis packet is a collection surface, not evidence by itself. Fill `inputs/*.json` from real owner/audit/monitoring/rollback records, then run:\n\n```bash\n./run_p1r_gate.sh\n```\n\nPassing P1-R means Round 2 A is assembled and the H3 gap mapper sees 16/16 production records. It still does not create L2 anchor, independent verification, or production transition authorization.\n""",
        encoding="utf-8",
    )


def _write_runner(path: Path, *, p0q_summary_path: Path, p1_summary_path: Path) -> None:
    script = f"""#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
AGENT_ROOT="${{CIVITASOS_AGENT_ROOT:-$(cd "$ROOT/../.." && pwd)}}"
PYTHON="${{CIVITASOS_AGENT_PYTHON:-$AGENT_ROOT/.venv/bin/python}}"
if [ ! -x "$PYTHON" ]; then
  PYTHON="python"
fi

EXTRA_ARGS=()
if [ "${{CIVITASOS_P1R_OPERATOR_ATTESTED_PRODUCTION:-${{CIVITASOS_P1R_OPERATOR_ATTESTED_CONTROLLED_PILOT:-false}}}}" = "true" ]; then
  EXTRA_ARGS+=(--operator-attested-production)
  EXTRA_ARGS+=(--operator-attester "${{CIVITASOS_P1R_OPERATOR_ATTESTER:?CIVITASOS_P1R_OPERATOR_ATTESTER is required}}")
  EXTRA_ARGS+=(--operator-attestation-statement "${{CIVITASOS_P1R_OPERATOR_ATTESTATION_STATEMENT:?CIVITASOS_P1R_OPERATOR_ATTESTATION_STATEMENT is required}}")
fi

cd "$AGENT_ROOT"
"$PYTHON" -m benchmarks.p1r_real_source_confirmation_gate \\
  --p0q-summary "${{CIVITASOS_P1R_P0Q_SUMMARY:-{p0q_summary_path.resolve()}}}" \\
  --p1-summary "${{CIVITASOS_P1R_P1_SUMMARY:-{p1_summary_path.resolve()}}}" \\
  --owner-confirmation "$ROOT/inputs/owner_confirmation.json" \\
  --audit-confirmation "$ROOT/inputs/audit_confirmation.json" \\
  --monitoring-confirmation "$ROOT/inputs/monitoring_confirmation.json" \\
  --rollback-confirmation "$ROOT/inputs/rollback_confirmation.json" \\
  --output-root "$ROOT/reports" \\
  "${{EXTRA_ARGS[@]}}"
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_pending_status(path: Path) -> None:
    write_json_object(
        path,
        {
            "schema_version": PACKET_SCHEMA,
            "ready_for_p1r_gate": False,
            "required_inputs": [f"inputs/{role}_confirmation.json" for role in ROLE_CONFIRMATION_FILES],
            "blocked_until": "operator_replaces_templates_with_real_production_origin_confirmations",
            "non_claims": list(NON_CLAIMS),
        },
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Write P1-R real source confirmation collection packet")
    parser.add_argument("--p0q-summary", required=True, type=Path)
    parser.add_argument("--p1-summary", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    summary = write_collection_packet(
        output_root=args.output_root,
        p0q_summary_path=args.p0q_summary,
        p1_summary_path=args.p1_summary,
        overwrite=args.overwrite,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
