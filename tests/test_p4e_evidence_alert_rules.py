from pathlib import Path

import yaml


RULES = (
    Path(__file__).resolve().parents[1]
    / "observability"
    / "prometheus"
    / "p4e_evidence_alert_rules.yml"
)


def test_p4e_evidence_alert_rules_are_actionable_and_bounded() -> None:
    document = yaml.safe_load(RULES.read_text())
    rules = document["groups"][0]["rules"]
    by_name = {rule["alert"]: rule for rule in rules}

    assert set(by_name) == {
        "CivitasOSEvidenceExportLagging",
        "CivitasOSEvidenceExportBacklogCritical",
        "CivitasOSEvidenceMetricsMissing",
    }
    assert by_name["CivitasOSEvidenceExportLagging"]["for"] == "2m"
    assert by_name["CivitasOSEvidenceExportBacklogCritical"]["for"] == "15m"
    assert by_name["CivitasOSEvidenceMetricsMissing"]["for"] == "5m"
    assert {rule["labels"]["severity"] for rule in rules} == {"warning", "critical"}
    assert all(rule["annotations"].get("runbook") for rule in rules)

    expressions = "\n".join(rule["expr"] for rule in rules)
    for metric in (
        "civitasos_evidence_export_lagging",
        "civitasos_evidence_export_pending",
        "civitasos_evidence_export_healthy",
    ):
        assert metric in expressions
