"""Closed, deterministic, minimized compat_115 interchange projections."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class InterchangeFinding:
    issue_id: str
    fingerprint: str
    rule_id: str
    title: str
    severity: str
    disposition: str
    resource_id: str
    location_id: str
    evidence_sha256: str
    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    component_purl: str | None
    reviewed: bool


def export_sarif(findings: tuple[InterchangeFinding, ...]) -> dict[str, object]:
    _reviewed(findings)
    rules = [{"id": item.rule_id, "name": item.title} for item in sorted(findings, key=lambda value: value.rule_id)]
    results = [{
        "ruleId": item.rule_id, "level": _sarif_level(item.severity),
        "message": {"text": item.title},
        "partialFingerprints": {"redagent/v1": item.fingerprint},
        "locations": [{"logicalLocations": [{"fullyQualifiedName": item.resource_id,
                                                "decoratedName": item.location_id}]}],
        "properties": {"issueId": item.issue_id, "disposition": item.disposition,
                       "evidenceSha256": item.evidence_sha256},
    } for item in sorted(findings, key=lambda value: value.issue_id)]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "RedAgent", "rules": rules}}, "results": results}]}


def export_ocsf(findings: tuple[InterchangeFinding, ...]) -> dict[str, object]:
    _reviewed(findings)
    if len(findings) != 1:
        raise ValueError("ocsf_single_finding_projection_required")
    item = findings[0]
    return {
        "metadata": {"product": {"name": "RedAgent"}, "version": "1.8.0"},
        "category_name": "Findings", "class_name": "Vulnerability Finding", "activity_name": "Create",
        "finding_info": {"uid": item.issue_id, "title": item.title, "status": item.disposition},
        "vulnerabilities": [{"cve": {"uid": cve}, "cwe": [{"uid": cwe} for cwe in item.cwe_ids]}
                            for cve in item.cve_ids],
        "resource": {"uid": item.resource_id},
        "evidences": [{"data": {"hash": item.evidence_sha256}}],
    }


def export_cyclonedx_vex(findings: tuple[InterchangeFinding, ...]) -> dict[str, object]:
    _reviewed(findings)
    vulnerabilities = []
    for item in sorted(findings, key=lambda value: value.issue_id):
        if item.component_purl is None:
            raise ValueError("vex_component_identity_required")
        vulnerabilities.append({
            "id": item.cve_ids[0] if item.cve_ids else item.issue_id,
            "affects": [{"ref": item.component_purl}],
            "analysis": {"state": _vex_state(item.disposition),
                         "detail": f"Reviewed RedAgent disposition {item.disposition}."},
            "properties": [{"name": "redagent:evidenceSha256", "value": item.evidence_sha256}],
        })
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "RedAgent reviewed findings"}},
            "vulnerabilities": vulnerabilities}


def _reviewed(findings: tuple[InterchangeFinding, ...]) -> None:
    if not findings or any(not item.reviewed or len(item.evidence_sha256) != 64 for item in findings):
        raise ValueError("interchange_review_required")


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "none")


def _vex_state(disposition: str) -> str:
    return {
        "confirmed": "exploitable", "false_positive": "false_positive", "mitigated": "resolved",
        "out_of_scope": "not_affected", "risk_accepted": "in_triage", "needs_review": "in_triage",
    }.get(disposition, "in_triage")
