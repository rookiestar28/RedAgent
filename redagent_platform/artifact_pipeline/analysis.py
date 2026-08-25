"""Deterministic compat_110 component, CI, and mobile checks over canonical data only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Mapping


_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class ComponentInput:
    component_id: str; component_type: str; name: str; version: str | None; purl: str | None; license_expression: str


@dataclass(frozen=True, kw_only=True)
class WorkflowInput:
    workflow_id: str; trigger: str; checks_out_untrusted_ref: bool; interpolates_untrusted_context: bool
    action_refs: tuple[str, ...]; token_permissions: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class MobileInput:
    platform: str; application_id: str; debuggable: bool; cleartext_traffic: bool; exported_components: int; signing_state: str


@dataclass(frozen=True, kw_only=True)
class PipelineFixture:
    artifact_sha256: str; manifest_sha256: str; components: tuple[ComponentInput, ...]
    workflows: tuple[WorkflowInput, ...]; mobile: tuple[MobileInput, ...]; complete: bool; partial_reasons: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class PromotedRules:
    bundle_id: str; bundle_sha256: str; schema_sha256: str
    def __post_init__(self) -> None:
        if not self.bundle_id or not _SHA.fullmatch(self.bundle_sha256) or not _SHA.fullmatch(self.schema_sha256): raise ValueError("artifact_rules_invalid")


@dataclass(frozen=True, kw_only=True)
class PromotedDatabase:
    database_id: str; database_sha256: str; schema_sha256: str; advisories: Mapping[str, tuple[str, str]]
    def __post_init__(self) -> None:
        if not self.database_id or not _SHA.fullmatch(self.database_sha256) or not _SHA.fullmatch(self.schema_sha256): raise ValueError("artifact_database_invalid")


@dataclass(frozen=True, kw_only=True)
class ComponentObservation:
    component_id: str; purl: str | None; identity_complete: bool; component_sha256: str


@dataclass(frozen=True, kw_only=True)
class StaticFinding:
    rule_id: str; resource_id: str; severity: str


@dataclass(frozen=True, kw_only=True)
class VulnerabilityMatch:
    component_id: str; advisory_id: str; severity: str; database_sha256: str


@dataclass(frozen=True, kw_only=True)
class PipelineResult:
    artifact_sha256: str; rules_sha256: str; database_sha256: str; complete: bool; clean: bool
    partial_reasons: tuple[str, ...]; components: tuple[ComponentObservation, ...]
    vulnerabilities: tuple[VulnerabilityMatch, ...]; static_findings: tuple[StaticFinding, ...]
    untrusted_execution_count: int; external_contact_count: int; analyzed_at: datetime; result_sha256: str


def analyze_fixture(*, fixture: PipelineFixture, rules: PromotedRules, database: PromotedDatabase, analyzed_at: datetime) -> PipelineResult:
    if analyzed_at.tzinfo is None or analyzed_at.utcoffset() is None or not _SHA.fullmatch(fixture.artifact_sha256) or not _SHA.fullmatch(fixture.manifest_sha256): raise ValueError("artifact_fixture_invalid")
    partial = set(fixture.partial_reasons); components = []
    for item in fixture.components:
        complete_identity = bool(item.purl and item.version and item.purl.startswith(f"pkg:{item.component_type}/"))
        if not complete_identity: partial.add("component-identity-incomplete")
        digest = _digest([item.component_id, item.component_type, item.name, item.version, item.purl, item.license_expression])
        components.append(ComponentObservation(component_id=item.component_id, purl=item.purl, identity_complete=complete_identity, component_sha256=digest))
    vulnerabilities = tuple(sorted((VulnerabilityMatch(component_id=item.component_id, advisory_id=database.advisories[item.purl][0], severity=database.advisories[item.purl][1], database_sha256=database.database_sha256)
        for item in fixture.components if item.purl in database.advisories), key=lambda row: (row.component_id, row.advisory_id)))
    findings = []
    for workflow in fixture.workflows:
        privileged = workflow.trigger in {"pull_request_target", "workflow_run"}
        if privileged and workflow.checks_out_untrusted_ref: findings.append(StaticFinding(rule_id="ci-dangerous-checkout", resource_id=workflow.workflow_id, severity="critical"))
        if workflow.interpolates_untrusted_context: findings.append(StaticFinding(rule_id="ci-context-injection", resource_id=workflow.workflow_id, severity="critical"))
        if any(not _pinned(ref) for ref in workflow.action_refs): findings.append(StaticFinding(rule_id="ci-unpinned-action", resource_id=workflow.workflow_id, severity="high"))
        if any(permission.endswith(":write") or permission == "write-all" for permission in workflow.token_permissions): findings.append(StaticFinding(rule_id="ci-token-write", resource_id=workflow.workflow_id, severity="high"))
    for mobile in fixture.mobile:
        if mobile.debuggable: findings.append(StaticFinding(rule_id="mobile-debuggable", resource_id=mobile.application_id, severity="high"))
        if mobile.cleartext_traffic: findings.append(StaticFinding(rule_id="mobile-cleartext", resource_id=mobile.application_id, severity="high"))
        if mobile.exported_components: findings.append(StaticFinding(rule_id="mobile-exported", resource_id=mobile.application_id, severity="medium"))
        if mobile.signing_state != "release": findings.append(StaticFinding(rule_id="mobile-debug-signing", resource_id=mobile.application_id, severity="high"))
    ordered_findings = tuple(sorted(findings, key=lambda row: (row.resource_id, row.rule_id)))
    ordered_components = tuple(sorted(components, key=lambda row: row.component_id)); complete = fixture.complete and not partial
    clean = complete and not vulnerabilities and not ordered_findings
    material = {"schema": "redagent.r110-result/v1", "artifact": fixture.artifact_sha256, "manifest": fixture.manifest_sha256,
        "rules": rules.bundle_sha256, "database": database.database_sha256, "complete": complete, "clean": clean,
        "partial": sorted(partial), "components": [item.__dict__ for item in ordered_components],
        "vulnerabilities": [item.__dict__ for item in vulnerabilities], "findings": [item.__dict__ for item in ordered_findings],
        "execution": 0, "contacts": 0, "analyzed_at": analyzed_at.isoformat()}
    return PipelineResult(artifact_sha256=fixture.artifact_sha256, rules_sha256=rules.bundle_sha256, database_sha256=database.database_sha256,
        complete=complete, clean=clean, partial_reasons=tuple(sorted(partial)), components=ordered_components, vulnerabilities=vulnerabilities,
        static_findings=ordered_findings, untrusted_execution_count=0, external_contact_count=0, analyzed_at=analyzed_at, result_sha256=_digest(material))


def _pinned(reference: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", reference))


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
