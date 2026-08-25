from datetime import datetime, timezone

import pytest

from redagent_platform import domain, passive_recon
from redagent_platform.evidence_chain import EvidenceChain, RedactionStatus
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


START = datetime(2026, 7, 8, 9, 0, tzinfo=timezone.utc)
END = datetime(2026, 7, 8, 17, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)


def scope(**overrides: object) -> EngagementScope:
    values = {
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "authorization_status": domain.AuthorizationStatus.APPROVED,
        "approved_by_user_id": "lead-1",
        "allowed_targets": (
            ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io"),
            ScopeTarget(target_type=domain.TargetType.DOMAIN, value="agentique.io"),
        ),
        "forbidden_targets": (),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
        "window_start": START,
        "window_end": END,
        "max_interactions": 20,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email",
    }
    values.update(overrides)
    return EngagementScope(**values)  # type: ignore[arg-type]


def target() -> ScopeTarget:
    return ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def test_passive_plan_includes_required_metadata_checks_without_payloads() -> None:
    plan = passive_recon.build_passive_recon_plan(
        scope=scope(),
        target=target(),
        requested_at=NOW,
        job_id="job-passive-1",
    )
    kinds = {spec.kind for spec in plan.specs}

    assert passive_recon.PassiveCheckKind.HTTP_HEADERS in kinds
    assert passive_recon.PassiveCheckKind.TLS_METADATA in kinds
    assert passive_recon.PassiveCheckKind.DNS_METADATA in kinds
    assert passive_recon.PassiveCheckKind.ROBOTS_TXT in kinds
    assert passive_recon.PassiveCheckKind.SECURITY_TXT in kinds
    assert passive_recon.PassiveCheckKind.TECH_FINGERPRINT in kinds
    assert passive_recon.PassiveCheckKind.OPENAPI_METADATA in kinds
    assert all(not spec.payload_present for spec in plan.specs)
    assert all(not spec.follow_redirects for spec in plan.specs)
    assert {spec.method for spec in plan.specs if spec.transport is passive_recon.PassiveTransport.HTTP} <= {"GET", "HEAD"}


def test_passive_plan_respects_scope_and_interaction_cap() -> None:
    with pytest.raises(ValueError, match="passive_scope_denied:target_not_in_allowlist"):
        passive_recon.build_passive_recon_plan(
            scope=scope(),
            target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io"),
            requested_at=NOW,
            job_id="job-passive-2",
        )

    with pytest.raises(ValueError, match="passive_scope_denied:interaction_cap_exceeded"):
        passive_recon.build_passive_recon_plan(
            scope=scope(max_interactions=2),
            target=target(),
            requested_at=NOW,
            job_id="job-passive-3",
        )


def test_passive_plan_records_minimum_delay_from_rate_limit() -> None:
    plan = passive_recon.build_passive_recon_plan(
        scope=scope(max_rate_per_second=0.5),
        target=target(),
        requested_at=NOW,
        job_id="job-passive-4",
    )

    assert plan.min_delay_seconds == 2.0
    assert plan.projected_interactions == sum(1 for spec in plan.specs if spec.target_interaction)


def test_passive_module_has_no_network_execution_surface() -> None:
    assert not hasattr(passive_recon, "send_request")
    assert not hasattr(passive_recon, "run_scan")
    assert not hasattr(passive_recon, "crawl")


def test_observation_evidence_is_redacted_before_storage() -> None:
    observation = passive_recon.PassiveObservation(
        spec_id="web:headers",
        kind=passive_recon.PassiveCheckKind.HTTP_HEADERS,
        target=target(),
        captured_at=NOW,
        status_code=200,
        headers=(
            passive_recon.HeaderObservation(name="server", value="cloudflare"),
            passive_recon.HeaderObservation(name="set-cookie", value="session=secret"),
        ),
        body_excerpt="Contact security@example.com with token=abc123",
    )

    result = passive_recon.append_passive_observation_evidence(
        chain=EvidenceChain(),
        observation=observation,
        evidence_id="evidence-passive-1",
        organization_id="org-1",
        source_job_id="job-passive-1",
    )

    assert result.record.kind is domain.EvidenceKind.HTTP_METADATA
    assert result.record.redaction_status is RedactionStatus.REDACTED
    assert result.sanitized_observation.redacted
    assert result.sanitized_observation.content["body_excerpt"] == "Contact [redacted-email] with token=[redacted]"


def test_passive_observation_finding_links_to_evidence() -> None:
    observation = passive_recon.PassiveObservation(
        spec_id="dns:agentique.io",
        kind=passive_recon.PassiveCheckKind.DNS_METADATA,
        target=ScopeTarget(target_type=domain.TargetType.DOMAIN, value="agentique.io"),
        captured_at=NOW,
        dns_records=("A redacted-edge",),
    )
    evidence = passive_recon.append_passive_observation_evidence(
        chain=EvidenceChain(),
        observation=observation,
        evidence_id="evidence-passive-2",
        organization_id="org-1",
        source_job_id="job-passive-2",
    ).record

    finding = passive_recon.build_passive_metadata_finding(
        finding_id="finding-passive-1",
        observation=observation,
        evidence_record=evidence,
    )

    assert finding.status is domain.FindingStatus.NEEDS_REVIEW
    assert finding.severity.value == "info"
    assert finding.evidence_links[0].evidence_id == "evidence-passive-2"
    assert finding.evidence_links[0].integrity_hash == evidence.integrity_hash
