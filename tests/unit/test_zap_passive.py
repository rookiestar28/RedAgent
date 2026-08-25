from datetime import datetime, timezone

import pytest

from redagent_platform import domain, zap_passive
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
            ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value="lab:crapi/lab-crapi-local"),
        ),
        "forbidden_targets": (),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN, domain.TestMode.LAB_ONLY_RUN),
        "window_start": START,
        "window_end": END,
        "max_interactions": 20,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email",
    }
    values.update(overrides)
    return EngagementScope(**values)  # type: ignore[arg-type]


def capture(**overrides: object) -> zap_passive.ZapPassiveCaptureContext:
    values = {
        "capture_id": "capture-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io"),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "captured_at": NOW,
        "projected_interactions": 1,
    }
    values.update(overrides)
    return zap_passive.ZapPassiveCaptureContext(**values)  # type: ignore[arg-type]


def alert(**overrides: object) -> zap_passive.ZapPassiveAlert:
    values = {
        "plugin_id": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "risk": zap_passive.ZapRisk.LOW,
        "confidence": zap_passive.ZapConfidence.MEDIUM,
        "url": "https://www.agentique.io/",
        "method": "GET",
        "evidence": "Missing x-content-type-options header",
        "description": "Passive header observation.",
        "solution": "Add the nosniff header.",
        "cwe_id": "693",
        "request_header": "GET / HTTP/1.1\r\nCookie: session=abc",
        "response_header": "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nX-Api-Key: secret",
    }
    values.update(overrides)
    return zap_passive.ZapPassiveAlert(**values)  # type: ignore[arg-type]


def test_authorized_passive_capture_is_accepted() -> None:
    decision = zap_passive.authorize_passive_capture(scope(), capture())

    assert decision.allowed
    assert decision.reason == "scope_authorized"


def test_lab_only_capture_requires_lab_target() -> None:
    allowed = zap_passive.authorize_passive_capture(
        scope(),
        capture(
            target=ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value="lab:crapi/lab-crapi-local"),
            mode=domain.TestMode.LAB_ONLY_RUN,
        ),
    )
    denied = zap_passive.authorize_passive_capture(scope(), capture(mode=domain.TestMode.LAB_ONLY_RUN))

    assert allowed.allowed
    assert denied.reason == "lab_target_required"


def test_out_of_scope_capture_is_rejected() -> None:
    decision = zap_passive.authorize_passive_capture(
        scope(),
        capture(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io")),
    )

    assert not decision.allowed
    assert decision.reason == "target_not_in_allowlist"


def test_evidence_preserves_redacted_request_response_metadata() -> None:
    decision = zap_passive.authorize_passive_capture(scope(), capture())
    result = zap_passive.append_zap_passive_evidence(
        chain=EvidenceChain(),
        capture=capture(),
        alert=alert(),
        evidence_id="evidence-zap-1",
        authorization=decision,
    )

    assert result.record.redaction_status is RedactionStatus.REDACTED
    assert result.redacted
    assert "Cookie: [redacted]" in result.sanitized_content["request_header"]
    assert "X-Api-Key: [redacted]" in result.sanitized_content["response_header"]


def test_zap_risk_confidence_and_rule_id_normalize_to_finding() -> None:
    decision = zap_passive.authorize_passive_capture(scope(), capture())
    evidence = zap_passive.append_zap_passive_evidence(
        chain=EvidenceChain(),
        capture=capture(),
        alert=alert(risk=zap_passive.ZapRisk.MEDIUM, confidence=zap_passive.ZapConfidence.HIGH),
        evidence_id="evidence-zap-2",
        authorization=decision,
    ).record
    finding = zap_passive.normalize_zap_alert_to_finding(
        finding_id="finding-zap-1",
        capture=capture(),
        alert=alert(risk=zap_passive.ZapRisk.MEDIUM, confidence=zap_passive.ZapConfidence.HIGH),
        evidence_record=evidence,
        authorization=decision,
    )

    assert finding.source == "zap_passive"
    assert finding.source_rule_id == "10021"
    assert finding.severity.value == "medium"
    assert finding.confidence.value == "high"
    assert finding.risk.vulnerability_intelligence.cwe_ids == ("CWE-693",)
    assert finding.evidence_links[0].evidence_id == "evidence-zap-2"


def test_denied_capture_cannot_create_evidence_or_finding() -> None:
    denied = zap_passive.authorize_passive_capture(
        scope(),
        capture(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io")),
    )

    with pytest.raises(ValueError, match="zap_passive_capture_denied"):
        zap_passive.append_zap_passive_evidence(
            chain=EvidenceChain(),
            capture=capture(),
            alert=alert(),
            evidence_id="evidence-zap-denied",
            authorization=denied,
        )


def test_active_scan_and_spider_apis_are_disabled_by_policy() -> None:
    with pytest.raises(ValueError, match="zap_active_scan_disabled_by_policy"):
        zap_passive.start_active_scan(target="https://www.agentique.io")

    with pytest.raises(ValueError, match="zap_spider_disabled_by_policy"):
        zap_passive.spider_target(target="https://www.agentique.io")
