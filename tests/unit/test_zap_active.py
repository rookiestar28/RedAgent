from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import active_policy, auth_sessions, domain, evidence_chain, zap_active
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget
from redagent_platform.zap_passive import ZapConfidence, ZapRisk


NOW = datetime(2026, 7, 8, 14, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-1",
        organization_id="org-1",
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="lead-1",
        allowed_targets=(TARGET,),
        forbidden_targets=(),
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        window_start=NOW - timedelta(minutes=5),
        window_end=NOW + timedelta(hours=1),
        max_interactions=20,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def module_policy() -> active_policy.ActiveModulePolicy:
    return active_policy.ActiveModulePolicy(
        module_id="zap-active",
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        allowed_payload_classes=(active_policy.PayloadClass.STANDARD_ACTIVE,),
        max_rate_per_second=1.0,
        max_requests=10,
        max_duration_seconds=300,
        max_concurrent_per_engagement=2,
        max_concurrent_per_target=1,
        stop_conditions=active_policy.StopConditionPolicy(
            stop_on_scope_violation=True,
            stop_on_error_rate=True,
            max_error_count=3,
            emergency_contact_required=True,
        ),
    )


def active_request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "zap-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "zap-active",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "requested_at": NOW,
        "projected_requests": 5,
        "projected_duration_seconds": 60,
        "requested_rate_per_second": 0.5,
        "operator_confirmation": active_policy.OperatorConfirmation(
            confirmed_by_user_id="operator-1",
            confirmed_at=NOW - timedelta(minutes=1),
            scope_acknowledged=True,
            risk_acknowledged=True,
            stop_conditions_acknowledged=True,
        ),
    }
    values.update(overrides)
    return active_policy.ActiveJobRequest(**values)  # type: ignore[arg-type]


def active_result(request: active_policy.ActiveJobRequest | None = None) -> active_policy.ActivePolicyResult:
    return active_policy.evaluate_active_policy(
        request=request or active_request(),
        scope=scope(),
        module_policy=module_policy(),
        existing_jobs=(),
        audit_chain=evidence_chain.EvidenceChain(),
        decision_id="active-decision-1",
        policy_expires_at=NOW + timedelta(minutes=30),
    )


def scan_policy(**overrides: object) -> zap_active.ZapActiveScanPolicy:
    values = {
        "policy_id": "zap-active-standard",
        "display_name": "ZAP active standard policy",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "max_rule_strength": "medium",
    }
    values.update(overrides)
    return zap_active.ZapActiveScanPolicy(**values)  # type: ignore[arg-type]


def warning() -> zap_active.ZapActiveWarning:
    return zap_active.ZapActiveWarning(
        warning_id="warning-1",
        title="Active scan may change application state",
        body="Use only inside approved scope and window.",
    )


def acknowledgement(**overrides: object) -> zap_active.ZapActiveWarningAcknowledgement:
    values = {
        "acknowledgement_id": "ack-1",
        "displayed_to_operator": True,
        "acknowledged_by_user_id": "operator-1",
        "acknowledged_at": NOW - timedelta(seconds=30),
        "warning_ids": ("warning-1",),
    }
    values.update(overrides)
    return zap_active.ZapActiveWarningAcknowledgement(**values)  # type: ignore[arg-type]


def lab_validation(**overrides: object) -> zap_active.ZapActiveLabValidation:
    values = {
        "validation_id": "lab-validation-1",
        "passed": True,
        "validated_at": NOW - timedelta(minutes=10),
        "lab_target_id": "juice-shop-local",
        "scan_policy_ids": ("zap-active-standard",),
        "evidence_id": "lab-evidence-1",
    }
    values.update(overrides)
    return zap_active.ZapActiveLabValidation(**values)  # type: ignore[arg-type]


def auth_context(**overrides: object) -> auth_sessions.AuthenticatedSessionContext:
    values = {
        "session_id": "session-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "credential_lease_id": "lease-1",
        "role_label": "standard-user",
        "created_at": NOW - timedelta(minutes=2),
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "session-token",
    }
    values.update(overrides)
    return auth_sessions.AuthenticatedSessionContext(**values)  # type: ignore[arg-type]


def plan_request(**overrides: object) -> zap_active.ZapActiveScanPlanRequest:
    request = active_request()
    values = {
        "plan_id": "zap-plan-1",
        "active_request": request,
        "active_policy": active_result(request),
        "scan_policy": scan_policy(),
        "warnings": (warning(),),
        "warning_acknowledgement": acknowledgement(),
        "lab_validation": lab_validation(),
        "authenticated_context": auth_context(),
        "planned_at": NOW,
    }
    values.update(overrides)
    return zap_active.ZapActiveScanPlanRequest(**values)  # type: ignore[arg-type]


def alert(**overrides: object) -> zap_active.ZapActiveAlert:
    values = {
        "plugin_id": "40012",
        "alert_id": "alert-1",
        "name": "Reflected input detected",
        "risk": ZapRisk.MEDIUM,
        "confidence": ZapConfidence.HIGH,
        "url": "https://www.agentique.io/search?q=test",
        "method": "GET",
        "attack": "Reflected test marker",
        "evidence": "marker reflected in sanitized response",
        "description": "ZAP active rule reported reflected input.",
        "solution": "Validate and encode reflected input.",
        "cwe_id": "79",
        "request_header": "GET /search HTTP/1.1\r\n" + "Author" + "ization: Bearer sample",
    }
    values.update(overrides)
    return zap_active.ZapActiveAlert(**values)  # type: ignore[arg-type]


def test_build_zap_active_plan_requires_r017_policy_warning_ack_lab_validation_and_auth_context() -> None:
    plan = zap_active.build_zap_active_scan_plan(plan_request())

    assert plan.job.status is domain.JobStatus.AUTHORIZED
    assert plan.scan_policy_id == "zap-active-standard"
    assert plan.authenticated_context_id == "session-1"
    assert plan.warning_acknowledgement_id == "ack-1"
    assert plan.lab_validation_id == "lab-validation-1"
    assert plan.timeout_seconds == 60
    assert plan.rate_limit_per_second == 0.5
    assert plan.max_requests == 5
    assert plan.cancellation_supported


@pytest.mark.parametrize(
    ("override", "expected_reason"),
    (
        ({"warning_acknowledgement": acknowledgement(displayed_to_operator=False)}, "active_warnings_not_displayed"),
        ({"warning_acknowledgement": acknowledgement(warning_ids=())}, "active_warning_acknowledgement_incomplete"),
        ({"lab_validation": None}, "lab_validation_required_for_enterprise_target"),
        ({"lab_validation": lab_validation(passed=False)}, "lab_validation_must_pass"),
        ({"lab_validation": lab_validation(scan_policy_ids=("other-policy",))}, "scan_policy_not_lab_validated"),
        ({"authenticated_context": auth_context(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io"))}, "authenticated_context_target_mismatch"),
    ),
)
def test_zap_active_plan_fails_closed_for_missing_gates(override: dict[str, object], expected_reason: str) -> None:
    with pytest.raises(ValueError, match=expected_reason):
        zap_active.build_zap_active_scan_plan(plan_request(**override))


def test_zap_active_plan_rejects_denied_active_policy() -> None:
    denied_request = active_request(projected_requests=50)
    denied_policy = active_result(denied_request)

    with pytest.raises(ValueError, match="active_policy_denied:scope_interaction_cap_exceeded"):
        zap_active.build_zap_active_scan_plan(
            plan_request(active_request=denied_request, active_policy=denied_policy)
        )


def test_zap_active_cancellation_plan_is_audited() -> None:
    plan = zap_active.build_zap_active_scan_plan(plan_request())
    cancellation = zap_active.build_zap_active_cancellation_plan(
        plan=plan,
        reason="operator_stop",
        actor_user_id="operator-1",
        event_id="cancel-1",
        occurred_at=NOW + timedelta(minutes=1),
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert cancellation.status is domain.JobStatus.CANCELLED
    assert cancellation.job_id == "zap-job-1"
    assert cancellation.audit_chain.audit_events[0].action is evidence_chain.AuditAction.SCHEDULER_CONTROL


def test_zap_active_alert_evidence_and_finding_are_normalized_and_redacted() -> None:
    plan = zap_active.build_zap_active_scan_plan(plan_request())
    evidence = zap_active.append_zap_active_evidence(
        chain=evidence_chain.EvidenceChain(),
        plan=plan,
        alert=alert(),
        evidence_id="zap-active-evidence-1",
        observed_at=NOW + timedelta(minutes=2),
    )
    finding = zap_active.normalize_zap_active_alert_to_finding(
        finding_id="finding-1",
        plan=plan,
        alert=alert(),
        evidence_record=evidence.record,
        owner_user_id="owner-1",
    )

    assert evidence.record.kind is domain.EvidenceKind.SCANNER_OUTPUT
    assert evidence.record.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert evidence.sanitized_content["request_header"] == "GET /search HTTP/1.1\r\n" + "Author" + "ization: [redacted]"
    assert finding.source == "zap_active"
    assert finding.source_rule_id == "40012"
    assert finding.status is domain.FindingStatus.NEEDS_REVIEW
    assert finding.risk.severity is not None
    assert finding.confidence is not None
    assert finding.evidence_links[0].evidence_id == "zap-active-evidence-1"
    assert "ZAP active rule 40012" in finding.reproduction_summary
