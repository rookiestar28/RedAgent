from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    active_policy,
    auth_sessions,
    credentials,
    domain,
    evidence_chain,
    job_queue,
    lab_validation,
    target_inventory,
    zap_active,
    zap_passive,
    zap_runtime,
)
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget
from redagent_platform.zap_passive import ZapConfidence, ZapRisk


NOW = datetime(2026, 7, 9, 18, 0, tzinfo=timezone.utc)
ENTERPRISE_TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")
LAB_TARGET = ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value="lab:juice-shop/runtime")


def enterprise_scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-1",
        organization_id="org-1",
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="lead-1",
        allowed_targets=(ENTERPRISE_TARGET,),
        forbidden_targets=(),
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        window_start=NOW - timedelta(minutes=5),
        window_end=NOW + timedelta(hours=1),
        max_interactions=20,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def module_policy(max_requests: int = 10) -> active_policy.ActiveModulePolicy:
    return active_policy.ActiveModulePolicy(
        module_id="zap-runtime",
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        allowed_payload_classes=(active_policy.PayloadClass.STANDARD_ACTIVE,),
        max_rate_per_second=1.0,
        max_requests=max_requests,
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
        "job_id": "zap-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": ENTERPRISE_TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "zap-runtime",
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
        scope=enterprise_scope(),
        module_policy=module_policy(),
        existing_jobs=(),
        audit_chain=evidence_chain.EvidenceChain(),
        decision_id="active-decision-1",
        policy_expires_at=NOW + timedelta(minutes=30),
    )


def active_scan_policy() -> zap_active.ZapActiveScanPolicy:
    return zap_active.ZapActiveScanPolicy(
        policy_id="zap-runtime-standard",
        display_name="ZAP runtime standard",
        payload_class=active_policy.PayloadClass.STANDARD_ACTIVE,
        max_rule_strength="medium",
    )


def active_warning() -> zap_active.ZapActiveWarning:
    return zap_active.ZapActiveWarning(
        warning_id="warning-1",
        title="Active ZAP runtime warning",
        body="Use only within approved scope.",
    )


def warning_ack() -> zap_active.ZapActiveWarningAcknowledgement:
    return zap_active.ZapActiveWarningAcknowledgement(
        acknowledgement_id="ack-1",
        displayed_to_operator=True,
        acknowledged_by_user_id="operator-1",
        acknowledged_at=NOW - timedelta(seconds=30),
        warning_ids=("warning-1",),
    )


def zap_lab_validation() -> zap_active.ZapActiveLabValidation:
    return zap_active.ZapActiveLabValidation(
        validation_id="zap-active-validation-1",
        passed=True,
        validated_at=NOW - timedelta(minutes=10),
        lab_target_id="juice-shop-local",
        scan_policy_ids=("zap-runtime-standard",),
        evidence_id="zap-validation-evidence-1",
    )


def auth_context() -> auth_sessions.AuthenticatedSessionContext:
    return auth_sessions.AuthenticatedSessionContext(
        session_id="session-1",
        organization_id="org-1",
        engagement_id="eng-1",
        target=ENTERPRISE_TARGET,
        mode=domain.TestMode.ACTIVE_SCAN,
        credential_lease_id="lease-zap-runtime",
        role_label="standard-user",
        created_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=20),
        redaction_label="session-token",
    )


def active_plan(**overrides: object) -> zap_active.ZapActiveScanPlan:
    request = active_request(**overrides.pop("active_request_overrides", {}))
    values = {
        "plan_id": "zap-runtime-plan-1",
        "active_request": request,
        "active_policy": active_result(request),
        "scan_policy": active_scan_policy(),
        "warnings": (active_warning(),),
        "warning_acknowledgement": warning_ack(),
        "lab_validation": zap_lab_validation(),
        "authenticated_context": auth_context(),
        "planned_at": NOW,
    }
    values.update(overrides)
    return zap_active.build_zap_active_scan_plan(zap_active.ZapActiveScanPlanRequest(**values))  # type: ignore[arg-type]


def lab_profile(*, modes: tuple[domain.TestMode, ...]) -> lab_validation.ScannerPolicyProfile:
    return lab_validation.ScannerPolicyProfile(
        profile_id="zap-runtime-profile",
        module_id="zap-runtime",
        allowed_modes=modes,
        required_fixture_kinds=(lab_validation.LabValidationFixtureKind.ZAP,),
        max_age_seconds=86_400,
    )


def runtime_profile(
    *,
    modes: tuple[domain.TestMode, ...] = (domain.TestMode.ACTIVE_SCAN,),
    max_requests: int = 10,
    max_duration_seconds: int = 120,
    api_actions: tuple[zap_runtime.ZapRuntimeApiAction, ...] | None = None,
) -> zap_runtime.ZapRuntimeProfile:
    return zap_runtime.ZapRuntimeProfile(
        profile_id="zap-runtime-profile",
        module_id="zap-runtime",
        scan_policy_id="zap-runtime-standard",
        allowed_modes=modes,
        max_rate_per_second=1.0,
        max_requests=max_requests,
        max_duration_seconds=max_duration_seconds,
        lab_profile=lab_profile(modes=modes),
        api_actions=api_actions
        or (
            zap_runtime.ZapRuntimeApiAction.LOAD_AUTH_CONTEXT,
            zap_runtime.ZapRuntimeApiAction.START_ACTIVE_SCAN,
            zap_runtime.ZapRuntimeApiAction.POLL_ACTIVE_SCAN,
            zap_runtime.ZapRuntimeApiAction.STOP_ACTIVE_SCAN,
            zap_runtime.ZapRuntimeApiAction.IMPORT_ACTIVE_ALERTS,
        ),
        allow_authenticated_context=True,
    )


def enterprise_inventory() -> target_inventory.InventoryTarget:
    return target_inventory.InventoryTarget(
        id="target-1",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="Ray Chiu",
        target_type=domain.TargetType.WEB_ORIGIN,
        value="https://www.agentique.io",
        environment=target_inventory.EnvironmentType.STAGING,
        data_sensitivity=target_inventory.DataSensitivity.INTERNAL,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        explicit_review=True,
        review_reason="approved enterprise target",
    )


def lab_inventory() -> target_inventory.InventoryTarget:
    return target_inventory.InventoryTarget(
        id="lab-target-1",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="RedAgent Lab",
        target_type=domain.TargetType.LAB_TARGET,
        value="lab:juice-shop/runtime",
        environment=target_inventory.EnvironmentType.LAB,
        data_sensitivity=target_inventory.DataSensitivity.PUBLIC,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        allowed_modes=(domain.TestMode.LAB_ONLY_RUN,),
        explicit_review=True,
        review_reason="local lab",
    )


def validation_record() -> lab_validation.LabValidationRecord:
    return lab_validation.LabValidationRecord(
        validation_id="runtime-validation-1",
        policy_profile_id="zap-runtime-profile",
        module_id="zap-runtime",
        lab_target_id="juice-shop-local",
        fixture_ids=("zap-runtime-profile:zap",),
        sanitized_artifact_ids=("sanitized:zap-runtime-profile:zap",),
        validated_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(days=1),
        passed=True,
    )


def runner(target: ScopeTarget = ENTERPRISE_TARGET, modes: tuple[domain.TestMode, ...] = (domain.TestMode.ACTIVE_SCAN,)) -> job_queue.RunnerContract:
    return job_queue.RunnerContract(
        runner_id="runner-1",
        organization_id="org-1",
        capabilities=modes,
        policy_token_reference="policy-ref-1",
        target_scope=target,
        timeout_seconds=120,
        heartbeat_interval_seconds=5,
        result_schema=("evidence_ids", "findings"),
        cleanup_callback="cleanup://runner-1/zap-runtime",
        credential_lease_id="lease-zap-runtime",
    )


def credential_lease() -> credentials.CredentialLease:
    return credentials.CredentialLease(
        id="lease-zap-runtime",
        credential_reference_id="cred-ref-1",
        job_id="zap-runtime-job-1",
        runner_id="runner-1",
        target=ENTERPRISE_TARGET,
        mode=domain.TestMode.ACTIVE_SCAN,
        scoped_permissions=("http:read",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
        redaction_label="credential:cred-ref-1",
    )


def active_runtime_request(**overrides: object) -> zap_runtime.ZapRuntimeRequest:
    values = {
        "runtime_id": "zap-runtime-1",
        "profile": runtime_profile(),
        "runner": runner(),
        "inventory_target": enterprise_inventory(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "lab_validation_records": (validation_record(),),
        "credential_lease": credential_lease(),
        "active_plan": active_plan(),
    }
    values.update(overrides)
    return zap_runtime.ZapRuntimeRequest(**values)  # type: ignore[arg-type]


def active_alert() -> zap_active.ZapActiveAlert:
    return zap_active.ZapActiveAlert(
        plugin_id="40012",
        alert_id="alert-1",
        name="Reflected input detected",
        risk=ZapRisk.MEDIUM,
        confidence=ZapConfidence.HIGH,
        url="https://www.agentique.io/search?q=test",
        method="GET",
        attack="Reflected marker",
        evidence="marker reflected",
        description="ZAP active rule reported reflected input.",
        solution="Validate and encode reflected input.",
        cwe_id="79",
        request_header="GET /search HTTP/1.1\r\n" + "Author" + "ization: Bearer sample",
    )


def passive_capture() -> zap_passive.ZapPassiveCaptureContext:
    return zap_passive.ZapPassiveCaptureContext(
        capture_id="zap-passive-runtime-1",
        organization_id="org-1",
        engagement_id="eng-1",
        target=LAB_TARGET,
        mode=domain.TestMode.LAB_ONLY_RUN,
        captured_at=NOW,
        projected_interactions=1,
    )


def passive_alert() -> zap_passive.ZapPassiveAlert:
    return zap_passive.ZapPassiveAlert(
        plugin_id="10021",
        name="X-Content-Type-Options header missing",
        risk=ZapRisk.LOW,
        confidence=ZapConfidence.MEDIUM,
        url="http://127.0.0.1:3000/",
        method="GET",
        evidence="Header not present",
        description="Passive header observation",
        solution="Set nosniff.",
        cwe_id="693",
        response_header="Set-Cookie: session=sample",
    )


def passive_runtime_request() -> zap_runtime.ZapRuntimeRequest:
    capture = passive_capture()
    return zap_runtime.ZapRuntimeRequest(
        runtime_id="zap-passive-runtime",
        profile=runtime_profile(
            modes=(domain.TestMode.LAB_ONLY_RUN,),
            api_actions=(zap_runtime.ZapRuntimeApiAction.IMPORT_PASSIVE_ALERTS,),
        ),
        runner=runner(target=LAB_TARGET, modes=(domain.TestMode.LAB_ONLY_RUN,)),
        inventory_target=lab_inventory(),
        requested_at=NOW,
        operator_user_id="operator-1",
        lab_validation_records=(),
        passive_capture=capture,
        passive_authorization=zap_passive.ZapPassiveAuthorization(allowed=True, reason="allowed"),
        passive_policy_decision_id="passive-policy-1",
        passive_policy_expires_at=NOW + timedelta(minutes=15),
    )


def test_runtime_rejects_denied_active_scan_and_arbitrary_controls() -> None:
    denied_request = active_request(projected_requests=50)
    denied_policy = active_result(denied_request)

    with pytest.raises(ValueError, match="active_policy_denied"):
        zap_active.build_zap_active_scan_plan(
            zap_active.ZapActiveScanPlanRequest(
                plan_id="denied",
                active_request=denied_request,
                active_policy=denied_policy,
                scan_policy=active_scan_policy(),
                warnings=(active_warning(),),
                warning_acknowledgement=warning_ack(),
                lab_validation=zap_lab_validation(),
                authenticated_context=auth_context(),
                planned_at=NOW,
            )
        )

    with pytest.raises(ValueError, match="zap_request_cap_exceeded"):
        zap_runtime.build_zap_runtime_plan(active_runtime_request(profile=runtime_profile(max_requests=2)))

    with pytest.raises(ValueError, match="arbitrary_zap_control_forbidden"):
        zap_runtime.assert_no_arbitrary_zap_controls({"command": "zap.sh", "zap_api_url": "http://127.0.0.1:8080"})


def test_lab_only_passive_runtime_imports_sanitized_alert_without_external_execution() -> None:
    request = passive_runtime_request()
    plan = zap_runtime.build_zap_runtime_plan(request)
    result = zap_runtime.execute_zap_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        passive_alerts=(passive_alert(),),
        passive_capture=request.passive_capture,
        passive_authorization=request.passive_authorization,
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.imported_evidence_ids == ("zap-passive-runtime:zap-passive-alert:1",)
    assert result.evidence_chain.evidence_records[0].kind is domain.EvidenceKind.HTTP_METADATA
    assert result.findings[0].source == "zap_passive"
    assert result.findings[0].source_rule_id == "10021"


def test_enterprise_runtime_requires_matching_lab_validation() -> None:
    with pytest.raises(ValueError, match="matching_lab_validation_required"):
        zap_runtime.build_zap_runtime_plan(active_runtime_request(lab_validation_records=()))

    plan = zap_runtime.build_zap_runtime_plan(active_runtime_request())

    assert plan.kind is zap_runtime.ZapRuntimeKind.ACTIVE_SCAN
    assert plan.lab_validation_id == "runtime-validation-1"
    assert plan.cancellation_supported
    assert plan.credential_lease_id == "lease-zap-runtime"


def test_active_runtime_imports_redacted_alerts_and_normalized_findings() -> None:
    request = active_runtime_request()
    plan = zap_runtime.build_zap_runtime_plan(request)
    result = zap_runtime.execute_zap_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        active_alerts=(active_alert(),),
        active_scan_plan=request.active_plan,
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.imported_evidence_ids == ("zap-runtime-1:zap-active-alert:1",)
    assert result.evidence_chain.evidence_records[0].redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert result.findings[0].source == "zap_active"
    assert result.findings[0].source_rule_id == "40012"
    assert "ZAP active rule 40012" in result.findings[0].reproduction_summary


def test_runtime_cancellation_uses_kill_switch_and_revokes_credential_lease() -> None:
    request = active_runtime_request()
    plan = zap_runtime.build_zap_runtime_plan(request)
    result = zap_runtime.execute_zap_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
        credential_broker=credentials.CredentialBroker(),
        credential_leases_by_job_id={plan.job.job_id: credential_lease()},
    )

    assert result.allowed
    assert result.reason == "cancelled"
    assert result.state.jobs[0].status is domain.JobStatus.CLEANUP
    assert result.cancellation_evidence[0].runner_status is zap_runtime.RunnerCancellationStatus.TERMINATED
    assert result.cancellation_evidence[0].credential_revoked
    assert result.credential_broker.audit_chain.audit_events[0].subject_id == "lease-zap-runtime"


def test_active_kill_switch_blocks_dispatch_before_runtime_starts() -> None:
    request = active_runtime_request()
    plan = zap_runtime.build_zap_runtime_plan(request)
    result = zap_runtime.execute_zap_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        kill_switch_scope=zap_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=ENTERPRISE_TARGET,
            modes=(domain.TestMode.ACTIVE_SCAN,),
        ),
    )

    assert not result.allowed
    assert result.reason == "kill_switch_active"
    assert result.state.jobs[0].status is domain.JobStatus.QUEUED
