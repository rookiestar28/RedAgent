from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    active_policy,
    api_lab,
    auth_sessions,
    credentials,
    domain,
    evidence_chain,
    job_queue,
    lab_harness,
    lab_validation,
    openapi_harness,
    target_inventory,
)
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 9, 22, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.API_SPEC, value="https://api.agentique.io/openapi.json")


def openapi_spec() -> dict[str, object]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "RedAgent API", "version": "1.0.0"},
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/accounts/{accountId}": {
                "get": {
                    "operationId": "getAccount",
                    "parameters": [{"name": "accountId", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}, "403": {"description": "forbidden"}},
                }
            },
            "/admin/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"201": {"description": "created"}, "403": {"description": "forbidden"}},
                }
            },
            "/status": {"get": {"operationId": "status", "security": [], "responses": {"200": {"description": "ok"}}}},
        },
    }


def lab_registration() -> lab_harness.LabTargetRegistration:
    approval = lab_harness.SandboxApproval(
        approval_id="sandbox-approval-1",
        organization_id="org-1",
        approved_by_user_id="lead-1",
        approved_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        allowed_kinds=(lab_harness.LabTargetKind.CRAPI,),
        allowed_actions=(lab_harness.LabHarnessAction.CONNECT_EXISTING,),
        plan_reference="PUBLIC_RELEASE.md",
        emergency_contact_method="email",
    )
    return lab_harness.register_lab_target(
        lab_harness.LabTargetRequest(
            target_id="lab-crapi-runtime",
            organization_id="org-1",
            engagement_id="eng-1",
            owner_label="Security Lab",
            kind=lab_harness.LabTargetKind.CRAPI,
            action=lab_harness.LabHarnessAction.CONNECT_EXISTING,
            base_url="http://localhost:8888",
            requested_at=NOW,
        ),
        approval,
    )


def cases() -> tuple[api_lab.ApiLabCase, ...]:
    document = api_lab.import_openapi_document(document_id="redagent-api", source_reference="fixture", spec=openapi_spec())
    generated = api_lab.generate_lab_api_cases(document, lab_registration())
    bfla = api_lab.ApiLabCase(
        case_id="redagent-api:createUser:bfla",
        case_type=api_lab.ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL,
        owasp_category=api_lab.OwaspApiTop10Category.API5_BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
        path="/admin/users",
        method=api_lab.HttpMethod.POST,
        operation_id="createUser",
        lab_target_id=lab_registration().target_id,
    )
    resource = api_lab.ApiLabCase(
        case_id="redagent-api:status:resource",
        case_type=api_lab.ApiLabCaseType.RESOURCE_CONSUMPTION_REVIEW,
        owasp_category=api_lab.OwaspApiTop10Category.API4_UNRESTRICTED_RESOURCE_CONSUMPTION,
        path="/status",
        method=api_lab.HttpMethod.GET,
        operation_id="status",
        lab_target_id=lab_registration().target_id,
    )
    return generated + (bfla, resource)


def reviewed(case: api_lab.ApiLabCase, **overrides: object) -> openapi_harness.ReviewedApiCase:
    values = {
        "case": case,
        "reviewer_user_id": "reviewer-1",
        "reviewed_at": NOW - timedelta(minutes=10),
        "approved": True,
        "mutation_requested": False,
        "resource_probe_requests": 1,
    }
    values.update(overrides)
    return openapi_harness.ReviewedApiCase(**values)  # type: ignore[arg-type]


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


def active_request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "openapi-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "openapi-harness",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "requested_at": NOW,
        "projected_requests": 4,
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
    req = request or active_request()
    return active_policy.evaluate_active_policy(
        request=req,
        scope=scope(),
        module_policy=active_policy.ActiveModulePolicy(
            module_id="openapi-harness",
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            allowed_payload_classes=(active_policy.PayloadClass.STANDARD_ACTIVE,),
            max_rate_per_second=1.0,
            max_requests=10,
            max_duration_seconds=120,
            max_concurrent_per_engagement=2,
            max_concurrent_per_target=1,
            stop_conditions=active_policy.StopConditionPolicy(
                stop_on_scope_violation=True,
                stop_on_error_rate=True,
                max_error_count=3,
                emergency_contact_required=True,
            ),
        ),
        existing_jobs=(),
        audit_chain=evidence_chain.EvidenceChain(),
        decision_id="active-decision-1",
        policy_expires_at=NOW + timedelta(minutes=30),
    )


def profile(**overrides: object) -> openapi_harness.OpenApiHarnessProfile:
    values = {
        "profile_id": "openapi-harness-profile",
        "module_id": "openapi-harness",
        "allowed_case_types": tuple(api_lab.ApiLabCaseType),
        "max_rate_per_second": 1.0,
        "max_requests": 10,
        "timeout_seconds": 120,
        "max_resource_probe_requests": 2,
        "lab_profile": lab_validation.ScannerPolicyProfile(
            profile_id="openapi-harness-profile",
            module_id="openapi-harness",
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            required_fixture_kinds=(lab_validation.LabValidationFixtureKind.API_LAB,),
            max_age_seconds=86_400,
        ),
    }
    values.update(overrides)
    return openapi_harness.OpenApiHarnessProfile(**values)  # type: ignore[arg-type]


def inventory() -> target_inventory.InventoryTarget:
    return target_inventory.InventoryTarget(
        id="api-target-1",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="Ray Chiu",
        target_type=domain.TargetType.API_SPEC,
        value="https://api.agentique.io/openapi.json",
        environment=target_inventory.EnvironmentType.STAGING,
        data_sensitivity=target_inventory.DataSensitivity.INTERNAL,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        explicit_review=True,
        review_reason="approved API target",
    )


def validation_record() -> lab_validation.LabValidationRecord:
    return lab_validation.LabValidationRecord(
        validation_id="api-validation-1",
        policy_profile_id="openapi-harness-profile",
        module_id="openapi-harness",
        lab_target_id="lab-crapi-runtime",
        fixture_ids=("openapi-harness-profile:api_lab",),
        sanitized_artifact_ids=("sanitized:openapi-harness-profile:api_lab",),
        validated_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(days=1),
        passed=True,
    )


def lease(lease_id: str, role: str) -> credentials.CredentialLease:
    return credentials.CredentialLease(
        id=lease_id,
        credential_reference_id=f"cred-ref-{role}",
        job_id="openapi-job-1",
        runner_id="runner-1",
        target=TARGET,
        mode=domain.TestMode.ACTIVE_SCAN,
        scoped_permissions=("http:read", "session:read"),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
        redaction_label=f"credential:{role}",
    )


def session(session_id: str, role: str, lease_id: str) -> auth_sessions.AuthenticatedSessionContext:
    return auth_sessions.build_authenticated_session_context(
        session_id=session_id,
        organization_id="org-1",
        engagement_id="eng-1",
        lease=lease(lease_id, role),
        role_label=role,
        created_at=NOW,
    )


def runner() -> job_queue.RunnerContract:
    return job_queue.RunnerContract(
        runner_id="runner-1",
        organization_id="org-1",
        capabilities=(domain.TestMode.ACTIVE_SCAN,),
        policy_token_reference="policy-ref-1",
        target_scope=TARGET,
        timeout_seconds=120,
        heartbeat_interval_seconds=5,
        result_schema=("evidence_ids", "findings"),
        cleanup_callback="cleanup://runner-1/openapi",
    )


def harness_request(**overrides: object) -> openapi_harness.OpenApiHarnessRequest:
    selected_cases = cases()
    req = active_request()
    values = {
        "runtime_id": "openapi-runtime-1",
        "profile": profile(),
        "active_request": req,
        "active_policy": active_result(req),
        "runner": runner(),
        "inventory_target": inventory(),
        "reviewed_cases": (reviewed(selected_cases[0]), reviewed(selected_cases[-1], resource_probe_requests=2)),
        "auth_contexts": (
            session("session-viewer", "viewer", "lease-viewer"),
            session("session-admin", "admin", "lease-admin"),
        ),
        "credential_leases": (lease("lease-viewer", "viewer"), lease("lease-admin", "admin")),
        "lab_validation_records": (validation_record(),),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return openapi_harness.OpenApiHarnessRequest(**values)  # type: ignore[arg-type]


def test_harness_generates_safe_specs_for_bola_bfla_and_resource_cases() -> None:
    selected = cases()
    request = harness_request(
        reviewed_cases=(
            reviewed(selected[0]),
            reviewed(next(case for case in selected if case.owasp_category is api_lab.OwaspApiTop10Category.API5_BROKEN_FUNCTION_LEVEL_AUTHORIZATION)),
            reviewed(selected[-1], resource_probe_requests=2),
        )
    )
    plan = openapi_harness.build_openapi_harness_plan(request)

    assert len(plan.request_specs) == 3
    assert {spec.case_type for spec in plan.request_specs} >= {api_lab.ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL}
    assert all(not spec.mutation_enabled for spec in plan.request_specs)
    assert all(spec.non_destructive for spec in plan.request_specs)
    assert sum(spec.planned_requests for spec in plan.request_specs) == 4


def test_harness_fails_closed_for_missing_auth_context_forbidden_mutation_and_rate_cap() -> None:
    selected = cases()
    with pytest.raises(ValueError, match="auth_context_pair_required"):
        openapi_harness.build_openapi_harness_plan(harness_request(auth_contexts=()))

    object_case = next(case for case in selected if case.case_type is api_lab.ApiLabCaseType.OBJECT_PROPERTY)
    with pytest.raises(ValueError, match="api_mutation_forbidden"):
        openapi_harness.build_openapi_harness_plan(harness_request(reviewed_cases=(reviewed(object_case, mutation_requested=True),)))

    fast = active_request(requested_rate_per_second=2.0)
    with pytest.raises(ValueError, match="active_policy_denied:rate_limit_exceeded"):
        openapi_harness.build_openapi_harness_plan(harness_request(active_request=fast, active_policy=active_result(fast)))


def test_harness_requires_lab_validation_for_enterprise_api_target() -> None:
    with pytest.raises(ValueError, match="matching_lab_validation_required"):
        openapi_harness.build_openapi_harness_plan(harness_request(lab_validation_records=()))


def test_harness_redacts_observations_and_maps_findings() -> None:
    request = harness_request()
    plan = openapi_harness.build_openapi_harness_plan(request)
    observation = openapi_harness.ApiObservation(
        case_id=plan.request_specs[0].case_id,
        observed_at=NOW,
        lower_status=200,
        higher_status=200,
        notes="Observed authorization differential with " + "Author" + "ization: Bearer sample",
        request_excerpt="GET /accounts/123 HTTP/1.1\r\n" + "Cookie: session=sample",
        response_excerpt="HTTP/1.1 200 OK",
    )
    result = openapi_harness.execute_openapi_harness_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        observations=(observation,),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.evidence_chain.evidence_records[0].redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert result.findings[0].source == "openapi_harness"
    assert result.findings[0].source_rule_id == api_lab.ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL.value
    assert result.findings[0].severity is not None


def test_harness_cancellation_uses_kill_switch_and_revokes_credential_lease() -> None:
    request = harness_request()
    plan = openapi_harness.build_openapi_harness_plan(request)
    result = openapi_harness.execute_openapi_harness_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
        credential_broker=credentials.CredentialBroker(),
        credential_leases_by_job_id={plan.job.job_id: lease("lease-viewer", "viewer")},
    )

    assert result.allowed
    assert result.reason == "cancelled"
    assert result.state.jobs[0].status is domain.JobStatus.CLEANUP
    assert result.cancellation_evidence[0].runner_status is openapi_harness.RunnerCancellationStatus.TERMINATED
    assert result.cancellation_evidence[0].credential_revoked


def test_harness_blocks_matching_kill_switch_before_dispatch() -> None:
    request = harness_request()
    plan = openapi_harness.build_openapi_harness_plan(request)
    result = openapi_harness.execute_openapi_harness_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        kill_switch_scope=openapi_harness.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.ACTIVE_SCAN,),
        ),
    )

    assert not result.allowed
    assert result.reason == "kill_switch_active"
    assert result.state.jobs[0].status is domain.JobStatus.QUEUED
