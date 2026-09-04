from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from types import MethodType

from fastapi.testclient import TestClient

from redagent_platform.api.app import create_app
from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.admission_start_contracts import (
    AutonomousCampaignAdmissionStartResultV1,
    AutonomousCampaignAdmissionStartState,
)
from redagent_platform.campaign_service.admission_start_api import _result_payload
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignLifecycle,
)
from tests.unit.test_autonomous_campaign_admission_start_service import (
    _approved_material,
)


ADMIT_AUTH = {
    "X-RedAgent-Test-Subject": "operator-a",
    "X-RedAgent-Test-Tenant": "tenant-a",
    "X-RedAgent-Test-Permissions": "campaign:admit,campaign:read",
    "X-RedAgent-Policy-Reference": "policy:r172:approval",
    "Idempotency-Key": "api-admission-start-a",
}


def _configured_app(monkeypatch):
    _stage, _key, bundle, _context = _approved_material()
    captured = []
    service = object.__new__(AutonomousCampaignAdmissionStartService)

    async def admit_and_queue(self, command):
        del self
        captured.append(command)
        return _result(bundle)

    service.admit_and_queue = MethodType(admit_and_queue, service)
    monkeypatch.setattr(
        "redagent_platform.campaign_service.admission_start_api._now",
        lambda: bundle.application.updated_at + timedelta(seconds=1),
    )
    return (
        create_app(
            test_issuer_enabled=True,
            autonomous_campaign_admission_start_service=service,
        ),
        bundle,
        captured,
    )


def test_admission_start_requires_exact_permission_etag_and_server_owned_command(
    monkeypatch,
) -> None:
    app, bundle, captured = _configured_app(monkeypatch)
    url = "/api/v1/autonomous-campaigns/campaign-a/admission-start"
    payload = {
        "approval_receipt_id": bundle.approval_receipt.receipt_id,
        "approval_receipt_sha256": bundle.approval_receipt.receipt_sha256,
    }
    denied = TestClient(app).post(
        url,
        headers={
            **ADMIT_AUTH,
            "X-RedAgent-Test-Permissions": "campaign:read",
            "If-Match": (
                f'"r173-{bundle.application.aggregate_revision}-'
                f'{bundle.approval_receipt.receipt_sha256}"'
            ),
        },
        json=payload,
    )
    assert denied.status_code == 403
    assert captured == []

    response = TestClient(app).post(
        url,
        headers={
            **ADMIT_AUTH,
            "If-Match": (
                f'"r173-{bundle.application.aggregate_revision}-'
                f'{bundle.approval_receipt.receipt_sha256}"'
            ),
        },
        json=payload,
    )
    assert response.status_code == 200, response.text
    assert response.headers["etag"].startswith('"r173-')
    data = response.json()["data"]
    assert data["admission"]["outcome"] == "admitted"
    assert data["start"]["state"] == "start_pending"
    assert data["start"]["reason_code"] is None
    assert data["application"]["lifecycle_state"] == "ADMITTED"
    assert data["application"]["admission_ready"] is False
    assert data["application"]["start_ready"] is False
    assert "workflow_input" not in response.text
    assert captured[0].actor_roles == ("test-operator",)
    assert captured[0].actor_permissions == ("campaign:admit", "campaign:read")


def test_admission_start_rejects_stale_etag_and_client_owned_workflow_material(
    monkeypatch,
) -> None:
    app, bundle, captured = _configured_app(monkeypatch)
    url = "/api/v1/autonomous-campaigns/campaign-a/admission-start"
    payload = {
        "approval_receipt_id": bundle.approval_receipt.receipt_id,
        "approval_receipt_sha256": bundle.approval_receipt.receipt_sha256,
    }
    stale = TestClient(app).post(
        url,
        headers={**ADMIT_AUTH, "If-Match": '"r173-1-' + "0" * 64 + '"'},
        json=payload,
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "admission_start_etag_mismatch"

    injected = TestClient(app).post(
        url,
        headers={
            **ADMIT_AUTH,
            "If-Match": (
                f'"r173-{bundle.application.aggregate_revision}-'
                f'{bundle.approval_receipt.receipt_sha256}"'
            ),
        },
        json={**payload, "workflow_id": "client-owned-workflow"},
    )
    assert injected.status_code == 422
    assert captured == []


def test_openapi_exposes_only_the_one_r173_admission_start_command() -> None:
    paths = create_app(test_issuer_enabled=True).openapi()["paths"]
    assert "/api/v1/autonomous-campaigns/{campaign_id}/admission-start" in paths
    assert not any(
        "workflow" in path or "execution-start" in path
        for path in paths
        if "autonomous" in path
    )


def test_reconciliation_projection_preserves_the_exact_start_reason() -> None:
    _stage, _key, bundle, _context = _approved_material()
    result = _result(bundle)
    reconciled = replace(
        result,
        application=replace(
            result.application,
            lifecycle_state=AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
            aggregate_revision=result.application.aggregate_revision + 1,
        ),
        start_state=AutonomousCampaignAdmissionStartState.RECONCILIATION_REQUIRED,
        start_reason_code="synthetic_start_outcome_unknown",
    )

    payload = _result_payload(reconciled)

    assert payload["start"]["reason_code"] == "synthetic_start_outcome_unknown"
    assert payload["application"]["unavailable_reason"] == (
        "synthetic_start_outcome_unknown"
    )


def _result(bundle) -> AutonomousCampaignAdmissionStartResultV1:
    application = replace(
        bundle.application,
        lifecycle_state=AutonomousCampaignLifecycle.ADMITTED,
        aggregate_revision=bundle.application.aggregate_revision + 1,
        updated_at=bundle.application.updated_at + timedelta(seconds=1),
    )
    receipt = PlanAdmissionReceiptV1(
        schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
        receipt_id="admission-receipt-a",
        tenant_id=bundle.application.tenant_id,
        campaign_id=bundle.application.campaign_id,
        engagement_id=bundle.application.engagement_id,
        signed_authority_sha256=bundle.approval_receipt.signed_authority_sha256,
        authority_sha256=bundle.approval_receipt.authority_sha256,
        domain_sha256=bundle.approval_receipt.domain_sha256,
        plan_sha256=bundle.approval_receipt.plan_sha256,
        certificate_sha256=bundle.approval_receipt.certificate_sha256,
        validator_version=bundle.approval_receipt.validator_version,
        validator_sha256=bundle.approval_receipt.validator_sha256,
        subset_proof_sha256="4" * 64,
        policy_decision_id="decision-r173-a",
        policy_input_sha256="5" * 64,
        policy_bundle_revision=bundle.approval_receipt.policy_revision,
        policy_bundle_sha256=bundle.approval_receipt.policy_bundle_sha256,
        pre_residual_budget_sha256="6" * 64,
        post_residual_budget_sha256="7" * 64,
        reserved_budget=bundle.preview.plan_budget,
        reservation_id="reservation-r173-a",
        idempotency_key="api-admission-start-a",
        request_sha256="8" * 64,
        lifecycle_epoch=bundle.approval_receipt.lifecycle_epoch,
        policy_revocation_epoch=bundle.approval_receipt.policy_revocation_epoch,
        roe_revocation_epoch=bundle.approval_receipt.roe_revocation_epoch,
        kill_switch_epoch=bundle.approval_receipt.kill_switch_epoch,
        issued_at=application.updated_at,
        expires_at=application.updated_at + timedelta(minutes=1),
        outcome=AdmissionOutcome.ADMITTED,
        denial_stage=None,
        reason_code="admitted",
        audit_id="audit-admission-r173-a",
        outbox_id="outbox-admission-r173-a",
    )
    return AutonomousCampaignAdmissionStartResultV1(
        application=application,
        approval_receipt_id=bundle.approval_receipt.receipt_id,
        approval_receipt_sha256=bundle.approval_receipt.receipt_sha256,
        admission_receipt=receipt,
        execution_run_id="execution-r173-a",
        workflow_id="redagent-autonomous-start-a",
        workflow_run_id=None,
        workflow_request_sha256="9" * 64,
        input_sha256="a" * 64,
        start_state=AutonomousCampaignAdmissionStartState.START_PENDING,
        start_reason_code=None,
        audit_ids=("audit-admission-r173-a", "audit-application-r173-a"),
        event_ids=("event-admission-r173-a", "event-application-r173-a"),
        outbox_event_id="outbox-start-r173-a",
        replayed=False,
    )
