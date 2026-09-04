from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.application_contracts import (
    APPLICATION_CONTRACT_VERSION,
    ApplicationApprovalExpired,
    ApplicationApprovalForbidden,
    ApplicationPlanInvalid,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
)
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)
from redagent_platform.campaign_service.approval_contracts import (
    APPROVAL_RECEIPT_SCHEMA_VERSION,
    PLAN_PREVIEW_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
    AutonomousCampaignApprovalDecision,
    AutonomousCampaignApprovalDecisionResultV1,
    AutonomousCampaignPlanPreviewResultV1,
    DenyAutonomousCampaignPlanV1,
    StageAutonomousCampaignPlanV1,
    canonical_approval_decision_request_sha256,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    SignedCampaignAuthorityEnvelopeV2,
    sign_campaign_authority,
)
from redagent_platform.campaign_service.planning.contracts import ValidationResult
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
    validate_candidate_plan,
)
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_authority_envelope import lifecycle, trusted_key
from tests.unit.test_campaign_planning_contracts import NOW, authority, domain, limits, world


def _state(
    *,
    lifecycle_state: AutonomousCampaignLifecycle = AutonomousCampaignLifecycle.INTENT_CREATED,
    aggregate_revision: int = 1,
) -> AutonomousCampaignApplicationStateV1:
    return AutonomousCampaignApplicationStateV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        engagement_id="engagement-a",
        target_id="target-a",
        created_by_user_id="operator-a",
        intent_sha256="1" * 64,
        source_binding_sha256="2" * 64,
        mode=AutonomousCampaignMode.PLAN_ONLY,
        lifecycle_state=lifecycle_state,
        aggregate_revision=aggregate_revision,
        attention_reason=None,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=aggregate_revision),
    )


def _stage_command(**overrides: object) -> tuple[StageAutonomousCampaignPlanV1, object]:
    current_authority = authority()
    private_key = Ed25519PrivateKey.generate()
    approval = sign_campaign_authority(
        current_authority,
        private_key,
        approver_id="approver-a",
        approver_role="campaign-owner",
        key_id="key-a",
        approved_at=current_authority.valid_from + timedelta(seconds=1),
        expires_at=current_authority.valid_from + timedelta(seconds=45),
    )
    signed_authority = SignedCampaignAuthorityEnvelopeV2(
        authority=current_authority,
        approvals=(approval,),
    )
    current_domain = domain()
    planned = plan_attack_path(current_domain, current_authority, world(), search_limits())
    assert planned.revision is not None
    certificate = validate_candidate_plan(
        planned.revision.candidate_plan,
        current_domain,
        current_authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=2),
    )
    values: dict[str, object] = {
        "schema_version": "redagent.autonomous-campaign-plan-stage/v1",
        "tenant_id": "tenant-a",
        "campaign_id": "campaign-a",
        "actor_user_id": "operator-a",
        "expected_revision": 1,
        "signed_authority": signed_authority,
        "authority_lifecycle": lifecycle(
            current_authority,
            observed_at=current_authority.valid_from + timedelta(seconds=1),
            valid_until=current_authority.expires_at,
        ),
        "domain": current_domain,
        "revision": planned.revision,
        "certificate": certificate,
        "idempotency_key": "stage-a",
        "correlation_id": "correlation-stage-a",
        "occurred_at": NOW + timedelta(seconds=3),
    }
    values.update(overrides)
    return StageAutonomousCampaignPlanV1(**values), trusted_key(private_key)


class Repository:
    def __init__(self) -> None:
        self.state = _state()
        self.preview = None
        self.receipt = None
        self.stage_calls = 0
        self.decision_calls = 0

    async def create_intent(self, command):
        raise AssertionError("create was not part of this scenario")

    async def read(self, *, tenant_id: str, campaign_id: str):
        if tenant_id == self.state.tenant_id and campaign_id == self.state.campaign_id:
            return self.state
        return None

    async def revoke_intent(self, command):
        raise AssertionError("revoke was not part of this scenario")

    async def stage_plan(self, command, preview):
        self.stage_calls += 1
        self.preview = preview
        self.state = replace(
            self.state,
            lifecycle_state=AutonomousCampaignLifecycle.AWAITING_APPROVAL,
            aggregate_revision=preview.application_revision,
            updated_at=command.occurred_at,
        )
        return AutonomousCampaignPlanPreviewResultV1(
            application=self.state,
            preview=preview,
            audit_ids=("audit-plan-valid", "audit-awaiting-approval"),
            event_ids=("event-plan-valid", "event-awaiting-approval"),
            replayed=False,
        )

    async def read_plan_preview(self, *, tenant_id: str, campaign_id: str):
        if tenant_id == self.state.tenant_id and campaign_id == self.state.campaign_id:
            return self.preview
        return None

    async def decide_plan(self, command, receipt):
        self.decision_calls += 1
        self.receipt = receipt
        next_state = (
            AutonomousCampaignLifecycle.APPROVED
            if receipt.decision is AutonomousCampaignApprovalDecision.APPROVED
            else AutonomousCampaignLifecycle.DENIED
        )
        self.state = replace(
            self.state,
            lifecycle_state=next_state,
            aggregate_revision=self.state.aggregate_revision + 1,
            updated_at=command.occurred_at,
        )
        return AutonomousCampaignApprovalDecisionResultV1(
            application=self.state,
            receipt=receipt,
            audit_id="audit-decision",
            event_id="event-decision",
            replayed=False,
        )


def _service(repository: Repository, command: StageAutonomousCampaignPlanV1, key: object):
    return AutonomousCampaignApplicationService(
        repository,
        trusted_approval_keys={"key-a": key},
        validation_limits=limits(),
        trusted_validator_version=VALIDATOR_VERSION,
        trusted_validator_sha256=VALIDATOR_SHA256,
    )


def test_server_staging_builds_complete_safe_immutable_preview_and_readiness() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)

    result = asyncio.run(service.stage_plan(command))
    preview = result.preview

    assert preview.schema_version == PLAN_PREVIEW_SCHEMA_VERSION
    assert preview.application_revision == 3
    assert preview.validation_result is ValidationResult.VALID
    assert preview.objective_id == "collect-posture"
    assert preview.target_id == "target-a"
    assert preview.capability_ids == ("artifact-posture",)
    assert preview.plan_budget.requests == 1
    assert preview.authorized_budget.requests > preview.plan_budget.requests
    assert preview.actions[0].operator_id == "collect-artifact-posture"
    assert preview.actions[0].cleanup_mode.value == "required"
    assert preview.required_approvers[0].principal_id == "approver-a"
    assert preview.preview_sha256 == replace(preview).preview_sha256
    serialized = repr(preview)
    assert "signature_hex" not in serialized
    assert "private_key" not in serialized
    assert "arguments=" not in serialized
    assert repository.stage_calls == 1

    readiness = service.project(result.application)
    assert readiness.plan_ready is True
    assert readiness.approval_ready is True
    assert readiness.admission_ready is False
    assert readiness.start_ready is False
    assert readiness.unavailable_reason == "human_approval_required"


def test_preview_contract_rejects_cross_field_capability_or_target_tamper() -> None:
    command, key = _stage_command()
    preview = asyncio.run(_service(Repository(), command, key).stage_plan(command)).preview

    with pytest.raises(ValueError, match="plan_preview_capability_binding_invalid"):
        replace(preview, capability_set_sha256="f" * 64)
    with pytest.raises(ValueError, match="plan_preview_action_binding_invalid"):
        replace(preview, actions=(replace(preview.actions[0], target_id="target-other"),))


def test_staging_rejects_unknown_or_tampered_validation_before_repository_mutation() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)

    unknown = replace(
        command.certificate,
        result=ValidationResult.UNKNOWN,
        bounded_reason="validation_resource_limit:max_nodes",
    )
    with pytest.raises(ApplicationPlanInvalid, match="plan_validation_not_valid"):
        asyncio.run(service.stage_plan(replace(command, certificate=unknown)))
    assert repository.stage_calls == 0

    with pytest.raises(ApplicationPlanInvalid, match="plan_validation_certificate_mismatch"):
        asyncio.run(service.stage_plan(replace(command, certificate=replace(command.certificate, validator_sha256="f" * 64))))
    assert repository.stage_calls == 0


def test_lifecycle_drift_revocation_and_expiry_fail_closed_before_decision() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)

    with pytest.raises(ApplicationPlanInvalid, match="campaign_lifecycle_epoch_mismatch"):
        asyncio.run(
            service.stage_plan(
                replace(
                    command,
                    authority_lifecycle=replace(
                        command.authority_lifecycle,
                        lifecycle_epoch=command.authority_lifecycle.lifecycle_epoch + 1,
                    ),
                )
            )
        )
    revoked = replace(
        command.authority_lifecycle,
        state=CampaignAuthorityLifecycleState.REVOKED,
        revoked_at=command.authority_lifecycle.observed_at,
        reason_code="operator_revoked",
    )
    with pytest.raises(ApplicationPlanInvalid, match="campaign_authority_not_active"):
        asyncio.run(service.stage_plan(replace(command, authority_lifecycle=revoked)))
    assert repository.stage_calls == 0

    staged = asyncio.run(service.stage_plan(command))
    expired = ApproveAutonomousCampaignPlanV1(
        schema_version="redagent.autonomous-campaign-plan-approve/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        preview_id=staged.preview.preview_id,
        preview_sha256=staged.preview.preview_sha256,
        actor_user_id="approver-a",
        actor_permissions=("campaign:approve",),
        expected_revision=staged.application.aggregate_revision,
        idempotency_key="approve-expired-a",
        correlation_id="correlation-approve-expired-a",
        occurred_at=staged.preview.expires_at,
    )
    with pytest.raises(ApplicationApprovalExpired, match="plan_approval_expired"):
        asyncio.run(service.approve_plan(expired))
    assert repository.decision_calls == 0


def test_exact_human_approval_binds_actor_permission_preview_epochs_and_zero_admission() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    staged = asyncio.run(service.stage_plan(command))

    approval = ApproveAutonomousCampaignPlanV1(
        schema_version="redagent.autonomous-campaign-plan-approve/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        preview_id=staged.preview.preview_id,
        preview_sha256=staged.preview.preview_sha256,
        actor_user_id="approver-a",
        actor_permissions=("campaign:approve", "campaign:read"),
        expected_revision=staged.application.aggregate_revision,
        idempotency_key="approve-a",
        correlation_id="correlation-approve-a",
        occurred_at=NOW + timedelta(seconds=4),
    )
    result = asyncio.run(service.approve_plan(approval))

    assert result.receipt.schema_version == APPROVAL_RECEIPT_SCHEMA_VERSION
    assert result.receipt.decision is AutonomousCampaignApprovalDecision.APPROVED
    assert result.receipt.approver_user_id == "approver-a"
    assert result.receipt.approver_role == "campaign-owner"
    assert result.receipt.preview_sha256 == staged.preview.preview_sha256
    assert result.receipt.plan_sha256 == staged.preview.plan_sha256
    assert result.receipt.lifecycle_epoch == staged.preview.lifecycle_epoch
    assert result.receipt.policy_revocation_epoch == staged.preview.policy_revocation_epoch
    assert result.receipt.permission_set_sha256
    assert result.receipt.request_sha256 == canonical_approval_decision_request_sha256(approval)
    assert result.receipt.receipt_sha256 == replace(result.receipt).receipt_sha256
    assert result.application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
    assert service.project(result.application).admission_ready is False
    assert service.project(result.application).start_ready is False
    assert repository.decision_calls == 1


def test_restage_supersedes_prior_approval_and_requires_a_new_exact_decision() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    first = asyncio.run(service.stage_plan(command))
    prior_approval = ApproveAutonomousCampaignPlanV1(
        schema_version="redagent.autonomous-campaign-plan-approve/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        preview_id=first.preview.preview_id,
        preview_sha256=first.preview.preview_sha256,
        actor_user_id="approver-a",
        actor_permissions=("campaign:approve",),
        expected_revision=first.application.aggregate_revision,
        idempotency_key="approve-before-restage-a",
        correlation_id="correlation-approve-before-restage-a",
        occurred_at=NOW + timedelta(seconds=4),
    )
    approved = asyncio.run(service.approve_plan(prior_approval))

    second = asyncio.run(
        service.stage_plan(
            replace(
                command,
                expected_revision=approved.application.aggregate_revision,
                idempotency_key="stage-superseding-a",
                correlation_id="correlation-stage-superseding-a",
                occurred_at=NOW + timedelta(seconds=5),
            )
        )
    )
    assert second.preview.preview_id != first.preview.preview_id
    assert second.application.lifecycle_state is AutonomousCampaignLifecycle.AWAITING_APPROVAL
    with pytest.raises(ApplicationPlanInvalid, match="approval_preview_mismatch"):
        asyncio.run(service.approve_plan(prior_approval))
    assert repository.decision_calls == 1


def test_nonrequired_actor_or_missing_exact_permission_cannot_approve() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    staged = asyncio.run(service.stage_plan(command))
    base = ApproveAutonomousCampaignPlanV1(
        schema_version="redagent.autonomous-campaign-plan-approve/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        preview_id=staged.preview.preview_id,
        preview_sha256=staged.preview.preview_sha256,
        actor_user_id="operator-a",
        actor_permissions=("campaign:approve",),
        expected_revision=3,
        idempotency_key="approve-denied-a",
        correlation_id="correlation-denied-a",
        occurred_at=NOW + timedelta(seconds=4),
    )
    with pytest.raises(ApplicationApprovalForbidden, match="approval_actor_not_required"):
        asyncio.run(service.approve_plan(base))
    with pytest.raises(ApplicationApprovalForbidden, match="approval_permission_required"):
        asyncio.run(
            service.approve_plan(
                replace(base, actor_user_id="approver-a", actor_permissions=("campaign:read",))
            )
        )
    assert repository.decision_calls == 0


def test_explicit_denial_is_a_bound_immutable_terminal_decision() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    staged = asyncio.run(service.stage_plan(command))
    denial = DenyAutonomousCampaignPlanV1(
        schema_version="redagent.autonomous-campaign-plan-deny/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        preview_id=staged.preview.preview_id,
        preview_sha256=staged.preview.preview_sha256,
        actor_user_id="approver-a",
        actor_permissions=("campaign:approve",),
        reason_code="operator_denied_exact_plan",
        expected_revision=3,
        idempotency_key="deny-a",
        correlation_id="correlation-deny-a",
        occurred_at=NOW + timedelta(seconds=4),
    )
    result = asyncio.run(service.deny_plan(denial))
    assert result.receipt.decision is AutonomousCampaignApprovalDecision.DENIED
    assert result.receipt.reason_code == "operator_denied_exact_plan"
    assert result.application.lifecycle_state is AutonomousCampaignLifecycle.DENIED


def test_approval_contracts_reject_client_supplied_or_noncanonical_fields() -> None:
    command, _ = _stage_command()
    assert isinstance(command.signed_authority, SignedCampaignAuthorityEnvelopeV2)
    with pytest.raises(TypeError):
        ApproveAutonomousCampaignPlanV1(
            schema_version="redagent.autonomous-campaign-plan-approve/v1",
            tenant_id="tenant-a",
            campaign_id="campaign-a",
            preview_id="preview-a",
            preview_sha256="a" * 64,
            actor_user_id="approver-a",
            actor_permissions=("campaign:approve",),
            expected_revision=3,
            idempotency_key="approve-a",
            correlation_id="correlation-a",
            occurred_at=NOW,
            client_approved=True,  # type: ignore[call-arg]
        )
    with pytest.raises(ValueError, match="approval_permissions_not_canonical"):
        ApproveAutonomousCampaignPlanV1(
            schema_version="redagent.autonomous-campaign-plan-approve/v1",
            tenant_id="tenant-a",
            campaign_id="campaign-a",
            preview_id="preview-a",
            preview_sha256="a" * 64,
            actor_user_id="approver-a",
            actor_permissions=("campaign:read", "campaign:approve"),
            expected_revision=3,
            idempotency_key="approve-a",
            correlation_id="correlation-a",
            occurred_at=NOW,
        )
