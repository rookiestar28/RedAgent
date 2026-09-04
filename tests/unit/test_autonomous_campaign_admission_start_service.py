from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter
from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_SCHEMA_VERSION,
    AutonomousCampaignAdmissionContextV1,
    AutonomousCampaignAdmissionStartCommandV1,
    AutonomousCampaignApprovalBundleV1,
    canonical_admission_start_request_sha256,
)
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
from redagent_platform.campaign_service.application_contracts import (
    ApplicationApprovalForbidden,
    ApplicationPlanInvalid,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.approval_contracts import (
    ApproveAutonomousCampaignPlanV1,
)
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
)
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from tests.unit.test_autonomous_campaign_plan_approval import (
    Repository as ApprovalRepository,
    _service as approval_service,
    _stage_command,
)
from tests.unit.test_campaign_planning_contracts import NOW, limits


class _Source:
    def __init__(self, bundle: AutonomousCampaignApprovalBundleV1 | None) -> None:
        self.bundle = bundle
        self.reads = 0

    async def read_current_approval_bundle(self, **values: object):
        self.reads += 1
        return self.bundle


class _ContextProvider:
    def __init__(self, context: AutonomousCampaignAdmissionContextV1 | None) -> None:
        self.context = context
        self.reads = 0

    async def read_current_admission_context(self, **values: object):
        self.reads += 1
        return self.context


class _Store:
    def __init__(self, replay_result=None) -> None:
        self.command = None
        self.denial = None
        self.replay_result = replay_result

    async def replay(self, **values: object):
        return self.replay_result

    async def preview_residual(self, **values: object):
        return values["authorized_budget"]

    async def admit(self, command):
        self.command = command
        return "r173-admitted"

    async def deny(self, **values: object):
        self.denial = values
        return "r173-denied"


class _StoreFactory:
    def __init__(self, replay_result=None) -> None:
        self.store = _Store(replay_result)
        self.calls: list[tuple[object, object, object]] = []

    def __call__(self, command, bundle, context):
        self.calls.append((command, bundle, context))
        return self.store


def _approved_material():
    stage, trusted_key = _stage_command()
    repository = ApprovalRepository()
    service = approval_service(repository, stage, trusted_key)
    staged = asyncio.run(service.stage_plan(stage))
    approved = asyncio.run(
        service.approve_plan(
            ApproveAutonomousCampaignPlanV1(
                schema_version="redagent.autonomous-campaign-plan-approve/v1",
                tenant_id=stage.tenant_id,
                campaign_id=stage.campaign_id,
                preview_id=staged.preview.preview_id,
                preview_sha256=staged.preview.preview_sha256,
                actor_user_id="approver-a",
                actor_permissions=("campaign:approve",),
                policy_reference="policy:r172:approval",
                expected_revision=staged.application.aggregate_revision,
                idempotency_key="approve-for-r173",
                correlation_id="correlation-approve-for-r173",
                occurred_at=NOW + timedelta(seconds=4),
            )
        )
    )
    assert approved.application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
    bundle = AutonomousCampaignApprovalBundleV1(
        application=approved.application,
        preview=staged.preview,
        approval_receipt=approved.receipt,
    )
    context = AutonomousCampaignAdmissionContextV1(
        tenant_id=stage.tenant_id,
        campaign_id=stage.campaign_id,
        signed_authority=stage.signed_authority,
        authority_lifecycle=stage.authority_lifecycle,
        domain=stage.domain,
        revision=stage.revision,
        certificate=stage.certificate,
    )
    return stage, trusted_key, bundle, context


def _command(bundle: AutonomousCampaignApprovalBundleV1, **overrides: object):
    values: dict[str, object] = {
        "schema_version": ADMISSION_START_SCHEMA_VERSION,
        "tenant_id": bundle.application.tenant_id,
        "campaign_id": bundle.application.campaign_id,
        "approval_receipt_id": bundle.approval_receipt.receipt_id,
        "approval_receipt_sha256": bundle.approval_receipt.receipt_sha256,
        "actor_user_id": "operator-a",
        "actor_roles": ("operator",),
        "actor_permissions": ("campaign:admit",),
        "policy_reference": bundle.approval_receipt.policy_reference,
        "expected_revision": bundle.application.aggregate_revision,
        "idempotency_key": "admit-start-a",
        "correlation_id": "correlation-admit-start-a",
        "occurred_at": NOW + timedelta(seconds=5),
    }
    values.update(overrides)
    return AutonomousCampaignAdmissionStartCommandV1(**values)


def _service(source, provider, factory, trusted_key, context):
    return AutonomousCampaignAdmissionStartService(
        source=source,
        context_provider=provider,
        store_factory=factory,
        policy=AdmissionPolicyAdapter(
            DeterministicFakePolicyProvider(revision=context.signed_authority.authority.policy_revision),
            required_revision=context.signed_authority.authority.policy_revision,
            trusted_bundle_sha256=context.signed_authority.authority.policy_bundle_sha256,
        ),
        trusted_keys={"key-a": trusted_key},
        validation_limits=limits(),
        trusted_validator_version=VALIDATOR_VERSION,
        trusted_validator_sha256=VALIDATOR_SHA256,
    )


def test_exact_current_approval_reaches_r158_admission_once() -> None:
    _stage, trusted_key, bundle, context = _approved_material()
    source = _Source(bundle)
    provider = _ContextProvider(context)
    factory = _StoreFactory()
    service = _service(source, provider, factory, trusted_key, context)

    result = asyncio.run(service.admit_and_queue(_command(bundle)))

    assert result == "r173-admitted"
    assert source.reads == 1
    assert provider.reads == 1
    assert len(factory.calls) == 1
    assert factory.store.command is not None
    assert factory.store.command.policy_request.permissions == ("campaign:admit",)
    assert factory.store.command.plan_sha256 == bundle.approval_receipt.plan_sha256


def test_semantic_request_digest_excludes_transport_and_retry_metadata() -> None:
    _stage, _trusted_key, bundle, _context = _approved_material()
    original = _command(bundle)
    retry = _command(
        bundle,
        idempotency_key="admit-start-retry",
        correlation_id="correlation-admit-start-retry",
        occurred_at=original.occurred_at + timedelta(seconds=9),
    )
    assert canonical_admission_start_request_sha256(original) == (
        canonical_admission_start_request_sha256(retry)
    )


def test_exact_retry_can_reload_the_accepted_post_approval_lineage() -> None:
    _stage, trusted_key, bundle, context = _approved_material()
    advanced = replace(
        bundle,
        application=replace(
            bundle.application,
            lifecycle_state=AutonomousCampaignLifecycle.ADMITTED,
            aggregate_revision=bundle.application.aggregate_revision + 1,
            updated_at=bundle.application.updated_at + timedelta(seconds=1),
        ),
    )
    factory = _StoreFactory("r173-replayed")
    service = _service(_Source(advanced), _ContextProvider(context), factory, trusted_key, context)

    assert asyncio.run(service.admit_and_queue(_command(bundle))) == "r173-replayed"
    assert factory.store.command is None

def test_missing_admit_permission_fails_before_server_material_or_policy() -> None:
    _stage, trusted_key, bundle, context = _approved_material()
    source = _Source(bundle)
    provider = _ContextProvider(context)
    factory = _StoreFactory()
    service = _service(source, provider, factory, trusted_key, context)

    with pytest.raises(ApplicationApprovalForbidden, match="admission_permission_required"):
        asyncio.run(
            service.admit_and_queue(
                _command(bundle, actor_permissions=("campaign:read",))
            )
        )

    assert source.reads == 0
    assert provider.reads == 0
    assert factory.calls == []


@pytest.mark.parametrize(
    "bundle_mutation",
    (
        lambda value: replace(
            value,
            application=replace(value.application, lifecycle_state=AutonomousCampaignLifecycle.AWAITING_APPROVAL),
        ),
        lambda value: replace(
            value,
            approval_receipt=replace(value.approval_receipt, plan_sha256="f" * 64),
        ),
    ),
)
def test_stale_or_mutated_r172_approval_fails_before_admission(bundle_mutation) -> None:
    _stage, trusted_key, bundle, context = _approved_material()
    source = _Source(bundle_mutation(bundle))
    provider = _ContextProvider(context)
    factory = _StoreFactory()
    service = _service(source, provider, factory, trusted_key, context)

    with pytest.raises(ApplicationPlanInvalid):
        asyncio.run(service.admit_and_queue(_command(bundle)))

    assert factory.calls == []


def test_current_material_epoch_drift_is_persisted_as_an_admission_denial() -> None:
    _stage, trusted_key, bundle, context = _approved_material()
    provider = _ContextProvider(
        replace(
            context,
            authority_lifecycle=replace(
                context.authority_lifecycle,
                lifecycle_epoch=context.authority_lifecycle.lifecycle_epoch + 1,
            ),
        )
    )
    factory = _StoreFactory()
    service = _service(_Source(bundle), provider, factory, trusted_key, context)

    result = asyncio.run(service.admit_and_queue(_command(bundle)))

    assert result == "r173-denied"
    assert factory.store.command is None
    assert factory.store.denial is not None
    assert factory.store.denial["denial_stage"] == "authority"
    assert factory.store.denial["reason_code"] == "campaign_lifecycle_epoch_mismatch"
