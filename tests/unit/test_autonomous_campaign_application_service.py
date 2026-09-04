from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.campaign_service.application_contracts import (
    APPLICATION_CONTRACT_VERSION,
    ApplicationDependencyUnavailable,
    ApplicationModeDisabled,
    ApplicationRevisionConflict,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
    AutonomousCampaignMutationResultV1,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
)
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


def _state() -> AutonomousCampaignApplicationStateV1:
    return AutonomousCampaignApplicationStateV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id="tenant-r171",
        campaign_id="campaign-r171",
        engagement_id="engagement-r171",
        target_id="target-r171",
        created_by_user_id="user-r171",
        intent_sha256="a" * 64,
        source_binding_sha256="b" * 64,
        mode=AutonomousCampaignMode.PLAN_ONLY,
        lifecycle_state=AutonomousCampaignLifecycle.INTENT_CREATED,
        aggregate_revision=1,
        attention_reason=None,
        created_at=NOW,
        updated_at=NOW,
    )


class Repository:
    def __init__(self) -> None:
        self.create_calls = 0
        self.read_calls = 0
        self.state = _state()

    async def create_intent(self, command):
        self.create_calls += 1
        return AutonomousCampaignMutationResultV1(
            application=self.state,
            audit_id="audit-r171",
            event_id="event-r171",
            replayed=False,
        )

    async def read(self, *, tenant_id: str, campaign_id: str):
        self.read_calls += 1
        if tenant_id == self.state.tenant_id and campaign_id == self.state.campaign_id:
            return self.state
        return None

    async def revoke_intent(self, command):
        raise AssertionError("revoke was not part of this scenario")


def _command() -> CreateAutonomousCampaignIntentV1:
    return CreateAutonomousCampaignIntentV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id="tenant-r171",
        campaign_id="campaign-r171",
        engagement_id="engagement-r171",
        target_id="target-r171",
        actor_user_id="user-r171",
        intent_sha256="a" * 64,
        source_binding_sha256="b" * 64,
        expected_revision=0,
        idempotency_key="create-r171",
        correlation_id="correlation-r171",
        occurred_at=NOW,
    )


def _revoke_command() -> RevokeAutonomousCampaignIntentV1:
    return RevokeAutonomousCampaignIntentV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id="tenant-r171",
        campaign_id="campaign-r171",
        actor_user_id="user-r171",
        reason_sha256="c" * 64,
        expected_revision=1,
        idempotency_key="revoke-r171",
        correlation_id="revoke-correlation-r171",
        occurred_at=NOW,
    )


def test_application_service_exposes_truthful_plan_only_readiness() -> None:
    repository = Repository()
    service = AutonomousCampaignApplicationService(repository, mode=AutonomousCampaignMode.PLAN_ONLY)
    result = asyncio.run(service.create_intent(_command()))
    projected = service.project(result.application)

    assert result.application.lifecycle_state is AutonomousCampaignLifecycle.INTENT_CREATED
    assert projected.mode is AutonomousCampaignMode.PLAN_ONLY
    assert projected.plan_ready is False
    assert projected.approval_ready is False
    assert projected.admission_ready is False
    assert projected.start_ready is False
    assert projected.unavailable_reason == "plan_not_prepared"
    assert repository.create_calls == 1


def test_disabled_mode_fails_before_persistence() -> None:
    repository = Repository()
    service = AutonomousCampaignApplicationService(repository, mode=AutonomousCampaignMode.DISABLED)
    with pytest.raises(ApplicationModeDisabled, match="autonomous_campaign_disabled"):
        asyncio.run(service.create_intent(_command()))
    with pytest.raises(ApplicationModeDisabled, match="autonomous_campaign_disabled"):
        asyncio.run(service.read(tenant_id="tenant-r171", campaign_id="campaign-r171"))
    assert repository.create_calls == 0
    assert repository.read_calls == 0


class DependencyFailureRepository(Repository):
    async def create_intent(self, command):
        raise OSError("driver detail must not cross the application boundary")

    async def read(self, *, tenant_id: str, campaign_id: str):
        raise OSError("driver detail must not cross the application boundary")

    async def revoke_intent(self, command):
        raise OSError("driver detail must not cross the application boundary")


def test_repository_failures_become_typed_dependency_outcomes() -> None:
    service = AutonomousCampaignApplicationService(DependencyFailureRepository())

    for operation in (
        service.create_intent(_command()),
        service.read(tenant_id="tenant-r171", campaign_id="campaign-r171"),
        service.revoke_intent(_revoke_command()),
    ):
        with pytest.raises(ApplicationDependencyUnavailable, match="application_dependency_unavailable") as caught:
            asyncio.run(operation)
        assert isinstance(caught.value.__cause__, OSError)


class DomainFailureRepository(Repository):
    async def create_intent(self, command):
        raise ApplicationRevisionConflict("application_revision_conflict")


def test_typed_domain_failure_is_not_reclassified_as_dependency_failure() -> None:
    service = AutonomousCampaignApplicationService(DomainFailureRepository())

    with pytest.raises(ApplicationRevisionConflict, match="application_revision_conflict"):
        asyncio.run(service.create_intent(_command()))
