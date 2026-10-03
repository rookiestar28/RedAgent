from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.application_contracts import (
    ApplicationDependencyUnavailable, ApplicationRevisionConflict, ApplicationIdempotencyConflict,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle, AutonomousCampaignMode, AutonomousCampaignMutationResultV1,
)
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.operator_service import AutonomousCampaignOperatorService
from redagent_platform.campaign_service.service import CampaignCoreService
from tests.unit.test_compat_124_campaign_service import NOW, Options, Starter, _operator_selections
from tests.unit.test_campaign_planning_contracts import limits, world
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_autonomous_campaign_plan_approval import (
    Repository as PlanRepository, ApprovalContextProvider, _stage_command, _service,
)
from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignRootPlanMaterialV1


class IntentRepository:
    def __init__(self) -> None:
        self.commands = []

    async def create_intent(self, command):
        self.commands.append(command)
        return AutonomousCampaignMutationResultV1(
            application=AutonomousCampaignApplicationStateV1(
                schema_version=command.schema_version, tenant_id=command.tenant_id,
                campaign_id=command.campaign_id, engagement_id=command.engagement_id,
                target_id=command.target_id, created_by_user_id=command.actor_user_id,
                intent_sha256=command.intent_sha256, source_binding_sha256=command.source_binding_sha256,
                mode=command.mode, lifecycle_state=AutonomousCampaignLifecycle.INTENT_CREATED,
                aggregate_revision=1, attention_reason=None,
                created_at=command.occurred_at, updated_at=command.occurred_at,
            ),
            audit_id="audit-operator", event_id="event-operator", replayed=False,
        )


class UnreadRootPlanSource:
    async def read_root_plan(self, **_values):
        raise AssertionError("intent creation must not prepare or execute a plan")


class UnusedNativeOwner:
    async def read_status(self, **_values):
        raise AssertionError("native status is outside this unit intent/preparation scenario")

    async def request_stop(self, _command):
        raise AssertionError("intent/preparation must not stop or execute")

    async def request_revoke(self, _command):
        raise AssertionError("intent/preparation must not revoke")


class UnusedStopGateway:
    async def stop_campaign_dag(self, *_args, **_values):
        raise AssertionError("intent/preparation must not signal a workflow")


def _operator(*, mode=AutonomousCampaignMode.PLAN_ONLY, source=True, create_enabled=True):
    options, starter, repository = Options(), Starter(), IntentRepository()
    options.targets = (replace(options.targets[0], revision="11:3"),)
    core = CampaignCoreService(options, starter)
    service = AutonomousCampaignOperatorService(
        core, AutonomousCampaignApplicationService(repository, mode=mode),
        root_plan_source=UnreadRootPlanSource() if source else None,
        validation_limits=limits(),
        native_owner=UnusedNativeOwner(), stop_gateway=UnusedStopGateway(),
        create_enabled=create_enabled,
    )
    return service, core, starter, repository


def test_normal_intent_uses_server_identity_source_mode_and_native_root_without_start() -> None:
    service, core, starter, repository = _operator(mode=AutonomousCampaignMode.BOUNDED_REPLAN)
    intent = _operator_selections(core)
    result = asyncio.run(service.create_intent(
        intent, tenant_id="tenant-r124", principal_id="operator-r124",
        idempotency_key="normal-intent-key", correlation_id="normal-intent-correlation", now=NOW,
    ))
    command = repository.commands[0]
    assert command.campaign_id.startswith("campaign-")
    assert command.expected_revision == 0
    assert command.actor_user_id == "operator-r124"
    assert command.mode is AutonomousCampaignMode.BOUNDED_REPLAN
    assert command.native_root.name == "Assess HTTP security posture"
    assert (command.native_root.engagement_revision, command.native_root.target_revision,
            command.native_root.roe_revision) == (7, 11, 3)
    assert result.application.lifecycle_state is AutonomousCampaignLifecycle.INTENT_CREATED
    assert len(command.intent_sha256) == len(command.source_binding_sha256) == 64
    assert starter.replay_calls == starter.calls == []


def test_normal_intent_identity_is_stable_and_changed_selections_cannot_alias_digest() -> None:
    service, core, starter, repository = _operator()
    intent = _operator_selections(core)
    for offset in (0, 1):
        asyncio.run(service.create_intent(
            intent, tenant_id="tenant-r124", principal_id="operator-r124",
            idempotency_key="normal-intent-key", correlation_id=f"correlation-{offset}",
            now=NOW + timedelta(seconds=offset),
        ))
    first, second = repository.commands
    assert first.campaign_id == second.campaign_id
    assert first.intent_sha256 == second.intent_sha256
    assert first.source_binding_sha256 == second.source_binding_sha256
    intent.objective = "Verify X-Content-Type-Options"
    asyncio.run(service.create_intent(
        intent, tenant_id="tenant-r124", principal_id="operator-r124",
        idempotency_key="normal-intent-key", correlation_id="changed-correlation", now=NOW,
    ))
    changed = repository.commands[-1]
    assert changed.campaign_id == first.campaign_id
    assert changed.intent_sha256 != first.intent_sha256
    assert starter.replay_calls == starter.calls == []


@pytest.mark.parametrize("configuration", [{"source": False}, {"create_enabled": False},
                                            {"mode": AutonomousCampaignMode.DISABLED}])
def test_normal_intent_unavailable_configuration_never_falls_back_to_legacy(configuration) -> None:
    service, _core, starter, repository = _operator(**configuration)
    with pytest.raises(ApplicationDependencyUnavailable, match="operator_creation_unavailable"):
        asyncio.run(service.create_intent(
            object(), tenant_id="tenant-r124", principal_id="operator-r124",
            idempotency_key="normal-intent-key", correlation_id="normal-correlation", now=NOW,
        ))
    assert repository.commands == starter.replay_calls == starter.calls == []


class RootPlanSource:
    def __init__(self, material):
        self.material = material
        self.read_calls = 0

    async def read_root_plan(self, **_values):
        self.read_calls += 1
        return self.material


class OperatorPlanRepository(PlanRepository):
    def __init__(self):
        super().__init__()
        self.preparations = {}

    async def read_operator_plan_replay(self, command):
        saved = self.preparations.get(command.idempotency_key)
        if saved is None:
            return None
        request, result = saved
        if request.request_sha256 != command.request_sha256:
            raise ApplicationIdempotencyConflict("operator_preparation_idempotency_mismatch")
        return replace(result, replayed=True)

    async def stage_plan(self, command, preview, *, operator_request=None):
        result = await super().stage_plan(command, preview)
        assert operator_request is not None
        self.preparations[operator_request.idempotency_key] = operator_request, result
        return result


def _preparation():
    command, key = _stage_command()
    repository = OperatorPlanRepository()
    application = _service(repository, command, key)
    source = RootPlanSource(AutonomousCampaignRootPlanMaterialV1(
        context=ApprovalContextProvider(command).context, domain=command.domain,
        initial_state=world(), search_limits=search_limits(),
    ))
    options = Options()
    options.engagements = (replace(options.engagements[0], resource_id=repository.state.engagement_id),)
    options.targets = (replace(options.targets[0], resource_id=repository.state.target_id,
                               parent_id=repository.state.engagement_id),)
    repository.options = options
    service = AutonomousCampaignOperatorService(
        CampaignCoreService(options, Starter()), application,
        root_plan_source=source, validation_limits=limits(),
        native_owner=UnusedNativeOwner(),
    )
    return service, source, repository, command


def test_operator_preparation_plans_and_independently_validates_before_native_staging() -> None:
    service, source, repository, command = _preparation()
    result = asyncio.run(service.prepare_plan(
        tenant_id=command.tenant_id, campaign_id=command.campaign_id,
        principal_id=command.actor_user_id, expected_revision=1,
        idempotency_key="normal-prepare", correlation_id="prepare-correlation", now=command.occurred_at,
    ))
    assert result.preview.target_id == repository.state.target_id
    assert result.preview.execution_mode is AutonomousCampaignMode.PLAN_ONLY
    assert result.application.lifecycle_state is AutonomousCampaignLifecycle.AWAITING_APPROVAL
    assert result.preview.validation_result.value == "valid"
    assert repository.stage_calls == source.read_calls == 1
    current_engagements = repository.options.engagements
    repository.options.engagements = ()
    with pytest.raises(ValueError, match="operator_application_scope_denied"):
        asyncio.run(service.prepare_plan(
            tenant_id=command.tenant_id, campaign_id=command.campaign_id,
            principal_id=command.actor_user_id, expected_revision=1,
            idempotency_key="normal-prepare", correlation_id="inactive-replay", now=command.occurred_at,
        ))
    assert repository.stage_calls == source.read_calls == 1
    repository.options.engagements = current_engagements
    assert repository.decision_calls == 0
    source.material = None
    replay = asyncio.run(service.prepare_plan(
        tenant_id=command.tenant_id, campaign_id=command.campaign_id,
        principal_id=command.actor_user_id, expected_revision=1,
        idempotency_key="normal-prepare", correlation_id="replay-correlation", now=command.occurred_at,
    ))
    assert replay.replayed and replay.preview == result.preview
    assert repository.stage_calls == source.read_calls == 1
    with pytest.raises(ApplicationIdempotencyConflict):
        asyncio.run(service.prepare_plan(
            tenant_id=command.tenant_id, campaign_id=command.campaign_id,
            principal_id=command.actor_user_id, expected_revision=3,
            idempotency_key="normal-prepare", correlation_id="changed-correlation", now=command.occurred_at,
        ))
    with pytest.raises(ApplicationRevisionConflict):
        asyncio.run(service.prepare_plan(
            tenant_id=command.tenant_id, campaign_id=command.campaign_id,
            principal_id=command.actor_user_id, expected_revision=1,
            idempotency_key="fresh-stale-prepare", correlation_id="stale-correlation", now=command.occurred_at,
        ))
    assert repository.stage_calls == source.read_calls == 1


def test_operator_preparation_source_binding_drift_is_denied_before_staging() -> None:
    service, source, repository, command = _preparation()
    source.material = replace(source.material, context=replace(source.material.context, campaign_id="other-campaign"))
    with pytest.raises(ValueError, match="operator_root_source_binding_mismatch"):
        asyncio.run(service.prepare_plan(
            tenant_id=command.tenant_id, campaign_id=command.campaign_id,
            principal_id=command.actor_user_id, expected_revision=1,
            idempotency_key="normal-prepare", correlation_id="prepare-correlation", now=command.occurred_at,
        ))
    assert repository.stage_calls == repository.decision_calls == 0
