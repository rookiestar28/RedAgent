from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.api.runtime import validate_r123_api_runtime_dependencies
from redagent_platform.campaign_service.qualification import (
    OwnedLoopbackQualificationIntentV1,
    QualificationFixtureBinding,
    R123QualificationService,
    R123StatusService,
)
from redagent_platform.campaign_service.registry import (
    ExecutionReadinessFacts,
    StrategyLoopMode,
)
from redagent_platform.campaign_service.repository import CampaignTransitionResult
from redagent_platform.campaign_service.service import CampaignStartRequest


NOW = datetime(2026, 8, 24, 3, 30, tzinfo=timezone.utc)


class FixtureOwner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def read_owned_loopback_fixture(self, **values: object) -> QualificationFixtureBinding:
        self.calls.append(values)
        return QualificationFixtureBinding(
            fixture_id="owned-loopback-http-first-slice",
            engagement_id="engagement-server-owned",
            target_id="target-server-owned",
            campaign_name="compat_123 owned-loopback qualification",
        )


class StartService:
    def __init__(self) -> None:
        self.requests: list[CampaignStartRequest] = []

    async def start(self, request: CampaignStartRequest, *, now: datetime) -> CampaignTransitionResult:
        self.requests.append(request)
        return CampaignTransitionResult(
            campaign_id="campaign-server-generated",
            workflow_id="workflow-server-generated",
            aggregate_sequence=1,
            audit_id="audit-server-generated",
            outbox_id="outbox-server-generated",
        )


def _facts(**overrides: bool) -> ExecutionReadinessFacts:
    values = {
        "database_ready": True,
        "temporal_ready": True,
        "resolver_ready": True,
        "policy_ready": True,
        "quota_ready": True,
        "runner_ready": True,
        "evidence_ready": True,
        "finding_import_ready": True,
        "kill_switch_ready": True,
        "zap_adapter_ready": True,
        "nuclei_adapter_ready": True,
    }
    values.update(overrides)
    return ExecutionReadinessFacts(**values)


class FactsOwner:
    def __init__(self, facts: ExecutionReadinessFacts) -> None:
        self.facts = facts
        self.calls = 0

    async def read(self, *, now: datetime) -> ExecutionReadinessFacts:
        self.calls += 1
        return self.facts


def test_qualification_intent_is_closed_and_contains_no_runtime_identity_surface() -> None:
    intent = OwnedLoopbackQualificationIntentV1(
        fixture_id="owned-loopback-http-first-slice",
        objective_kind="http_posture",
        header_code=None,
        require_corroboration=False,
        risk_profile="tier1_passive",
    )

    assert set(intent.to_public_dict()) == {
        "schema_version",
        "fixture_id",
        "objective_kind",
        "header_code",
        "require_corroboration",
        "risk_profile",
    }
    assert not {
        "tenant_id", "principal_id", "engagement_id", "target_id", "runner_id",
        "workflow_id", "campaign_id", "adapter_id", "url", "command",
    }.intersection(intent.to_public_dict())
    with pytest.raises(ValueError, match="r123_qualification_fixture_invalid"):
        OwnedLoopbackQualificationIntentV1(
            fixture_id="caller-selected-target",
            objective_kind="http_posture",
            header_code=None,
            require_corroboration=False,
            risk_profile="tier1_passive",
        )


def test_qualification_service_resolves_server_fixture_and_never_accepts_runtime_ids() -> None:
    fixtures = FixtureOwner()
    starter = StartService()
    service = R123QualificationService(fixtures, starter)
    intent = OwnedLoopbackQualificationIntentV1(
        fixture_id="owned-loopback-http-first-slice",
        objective_kind="security_header_assertion",
        header_code="x-content-type-options",
        require_corroboration=True,
        risk_profile="tier1_passive",
    )

    receipt = asyncio.run(
        service.start(intent, tenant_id="tenant-from-auth", principal_id="principal-from-auth", now=NOW)
    )

    assert fixtures.calls == [{
        "tenant_id": "tenant-from-auth",
        "principal_id": "principal-from-auth",
        "fixture_id": "owned-loopback-http-first-slice",
        "now": NOW,
    }]
    request = starter.requests[0]
    assert request == CampaignStartRequest(
        tenant_id="tenant-from-auth",
        principal_id="principal-from-auth",
        engagement_id="engagement-server-owned",
        target_id="target-server-owned",
        name="compat_123 owned-loopback qualification",
        objective_kind="security_header_assertion",
        header_code="x-content-type-options",
        require_corroboration=True,
        risk_profile="tier1_passive",
    )
    assert receipt.campaign_id == "campaign-server-generated"
    assert receipt.aggregate_sequence == 1
    assert receipt.status == "dispatch_pending"
    assert not hasattr(receipt, "workflow_id")


def test_status_service_is_default_disabled_and_enabled_mode_fails_closed() -> None:
    disabled_owner = FactsOwner(_facts(database_ready=False))
    disabled = asyncio.run(
        R123StatusService(StrategyLoopMode.DISABLED, disabled_owner).read(now=NOW)
    )
    assert disabled.ready is True
    assert disabled.execution_enabled is False
    assert disabled.reason == "strategy_loop_disabled"
    assert disabled_owner.calls == 0

    missing_owner = FactsOwner(_facts(evidence_ready=False))
    missing = asyncio.run(
        R123StatusService(StrategyLoopMode.TWO_CAPABILITY, missing_owner).read(now=NOW)
    )
    assert missing.ready is False
    assert missing.execution_enabled is False
    assert missing.reason == "strategy_loop_dependency_missing:evidence_ready"
    assert missing_owner.calls == 1

    temporal_owner = FactsOwner(_facts(temporal_ready=False))
    temporal = asyncio.run(
        R123StatusService(StrategyLoopMode.TWO_CAPABILITY, temporal_owner).read(now=NOW)
    )
    assert temporal.ready is False
    assert temporal.execution_enabled is False
    assert temporal.reason == "strategy_loop_dependency_missing:temporal_ready"


def test_status_service_rejects_enabled_mode_without_current_facts_owner() -> None:
    with pytest.raises(ValueError, match="r123_status_facts_owner_required"):
        R123StatusService(StrategyLoopMode.TWO_CAPABILITY, None)


def test_api_runtime_mode_cannot_silently_drift_from_composed_r123_services() -> None:
    disabled = R123StatusService(StrategyLoopMode.DISABLED, None)
    assert validate_r123_api_runtime_dependencies(
        {},
        qualification_service=None,
        status_service=disabled,
    ) is StrategyLoopMode.DISABLED
    with pytest.raises(ValueError, match="r123_api_runtime_services_required"):
        validate_r123_api_runtime_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            qualification_service=None,
            status_service=disabled,
        )
    with pytest.raises(ValueError, match="r123_api_runtime_services_forbidden_when_disabled"):
        validate_r123_api_runtime_dependencies(
            {},
            qualification_service=object(),
            status_service=disabled,
        )
    enabled = R123StatusService(StrategyLoopMode.TWO_CAPABILITY, FactsOwner(_facts()))
    assert validate_r123_api_runtime_dependencies(
        {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
        qualification_service=object(),
        status_service=enabled,
    ) is StrategyLoopMode.TWO_CAPABILITY


def test_api_runtime_enabled_mode_accepts_only_an_unambiguous_lifespan_factory() -> None:
    disabled = R123StatusService(StrategyLoopMode.DISABLED, None)
    factory = object()

    assert validate_r123_api_runtime_dependencies(
        {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
        qualification_service=None,
        status_service=disabled,
        campaign_status_owner=None,
        service_factory=factory,
    ) is StrategyLoopMode.TWO_CAPABILITY
    with pytest.raises(ValueError, match="r123_api_runtime_services_ambiguous"):
        validate_r123_api_runtime_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            qualification_service=object(),
            status_service=disabled,
            campaign_status_owner=None,
            service_factory=factory,
        )
    with pytest.raises(ValueError, match="r123_api_runtime_services_forbidden_when_disabled"):
        validate_r123_api_runtime_dependencies(
            {},
            qualification_service=None,
            status_service=disabled,
            campaign_status_owner=None,
            service_factory=factory,
        )
