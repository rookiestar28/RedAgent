from __future__ import annotations

from pathlib import Path
import asyncio

import pytest

from fastapi.testclient import TestClient
from sqlalchemy.engine import URL

from redagent_platform.api.app import create_app
from redagent_platform.api.runtime import build_runtime_app
from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
)
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)
from redagent_platform.campaign_service.composition import (
    build_autonomous_campaign_application_factory,
)
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_APPROVE_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
)
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
)
from tests.unit.test_autonomous_campaign_plan_approval import (
    ApprovalContextProvider,
    Repository,
    _stage_command,
)
from tests.unit.test_campaign_planning_contracts import limits


def test_r172_factory_is_unavailable_without_the_complete_closed_configuration() -> None:
    assert build_autonomous_campaign_application_factory({}) is None
    assert build_autonomous_campaign_application_factory({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled"}) is None
    stage, _ = _stage_command()
    with pytest.raises(ValueError, match="r172_approval_configuration_incomplete"):
        build_autonomous_campaign_application_factory(
            {},
            approval_context_provider=ApprovalContextProvider(stage),
        )


def test_r172_configured_factory_can_stage_and_decide_end_to_end(monkeypatch) -> None:
    stage, key = _stage_command()
    repository = Repository()
    provider = ApprovalContextProvider(stage)
    monkeypatch.setattr(
        "redagent_platform.campaign_service.composition.PostgresAutonomousCampaignApplicationRepository",
        lambda sessions: repository,
    )
    factory = build_autonomous_campaign_application_factory(
        {},
        approval_context_provider=provider,
        trusted_approval_keys={"key-a": key},
        validation_limits=limits(),
        trusted_validator_version=VALIDATOR_VERSION,
        trusted_validator_sha256=VALIDATOR_SHA256,
    )
    assert factory is not None
    service = factory(object())
    assert isinstance(service, AutonomousCampaignApplicationService)
    assert service.mode is AutonomousCampaignMode.PLAN_ONLY

    staged = asyncio.run(service.stage_plan(stage))
    approved = asyncio.run(
        service.approve_plan(
            ApproveAutonomousCampaignPlanV1(
                schema_version=PLAN_APPROVE_SCHEMA_VERSION,
                tenant_id=stage.tenant_id,
                campaign_id=stage.campaign_id,
                preview_id=staged.preview.preview_id,
                preview_sha256=staged.preview.preview_sha256,
                actor_user_id="approver-a",
                actor_permissions=("campaign:approve",),
                policy_reference="policy:r172:composition",
                expected_revision=staged.application.aggregate_revision,
                idempotency_key="approve-composition-a",
                correlation_id="correlation-composition-a",
                occurred_at=stage.occurred_at,
            )
        )
    )
    assert approved.application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED


def test_application_exposes_current_plan_decision_start_and_child_routes() -> None:
    paths = create_app(test_issuer_enabled=True).openapi()["paths"]
    autonomous = {path for path in paths if "autonomous" in path}
    assert autonomous == {
        "/api/v1/autonomous-campaigns",
        "/api/v1/autonomous-campaigns/{campaign_id}",
        "/api/v1/autonomous-campaigns/{campaign_id}/prepare-plan",
        "/api/v1/autonomous-campaigns/{campaign_id}/stop",
        "/api/v1/autonomous-campaigns/{campaign_id}/revoke",
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-preview",
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-approval",
        "/api/v1/autonomous-campaigns/{campaign_id}/plan-denial",
        "/api/v1/autonomous-campaigns/{campaign_id}/admission-start",
        "/api/v1/autonomous-campaigns/{campaign_id}/child-replan",
    }
    assert "/api/v1/campaign-core/campaigns" in paths
    assert "/api/v1/campaign-core/operator-availability" in paths
    assert "/api/v1/internal/r123/qualification" in paths


def test_r172_unconfigured_runtime_lifespan_keeps_the_service_unavailable(tmp_path: Path) -> None:
    database = tmp_path / ".local" / "database-url"
    database.parent.mkdir(parents=True)
    url = URL.create(
        "postgresql+asyncpg",
        "runtime",
        "synthetic",
        "127.0.0.1",
        55432,
        "redagent",
    )
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    app = build_runtime_app(
        tmp_path,
        env={"REDAGENT_DATABASE_URL_FILE": str(database)},
    )

    assert app.state.autonomous_campaign_application_service is None
    with TestClient(app):
        assert app.state.autonomous_campaign_application_service is None
    assert app.state.autonomous_campaign_application_service is None


def test_r173_admission_factory_requires_database_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="autonomous_campaign_admission_factory_requires_database",
    ):
        create_app(
            test_issuer_enabled=True,
            autonomous_campaign_admission_start_service_factory=lambda _: object(),
        )
