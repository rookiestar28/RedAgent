from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.engine import URL

from redagent_platform.api.app import create_app
from redagent_platform.api.runtime import build_runtime_app
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)
from redagent_platform.campaign_service.composition import (
    build_autonomous_campaign_application_factory,
)


def test_r171_factory_defaults_plan_only_and_can_only_disable() -> None:
    factory = build_autonomous_campaign_application_factory({})
    assert factory is not None
    service = factory(object())
    assert isinstance(service, AutonomousCampaignApplicationService)
    assert service.mode is AutonomousCampaignMode.PLAN_ONLY
    assert build_autonomous_campaign_application_factory({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled"}) is None


def test_r171_does_not_register_a_premature_network_mutation_route() -> None:
    paths = create_app(test_issuer_enabled=True).openapi()["paths"]
    assert not any("autonomous" in path for path in paths)
    assert "/api/v1/campaign-core/campaigns" in paths
    assert "/api/v1/internal/r123/qualification" in paths


def test_r171_runtime_lifespan_injects_only_the_plan_only_service(tmp_path: Path) -> None:
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
        service = app.state.autonomous_campaign_application_service
        assert isinstance(service, AutonomousCampaignApplicationService)
        assert service.mode is AutonomousCampaignMode.PLAN_ONLY
    assert app.state.autonomous_campaign_application_service is None
