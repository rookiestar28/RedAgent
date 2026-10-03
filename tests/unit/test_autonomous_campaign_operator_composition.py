from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.engine import URL

from redagent_platform.api.app import create_app
from redagent_platform.api.runtime import build_runtime_app
from tests.unit.test_autonomous_campaign_operator_api import READ
from tests.unit.test_autonomous_campaign_operator_service import _operator
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode


def _runtime_env(tmp_path: Path):
    database = tmp_path / ".local/database-url"
    database.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    return {"REDAGENT_DATABASE_URL_FILE": str(database)}


def test_operator_factory_requires_database_and_rejects_ambiguous_direct_or_other_owner_factories(tmp_path):
    operator, core, _starter, _repository = _operator()
    with pytest.raises(ValueError, match="autonomous_campaign_operator_factory_requires_database"):
        create_app(autonomous_campaign_operator_service_factory=lambda _: operator)
    from redagent_platform.persistence.database import load_database_settings
    settings = load_database_settings(tmp_path, env=_runtime_env(tmp_path))
    for competing in (
        {"autonomous_campaign_operator_service": operator},
        {"autonomous_campaign_application_service": operator.application_service},
        {"r124_campaign_core_service": core},
        {"autonomous_campaign_service_factory": lambda _: operator.application_service},
        {"r123_service_factory": lambda _: object()},
    ):
        with pytest.raises(ValueError, match="autonomous_campaign_operator_runtime_services_ambiguous"):
            create_app(database_settings=settings, autonomous_campaign_operator_service_factory=lambda _: operator,
                       **competing)


@pytest.mark.parametrize("invalid", [object(), None])
def test_runtime_operator_factory_result_fails_closed_and_clears_owners(tmp_path, invalid):
    app = build_runtime_app(tmp_path, env=_runtime_env(tmp_path), test_issuer_enabled=True,
                            autonomous_campaign_operator_service_factory=lambda _: invalid)
    with pytest.raises(RuntimeError, match="autonomous_campaign_operator_factory_result_invalid"):
        with TestClient(app):
            pass
    assert app.state.autonomous_campaign_operator_service is None
    assert app.state.autonomous_campaign_application_service is None
    assert app.state.r124_campaign_core_service is None


def test_stock_runtime_uses_one_complete_explicit_operator_composition_and_removes_it_on_shutdown(tmp_path):
    operator, core, _starter, _repository = _operator()
    seen = []
    async def factory(sessions):
        seen.append(sessions)
        return operator
    app = build_runtime_app(tmp_path, env=_runtime_env(tmp_path), test_issuer_enabled=True,
                            autonomous_campaign_operator_service_factory=factory)
    assert app.state.autonomous_campaign_operator_service is None
    with TestClient(app) as client:
        assert seen == [app.state.session_factory]
        assert app.state.autonomous_campaign_operator_service is operator
        assert app.state.autonomous_campaign_application_service is operator.application_service
        assert app.state.r124_campaign_core_service is core
        availability = client.get("/api/v1/campaign-core/operator-availability", headers=READ)
        assert availability.status_code == 200 and availability.json()["data"]["create_available"] is True
    assert app.state.autonomous_campaign_operator_service is None
    assert app.state.autonomous_campaign_application_service is None
    assert app.state.r124_campaign_core_service is None


@pytest.mark.parametrize("configuration,reason", [
    ({"source": False}, "autonomous_campaign_operator_factory_configuration_incomplete"),
    ({"mode": AutonomousCampaignMode.OWNED_LOOPBACK_AUTO}, "autonomous_campaign_operator_admission_configuration_incomplete"),
])
def test_runtime_rejects_partial_enabled_operator_configuration(tmp_path, configuration, reason):
    operator, _core, _starter, _repository = _operator(**configuration)
    app = build_runtime_app(tmp_path, env=_runtime_env(tmp_path), test_issuer_enabled=True,
                            autonomous_campaign_operator_service_factory=lambda _: operator)
    with pytest.raises(RuntimeError, match=reason):
        with TestClient(app):
            pass
    assert app.state.autonomous_campaign_operator_service is None
