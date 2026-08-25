from __future__ import annotations

import asyncio
import inspect

from redagent_platform.api.app import _list_response, create_app
from redagent_platform.api.routers import observability as observability_routes
from redagent_platform.api.schemas import PageData, PaginationQuery
from redagent_platform.telemetry_service.operations import IncidentRepository
from redagent_platform.telemetry_service.repository import TelemetryRepository


def test_page_data_exposes_authoritative_optional_continuation() -> None:
    page = PageData(limit=2, offset=0, returned=2, next_offset=2)

    assert page.model_dump() == {
        "limit": 2,
        "offset": 0,
        "returned": 2,
        "next_offset": 2,
    }


def test_list_response_truncates_probe_row_and_emits_next_offset() -> None:
    response = _list_response(
        [{"id": "one"}, {"id": "two"}, {"id": "probe"}],
        PaginationQuery(limit=2, offset=4),
    )

    assert response == {
        "data": [{"id": "one"}, {"id": "two"}],
        "page": {"limit": 2, "offset": 4, "returned": 2, "next_offset": 6},
    }


def test_list_response_omits_continuation_without_probe_row() -> None:
    response = _list_response(
        [{"id": "one"}, {"id": "two"}],
        PaginationQuery(limit=2, offset=4),
    )

    assert response["page"]["next_offset"] is None


def test_openapi_page_contract_contains_next_offset() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    page_schema = schema["components"]["schemas"]["PageData"]

    assert "next_offset" in page_schema["properties"]


def test_incident_and_correlation_repositories_apply_authoritative_offset() -> None:
    incident_session = _Session()
    telemetry_session = _Session()

    asyncio.run(IncidentRepository(
        incident_session, tenant_id="tenant-1", actor_user_id="operator-1",
        correlation_id="correlation-1",
    ).list_incidents(limit=3, offset=7))
    asyncio.run(TelemetryRepository(
        telemetry_session, tenant_id="tenant-1", actor_user_id="operator-1",
        correlation_id="correlation-1",
    ).lookup_correlation(correlation_id="correlation-1", limit=3, offset=7))

    for session in (incident_session, telemetry_session):
        statement = session.statements[-1]
        assert statement._limit_clause.value == 3
        assert statement._offset_clause.value == 7


def test_observability_list_routes_request_one_row_probe_and_forward_offset() -> None:
    source = inspect.getsource(observability_routes.register_observability_incident_routes)
    incident_block = source.split("async def list_incidents(", 1)[1].split("@app.get(", 1)[0]
    correlation_block = source.split("async def lookup_observability_correlation(", 1)[1].split("@app.get(", 1)[0]

    for block in (incident_block, correlation_block):
        assert "limit=_probe_limit(query)" in block
        assert "offset=query.offset" in block


class _Rows:
    def mappings(self):
        return self

    def all(self):
        return []


class _Session:
    def __init__(self) -> None:
        self.statements = []

    async def execute(self, statement, *_args, **_kwargs):
        self.statements.append(statement)
        return _Rows()
