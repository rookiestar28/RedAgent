from __future__ import annotations

from http.server import ThreadingHTTPServer
from threading import Thread

import pytest

from redagent_platform.cloud_connectors.collector import collect_snapshot
from redagent_platform.cloud_connectors.compiler import compile_collection_plan
from redagent_platform.cloud_connectors.contracts import CollectionAuthorization, ProviderKind
from redagent_platform.cloud_connectors.emulator import EmulatorHandler, EmulatorScenario
from redagent_platform.cloud_connectors.http_transport import ClosedHttpCollectionTransport
from redagent_platform.cloud_connectors.profiles import emulator_profiles
from tests.unit.test_compat_108_cloud_connector_contracts import NOW


def authorization(provider: ProviderKind) -> CollectionAuthorization:
    profile = emulator_profiles()[provider]
    permissions = tuple(operation.action for operation in profile.operations)
    return CollectionAuthorization(
        tenant_id="tenant-r108",
        policy_decision_id="decision-r108",
        policy_revision="r099-v1",
        reservation_id="reservation-r108",
        credential_lease_id="lease-r108",
        profile_id=profile.profile_id,
        effective_permissions=permissions,
        approved_permissions=permissions,
        approved_at=NOW,
        expires_at=NOW.replace(hour=15),
    )


@pytest.mark.parametrize("provider", tuple(ProviderKind))
def test_closed_http_transport_collects_each_provider_emulator_without_external_contact(provider: ProviderKind) -> None:
    profile = emulator_profiles()[provider]
    plan = compile_collection_plan(profile=profile, authorization=authorization(provider), now=NOW)
    scenario = EmulatorScenario.for_profile(profile)
    with running_emulator(scenario) as endpoint:
        transport = ClosedHttpCollectionTransport(
            endpoint=endpoint,
            expected_port=int(endpoint.rsplit(":", 1)[1]),
            lease_reference="lease-r108",
            max_response_bytes=plan.max_response_bytes,
        )
        result = collect_snapshot(plan=plan, transport=transport, collected_at=NOW)
        assert result.identity == profile.expected_identity
        assert result.complete is True
        assert result.resource_count >= 1
        assert scenario.external_contact_count == 0
        assert scenario.mutation_attempt_count == 0


def test_closed_http_transport_rejects_non_loopback_redirect_and_unknown_operation() -> None:
    with pytest.raises(ValueError, match="cloud_emulator_endpoint_forbidden"):
        ClosedHttpCollectionTransport(
            endpoint="https://example.test:443", expected_port=443, lease_reference="lease-r108", max_response_bytes=1000
        )
    profile = emulator_profiles()[ProviderKind.AWS]
    scenario = EmulatorScenario.for_profile(profile, redirect_identity=True)
    with running_emulator(scenario) as endpoint:
        transport = ClosedHttpCollectionTransport(
            endpoint=endpoint,
            expected_port=int(endpoint.rsplit(":", 1)[1]),
            lease_reference="lease-r108",
            max_response_bytes=10_000,
        )
        with pytest.raises(ValueError, match="cloud_http_redirect_denied"):
            transport.verify_identity()


class running_emulator:
    def __init__(self, scenario: EmulatorScenario) -> None:
        self.scenario = scenario

    def __enter__(self) -> str:
        handler = type("BoundEmulatorHandler", (EmulatorHandler,), {"scenario": self.scenario})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
