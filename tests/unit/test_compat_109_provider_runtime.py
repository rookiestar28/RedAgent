from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest

from redagent_platform.identity_saas.collector import collect_identity_snapshot
from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import IdentityAuthorization
from redagent_platform.identity_saas.emulator import IdentityEmulatorHandler, IdentityEmulatorScenario
from redagent_platform.identity_saas.http_transport import ClosedIdentityHttpTransport
from redagent_platform.identity_saas.profiles import emulator_profiles


NOW = datetime(2026, 7, 11, 4, 0, tzinfo=timezone.utc)


def _authorization(profile):
    return IdentityAuthorization(
        authorization_id="auth-r109", policy_decision_id="policy-r109", policy_revision="r109-v1",
        reservation_id="reservation-r109", credential_lease_id="lease-r109",
        tenant_id=profile.tenant_id, audience=profile.audience, consent_mode=profile.consent_mode,
        granted_scopes=tuple(item.permission_scope for item in profile.operations),
        effective_role_permissions=tuple(item.effective_role_permission for item in profile.operations),
        approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10),
    )


@pytest.mark.parametrize("profile", emulator_profiles().values(), ids=lambda item: item.provider.value)
def test_repo_owned_provider_emulators_produce_minimized_deterministic_snapshots(profile):
    plan = compile_identity_plan(profile=profile, authorization=_authorization(profile), now=NOW)
    scenario = IdentityEmulatorScenario.for_profile(profile)
    handler = type("BoundIdentityHandler", (IdentityEmulatorHandler,), {"scenario": scenario})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        transport = ClosedIdentityHttpTransport(
            endpoint=f"http://127.0.0.1:{server.server_port}", expected_port=server.server_port,
            lease_reference="lease-r109", max_response_bytes=profile.max_bytes,
        )
        first = collect_identity_snapshot(plan=plan, profile=profile, transport=transport, collected_at=NOW)
        second = collect_identity_snapshot(plan=plan, profile=profile, transport=transport, collected_at=NOW)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    assert first.snapshot_sha256 == second.snapshot_sha256
    assert first.complete is True
    assert first.tenant_id == profile.tenant_id
    assert first.audience == profile.audience
    assert first.granted_scopes == plan.scopes
    assert first.redaction_sha256
    assert scenario.external_contact_count == 0
    for resource in first.resources:
        operation = next(item for item in profile.operations if item.operation_id == resource.operation_id)
        assert set(resource.attributes) <= set(operation.selected_fields)


def test_collector_rejects_unselected_sensitive_field_and_wrong_tenant():
    profile = next(iter(emulator_profiles().values()))
    plan = compile_identity_plan(profile=profile, authorization=_authorization(profile), now=NOW)
    scenario = IdentityEmulatorScenario.for_profile(profile)
    scenario.tenant_id = "wrong-tenant"
    handler = type("WrongTenantHandler", (IdentityEmulatorHandler,), {"scenario": scenario})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler); thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        transport = ClosedIdentityHttpTransport(endpoint=f"http://127.0.0.1:{server.server_port}", expected_port=server.server_port, lease_reference="lease-r109", max_response_bytes=profile.max_bytes)
        with pytest.raises(ValueError, match="identity_provider_binding_mismatch"):
            collect_identity_snapshot(plan=plan, profile=profile, transport=transport, collected_at=NOW)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_transport_denies_redirect_and_non_loopback_endpoint():
    with pytest.raises(ValueError, match="identity_emulator_endpoint_forbidden"):
        ClosedIdentityHttpTransport(endpoint="https://graph.microsoft.com", expected_port=443, lease_reference="lease-r109", max_response_bytes=100)
