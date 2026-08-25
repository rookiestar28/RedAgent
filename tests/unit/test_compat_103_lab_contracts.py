from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.lab_service.contracts import (
    LAB_SCHEMA, FixtureKind, LabBundleManifest, LabTargetAttestation, LabTargetLease,
    TargetAccessRequest, TestClass as LabTestClass, authorize_target_access, enforce_runner_target,
)
from redagent_platform.lab_service.scenarios import (
    REQUIRED_GOLDEN_SCENARIOS, ScenarioState, ScenarioStatus, advance_scenario,
    golden_scenario_registry,
)
from redagent_platform.lab_service.runner_guard import contact_guarded_lab_target


NOW = datetime(2026, 7, 11, 10, 0, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
SHA = "b" * 64


def _manifest(**changes: object) -> LabBundleManifest:
    values = {
        "schema": LAB_SCHEMA, "bundle_id": "r103-synthetic-lab", "revision": 1,
        "fixture_digest": DIGEST, "seed_manifest_sha256": SHA,
        "fixture_kinds": tuple(FixtureKind), "allowed_test_classes": tuple(LabTestClass),
        "network_id": "redagent-r103-lab", "non_production": True,
        "created_at": NOW, "expires_at": NOW + timedelta(hours=2),
    }
    values.update(changes)
    return LabBundleManifest(**values)


def _attestation(**changes: object) -> LabTargetAttestation:
    values = {
        "attestation_id": "attestation-1", "tenant_id": "tenant-1",
        "target_id": "target-web-1", "bundle_id": "r103-synthetic-lab",
        "bundle_digest": DIGEST, "fixture_kind": FixtureKind.WEB,
        "endpoint": "http://127.0.0.1:58880", "network_id": "redagent-r103-lab",
        "allowed_test_classes": (LabTestClass.HEALTH, LabTestClass.HAPPY_PATH, LabTestClass.FINDING_MAPPING),
        "expected_finding_manifest_sha256": SHA, "non_production": True,
        "issued_at": NOW, "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return LabTargetAttestation(**values)


def _lease(attestation: LabTargetAttestation, **changes: object) -> LabTargetLease:
    values = {
        "lease_id": "lab-lease-1", "tenant_id": "tenant-1", "target_id": "target-web-1",
        "attestation_sha256": attestation.canonical_sha256, "runner_id": "runner-1",
        "test_class": LabTestClass.HAPPY_PATH, "endpoint": attestation.endpoint,
        "issued_at": NOW, "expires_at": NOW + timedelta(minutes=10),
        "policy_reference": "policy:compat_103:1", "roe_version_id": "roe-r103-1",
    }
    values.update(changes)
    return LabTargetLease(**values)


def test_exact_current_attestation_and_lease_allow_only_the_bound_local_target() -> None:
    manifest = _manifest()
    attestation = _attestation()
    lease = _lease(attestation)
    decision = authorize_target_access(
        manifest=manifest, attestation=attestation, lease=lease,
        request=TargetAccessRequest(
            tenant_id="tenant-1", target_id="target-web-1", runner_id="runner-1",
            test_class=LabTestClass.HAPPY_PATH, endpoint="http://127.0.0.1:58880",
            policy_reference="policy:compat_103:1", roe_version_id="roe-r103-1", requested_at=NOW,
        ),
    )
    assert decision.allowed and decision.reason_code == "local_lab_target_authorized"
    enforced = enforce_runner_target(
        manifest=manifest, attestation=attestation, lease=lease,
        observed_endpoint="http://127.0.0.1:58880", observed_ip="127.0.0.1",
        occurred_at=NOW + timedelta(seconds=1),
    )
    assert enforced.allowed and enforced.reason_code == "runner_local_lab_target_enforced"


@pytest.mark.parametrize(("manifest_change", "attestation_change", "lease_change", "expected"), (
    ({"non_production": False}, {}, {}, "lab_bundle_non_production_required"),
    ({}, {"non_production": False}, {}, "lab_target_non_production_required"),
    ({}, {"endpoint": "https://demo.owasp-juice.shop"}, {}, "lab_target_endpoint_local_required"),
    ({}, {"endpoint": "http://10.0.0.8:8080", "network_id": "unknown"}, {}, "lab_target_network_invalid"),
    ({}, {"issued_at": NOW - timedelta(hours=2), "expires_at": NOW - timedelta(hours=1)}, {}, "lab_target_attestation_expired"),
    ({}, {}, {"issued_at": NOW - timedelta(minutes=2), "expires_at": NOW - timedelta(seconds=1)}, "lab_target_lease_expired"),
    ({}, {}, {"attestation_sha256": "c" * 64}, "lab_target_attestation_mismatch"),
))
def test_unsafe_unknown_expired_or_mutated_target_fails_closed(
    manifest_change: dict[str, object], attestation_change: dict[str, object],
    lease_change: dict[str, object], expected: str,
) -> None:
    with pytest.raises(ValueError, match=expected):
        manifest = _manifest(**manifest_change)
        attestation = _attestation(**attestation_change)
        lease = _lease(attestation, **lease_change)
        authorize_target_access(
            manifest=manifest, attestation=attestation, lease=lease,
            request=TargetAccessRequest(
                tenant_id="tenant-1", target_id="target-web-1", runner_id="runner-1",
                test_class=LabTestClass.HAPPY_PATH, endpoint=attestation.endpoint,
                policy_reference="policy:compat_103:1", roe_version_id="roe-r103-1",
                requested_at=NOW,
            ),
        )


def test_runner_rechecks_exact_endpoint_and_rejects_rebinding_or_public_ip() -> None:
    manifest = _manifest()
    attestation = _attestation()
    lease = _lease(attestation)
    for endpoint, ip, reason in (
        ("http://127.0.0.1:58881", "127.0.0.1", "runner_lab_endpoint_mismatch"),
        ("http://127.0.0.1:58880", "203.0.113.10", "runner_lab_ip_mismatch"),
    ):
        with pytest.raises(ValueError, match=reason):
            enforce_runner_target(
                manifest=manifest, attestation=attestation, lease=lease,
                observed_endpoint=endpoint, observed_ip=ip, occurred_at=NOW,
            )


def test_runner_denial_has_zero_contact_and_exact_allow_contacts_once() -> None:
    asyncio.run(_runner_contact_scenario())


async def _runner_contact_scenario() -> None:
    contacts = 0
    async def contact() -> str:
        nonlocal contacts
        contacts += 1
        return "synthetic-response"

    manifest = _manifest(); attestation = _attestation(); lease = _lease(attestation)
    with pytest.raises(ValueError, match="runner_lab_ip_mismatch"):
        await contact_guarded_lab_target(
            manifest=manifest, attestation=attestation, lease=lease,
            observed_endpoint=lease.endpoint, observed_ip="203.0.113.10",
            occurred_at=NOW, contact=contact,
        )
    assert contacts == 0
    assert await contact_guarded_lab_target(
        manifest=manifest, attestation=attestation, lease=lease,
        observed_endpoint=lease.endpoint, observed_ip="127.0.0.1",
        occurred_at=NOW, contact=contact,
    ) == "synthetic-response"
    assert contacts == 1


def test_golden_registry_is_complete_bounded_and_state_machine_is_restart_safe() -> None:
    registry = golden_scenario_registry()
    assert set(registry) == REQUIRED_GOLDEN_SCENARIOS
    assert all(1 <= item.timeout_seconds <= 300 for item in registry.values())
    assert all(item.compensation_steps for item in registry.values())
    state = ScenarioState(
        run_id="run-1", scenario_id="authorize_deny", status=ScenarioStatus.PENDING,
        current_step=0, version=1, last_action_id=None, reason_code="scenario_registered",
    )
    running = advance_scenario(
        state, action_id="action-start", expected_version=1,
        next_status=ScenarioStatus.RUNNING, reason_code="scenario_started",
    )
    replay = advance_scenario(
        running, action_id="action-start", expected_version=1,
        next_status=ScenarioStatus.RUNNING, reason_code="scenario_started",
    )
    assert replay == running
    completed = advance_scenario(
        running, action_id="action-finish", expected_version=2,
        next_status=ScenarioStatus.SUCCEEDED, reason_code="scenario_succeeded",
    )
    assert completed.version == 3
    with pytest.raises(ValueError, match="scenario_transition_invalid"):
        advance_scenario(
            completed, action_id="action-invalid", expected_version=3,
            next_status=ScenarioStatus.RUNNING, reason_code="scenario_started",
        )
