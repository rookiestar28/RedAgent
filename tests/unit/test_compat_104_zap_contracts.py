from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.zap_service.contracts import (
    ACTIVE_RULE_ID,
    PASSIVE_RULE_ID,
    ZAP_IMAGE_DIGEST_BY_PLATFORM,
    ApprovalClass,
    CertifiedProfileId,
    ZapAuthorization,
    ZapTargetBinding,
    certified_profiles,
)
from redagent_platform.zap_service.compiler import compile_zap_plan
from redagent_platform.zap_service.normalization import normalize_alerts
from redagent_platform.zap_service.topology import certified_topology


NOW = datetime(2026, 7, 11, 2, 0, tzinfo=timezone.utc)


def target(**overrides: object) -> ZapTargetBinding:
    values: dict[str, object] = {
        "target_id": "r104-owned-web-fixture",
        "attestation_sha256": "a" * 64,
        "endpoint": "http://redagent-r104-gateway:8080",
        "allowed_paths": ("/passive/missing-header",),
        "network_id": "redagent-r104-gateway-target",
        "non_production": True,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(overrides)
    return ZapTargetBinding(**values)  # type: ignore[arg-type]


def authorization(**overrides: object) -> ZapAuthorization:
    values: dict[str, object] = {
        "tenant_id": "tenant-r104",
        "policy_decision_id": "decision-r104",
        "policy_revision": "r099-v1",
        "roe_version_id": "roe-r104",
        "approval_class": ApprovalClass.LOW_RISK,
        "approved_profile_ids": (CertifiedProfileId.PASSIVE,),
        "credential_reference_ids": (),
        "approved_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return ZapAuthorization(**values)  # type: ignore[arg-type]


def test_certified_inventory_is_closed_pinned_and_profile_specific() -> None:
    profiles = certified_profiles()
    assert set(profiles) == set(CertifiedProfileId)
    assert ZAP_IMAGE_DIGEST_BY_PLATFORM == {
        "linux/amd64": "sha256:ccd16df57aed6724abdafe71b1077099c2b992d0945359d32d84f0939186b0c3",
    }
    assert profiles[CertifiedProfileId.PASSIVE].passive_rule_ids == (PASSIVE_RULE_ID,)
    assert profiles[CertifiedProfileId.ACTIVE_XSS_LAB].active_rule_ids == (ACTIVE_RULE_ID,)
    assert profiles[CertifiedProfileId.CLIENT_SPIDER].scope_check == "Strict"
    assert profiles[CertifiedProfileId.CLIENT_SPIDER].browser_count == 1
    assert profiles[CertifiedProfileId.ACTIVE_XSS_LAB].concurrency == 1
    assert all(profile.request_rate_per_second <= 3 for profile in profiles.values())
    assert all(profile.timeout_seconds <= 300 for profile in profiles.values())


def test_target_and_authorization_are_immutable_expiring_owned_bindings() -> None:
    bound = target()
    with pytest.raises(FrozenInstanceError):
        bound.endpoint = "http://example.com"  # type: ignore[misc]
    for change, reason in (
        ({"endpoint": "https://example.com"}, "zap_target_endpoint_invalid"),
        ({"endpoint": "http://127.0.0.1:8080"}, "zap_target_endpoint_invalid"),
        ({"network_id": "bridge"}, "zap_target_network_invalid"),
        ({"non_production": False}, "zap_target_non_production_required"),
        ({"allowed_paths": ("/",)}, "zap_target_path_invalid"),
        ({"expires_at": NOW + timedelta(minutes=16)}, "zap_target_ttl_exceeded"),
    ):
        with pytest.raises(ValueError, match=reason):
            target(**change)
    with pytest.raises(ValueError, match="zap_authorization_ttl_exceeded"):
        authorization(expires_at=NOW + timedelta(minutes=11))


def test_compiler_is_deterministic_and_emits_only_reviewed_automation_jobs() -> None:
    first = compile_zap_plan(
        profile_id=CertifiedProfileId.PASSIVE,
        target=target(),
        authorization=authorization(),
        now=NOW + timedelta(seconds=1),
    )
    second = compile_zap_plan(
        profile_id=CertifiedProfileId.PASSIVE,
        target=target(),
        authorization=authorization(),
        now=NOW + timedelta(seconds=1),
    )
    assert first == second
    assert len(first.plan_sha256) == 64
    assert first.plan["env"]["contexts"][0]["urls"] == [
        "http://redagent-r104-gateway:8080/passive/missing-header"
    ]
    assert first.plan["env"]["contexts"][0]["includePaths"] == [
        r"\Qhttp://redagent-r104-gateway:8080/passive/missing-header\E"
    ]
    assert [job["type"] for job in first.plan["jobs"]] == ["spider", "passiveScan-wait"]
    rendered = str(first).lower()
    for forbidden in ("apikey", "authorization", "cookie", "password", "script"):
        assert forbidden not in rendered


def test_compiler_rejects_profile_policy_approval_secret_and_time_mismatch() -> None:
    with pytest.raises(ValueError, match="zap_profile_not_approved"):
        compile_zap_plan(
            profile_id=CertifiedProfileId.ACTIVE_XSS_LAB,
            target=target(allowed_paths=("/active/reflected-input",)),
            authorization=authorization(), now=NOW,
        )
    active_auth = authorization(
        approval_class=ApprovalClass.ACTIVE_LAB,
        approved_profile_ids=(CertifiedProfileId.ACTIVE_XSS_LAB,),
    )
    with pytest.raises(ValueError, match="zap_active_path_required"):
        compile_zap_plan(
            profile_id=CertifiedProfileId.ACTIVE_XSS_LAB,
            target=target(), authorization=active_auth, now=NOW,
        )
    with pytest.raises(ValueError, match="zap_authorization_expired"):
        compile_zap_plan(
            profile_id=CertifiedProfileId.PASSIVE,
            target=target(), authorization=authorization(),
            now=NOW + timedelta(minutes=11),
        )
    with pytest.raises(ValueError, match="zap_credentials_forbidden"):
        compile_zap_plan(
            profile_id=CertifiedProfileId.PASSIVE,
            target=target(),
            authorization=authorization(credential_reference_ids=("secret-1",)),
            now=NOW,
        )


def test_topology_has_two_internal_networks_no_api_publication_and_no_direct_target_route() -> None:
    topology = certified_topology()
    assert topology.networks == {
        "redagent-r104-zap-gateway": {"internal": True},
        "redagent-r104-gateway-target": {"internal": True},
    }
    assert topology.attachments["zap"] == ("redagent-r104-zap-gateway",)
    assert topology.attachments["target"] == ("redagent-r104-gateway-target",)
    assert set(topology.attachments["gateway"]) == set(topology.networks)
    assert topology.published_ports == {}
    assert topology.zap_api_bind == "127.0.0.1"
    assert topology.file_transfer_enabled is False
    assert topology.jsonp_enabled is False
    assert topology.keyless_safe_operations is False


def test_normalization_accepts_only_certified_rules_and_redacts_sensitive_material() -> None:
    alerts = normalize_alerts([
        {
            "pluginId": PASSIVE_RULE_ID,
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "url": "http://redagent-r104-gateway:8080/passive/missing-header?token=secret-value",
            "method": "GET",
            "evidence": "password=do-not-store",
        }
    ], profile_id=CertifiedProfileId.PASSIVE)
    assert len(alerts) == 1 and alerts[0].rule_id == PASSIVE_RULE_ID
    assert alerts[0].affected_resource == "/passive/missing-header"
    assert len(alerts[0].fingerprint) == 64
    assert "secret-value" not in repr(alerts) and "do-not-store" not in repr(alerts)
    with pytest.raises(ValueError, match="zap_alert_rule_denied"):
        normalize_alerts([{"pluginId": "40018", "name": "SQL Injection", "risk": "High",
                           "confidence": "High", "url": "http://redagent-r104-gateway:8080/active/reflected-input",
                           "method": "GET"}], profile_id=CertifiedProfileId.ACTIVE_XSS_LAB)
    with pytest.raises(ValueError, match="zap_alert_count_exceeded"):
        normalize_alerts([], profile_id=CertifiedProfileId.PASSIVE, declared_count=1001)
