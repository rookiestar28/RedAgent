"""Local signing must deny incomplete, stale, or drifted physical qualification."""

from datetime import datetime, timedelta, timezone

import pytest

from scripts import owned_runtime_authority_v3 as issuer


@pytest.mark.parametrize("mutation", ("wrong_image", "wrong_lock", "external_contact", "residual",
                                     "native_stop", "future_clock", "stale_clock", "isolation"))
def test_local_issuance_denies_unqualified_profile(mutation):
    now = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
    result = {
        "profile_id": "zap-passive-v1", "ok": True, "engine_image_id": "sha256:" + "a" * 64,
        "runtime_lock_sha256": "b" * 64, "qualified_at": now.isoformat(),
        "external_target_contacts": 0, "network_isolation_verified": True,
        "cleanup": {"cleanup_complete": True, "residual_resource_count": 0},
        "cancel": {"native_stop_acknowledged": True, "sensitive_files_remaining": 0},
    }
    if mutation == "wrong_image":
        result["engine_image_id"] = "sha256:" + "c" * 64
    elif mutation == "wrong_lock":
        result["runtime_lock_sha256"] = "d" * 64
    elif mutation == "external_contact":
        result["external_target_contacts"] = 1
    elif mutation == "residual":
        result["cleanup"]["residual_resource_count"] = 1
    elif mutation == "native_stop":
        result["cancel"]["native_stop_acknowledged"] = False
    elif mutation == "future_clock":
        result["qualified_at"] = (now + timedelta(seconds=1)).isoformat()
    elif mutation == "stale_clock":
        result["qualified_at"] = (now - timedelta(days=3)).isoformat()
    elif mutation == "isolation":
        result["network_isolation_verified"] = False
    with pytest.raises(issuer.AuthorityIssuanceError):
        issuer.verify_profile(result, profile="zap-passive-v1", image="sha256:" + "a" * 64,
                              lock_sha256="b" * 64, now=now)
