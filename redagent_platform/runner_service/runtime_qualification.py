"""Closed physical-profile claims consumed by current local runtime authorities."""

from __future__ import annotations

from datetime import datetime, timedelta


def verify_owned_profile_qualification(
    receipt: dict[str, object], *, profiles: frozenset[str], issued_at: datetime,
) -> None:
    """Require every expected profile and its physical safety result before issuance."""
    try:
        qualified = receipt["qualified_at"]
        items = receipt["profiles"]
        if not isinstance(qualified, str) or not isinstance(items, list):
            raise ValueError("qualification_shape_invalid")
        if any(not isinstance(item, dict) for item in items):
            raise ValueError("qualification_profile_invalid")
        qualified_at = datetime.fromisoformat(qualified)
        valid = (
            len(items) == len(profiles)
            and {item.get("profile_id") for item in items} == profiles
            and receipt.get("production_qualified") is False
            and receipt.get("network_isolation_verified") is True
            and receipt.get("direct_target_route") is False
            and type(receipt.get("external_target_contacts")) is int
            and receipt.get("external_target_contacts") == 0
            and type(receipt.get("cleanup_residual_resource_count")) is int
            and receipt.get("cleanup_residual_resource_count") == 0
            and qualified_at.tzinfo is not None
            and issued_at.tzinfo is not None
            and timedelta(0) <= issued_at - qualified_at <= timedelta(days=2)
        )
        # CRITICAL: aggregate PASS never replaces each profile's confinement, native
        # stop and cleanup proof; duplicate or failed entries cannot grant authority.
        valid = valid and all(
            item.get("passed") is True
            and item.get("network_isolation_verified") is True
            and item.get("native_stop_acknowledged") is True
            and type(item.get("external_target_contacts")) is int
            and item.get("external_target_contacts") == 0
            and type(item.get("cleanup_residual_resource_count")) is int
            and item.get("cleanup_residual_resource_count") == 0
            for item in items
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("owned_profile_qualification_invalid") from exc
    if not valid:
        raise ValueError("owned_profile_qualification_invalid")
