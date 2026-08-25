"""Closed cancellation ordering for compat_104 scanner containment."""

from __future__ import annotations


def cancellation_actions(*, native_stop_acknowledged: bool) -> tuple[str, ...]:
    if not isinstance(native_stop_acknowledged, bool):
        raise ValueError("zap_native_stop_ack_invalid")
    actions = [
        "block_gateway", "automation_stop", "spider_stop", "client_spider_stop",
        "active_scan_stop", "wait_native_ack", "revoke_credential_lease",
        "finalize_partial_evidence",
    ]
    if not native_stop_acknowledged:
        actions.append("terminate_workload")
    actions.extend(("erase_key_and_home", "remove_owned_resources", "verify_absence"))
    return tuple(actions)
