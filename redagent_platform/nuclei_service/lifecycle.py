"""Closed cancellation and cleanup ordering for R105."""

from __future__ import annotations


def cancellation_actions(*, native_stop_acknowledged: bool) -> tuple[str, ...]:
    if not isinstance(native_stop_acknowledged, bool):
        raise ValueError("nuclei_native_stop_ack_invalid")
    actions = [
        "block_gateway", "signal_workload", "wait_native_ack", "revoke_lease",
        "finalize_partial_evidence",
    ]
    if not native_stop_acknowledged:
        actions.append("terminate_workload")
    actions.extend(("erase_home_output_and_keys", "remove_owned_resources", "verify_absence"))
    return tuple(actions)
