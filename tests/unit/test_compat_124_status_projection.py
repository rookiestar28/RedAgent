from __future__ import annotations

from datetime import datetime, timezone

from redagent_platform.campaign_service.status import (
    _public_finding,
    _recovery_guidance,
    _campaign_core_attention_sort_key,
)


def test_r124_public_finding_projects_assignment_state_without_raw_owner_id() -> None:
    projected = _public_finding({
        "title": "Missing response header",
        "severity": "medium",
        "disposition": "needs_review",
        "owner_id": "user-sensitive-reviewer-id",
        "issue_state": "open",
        "coverage_state": "covered",
        "result_state": "pending",
    })

    assert projected["owner"] == "Assigned"
    assert "user-sensitive-reviewer-id" not in str(projected)


def test_r124_cleanup_obligation_keeps_recovery_visible_after_campaign_terminal_state() -> None:
    recovery = _recovery_guidance(
        {"status": "completed"},
        [{"effect_state": "confirmed", "cleanup_receipt_id": None}],
    )

    assert recovery["cleanup_required"] is True
    assert recovery["stop_visible"] is True
    assert recovery["revoke_visible"] is True


def test_r124_attention_order_is_newest_first_then_stable_binding() -> None:
    now = datetime(2026, 8, 24, 15, 0, tzinfo=timezone.utc)
    items = [
        {"occurred_at": now, "binding": "b"},
        {"occurred_at": now, "binding": "a"},
        {"occurred_at": datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc), "binding": "c"},
    ]

    assert [item["binding"] for item in sorted(items, key=_campaign_core_attention_sort_key)] == [
        "a", "b", "c"
    ]
