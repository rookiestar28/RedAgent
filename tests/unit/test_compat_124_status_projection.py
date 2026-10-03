from __future__ import annotations

from datetime import datetime, timezone
import asyncio
from types import SimpleNamespace
from contextlib import asynccontextmanager

import pytest

from redagent_platform.campaign_service.status import (
    _public_finding,
    _recovery_guidance,
    _campaign_core_attention_sort_key,
    PostgresCampaignCorePresentationOwner,
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


@pytest.mark.parametrize("issue_state,coverage,result,category", [
    ("open", "complete", "passed", "finding"),
    ("closed", "incomplete", "pending", "retest"),
])
def test_attention_with_external_receipt_queries_native_finding_tables_and_keeps_review_open(
    monkeypatch, issue_state, coverage, result, category,
):
    async def scenario():
        now = datetime(2026, 10, 3, tzinfo=timezone.utc)
        # This unit boundary supplies SQL result rows only. Current principal enforcement is
        # separately proven with native PostgreSQL; the product still builds and executes its query.
        async def current_principal(*_args, **_kwargs):
            return None
        monkeypatch.setattr("redagent_platform.campaign_service.status._require_campaign_core_principal", current_principal)
        campaign_rows = [{"id": "campaign-a", "name": "Owned posture", "attention_reason": None,
                          "updated_at": now, "delivery_state": "delivered", "outbox_reconciliation": "confirmed",
                          "effect_state": "confirmed", "effect_reconciliation": "confirmed",
                          "cleanup_receipt_id": "cleanup-a", "failure_code": None,
                          "external_receipt_id": "execution-a"}]
        finding_rows = [{"run_id": "execution-a", "issue_state": issue_state, "disposition": "needs_review",
                         "coverage_state": coverage, "result_state": result}]

        class Session:
            def __init__(self):
                self.results = iter([[], campaign_rows, finding_rows])
                self.queries = []

            @asynccontextmanager
            async def transaction(self):
                yield self

            def begin(self):
                return self.transaction()

            async def execute(self, query):
                self.queries.append(str(query))
                rows = next(self.results)
                return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: rows))

        session = Session()
        owner = PostgresCampaignCorePresentationOwner(session.transaction)
        page = await owner.list_attention(tenant_id="tenant-a", principal_id="operator-a", limit=10, cursor=None, now=now)
        assert [(item["campaign_label"], item["category"]) for item in page["data"]] == [("Owned posture", category)]
        assert "finding_import_sessions" in session.queries[-1]
        assert "managed_issues" in session.queries[-1]
        assert "finding_retests" in session.queries[-1]
    asyncio.run(scenario())
