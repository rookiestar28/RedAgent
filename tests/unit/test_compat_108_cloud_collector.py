from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from redagent_platform.cloud_connectors.collector import (
    CollectionPage,
    CollectionTransport,
    collect_snapshot,
)
from redagent_platform.cloud_connectors.contracts import ProviderIdentity, ProviderKind
from tests.unit.test_compat_108_cloud_connector_contracts import NOW, authorization, profile
from redagent_platform.cloud_connectors.compiler import compile_collection_plan


@dataclass
class FakeTransport(CollectionTransport):
    identity: ProviderIdentity
    pages: tuple[CollectionPage, ...]
    revoked_after: int | None = None

    def verify_identity(self) -> ProviderIdentity:
        return self.identity

    def fetch_page(self, *, operation_id: str, cursor: str | None) -> CollectionPage:
        index = 0 if cursor is None else int(cursor)
        if self.revoked_after is not None and index >= self.revoked_after:
            raise PermissionError("credential_lease_revoked")
        return self.pages[index]


def page(index: int, next_cursor: str | None, *, partial_reason: str | None = None) -> CollectionPage:
    return CollectionPage(
        operation_id="aws-iam-list-roles-v1",
        page_index=index,
        next_cursor=next_cursor,
        resources=(
            {"resource_id": f"arn:aws:iam::123456789012:role/role-{index}", "mfa_required": index == 0},
        ),
        response_bytes=180,
        partial_reason=partial_reason,
    )


def test_collector_verifies_identity_paginates_and_hashes_deterministically() -> None:
    plan = compile_collection_plan(profile=profile(), authorization=authorization(), now=NOW)
    transport = FakeTransport(
        ProviderIdentity(provider=ProviderKind.AWS, tenant="123456789012"),
        (page(0, "1"), page(1, None)),
    )

    first = collect_snapshot(plan=plan, transport=transport, collected_at=NOW)
    second = collect_snapshot(plan=plan, transport=transport, collected_at=NOW)

    assert first == second
    assert first.complete is True and first.partial_reasons == ()
    assert first.identity == plan.expected_identity
    assert first.page_count == 2 and first.resource_count == 2
    assert len(first.snapshot_sha256) == 64
    assert "mfa_required" in first.resources[0].attributes


def test_collector_denies_wrong_identity_page_loop_and_revoked_lease() -> None:
    plan = compile_collection_plan(profile=profile(), authorization=authorization(), now=NOW)
    with pytest.raises(ValueError, match="cloud_provider_identity_mismatch"):
        collect_snapshot(
            plan=plan,
            transport=FakeTransport(
                ProviderIdentity(provider=ProviderKind.AWS, tenant="999999999999"), (page(0, None),)
            ),
            collected_at=NOW,
        )
    with pytest.raises(ValueError, match="cloud_pagination_loop"):
        collect_snapshot(
            plan=plan,
            transport=FakeTransport(plan.expected_identity, (page(0, "0"),)),
            collected_at=NOW,
        )
    with pytest.raises(PermissionError, match="credential_lease_revoked"):
        collect_snapshot(
            plan=plan,
            transport=FakeTransport(plan.expected_identity, (page(0, "1"), page(1, None)), revoked_after=1),
            collected_at=NOW,
        )


def test_collector_preserves_partial_failure_and_never_reports_clean() -> None:
    plan = compile_collection_plan(profile=profile(), authorization=authorization(), now=NOW)
    result = collect_snapshot(
        plan=plan,
        transport=FakeTransport(plan.expected_identity, (page(0, None, partial_reason="iam_throttled"),)),
        collected_at=datetime(2026, 7, 11, 14, 1, tzinfo=timezone.utc),
    )
    assert result.complete is False
    assert result.partial_reasons == ("iam_throttled",)
