from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.containment_service.revocation import (
    REVOCATION_SLO_MS, AuthorityFacts, RevocationMonitor,
)


NOW = datetime(2026, 7, 10, 21, 0, tzinfo=timezone.utc)


def test_all_four_current_authority_revocations_activate_exact_job_stops_within_r091_slo() -> None:
    jobs = ("authorization", "roe", "policy", "credential")
    activated: list[tuple[str, str]] = []

    async def facts(job_id: str, occurred_at: datetime) -> AuthorityFacts:
        values = {name: True for name in jobs}
        values[job_id] = False
        return AuthorityFacts(
            tenant_id="tenant-1", job_id=job_id,
            authorization_current=values["authorization"], roe_current=values["roe"],
            policy_current=values["policy"], credential_current=values["credential"],
            checked_at=occurred_at, invalidated_at=occurred_at - timedelta(seconds=2),
        )

    async def activate(current: AuthorityFacts, reason: str, occurred_at: datetime) -> str:
        activated.append((current.job_id, reason))
        return f"stop-{current.job_id}"

    result = asyncio.run(RevocationMonitor(facts, activate).reconcile(jobs, occurred_at=NOW))
    assert {item.reason_code for item in result} == {
        "authorization_revoked", "roe_revoked", "policy_revoked", "credential_revoked",
    }
    assert all(item.within_slo and item.propagation_ms == 2_000 for item in result)
    assert len(activated) == 4 and REVOCATION_SLO_MS == 10_000


def test_stale_or_mismatched_current_facts_never_silently_authorize() -> None:
    async def stale(job_id: str, occurred_at: datetime) -> AuthorityFacts:
        return AuthorityFacts(
            tenant_id="tenant-1", job_id=job_id,
            authorization_current=False, roe_current=True, policy_current=True, credential_current=True,
            checked_at=occurred_at - timedelta(seconds=1), invalidated_at=occurred_at - timedelta(seconds=2),
        )

    async def activate(current: AuthorityFacts, reason: str, occurred_at: datetime) -> str:
        return "stop-1"

    with pytest.raises(RuntimeError, match="revocation_facts_not_current"):
        asyncio.run(RevocationMonitor(stale, activate).reconcile(("job-1",), occurred_at=NOW))
