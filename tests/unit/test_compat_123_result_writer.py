from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.runner_service.campaign_dispatch import CampaignAdapterRequest
from redagent_platform.runner_service.campaign_result import (
    AdapterResultMaterialV1,
    PostgresAdapterResultWriter,
    _advance_retests,
)


class _Dependency:
    pass


class _Result:
    def __init__(self, values):
        self._values = values

    def mappings(self):
        return self

    def scalars(self):
        return self

    def all(self):
        return self._values


class _RetestSession:
    def __init__(self, *, successor: bool = True) -> None:
        rows = [
            {
                "effect_id": "effect-primary",
                "external_receipt_id": "execution-primary",
            }
        ]
        if successor:
            rows.append(
                {
                    "effect_id": "effect-successor",
                    "external_receipt_id": None,
                }
            )
        self._results = [_Result(rows)]

    async def execute(self, statement):
        return self._results.pop(0)

    async def scalar(self, statement):
        return None


class _RetestRepository:
    def __init__(self) -> None:
        self.completed = []
        self.requested = []

    async def request_retest(self, **values):
        self.requested.append(values)

    async def complete_retest(self, **values):
        self.completed.append(values)


def _request(capability_key: str = "nuclei-trusted-runtime@3") -> CampaignAdapterRequest:
    binding = closed_execution_registry()[capability_key]
    suffix = "successor" if capability_key.startswith("nuclei") else "primary"
    return CampaignAdapterRequest(
        tenant_id="tenant-r123",
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
        invocation_id=f"invocation-{suffix}",
        effect_id=f"effect-{suffix}",
        envelope_sha256="a" * 64,
        manifest_v2_sha256="b" * 64,
    )


def test_result_writer_rejects_actor_identifier_that_cannot_fit_evidence_owner() -> None:
    with pytest.raises(ValueError, match="r123_result_writer_config_invalid"):
        PostgresAdapterResultWriter(
            _Dependency(),
            _Dependency(),
            actor_user_id="a" * 65,
            kms_reference="kms:r123:test",
        )


def test_result_material_preserves_canonical_partial_coverage_for_successor_decision() -> None:
    material = AdapterResultMaterialV1(
        request=_request("zap-controlled-runtime@3"),
        report_safe_content=b'{"schema":"redagent.r123-result/v1"}',
        findings=(),
        coverage_state=CoverageState.PARTIAL,
        cleanup_receipt_id="cleanup-primary",
        observed_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )

    assert material.coverage_state is CoverageState.PARTIAL


def test_successor_result_never_fabricates_a_passed_retest_for_primary_findings() -> None:
    session = _RetestSession()
    repository = _RetestRepository()

    asyncio.run(
        _advance_retests(
            session,
            repository,
            request=_request(),
            campaign_id="campaign-r123",
            execution_id="execution-successor",
            issue_ids=(),
            occurred_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )
    )

    assert repository.completed == []


def test_primary_result_requests_retest_through_r115_owner_for_each_imported_issue() -> None:
    session = _RetestSession(successor=False)
    repository = _RetestRepository()

    asyncio.run(
        _advance_retests(
            session,
            repository,
            request=_request("zap-controlled-runtime@3"),
            campaign_id="campaign-r123",
            execution_id="execution-primary",
            issue_ids=("issue-r123",),
            occurred_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )
    )

    assert len(repository.requested) == 1
    assert repository.requested[0]["issue_id"] == "issue-r123"
    assert repository.requested[0]["baseline_run_id"] == "execution-primary"
    assert repository.completed == []
