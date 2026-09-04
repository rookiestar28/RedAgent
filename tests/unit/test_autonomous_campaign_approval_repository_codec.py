from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.application_contracts import ApplicationBindingConflict
from redagent_platform.campaign_service.application_repository import (
    _approval_decision_result_from_payload,
    _approval_decision_result_payload,
    _json_payload,
    _plan_preview_result_from_payload,
    _plan_preview_result_payload,
    _preview_from_payload,
    _receipt_from_payload,
    _verified_preview_from_payload,
)
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_APPROVE_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
)
from tests.unit.test_autonomous_campaign_plan_approval import (
    Repository,
    _service,
    _stage_command,
)


def test_preview_and_decision_persistence_codecs_round_trip_exact_contracts() -> None:
    stage, key = _stage_command()
    repository = Repository()
    service = _service(repository, stage, key)
    staged = asyncio.run(service.stage_plan(stage))

    assert _preview_from_payload(_json_payload(staged.preview)) == staged.preview
    assert _plan_preview_result_from_payload(
        _plan_preview_result_payload(staged),
        replayed=True,
    ).preview == staged.preview

    approved = asyncio.run(
        service.approve_plan(
            ApproveAutonomousCampaignPlanV1(
                schema_version=PLAN_APPROVE_SCHEMA_VERSION,
                tenant_id=stage.tenant_id,
                campaign_id=stage.campaign_id,
                preview_id=staged.preview.preview_id,
                preview_sha256=staged.preview.preview_sha256,
                actor_user_id="approver-a",
                actor_permissions=("campaign:approve",),
                policy_reference="policy:r172:approval",
                expected_revision=staged.application.aggregate_revision,
                idempotency_key="codec-approval-a",
                correlation_id="codec-correlation-a",
                occurred_at=stage.occurred_at + timedelta(seconds=1),
            )
        )
    )
    assert _receipt_from_payload(_json_payload(approved.receipt)) == approved.receipt
    replayed = _approval_decision_result_from_payload(
        _approval_decision_result_payload(approved),
        replayed=True,
    )
    assert replayed.receipt == approved.receipt
    assert replayed.application == approved.application
    assert replayed.replayed is True


def test_preview_persistence_codec_verifies_the_stored_digest() -> None:
    stage, key = _stage_command()
    staged = asyncio.run(_service(Repository(), stage, key).stage_plan(stage))
    payload = _json_payload(staged.preview)

    assert _verified_preview_from_payload(payload, staged.preview.preview_sha256) == staged.preview
    payload["objective_id"] = "tampered-objective"
    with pytest.raises(ApplicationBindingConflict, match="plan_preview_persistence_digest_mismatch"):
        _verified_preview_from_payload(payload, staged.preview.preview_sha256)
