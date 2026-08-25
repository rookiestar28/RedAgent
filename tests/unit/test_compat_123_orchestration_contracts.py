from __future__ import annotations

from dataclasses import fields, replace

import pytest

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    R123CampaignSnapshot,
    R123CampaignWorkflowInput,
    R123ReconcileActivityResult,
    deterministic_r123_campaign_workflow_id,
    r123_workflow_request_sha256,
)
from redagent_platform.orchestration.worker import worker_registration
from redagent_platform.orchestration.workflow import r123_activity_retry_policy


def _request(**overrides: object) -> R123CampaignWorkflowInput:
    values: dict[str, object] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "tenant_id": "tenant-r123",
        "campaign_id": "campaign-r123",
        "strategy_revision_id": "strategy-r123-v1",
        "envelope_sha256": "1" * 64,
        "max_depth": 2,
        "max_replan_count": 1,
        "max_activity_attempts": 3,
    }
    values.update(overrides)
    return R123CampaignWorkflowInput(**values)  # type: ignore[arg-type]


def test_r123_workflow_input_is_metadata_only_versioned_and_bounded() -> None:
    request = _request()

    assert {field.name for field in fields(request)} == {
        "schema_version",
        "tenant_id",
        "campaign_id",
        "strategy_revision_id",
        "envelope_sha256",
        "max_depth",
        "max_replan_count",
        "max_activity_attempts",
    }
    assert all(field.type not in (dict, object) for field in fields(request))
    assert r123_workflow_request_sha256(request) == r123_workflow_request_sha256(request)
    assert r123_workflow_request_sha256(request) != r123_workflow_request_sha256(
        replace(request, envelope_sha256="2" * 64)
    )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"max_depth": 0}, "r123_max_depth_invalid"),
        ({"max_depth": 3}, "r123_max_depth_invalid"),
        ({"max_replan_count": 2}, "r123_max_replan_count_invalid"),
        ({"max_activity_attempts": 6}, "activity_attempts_invalid"),
        ({"envelope_sha256": "not-a-hash"}, "r123_envelope_sha256_invalid"),
    ],
)
def test_r123_workflow_input_rejects_unbounded_or_unbound_values(
    overrides: dict[str, object], reason: str
) -> None:
    with pytest.raises(ValueError, match=reason):
        _request(**overrides)


def test_r123_deterministic_workflow_id_is_stable_non_disclosing_and_distinct_from_r096() -> None:
    first = deterministic_r123_campaign_workflow_id("tenant-r123", "campaign-r123")
    second = deterministic_r123_campaign_workflow_id("tenant-r123", "campaign-r123")
    other = deterministic_r123_campaign_workflow_id("tenant-r124", "campaign-r123")

    assert first == second
    assert first != other
    assert first.startswith("redagent-r123-")
    assert "tenant-r123" not in first and "campaign-r123" not in first
    assert len(first) <= 64


def test_r123_reconcile_result_has_closed_six_outcomes_and_terminal_shape() -> None:
    base = dict(
        schema_version=CONTRACT_SCHEMA_VERSION,
        campaign_id="campaign-r123",
        strategy_revision_id="strategy-r123-v1",
        revision=2,
        depth=1,
        replan_count=0,
        node_id="node-zap",
        effect_id="effect-zap",
        reason="effect_reserved",
    )
    for outcome in (
        "settled",
        "dispatch_once",
        "retry_at",
        "blocked",
        "contained",
        "terminal_failure",
    ):
        result = R123ReconcileActivityResult(
            **base,
            outcome=outcome,
            terminal=outcome in {"settled", "blocked", "contained", "terminal_failure"},
            retry_delay_seconds=1 if outcome == "retry_at" else None,
        )
        assert result.outcome == outcome

    with pytest.raises(ValueError, match="r123_reconcile_outcome_invalid"):
        R123ReconcileActivityResult(
            **base, outcome="dispatch_many", terminal=False, retry_delay_seconds=None
        )
    with pytest.raises(ValueError, match="r123_retry_delay_required"):
        R123ReconcileActivityResult(
            **base, outcome="retry_at", terminal=False, retry_delay_seconds=None
        )


def test_worker_registration_adds_r123_without_changing_r096_names() -> None:
    registration = worker_registration()

    assert registration.workflow_names[:2] == (
        "redagent.r096.job-lifecycle.v1",
        "redagent.r096.campaign-lifecycle.v1",
    )
    assert registration.workflow_names[2:] == ("redagent.r123.campaign-closed-loop.v1",)
    assert registration.activity_names[:6] == (
        "r096_admit_job",
        "r096_apply_command",
        "r096_record_system_state",
        "r096_admit_campaign",
        "r100_dispatch_synthetic_job",
        "r101_contain_synthetic_job",
    )
    assert registration.activity_names[6:] == (
        "redagent.r123.reconcile-level.v1",
        "redagent.r123.dispatch-effect.v1",
        "redagent.r123.contain.v1",
    )


def test_r123_retry_policy_adds_only_its_versioned_permanent_failures() -> None:
    policy = r123_activity_retry_policy(3)

    assert set(policy.non_retryable_error_types or ()) == {
        "AuthorizationDenied",
        "InvalidWorkflowInput",
        "PolicyDenied",
        "ScopeDenied",
        "UnsupportedCapability",
        "WorkflowVersionConflict",
        "ExecutionDisabled",
        "DispatchDenied",
    }


def test_r123_snapshot_never_contains_executable_arguments_or_authority_payloads() -> None:
    snapshot = R123CampaignSnapshot(
        schema_version=CONTRACT_SCHEMA_VERSION,
        campaign_id="campaign-r123",
        strategy_revision_id="strategy-r123-v1",
        workflow_request_sha256="3" * 64,
        state="running",
        revision=1,
        depth=0,
        replan_count=0,
        current_node_id=None,
        terminal_reason=None,
        stop_requested=False,
    )
    assert {field.name for field in fields(snapshot)} == {
        "schema_version",
        "campaign_id",
        "strategy_revision_id",
        "workflow_request_sha256",
        "state",
        "revision",
        "depth",
        "replan_count",
        "current_node_id",
        "terminal_reason",
        "stop_requested",
    }
