from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from redagent_platform.campaign_service.operations import (
    CampaignOperationsProjectionInvalid,
    CampaignOperationsSource,
    project_campaign_operations,
)


NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def test_operations_projection_exposes_bound_server_truth_without_raw_operator_ids() -> None:
    projected = project_campaign_operations(_source(), now=NOW)

    assert projected["schema_version"] == "redagent.campaign-operations/v1"
    assert projected["preparation_state"] == "executing"
    assert projected["authority"] == {
        "state": "admitted",
        "signed_authority_sha256": "a" * 64,
        "authority_sha256": "b" * 64,
        "lifecycle_epoch": 4,
        "policy_revocation_epoch": 2,
        "roe_revocation_epoch": 1,
        "kill_switch_epoch": 0,
        "expires_at": "2026-08-29T13:00:00+00:00",
    }
    assert projected["validation"]["result"] == "valid"
    assert projected["admission"]["outcome"] == "admitted"
    assert projected["plan"]["nodes"] == [
        {
            "label": "Step 1",
            "capability": "HTTP posture",
            "state": "running",
            "order": 0,
        }
    ]
    assert projected["budget"]["dimensions"]["requests"] == {
        "authorized": 100,
        "committed": 25,
        "residual": 75,
        "unit": "requests",
    }
    assert projected["revisions"][0]["invalidated_count"] == 1
    assert projected["revisions"][0]["retained_count"] == 1
    assert projected["revisions"][0]["substitution_count"] == 1
    assert projected["evidence"]["evidence_count"] == 2
    assert projected["evidence"]["cleanup_state"] == "complete"
    assert projected["evidence"]["export_state"] == "unavailable_without_verified_bundle"
    serialized = json.dumps(projected, sort_keys=True)
    assert "operator-internal" not in serialized
    assert "secret-detail" not in serialized
    assert "target-internal" not in serialized


def test_operations_projection_marks_legacy_campaign_not_prepared_without_inference() -> None:
    projected = project_campaign_operations(
        CampaignOperationsSource(campaign={"id": "campaign-a", "version": 2}),
        now=NOW,
    )

    assert projected["preparation_state"] == "not_prepared"
    assert projected["authority"]["state"] == "unavailable"
    assert projected["validation"]["result"] == "unavailable"
    assert projected["admission"]["outcome"] == "unavailable"
    assert projected["execution"]["state"] == "unavailable"
    assert projected["evidence"]["export_state"] == "unavailable_without_verified_bundle"


def test_operations_projection_fails_closed_on_unbounded_or_malformed_stored_json() -> None:
    source = _source()
    oversized_nodes = tuple({**source.nodes[0], "node_id": f"node-{index}"} for index in range(101))
    with pytest.raises(CampaignOperationsProjectionInvalid, match="operations_nodes_unbounded"):
        project_campaign_operations(
            replace(source, nodes=oversized_nodes),
            now=NOW,
        )

    malformed = dict(source.execution)
    malformed["input_payload"] = {"revision": {"candidate_plan": {"nodes": "not-a-list"}}}
    with pytest.raises(CampaignOperationsProjectionInvalid, match="operations_plan_nodes_invalid"):
        project_campaign_operations(
            replace(source, execution=malformed),
            now=NOW,
        )

    malformed_effect = dict(source.effects[0])
    malformed_effect["evidence_ids"] = "not-a-list"
    with pytest.raises(CampaignOperationsProjectionInvalid, match="operations_effect_evidence_invalid"):
        project_campaign_operations(
            replace(source, effects=(malformed_effect,)),
            now=NOW,
        )

    malformed_node = dict(source.nodes[0])
    malformed_node["node_state"] = None
    with pytest.raises(CampaignOperationsProjectionInvalid, match="operations_node_state_invalid"):
        project_campaign_operations(
            replace(source, nodes=(malformed_node,)),
            now=NOW,
        )

    malformed_campaign = CampaignOperationsSource(campaign=[])
    with pytest.raises(CampaignOperationsProjectionInvalid, match="operations_campaign_row_invalid"):
        project_campaign_operations(malformed_campaign, now=NOW)


def _source() -> CampaignOperationsSource:
    budget = {
        "duration_seconds": 3600,
        "requests": 100,
        "rate_per_minute": 20,
        "concurrency": 2,
        "risk_micropoints": 1_000,
        "cost_microunits": 2_000,
        "evidence_bytes": 4_096,
        "data_bytes": 8_192,
    }
    reservation = {name: value // 4 for name, value in budget.items()}
    proposal_payload = {
        "invalidated_parent_node_ids": ["node-old"],
        "retained_parent_node_ids": ["node-stable"],
        "substitutions": [
            {
                "parent_node_id": "node-old",
                "child_node_id": "node-new",
                "reason_code": "trusted_observation",
            }
        ],
        "child_revision": {"revision_id": "revision-child"},
    }
    return CampaignOperationsSource(
        campaign={"id": "campaign-a", "version": 7},
        admission={
            "outcome": "admitted",
            "reason_code": "admitted",
            "receipt_sha256": "c" * 64,
            "receipt_payload": {
                "signed_authority_sha256": "a" * 64,
                "authority_sha256": "b" * 64,
                "certificate_sha256": "d" * 64,
                "lifecycle_epoch": 4,
                "policy_revocation_epoch": 2,
                "roe_revocation_epoch": 1,
                "kill_switch_epoch": 0,
                "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            },
        },
        ledger=budget,
        reservations=({"reservation_state": "reserved", **reservation},),
        execution={
            "run_state": "running",
            "transition_count": 3,
            "max_transitions": 20,
            "stop_requested": False,
            "terminal_reason": None,
            "authority_sha256": "b" * 64,
            "signed_authority_sha256": "a" * 64,
            "lifecycle_epoch": 4,
            "policy_revocation_epoch": 2,
            "roe_revocation_epoch": 1,
            "kill_switch_epoch": 0,
            "input_payload": {
                "revision": {
                    "revision_id": "revision-initial",
                    "parent_revision_id": None,
                    "candidate_plan": {
                        "nodes": [
                            {
                                "node_id": "node-internal",
                                "operator_id": "http-posture",
                                "target_id": "target-internal",
                                "order": 0,
                            }
                        ],
                        "edges": [],
                    },
                },
                "certificate": {
                    "result": "valid",
                    "counterexamples": [],
                    "bounded_reason": None,
                },
            },
        },
        nodes=(
            {
                "node_id": "node-internal",
                "node_order": 0,
                "capability_id": "http-posture",
                "node_state": "running",
            },
        ),
        observations=(
            {
                "fact_id": "http_header_present",
                "producer_kind": "dag_runner_result",
                "observation_sha256": "e" * 64,
                "provenance_sha256": "f" * 64,
                "observed_at": NOW,
                "expires_at": NOW + timedelta(minutes=10),
                "producer_id": "operator-internal",
            },
        ),
        proposals=(
            {
                "proposal_sha256": "1" * 64,
                "replan_sequence": 1,
                "proposal_payload": proposal_payload,
                "accepted": False,
            },
        ),
        audits=(
            {
                "action": "campaign.dag.start.requested",
                "created_at": NOW,
                "correlation_id": "corr-safe",
                "details": {"plan_sha256": "2" * 64, "secret": "secret-detail"},
                "actor_user_id": "operator-internal",
            },
        ),
        effects=(
            {
                "effect_state": "confirmed",
                "reconciliation_state": "confirmed",
                "evidence_ids": ["evidence-a", "evidence-b"],
                "cleanup_receipt_id": "cleanup-a",
            },
        ),
    )
