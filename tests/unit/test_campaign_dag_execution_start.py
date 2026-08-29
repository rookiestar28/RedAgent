from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    CampaignBudgetVectorV1,
    PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionMode,
    DagExecutionSnapshotV1,
    DagRunState,
)
from redagent_platform.campaign_service.dag_execution_service import (
    DagExecutionStartRequestV1,
    DagExecutionStartService,
)
from redagent_platform.campaign_service.planning.contracts import (
    CapabilityIdentityV1,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.campaign_service.registry import closed_execution_registry
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import (
    NOW,
    authority,
    domain,
    limits,
    operator,
    world,
)


def _admitted_inputs(capability_key: str = "zap-controlled-runtime@2"):
    binding = closed_execution_registry()[capability_key]
    capability = CapabilityIdentityV1(
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        execution_manifest_sha256="1" * 64,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
    )
    current_domain = domain(operators=(replace(operator(), capability=capability),))
    current_authority = authority(capability_ids=(binding.capability_id,))
    result = plan_attack_path(current_domain, current_authority, world(), search_limits())
    assert result.revision is not None
    certificate = validate_candidate_plan(
        result.revision.candidate_plan,
        current_domain,
        current_authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=20),
    )
    receipt = PlanAdmissionReceiptV1(
        schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
        receipt_id="receipt-a",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        engagement_id="engagement-a",
        signed_authority_sha256="2" * 64,
        authority_sha256=current_authority.authority_sha256,
        domain_sha256=current_domain.domain_sha256,
        plan_sha256=result.revision.candidate_plan.plan_sha256,
        certificate_sha256=certificate.certificate_sha256,
        validator_version=certificate.validator_version,
        validator_sha256=certificate.validator_sha256,
        subset_proof_sha256="3" * 64,
        policy_decision_id="decision-a",
        policy_input_sha256="4" * 64,
        policy_bundle_revision="policy-a",
        policy_bundle_sha256="5" * 64,
        pre_residual_budget_sha256="6" * 64,
        post_residual_budget_sha256="7" * 64,
        reserved_budget=CampaignBudgetVectorV1(
            duration_seconds=10,
            requests=1,
            rate_per_minute=1,
            concurrency=1,
            risk_micropoints=10,
            cost_microunits=100,
            evidence_bytes=1_024,
            data_bytes=512,
        ),
        reservation_id="reservation-a",
        idempotency_key="admission-a",
        request_sha256="8" * 64,
        lifecycle_epoch=1,
        policy_revocation_epoch=2,
        roe_revocation_epoch=3,
        kill_switch_epoch=4,
        issued_at=NOW + timedelta(seconds=30),
        expires_at=NOW + timedelta(seconds=55),
        outcome=AdmissionOutcome.ADMITTED,
        denial_stage=None,
        reason_code="admitted",
        audit_id="audit-a",
        outbox_id="outbox-a",
    )
    return current_domain, result.revision, certificate, receipt


class Store:
    def __init__(self) -> None:
        self.materials = []

    async def start(self, material, *, now):
        self.materials.append((material, now))
        return DagExecutionSnapshotV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            execution_run_id=material.execution_run_id,
            workflow_request_sha256=material.workflow_request_sha256,
            state=DagRunState.START_PENDING,
            revision=1,
            transition_count=0,
            current_node_id=material.nodes[0].node_id,
            current_node_state=material.nodes[0].node_state,
            stop_requested=False,
            terminal_reason=None,
        )


def _request(**changes):
    capability_key = changes.pop("_capability_key", "zap-controlled-runtime@2")
    current_domain, revision, certificate, receipt = _admitted_inputs(capability_key)
    values = {
        "tenant_id": "tenant-a",
        "principal_id": "principal-a",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-a",
        "execution_id": "execution-a",
        "idempotency_key": "dag-start-a",
        "revision": revision,
        "domain": current_domain,
        "certificate": certificate,
        "admission_receipt": receipt,
        "max_activity_attempts": 2,
        "max_transitions": 16,
    }
    values.update(changes)
    return DagExecutionStartRequestV1(**values)


def test_start_material_is_canonical_admission_bound_and_outbox_only() -> None:
    store = Store()
    snapshot = asyncio.run(
        DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, store).start(
            _request(), now=NOW + timedelta(seconds=40)
        )
    )

    assert snapshot.state is DagRunState.START_PENDING
    material, occurred_at = store.materials[0]
    assert occurred_at == NOW + timedelta(seconds=40)
    assert material.workflow_id.startswith("redagent-campaign-dag-v1-")
    assert len(material.input_sha256) == len(material.workflow_request_sha256) == 64
    assert material.run_state is DagRunState.START_PENDING
    assert material.nodes[0].capability_id == "zap-controlled-runtime"
    assert material.nodes[0].node_state.value == "pending"
    assert material.outbox_event_type == "campaign.dag.start.requested.v1"
    assert material.reserved_budget_sha256 == _request().admission_receipt.reserved_budget.budget_sha256


@pytest.mark.parametrize(
    "request_change, now, message",
    (
        ({"campaign_id": "campaign-b"}, NOW + timedelta(seconds=40), "dag_start_admission_binding_mismatch"),
        ({}, NOW + timedelta(seconds=56), "dag_start_admission_expired"),
    ),
)
def test_start_denies_substitution_or_expiry_before_store(request_change, now, message) -> None:
    store = Store()
    with pytest.raises(ValueError, match=message):
        asyncio.run(
            DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, store).start(
                _request(**request_change), now=now
            )
        )
    assert store.materials == []


def test_disabled_mode_and_unregistered_capability_never_reach_store() -> None:
    store = Store()
    with pytest.raises(RuntimeError, match="dag_execution_disabled"):
        asyncio.run(
            DagExecutionStartService(DagExecutionMode.DISABLED, store).start(
                _request(), now=NOW + timedelta(seconds=40)
            )
        )
    with pytest.raises(ValueError, match="dag_start_capability_not_closed"):
        asyncio.run(
            DagExecutionStartService(DagExecutionMode.OWNED_LOOPBACK, store).start(
                _request(_capability_key="artifact-posture@1"),
                now=NOW + timedelta(seconds=40),
            )
        )
    assert store.materials == []
