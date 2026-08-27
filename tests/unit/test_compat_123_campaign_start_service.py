from __future__ import annotations

import asyncio
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)
from redagent_platform.campaign_service.runtime import (
    LocalCampaignPlanningFactsOwner,
    PolicyBoundCampaignAuthorizationOwner,
)
from redagent_platform.campaign_service.service import (
    CampaignAuthorizationMaterial,
    CampaignPlanningFacts,
    CampaignStartMaterial,
    CampaignStartRequest,
    DeterministicCampaignStartPlanner,
    CampaignStartService,
    binding_from_campaign_context,
)
from redagent_platform.campaign_service.execution import (
    ApprovalTier,
    CapabilityExecutionCeilingV1,
    EffectBudgetV1,
    ExecutableEnvelopeCoreV1,
    ProposalSafetyCeilingV1,
    SafetyObligationsV1,
    build_safety_envelope,
    sign_approval_receipt,
)
from redagent_platform.campaign_service.contracts import StrategyObjectiveKind
from tests.unit.test_compat_121_autonomous_strategy import NOW as R121_NOW, empty_snapshot

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redagent_platform.orchestration.contracts import (
    ClosedLoopCampaignWorkflowInput,
    closed_loop_workflow_request_sha256,
)


NOW = datetime(2026, 8, 24, 1, 30, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


class AuthorityProvider:
    def __init__(self, snapshot: CanonicalAuthoritySnapshot | None) -> None:
        self.snapshot = snapshot
        self.calls: list[ResolutionRequest] = []

    async def read_current_authority(
        self, request: ResolutionRequest
    ) -> CanonicalAuthoritySnapshot | None:
        self.calls.append(request)
        return self.snapshot


class Planner:
    def __init__(self, material: CampaignStartMaterial) -> None:
        self.material = material
        self.calls: list[tuple[CampaignStartRequest, CanonicalAuthoritySnapshot, str]] = []

    async def prepare(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        *,
        campaign_id: str,
        now: datetime,
    ) -> CampaignStartMaterial:
        assert now == NOW
        self.calls.append((request, authority, campaign_id))
        return self.material


class Identities:
    def new_campaign_id(self) -> str:
        return "campaign-server-generated"

    def new_strategy_record_id(self) -> str:
        return "strategy-record-server-generated"


class Store:
    def __init__(self) -> None:
        self.commands = []

    async def start(
        self,
        command,
        *,
        tenant_id: str,
        actor_user_id: str,
        occurred_at: datetime,
    ):
        self.commands.append((command, tenant_id, actor_user_id, occurred_at))
        return command


class FactsOwner:
    async def read(self, request, authority, *, now):
        snapshot, r119_authority, projections = empty_snapshot()
        return CampaignPlanningFacts(snapshot, r119_authority, projections)


class AuthorizationOwner:
    async def authorize(self, request, authority, objective, receipt, plan, *, now):
        allowed = tuple(
            CapabilityExecutionCeilingV1(
                capability_id=item.binding_key.capability_id,
                capability_revision=item.binding_key.capability_revision,
                execution_manifest_sha256=item.binding_key.execution_manifest_sha256,
                adapter_id=item.binding_key.adapter_id,
                adapter_version=item.binding_key.adapter_version,
                profile_id=item.binding_key.profile_id,
                profile_revision=item.binding_key.profile_revision,
                profile_sha256=item.binding_key.profile_sha256,
                bundle_id=item.binding_key.bundle_id,
                bundle_revision=item.binding_key.bundle_revision,
                bundle_sha256=item.binding_key.bundle_sha256,
                semantics_sha256=item.binding_key.semantics_sha256,
                execution_mode="passive-read-only",
                arguments_schema_sha256="a" * 64,
                arguments_ceiling_sha256="b" * 64,
                arguments_max_bytes=4096,
            )
            for item in receipt.snapshot.semantics
        )
        budget = EffectBudgetV1(
            duration_seconds=60,
            request_count=60,
            concurrency=1,
            data_bytes=1024 * 1024,
            evidence_bytes=1024 * 1024,
            impact_count=0,
            replan_count=1,
            plan_depth=2,
        )
        obligations = SafetyObligationsV1(
            evidence_required=True,
            report_safe_evidence_required=True,
            cleanup_required=True,
            compensation_required=True,
            reconciliation_required=True,
            secret_revocation_required=True,
            containment_required=True,
            residual_risk_required=True,
            finding_or_coverage_required=True,
            retest_required=True,
            stop_on_authority_drift=True,
        )
        ceiling = ProposalSafetyCeilingV1(
            schema_version="redagent.r123-proposal-safety-ceiling/v1",
            tenant_id=request.tenant_id,
            engagement_id=request.engagement_id,
            actor_id=request.principal_id,
            workload_identity=authority.runner_workload_identity,
            objective_sha256=receipt.objective_sha256,
            target_revision=authority.target_revision,
            target_sha256=authority.target_sha256,
            target_resolution_mode=authority.target_resolution_mode,
            allowed_capabilities=allowed,
            policy_sha256=authority.policy_sha256,
            policy_revocation_epoch=authority.policy_revocation_epoch,
            roe_sha256=authority.roe_sha256,
            roe_revocation_epoch=authority.roe_revocation_epoch,
            credential_class="none",
            credential_reference_id=None,
            destination=authority.target_value,
            egress_profile="owned-loopback-only",
            sandbox_class="container-non-root-read-only",
            runner_class="owned-loopback-runner",
            risk_ceiling="tier1-passive-read-only",
            budget=budget,
            observation_freshness_seconds=300,
            obligations=obligations,
            approval_tier=ApprovalTier.TIER_1,
            expires_at=now + timedelta(minutes=2),
            nonce="planner-ceiling-nonce",
        )
        core = ExecutableEnvelopeCoreV1(
            schema_version="redagent.r123-executable-envelope-core/v1",
            tenant_id=request.tenant_id,
            proposal_ceiling_sha256=ceiling.proposal_ceiling_sha256,
            plan_sha256=plan.plan_sha256,
            approver_requirement="standing-tier1-owned-loopback",
            workload_identity=authority.runner_workload_identity,
            target_sha256=authority.target_sha256,
            destination=authority.target_value,
            sandbox_class="container-non-root-read-only",
            runner_class="owned-loopback-runner",
            reservation_id=authority.reservation_id,
            lease_id=authority.lease_id,
            arguments_sha256="c" * 64,
            effect_sha256="d" * 64,
            effective_budget=budget,
            policy_revocation_epoch=authority.policy_revocation_epoch,
            roe_revocation_epoch=authority.roe_revocation_epoch,
            issued_at=now,
            expires_at=now + timedelta(minutes=2),
            nonce="planner-envelope-nonce",
        )
        key = Ed25519PrivateKey.generate()
        approval = sign_approval_receipt(
            core,
            key,
            approval_id="approval-planner",
            approval_revision=1,
            approver_id="tier1-standing-owner",
            key_id="planner-approval-key",
            approved_at=now,
            expires_at=now + timedelta(minutes=2),
        )
        return CampaignAuthorizationMaterial(
            ceiling,
            approval,
            build_safety_envelope(core, approval, key.public_key(), now=now),
        )


def _request() -> CampaignStartRequest:
    return CampaignStartRequest(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="eng-r123",
        target_id="target-r123",
        name="Owned loopback posture",
        objective_kind="http_posture",
        header_code=None,
        require_corroboration=False,
        risk_profile="tier1_passive",
    )


def _snapshot() -> CanonicalAuthoritySnapshot:
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="eng-r123",
        engagement_version=1,
        roe_version_id="roe-r123-v1",
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=1,
        policy_decision_id="policy-decision-r123",
        policy_revision="policy-r123-v1",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=1,
        target_id="target-r123",
        target_revision=1,
        target_sha256=_target_digest("target-r123"),
        target_value="http://127.0.0.1:41731",
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-r123",
        quota_available=True,
        runner_id="runner-r123",
        runner_workload_identity="spiffe://redagent.test/runner/r123",
        runner_ready=True,
        reservation_id="reservation-r123",
        lease_id="lease-r123",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )


def _material(**overrides: object) -> CampaignStartMaterial:
    values: dict[str, object] = {
        "tenant_id": "tenant-r123",
        "engagement_id": "eng-r123",
        "target_id": "target-r123",
        "target_sha256": _target_digest("target-r123"),
        "objective_sha256": "4" * 64,
        "context_schema": "redagent.r119-decision-context/v1",
        "context_sha256": "5" * 64,
        "context_payload": {"tenant_id": "tenant-r123", "target_id": "target-r123"},
        "decision_schema": "redagent.r121-strategy-receipt/v1",
        "decision_sha256": "6" * 64,
        "decision_payload": {"outcome": "select", "objective_sha256": "4" * 64},
        "plan_revision_id": "plan-server-generated",
        "plan_revision": 1,
        "plan_sha256": "7" * 64,
        "plan_payload": {"width": 1, "depth": 1},
        "proposal_ceiling_sha256": "8" * 64,
        "approval_receipt_id": "approval-owner-generated",
        "approval_receipt_revision": 1,
        "approval_receipt_sha256": "9" * 64,
        "envelope_core_sha256": "a" * 64,
        "envelope_sha256": "b" * 64,
    }
    values.update(overrides)
    return CampaignStartMaterial(**values)  # type: ignore[arg-type]


def _target_digest(target_id: str) -> str:
    return hashlib.sha256(json.dumps({
        "target_id": target_id,
        "revision": 1,
        "target_type": "url",
        "normalized_value": "http://127.0.0.1:41731",
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_start_request_has_no_runtime_identity_or_idempotency_input() -> None:
    names = {field.name for field in fields(CampaignStartRequest)}
    forbidden = {
        "campaign_id", "plan_id", "strategy_revision_id", "workflow_id", "job_id",
        "evidence_id", "finding_id", "retest_id", "lease_id", "reservation_id",
        "approval_id", "effect_id", "idempotency_key", "adapter_id", "runner_id",
    }
    assert names.isdisjoint(forbidden)


def test_start_resolves_current_authority_generates_identities_and_commits_once() -> None:
    provider = AuthorityProvider(_snapshot())
    planner = Planner(_material())
    store = Store()
    service = CampaignStartService(
        CampaignContextResolver(provider), planner, store, Identities()
    )

    result = asyncio.run(service.start(_request(), now=NOW))

    assert result.campaign_id == "campaign-server-generated"
    assert planner.calls == [(_request(), _snapshot(), "campaign-server-generated")]
    assert len(store.commands) == 1
    command, tenant_id, actor_user_id, occurred_at = store.commands[0]
    assert occurred_at == NOW
    assert tenant_id == _request().tenant_id
    assert actor_user_id == _request().principal_id
    assert command.campaign_id == "campaign-server-generated"
    assert command.strategy_record_id == "strategy-record-server-generated"
    assert command.strategy_revision_id == "plan-server-generated"
    assert command.roe_id == "roe-r123-v1"
    expected = ClosedLoopCampaignWorkflowInput(
        "1.0",
        "tenant-r123",
        "campaign-server-generated",
        "plan-server-generated",
        "b" * 64,
        2,
        1,
        3,
    )
    assert command.workflow_request_sha256 == closed_loop_workflow_request_sha256(expected)


def test_start_denial_or_planning_binding_drift_never_writes() -> None:
    denied_store = Store()
    denied_planner = Planner(_material())
    denied = CampaignStartService(
        CampaignContextResolver(AuthorityProvider(None)),
        denied_planner,
        denied_store,
        Identities(),
    )
    with pytest.raises(RuntimeError, match="campaign_start_denied:canonical_authority_not_found"):
        asyncio.run(denied.start(_request(), now=NOW))
    assert denied_planner.calls == [] and denied_store.commands == []

    drift_store = Store()
    drift = CampaignStartService(
        CampaignContextResolver(AuthorityProvider(_snapshot())),
        Planner(replace(_material(), target_sha256="f" * 64)),
        drift_store,
        Identities(),
    )
    with pytest.raises(ValueError, match="campaign_start_material_authority_mismatch"):
        asyncio.run(drift.start(_request(), now=NOW))
    assert drift_store.commands == []


def test_concrete_planner_runs_canonical_r119_r121_and_envelope_owners() -> None:
    snapshot, r119_authority, _ = empty_snapshot()
    resolver_authority = replace(
        _snapshot(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        roe_version_id="roe-v1",
        roe_sha256="a" * 64,
        policy_decision_id="policy-decision-1",
        policy_revision="policy-v1",
        policy_sha256="b" * 64,
        target_id="target-a",
        target_sha256="a" * 64,
        observed_at=R121_NOW,
        expires_at=R121_NOW + timedelta(minutes=20),
        lease_expires_at=R121_NOW + timedelta(minutes=20),
    )
    request = replace(
        _request(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        target_id="target-a",
    )
    planner = DeterministicCampaignStartPlanner(FactsOwner(), AuthorizationOwner())

    material = asyncio.run(
        planner.prepare(
            request,
            resolver_authority,
            campaign_id="campaign-canonical",
            now=R121_NOW + timedelta(minutes=1),
        )
    )

    assert material.context_sha256 == snapshot.snapshot_sha256
    assert material.plan_payload["primary"]["capability_id"] == "zap-controlled-runtime"
    assert material.decision_payload["outcome"] == "select"
    assert material.context_payload["target_id"] == r119_authority.target.reference_id
    assert len(material.context_payload["bindings"]) == 2
    binding = binding_from_campaign_context(
        material.context_payload, "zap-controlled-runtime"
    )
    assert binding.profile_id == "zap-passive-v1"

    with pytest.raises(ValueError, match="campaign_context_binding_inventory_invalid"):
        binding_from_campaign_context(
            {**material.context_payload, "bindings": material.context_payload["bindings"][:1]},
            "zap-controlled-runtime",
        )


def test_local_concrete_planning_and_policy_authorization_owners_build_bound_material() -> None:
    now = R121_NOW + timedelta(minutes=1)
    authority = replace(
        _snapshot(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        roe_version_id="roe-v1",
        roe_sha256="a" * 64,
        policy_decision_id="policy-decision-1",
        policy_revision="policy-v1",
        policy_sha256="b" * 64,
        target_id="target-a",
        target_sha256="a" * 64,
        observed_at=R121_NOW,
        expires_at=R121_NOW + timedelta(minutes=20),
        lease_expires_at=R121_NOW + timedelta(minutes=20),
    )
    request = replace(
        _request(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        target_id="target-a",
    )
    planner = DeterministicCampaignStartPlanner(
        LocalCampaignPlanningFactsOwner(ROOT),
        PolicyBoundCampaignAuthorizationOwner(
            Ed25519PrivateKey.generate(),
            signing_key_id="r123-policy-boundary-key",
        ),
    )

    material = asyncio.run(
        planner.prepare(request, authority, campaign_id="campaign-concrete", now=now)
    )

    assert material.approval_receipt_id == authority.policy_decision_id
    assert material.context_payload["snapshot"]["collection_state"] == "complete"
    assert {item["capability_id"] for item in material.context_payload["bindings"]} == {
        "zap-controlled-runtime",
        "nuclei-trusted-runtime",
    }


def test_local_planning_owner_rejects_expired_signed_promotions_before_planning() -> None:
    owner = LocalCampaignPlanningFactsOwner(ROOT)
    with pytest.raises(ValueError, match="promotion_expired"):
        asyncio.run(owner.read(_request(), _snapshot(), now=NOW))
