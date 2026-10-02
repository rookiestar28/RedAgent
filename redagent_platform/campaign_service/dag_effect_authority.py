"""Fresh, fail-closed authority gate for one admitted DAG effect."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
from typing import Protocol

from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    ResolutionRequest,
)
from redagent_platform.campaign_service.service import (
    AuthorityRecheck,
    EffectDispatchCommand,
)
from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EFFECT_STATES = frozenset({"reserved", "claimed", "dispatching"})


@dataclass(frozen=True, slots=True, kw_only=True)
class DagAuthorityMaterialV1:
    tenant_id: str
    principal_id: str
    campaign_id: str
    engagement_id: str
    execution_run_id: str
    node_id: str
    node_sha256: str
    target_id: str
    effect_id: str
    effect_intent_sha256: str
    envelope_sha256: str
    authority_sha256: str
    policy_bundle_revision: str
    policy_bundle_sha256: str
    domain_sha256: str
    plan_sha256: str
    certificate_sha256: str
    subset_proof_sha256: str
    admission_receipt_sha256: str
    post_residual_budget_sha256: str
    reserved_budget_sha256: str
    reservation_id: str
    reservation_state: str
    reservation_lease_expires_at: datetime
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    capability_id: str
    effect_class: str
    data_access_class: str
    credential_class: str
    environment_class: str
    rate_limit: int
    rate_claimed_requests: int
    concurrency_limit: int
    active_concurrency: int
    run_state: DagRunState
    node_state: DagNodeState
    effect_state: str

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "principal_id",
            "campaign_id",
            "engagement_id",
            "execution_run_id",
            "node_id",
            "target_id",
            "effect_id",
            "policy_bundle_revision",
            "reservation_id",
            "reservation_state",
            "capability_id",
            "effect_class",
            "data_access_class",
            "credential_class",
            "environment_class",
            "effect_state",
        ):
            _identifier(f"dag_authority_{name}", getattr(self, name))
        for name in (
            "node_sha256",
            "effect_intent_sha256",
            "envelope_sha256",
            "authority_sha256",
            "policy_bundle_sha256",
            "domain_sha256",
            "plan_sha256",
            "certificate_sha256",
            "subset_proof_sha256",
            "admission_receipt_sha256",
            "post_residual_budget_sha256",
            "reserved_budget_sha256",
        ):
            _digest(f"dag_authority_{name}", getattr(self, name))
        _aware("dag_authority_reservation_expiry", self.reservation_lease_expires_at)
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
            "rate_limit",
            "rate_claimed_requests",
            "concurrency_limit",
            "active_concurrency",
        ):
            _bounded(f"dag_authority_{name}", getattr(self, name), 0, 2_147_483_647)
        if self.rate_limit < 1 or self.concurrency_limit < 1:
            raise ValueError("dag_authority_limit_invalid")
        if not isinstance(self.run_state, DagRunState) or not isinstance(
            self.node_state, DagNodeState
        ):
            raise ValueError("dag_authority_state_invalid")
        if self.effect_state not in _EFFECT_STATES:
            raise ValueError("dag_authority_effect_state_invalid")


class DagEffectAuthorityStateOwner(Protocol):
    async def read(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> DagAuthorityMaterialV1: ...

    async def observe_lifecycle(
        self,
        material: DagAuthorityMaterialV1,
        lifecycle: CampaignAuthorityLifecycleV2,
        *,
        now: datetime,
    ) -> None: ...

    async def commit_pre_io(
        self,
        material: DagAuthorityMaterialV1,
        *,
        decision: PolicyDecision,
        request: PolicyDecisionInput,
        runner_binding_sha256: str,
        now: datetime,
    ) -> None: ...


class DagLifecycleOwner(Protocol):
    async def read_current_lifecycle(
        self, *, tenant_id: str, authority_sha256: str
    ) -> CampaignAuthorityLifecycleV2 | None: ...


class DagPolicyOwner(Protocol):
    async def decide(
        self, request: PolicyDecisionInput, *, now: datetime
    ) -> PolicyDecision: ...


class DagEffectAuthorityGate:
    def __init__(
        self,
        state: DagEffectAuthorityStateOwner,
        resolver: CampaignContextResolver,
        lifecycle: DagLifecycleOwner,
        policy: DagPolicyOwner,
    ) -> None:
        self._state = state
        self._resolver = resolver
        self._lifecycle = lifecycle
        self._policy = policy

    async def recheck(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> AuthorityRecheck:
        if not isinstance(command, EffectDispatchCommand):
            raise ValueError("dag_authority_command_invalid")
        _aware("dag_authority_now", now)
        from redagent_platform.campaign_service.owned_execution import OwnedExecutionDenied

        try:
            material = await self._state.read(command, now=now)
        except OwnedExecutionDenied as exc:
            return _deny(str(exc))
        binding_reason = _command_reason(material, command)
        if binding_reason is not None:
            return _deny(binding_reason)
        if material.run_state is not DagRunState.RUNNING:
            return _deny("execution_not_running")
        if material.node_state not in {
            DagNodeState.RESERVED,
            DagNodeState.CLAIMED,
            DagNodeState.DISPATCHING,
        }:
            return _deny("node_not_dispatchable")
        if material.reservation_state not in {"reserved", "held"}:
            return _deny("reservation_not_active")
        if now >= material.reservation_lease_expires_at:
            return _deny("reservation_expired")
        if material.rate_claimed_requests >= material.rate_limit:
            return _deny("rate_limit_exhausted")
        if material.active_concurrency >= material.concurrency_limit:
            return _deny("concurrency_limit_exhausted")

        resolved = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=material.tenant_id,
                principal_id=material.principal_id,
                engagement_id=material.engagement_id,
                target_id=material.target_id,
            ),
            now=now,
        )
        snapshot = resolved.bindings
        if not resolved.allowed or snapshot is None:
            return _deny(resolved.reason)
        if (
            snapshot.tenant_id != material.tenant_id
            or snapshot.principal_id != material.principal_id
            or snapshot.engagement_id != material.engagement_id
            or snapshot.target_id != material.target_id
            or snapshot.policy_revision != material.policy_bundle_revision
            or snapshot.policy_sha256 != material.policy_bundle_sha256
            or snapshot.policy_revocation_epoch != material.policy_revocation_epoch
            or snapshot.roe_revocation_epoch != material.roe_revocation_epoch
            or snapshot.reservation_id != material.reservation_id
            or snapshot.lease_expires_at < material.reservation_lease_expires_at
            or snapshot.expires_at <= now
            or snapshot.stop_requested
        ):
            return _deny("resolver_binding_drift")

        lifecycle = await self._lifecycle.read_current_lifecycle(
            tenant_id=material.tenant_id,
            authority_sha256=material.authority_sha256,
        )
        if lifecycle is not None and (
            lifecycle.tenant_id == material.tenant_id
            and lifecycle.engagement_id == material.engagement_id
            and lifecycle.authority_sha256 == material.authority_sha256
        ):
            await self._state.observe_lifecycle(material, lifecycle, now=now)
        lifecycle_reason = _lifecycle_reason(material, lifecycle, now=now)
        if lifecycle_reason is not None:
            return _deny(lifecycle_reason)
        assert lifecycle is not None

        runner_binding_sha256 = hashlib.sha256(
            (
                f"{snapshot.runner_id}\0{snapshot.runner_workload_identity}\0"
                f"{snapshot.target_sha256}\0{snapshot.policy_sha256}"
            ).encode("utf-8")
        ).hexdigest()
        request = _policy_request(
            material,
            command,
            lifecycle,
            runner_binding_sha256=runner_binding_sha256,
            roe_version_id=snapshot.roe_version_id,
            now=now,
        )
        try:
            decision = await self._policy.decide(request, now=now)
        except Exception:  # noqa: BLE001
            return _deny("policy_unavailable")
        if not isinstance(decision, PolicyDecision):
            return _deny("policy_malformed")
        try:
            decision.assert_current(
                request, required_revision=material.policy_bundle_revision, now=now
            )
        except ValueError:
            return _deny("policy_stale")
        if not decision.allowed:
            return _deny(decision.reason_code)
        if not {
            PolicyObligation.AUDIT,
            PolicyObligation.REQUIRE_EXPECTED_VERSION,
        } <= set(decision.obligations):
            return _deny("policy_obligations_incomplete")

        if material.effect_state == "dispatching":
            # CRITICAL: this locked commit is the final current-policy fact; dispatcher I/O is next.
            try:
                await self._state.commit_pre_io(
                    material,
                    decision=decision,
                    request=request,
                    runner_binding_sha256=runner_binding_sha256,
                    now=now,
                )
            except OwnedExecutionDenied as exc:
                return _deny(str(exc))
        return AuthorityRecheck(
            True,
            "allowed",
            snapshot.runner_id,
            snapshot.runner_workload_identity,
            policy_decision_id=decision.decision_id,
            policy_bundle_revision=decision.bundle_revision,
            policy_input_sha256=policy_input_hash(request),
            policy_valid_until=decision.valid_until,
        )


def _command_reason(
    material: DagAuthorityMaterialV1, command: EffectDispatchCommand
) -> str | None:
    if (
        material.tenant_id != command.tenant_id
        or material.principal_id != command.principal_id
        or material.engagement_id != command.engagement_id
        or material.target_id != command.target_id
        or material.effect_id != command.effect_id
        or material.effect_intent_sha256 != command.effect_intent_sha256
        or material.envelope_sha256 != command.envelope_sha256
        or material.capability_id != command.binding.capability_id
    ):
        return "effect_command_binding_mismatch"
    return None


def _lifecycle_reason(
    material: DagAuthorityMaterialV1,
    lifecycle: CampaignAuthorityLifecycleV2 | None,
    *,
    now: datetime,
) -> str | None:
    if lifecycle is None:
        return "lifecycle_unavailable"
    if (
        lifecycle.tenant_id != material.tenant_id
        or lifecycle.engagement_id != material.engagement_id
        or lifecycle.authority_sha256 != material.authority_sha256
    ):
        return "lifecycle_binding_mismatch"
    if lifecycle.state is not CampaignAuthorityLifecycleState.ACTIVE:
        return "lifecycle_inactive"
    for name in (
        "lifecycle_epoch",
        "policy_revocation_epoch",
        "roe_revocation_epoch",
        "kill_switch_epoch",
    ):
        if getattr(lifecycle, name) != getattr(material, name):
            return f"{name}_drift"
    if not lifecycle.observed_at <= now < lifecycle.valid_until:
        return "lifecycle_stale"
    return None


def _policy_request(
    material: DagAuthorityMaterialV1,
    command: EffectDispatchCommand,
    lifecycle: CampaignAuthorityLifecycleV2,
    *,
    runner_binding_sha256: str,
    roe_version_id: str,
    now: datetime,
) -> PolicyDecisionInput:
    attributes = {
        "campaign_authority_sha256": material.authority_sha256,
        "campaign_policy_bundle_sha256": material.policy_bundle_sha256,
        "campaign_domain_sha256": material.domain_sha256,
        "campaign_plan_sha256": material.plan_sha256,
        "campaign_certificate_sha256": material.certificate_sha256,
        "campaign_subset_proof_sha256": material.subset_proof_sha256,
        "campaign_capability_id": material.capability_id,
        "campaign_credential_class": material.credential_class,
        "campaign_data_access_class": material.data_access_class,
        "campaign_effect_class": material.effect_class,
        "campaign_environment_class": material.environment_class,
        "campaign_kill_switch_epoch": lifecycle.kill_switch_epoch,
        "campaign_policy_revocation_epoch": lifecycle.policy_revocation_epoch,
        "campaign_roe_revocation_epoch": lifecycle.roe_revocation_epoch,
        "campaign_lifecycle_epoch": lifecycle.lifecycle_epoch,
        "campaign_lifecycle_state": lifecycle.state.value,
        "campaign_residual_budget_sha256": material.post_residual_budget_sha256,
        "campaign_target_id": material.target_id,
        "campaign_admission_receipt_sha256": material.admission_receipt_sha256,
        "campaign_reservation_id": material.reservation_id,
        "campaign_reserved_budget_sha256": material.reserved_budget_sha256,
        "campaign_node_id": material.node_id,
        "campaign_node_sha256": material.node_sha256,
        "campaign_effect_intent_sha256": material.effect_intent_sha256,
        "campaign_rate_claimed_requests": material.rate_claimed_requests,
        "campaign_active_concurrency": material.active_concurrency,
        "campaign_reservation_state": material.reservation_state,
        "campaign_reservation_lease_expires_at": material.reservation_lease_expires_at.isoformat().replace(
            "+00:00", "Z"
        ),
        "campaign_runner_binding_sha256": runner_binding_sha256,
        "campaign_rate_limit": material.rate_limit,
        "campaign_concurrency_limit": material.concurrency_limit,
        "campaign_execution_run_id": material.execution_run_id,
    }
    return PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign.node.execute",
        tenant_id=material.tenant_id,
        subject_id=material.principal_id,
        roles=("campaign-operator",),
        permissions=("campaign:execute",),
        resource_type="campaign_effect",
        resource_id=command.effect_id,
        policy_reference=material.policy_bundle_revision,
        roe_version_id=roe_version_id,
        correlation_id=f"dag-effect-{hashlib.sha256(command.effect_id.encode()).hexdigest()[:16]}",
        requested_at=now,
        attributes=attributes,
    )


def _deny(reason: str) -> AuthorityRecheck:
    return AuthorityRecheck(False, reason, "unresolved-runner", "unresolved-workload")


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _bounded(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")
