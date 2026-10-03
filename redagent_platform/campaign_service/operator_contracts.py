"""Typed server-owned root planning inputs for the normal operator boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignApplicationStateV1, AutonomousCampaignMutationResultV1,
    APPLICATION_CONTRACT_VERSION, RevokeAutonomousCampaignIntentV1,
)
from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignApprovalContextV1
from redagent_platform.campaign_service.planning.contracts import PlanningDomainV1, WorldStateV1, canonical_planning_sha256
from redagent_platform.campaign_service.planning.search_contracts import PlannerSearchLimitsV1
from redagent_platform.campaign_service.dag_execution_contracts import DagStopSignalV1


@dataclass(frozen=True, slots=True)
class AutonomousCampaignRootPlanMaterialV1:
    context: AutonomousCampaignApprovalContextV1
    domain: PlanningDomainV1
    initial_state: WorldStateV1
    search_limits: PlannerSearchLimitsV1

    def __post_init__(self) -> None:
        if not (
            isinstance(self.context, AutonomousCampaignApprovalContextV1)
            and isinstance(self.domain, PlanningDomainV1)
            and isinstance(self.initial_state, WorldStateV1)
            and isinstance(self.search_limits, PlannerSearchLimitsV1)
        ):
            raise ValueError("operator_root_plan_material_invalid")


class AutonomousCampaignRootPlanSource(Protocol):
    async def read_root_plan(
        self, *, application: AutonomousCampaignApplicationStateV1, now: datetime,
    ) -> AutonomousCampaignRootPlanMaterialV1 | None: ...


@dataclass(frozen=True, slots=True)
class AutonomousCampaignOperatorRecoveryV1:
    action: str
    tenant_id: str
    campaign_id: str
    actor_user_id: str
    expected_revision: int
    reason_sha256: str
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.action not in {"stop", "revoke"}:
            raise ValueError("operator_recovery_action_invalid")
        self.revoke_command()

    def revoke_command(self) -> RevokeAutonomousCampaignIntentV1:
        return RevokeAutonomousCampaignIntentV1(
            schema_version=APPLICATION_CONTRACT_VERSION, tenant_id=self.tenant_id,
            campaign_id=self.campaign_id, actor_user_id=self.actor_user_id,
            expected_revision=self.expected_revision, reason_sha256=self.reason_sha256,
            idempotency_key=self.idempotency_key, correlation_id=self.correlation_id, occurred_at=self.occurred_at,
        )

    @property
    def request_sha256(self) -> str:
        return canonical_planning_sha256({
            "schema_version": "redagent.autonomous-campaign-operator-recovery/v1",
            "action": self.action, "tenant_id": self.tenant_id, "campaign_id": self.campaign_id,
            "actor_user_id": self.actor_user_id, "expected_revision": self.expected_revision,
            "reason_sha256": self.reason_sha256,
        })


@dataclass(frozen=True, slots=True)
class AutonomousCampaignOperatorStopCommitV1:
    mutation: AutonomousCampaignMutationResultV1
    execution_run_id: str
    workflow_id: str
    workflow_run_id: str | None
    signal_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.mutation, AutonomousCampaignMutationResultV1):
            raise ValueError("operator_stop_mutation_invalid")
        for name, maximum in (("execution_run_id", 64), ("workflow_id", 100), ("signal_id", 100)):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > maximum or value != value.strip():
                raise ValueError("operator_stop_identity_invalid")
        if self.workflow_run_id is not None and (
            not isinstance(self.workflow_run_id, str) or not 1 <= len(self.workflow_run_id) <= 100
        ):
            raise ValueError("operator_stop_workflow_run_invalid")


class AutonomousCampaignOperatorNativeOwner(Protocol):
    async def read_status(
        self, *, tenant_id: str, campaign_id: str, principal_id: str, now: datetime,
    ) -> dict[str, object]: ...

    async def request_revoke(
        self, command: AutonomousCampaignOperatorRecoveryV1,
    ) -> AutonomousCampaignMutationResultV1: ...

    async def request_stop(
        self, command: AutonomousCampaignOperatorRecoveryV1,
    ) -> AutonomousCampaignOperatorStopCommitV1: ...


class AutonomousCampaignOperatorStopGateway(Protocol):
    async def stop_campaign_dag(
        self, workflow_id: str, request: DagStopSignalV1, *, run_id: str | None = None,
    ) -> None: ...
