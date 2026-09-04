"""Stock composition for the R173 zero-Activity admission-start bridge."""

from __future__ import annotations

from typing import Callable, Mapping, cast
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from temporalio.client import Client

from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter
from redagent_platform.campaign_service.admission_start_contracts import (
    AutonomousCampaignAdmissionContextProvider,
)
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
from redagent_platform.campaign_service.admission_start_store import (
    PostgresAutonomousCampaignAdmissionStartStore,
)
from redagent_platform.campaign_service.admission_start_relay_runtime import (
    AutonomousCampaignStartBridgeRelayPump,
    postgres_admission_start_bridge_relay_repository_factory,
)
from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignMode,
    load_autonomous_campaign_mode,
)
from redagent_platform.campaign_service.application_repository import (
    PostgresAutonomousCampaignApplicationRepository,
)
from redagent_platform.campaign_service.authority_envelope import (
    TrustedCampaignApproverKeyV2,
)
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
from redagent_platform.campaign_service.relay_runtime import PostgresRelayTenantSource
from redagent_platform.orchestration.admission_start_gateway import (
    AutonomousCampaignStartBridgeTemporalGateway,
)
from redagent_platform.orchestration.config import TemporalSettings


def build_autonomous_campaign_admission_start_factory(
    env: Mapping[str, str],
    *,
    admission_context_provider: AutonomousCampaignAdmissionContextProvider | None = None,
    policy: AdmissionPolicyAdapter | None = None,
    trusted_approval_keys: Mapping[str, TrustedCampaignApproverKeyV2] | None = None,
    validation_limits: ValidationLimitsV1 | None = None,
    trusted_validator_version: str | None = None,
    trusted_validator_sha256: str | None = None,
) -> Callable[[object], AutonomousCampaignAdmissionStartService] | None:
    """Build R173 only when every current-authority dependency is explicit."""
    mode = load_autonomous_campaign_mode(env)
    if mode is AutonomousCampaignMode.DISABLED:
        return None
    if (
        admission_context_provider is None
        and policy is None
        and not trusted_approval_keys
        and validation_limits is None
        and not trusted_validator_version
        and not trusted_validator_sha256
    ):
        return None
    if (
        admission_context_provider is None
        or policy is None
        or not trusted_approval_keys
        or validation_limits is None
        or not trusted_validator_version
        or not trusted_validator_sha256
    ):
        raise ValueError("r173_admission_start_configuration_incomplete")

    def factory(sessions: object) -> AutonomousCampaignAdmissionStartService:
        typed_sessions = cast(async_sessionmaker[AsyncSession], sessions)
        source = PostgresAutonomousCampaignApplicationRepository(typed_sessions)

        def store_factory(command, bundle, context):
            return PostgresAutonomousCampaignAdmissionStartStore(
                typed_sessions,
                command=command,
                bundle=bundle,
                context=context,
            )

        return AutonomousCampaignAdmissionStartService(
            source=source,
            context_provider=admission_context_provider,
            store_factory=store_factory,
            policy=policy,
            trusted_keys=trusted_approval_keys,
            validation_limits=validation_limits,
            trusted_validator_version=trusted_validator_version,
            trusted_validator_sha256=trusted_validator_sha256,
        )

    return factory


def build_stock_autonomous_campaign_start_bridge_relay_factory(
    env: Mapping[str, str],
):
    """Bind the inert Workflow and relay to the enabled autonomous application mode."""
    mode = load_autonomous_campaign_mode(env)
    if mode is AutonomousCampaignMode.DISABLED:
        return None
    instance_id = uuid4().hex[:12]

    def factory(
        sessions: async_sessionmaker[AsyncSession],
        client: Client,
        settings: TemporalSettings,
    ) -> AutonomousCampaignStartBridgeRelayPump:
        task_queue = getattr(settings, "task_queue", None)
        if not isinstance(task_queue, str):
            raise ValueError("start_bridge_relay_temporal_settings_invalid")
        return AutonomousCampaignStartBridgeRelayPump(
            tenant_source=PostgresRelayTenantSource(sessions),
            repository_factory=postgres_admission_start_bridge_relay_repository_factory(
                sessions,
                instance_id=instance_id,
            ),
            gateway=AutonomousCampaignStartBridgeTemporalGateway(
                client,
                task_queue=task_queue,
            ),
            claim_owner=f"start-bridge-{instance_id}",
        )

    return factory
