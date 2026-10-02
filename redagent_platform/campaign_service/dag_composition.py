"""Explicit composition of the durable DAG Temporal Activity graph."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from temporalio.client import Client

from redagent_platform.campaign_service.activity_store import (
    ActivityContainmentOwner,
    PostgresActivityContainmentOwner,
)
from redagent_platform.campaign_service.composition import (
    CampaignWorkerReadinessFactsOwner,
    build_runner_owned_campaign_dispatcher,
    load_campaign_signing_identity,
)
from redagent_platform.campaign_service.dag_containment_store import (
    PostgresDagContainmentOwner,
)
from redagent_platform.campaign_service.dag_effect_authority import (
    DagEffectAuthorityGate,
    DagLifecycleOwner,
    DagPolicyOwner,
)
from redagent_platform.campaign_service.dag_effect_authority_store import (
    PostgresDagEffectAuthorityStateOwner,
)
from redagent_platform.campaign_service.dag_effect_transition_store import (
    PostgresDagEffectTransitionStore,
)
from redagent_platform.campaign_service.dag_execution_activity import DagExecutionActivity
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode, load_autonomous_campaign_mode
from redagent_platform.campaign_service.dag_execution_activity_store import (
    PostgresDagExecutionActivityStateOwner,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagExecutionMode,
    load_dag_execution_mode,
)
from redagent_platform.campaign_service.dag_lifecycle_store import (
    PostgresDagLifecycleOwner,
)
from redagent_platform.campaign_service.dag_manifest_lineage import (
    PostgresDagManifestLineageOwner,
)
from redagent_platform.campaign_service.dag_policy import DagPolicyDecisionAdapter
from redagent_platform.campaign_service.dag_relay_runtime import (
    DagRelayPump,
    postgres_dag_relay_repository_factory,
)
from redagent_platform.campaign_service.relay_runtime import PostgresRelayTenantSource
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.campaign_service.runtime import (
    PostgresCanonicalAuthorityProvider,
    PostgresRunnerIdentityOwner,
)
from redagent_platform.campaign_service.service import (
    CampaignEffectCoordinator,
    EffectDispatcher,
    PostgresEffectResultOwner,
    PostgresManifestV2Issuer,
)
from redagent_platform.orchestration.dag_execution_activities import (
    DagExecutionTemporalActivities,
)
from redagent_platform.orchestration.dag_execution_gateway import (
    DagExecutionTemporalStartGateway,
)
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.gateway import TemporalOrchestrationGateway
from redagent_platform.evidence_service.config import load_evidence_settings
from redagent_platform.evidence_service.runtime import build_evidence_backend
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.policy_service.config import load_policy_settings
from redagent_platform.policy_service.runtime import build_policy_provider


def build_dag_execution_temporal_activities(
    *,
    sessions: async_sessionmaker[AsyncSession],
    resolver: CampaignContextResolver,
    lifecycle: DagLifecycleOwner,
    policy: DagPolicyOwner,
    dispatcher: EffectDispatcher,
    containment: ActivityContainmentOwner,
    signing_key: Ed25519PrivateKey,
    signing_key_id: str,
    actor_user_id: str = "redagent-dag-worker",
    owned_execution_enabled: bool = False,
) -> DagExecutionTemporalActivities:
    state = PostgresDagExecutionActivityStateOwner(
        sessions,
        actor_user_id=actor_user_id,
        correlation_prefix="dag-frontier",
        owned_execution_enabled=owned_execution_enabled,
    )
    authority = DagEffectAuthorityGate(
        PostgresDagEffectAuthorityStateOwner(
            sessions,
            actor_user_id=actor_user_id,
            correlation_prefix="dag-authority",
            owned_execution_enabled=owned_execution_enabled,
        ),
        resolver,
        lifecycle,
        policy,
    )
    coordinator = CampaignEffectCoordinator(
        authority,
        PostgresDagEffectTransitionStore(
            sessions,
            actor_user_id=actor_user_id,
            correlation_prefix="dag-effect",
        ),
        PostgresManifestV2Issuer(
            sessions,
            resolver=resolver,
            actor_user_id=actor_user_id,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            lineage_owner=PostgresDagManifestLineageOwner(),
        ),
        dispatcher,
        PostgresEffectResultOwner(
            sessions,
            actor_user_id=actor_user_id,
            correlation_prefix="dag-result",
        ),
    )
    application = DagExecutionActivity(state, coordinator)
    containment_owner = PostgresDagContainmentOwner(
        sessions,
        containment,
        correlation_prefix="dag-containment",
    )
    return DagExecutionTemporalActivities(state, application, containment_owner)


def build_stock_campaign_dag_factory(
    workspace: Path,
    env: Mapping[str, str],
):
    """Build the stock DAG Activity graph only for explicitly enabled owned-loopback mode."""
    mode = load_dag_execution_mode(env)
    if mode is DagExecutionMode.DISABLED:
        return None
    signing_key, signing_key_id = load_campaign_signing_identity(workspace, env)
    evidence_settings = load_evidence_settings(workspace, env)
    evidence_backend = build_evidence_backend(evidence_settings, env)
    # IMPORTANT: this fallback is persisted as evidence metadata; keep it product-neutral.
    kms_reference = evidence_settings.kms_reference or "kms:redagent:synthetic-local"
    policy_settings = load_policy_settings(workspace, env)
    if (
        policy_settings.provider != "opa"
        or policy_settings.required_revision is None
    ):
        raise ValueError("dag_execution_opa_required")

    async def factory(
        sessions: async_sessionmaker[AsyncSession],
        temporal_gateway: TemporalOrchestrationGateway,
    ) -> DagExecutionTemporalActivities:
        if not isinstance(temporal_gateway, TemporalOrchestrationGateway):
            raise ValueError("dag_temporal_readiness_owner_required")
        policy_provider = build_policy_provider(policy_settings)
        readiness_owner = CampaignWorkerReadinessFactsOwner(
            workspace,
            sessions,
            evidence_backend,
            temporal_probe=temporal_gateway.health,
        )
        facts = await readiness_owner.read(
            tenant_id="dag-worker-readiness",
            capability_id="zap-controlled-runtime",
            now=datetime.now(timezone.utc),
        )
        required_facts = (
            facts.database_ready,
            facts.temporal_ready,
            facts.resolver_ready,
            facts.policy_ready,
            facts.quota_ready,
            facts.runner_ready,
            facts.evidence_ready,
            facts.finding_import_ready,
            facts.kill_switch_ready,
            facts.zap_adapter_ready,
            facts.nuclei_adapter_ready,
        )
        if not all(required_facts):
            raise ValueError("dag_execution_dependencies_not_ready")
        assert policy_settings.required_revision is not None
        policy_readiness = await policy_provider.assess_readiness(
            required_revision=policy_settings.required_revision
        )
        if (
            policy_readiness.ready is not True
            or policy_readiness.active_revision != policy_settings.required_revision
            or policy_readiness.bundle_plugin_state != "OK"
        ):
            raise ValueError("dag_execution_policy_not_ready")
        resolver = CampaignContextResolver(PostgresCanonicalAuthorityProvider(sessions))
        dispatcher = build_runner_owned_campaign_dispatcher(
            workspace,
            sessions,
            runner_identity_owner=PostgresRunnerIdentityOwner(sessions),
            evidence_service=EvidenceService(sessions, evidence_backend),
            actor_user_id="redagent-dag-worker",
            kms_reference=kms_reference,
            owned_execution=(load_autonomous_campaign_mode(env) is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO),
        )
        return build_dag_execution_temporal_activities(
            sessions=sessions,
            resolver=resolver,
            lifecycle=PostgresDagLifecycleOwner(sessions),
            policy=DagPolicyDecisionAdapter(policy_provider),
            dispatcher=dispatcher,
            containment=PostgresActivityContainmentOwner(sessions),
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            owned_execution_enabled=(load_autonomous_campaign_mode(env) is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO),
        )

    setattr(factory, "_redagent_temporal_readiness_factory", True)
    return factory


def build_stock_campaign_dag_relay_factory(env: Mapping[str, str]):
    """Compose the tenant-partitioned DAG start relay only for enabled mode."""
    mode = load_dag_execution_mode(env)
    if mode is DagExecutionMode.DISABLED:
        return None
    instance_id = uuid4().hex[:12]

    def factory(
        sessions: async_sessionmaker[AsyncSession],
        client: Client,
        settings: TemporalSettings,
    ) -> DagRelayPump:
        task_queue = getattr(settings, "task_queue", None)
        if not isinstance(task_queue, str):
            raise ValueError("dag_relay_temporal_settings_invalid")
        return DagRelayPump(
            tenant_source=PostgresRelayTenantSource(sessions),
            repository_factory=postgres_dag_relay_repository_factory(
                sessions,
                instance_id=instance_id,
            ),
            gateway=DagExecutionTemporalStartGateway(
                client,
                task_queue=task_queue,
            ),
            claim_owner=f"dag-relay-{instance_id}",
        )

    return factory
