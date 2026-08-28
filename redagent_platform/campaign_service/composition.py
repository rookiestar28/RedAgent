"""Explicit production composition for the compat_123 two-capability Activity coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from typing import Awaitable, Callable, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from redagent_platform.artifact_pipeline.campaign_adapter import ArtifactCampaignAdapter
from redagent_platform.campaign_service.activity_coordinator import CampaignActivityCoordinator
from redagent_platform.campaign_service.activity_store import (
    ActivityReadinessFactsOwner,
    PostgresActivityContainmentOwner,
    PostgresCampaignActivityStateOwner,
    PostgresCampaignCoreRecoveryOwner,
    ResolverActivitySafetyGate,
)
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.campaign_service.relay_runtime import (
    PostgresRelayTenantSource,
    CampaignRelayPump,
    postgres_relay_repository_factory,
)
from redagent_platform.campaign_service.runtime import (
    LocalCampaignPlanningFactsOwner,
    PolicyBoundCampaignAuthorizationOwner,
    PostgresCanonicalAuthorityProvider,
    PostgresEnvelopeAuthorityVerifier,
    PostgresQualificationFixtureOwner,
    PostgresRunnerIdentityOwner,
    local_artifact_promotion_readiness,
    local_campaign_promotion_readiness,
)
from redagent_platform.campaign_service.registry import (
    ExecutionReadinessFacts,
    StrategyLoopMode,
    closed_execution_binding_for,
    evaluate_strategy_loop_readiness,
    load_strategy_loop_mode,
)
from redagent_platform.campaign_service.service import (
    EnvelopeAuthorityVerifier,
    PostgresCampaignStartStore,
    PostgresEffectResultOwner,
    PostgresEffectTransitionStore,
    PostgresManifestV2Issuer,
    DeterministicCampaignStartPlanner,
    CampaignStartService,
    CampaignCoreService,
    CampaignEffectCoordinator,
    ResolverAuthorityGate,
)
from redagent_platform.campaign_service.repository import PostgresCampaignCoreAuthorizedOptionOwner
from redagent_platform.campaign_service.qualification import (
    CampaignQualificationService,
    CampaignStatusService,
)
from redagent_platform.campaign_service.status import (
    PostgresCampaignCorePresentationOwner,
    PostgresCampaignStatusOwner,
    CampaignStatusOwner,
)
from redagent_platform.nuclei_service.campaign_adapter import NucleiCampaignAdapter
from redagent_platform.nuclei_service.campaign_transport import NucleiDockerTransport
from redagent_platform.orchestration.closed_loop_gateway import ClosedLoopTemporalStartGateway
from redagent_platform.orchestration.gateway import TemporalOrchestrationGateway
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.config import load_evidence_settings
from redagent_platform.evidence_service.runtime import build_evidence_backend
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.runner_service.campaign_dispatch import (
    ClosedCampaignDispatcher,
    RunnerOwnedCampaignDispatcher,
)
from redagent_platform.runner_service.campaign_lifecycle import (
    PostgresRunnerLifecycleOwner,
    RunnerIdentityOwner,
)
from redagent_platform.runner_service.campaign_result import PostgresAdapterResultWriter
from redagent_platform.zap_service.campaign_adapter import ZapCampaignAdapter
from redagent_platform.zap_service.campaign_transport import ZapDockerTransport


_KEY_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"  # pragma: allowlist secret


async def _temporal_unavailable() -> bool:
    return False


class CampaignWorkerReadinessFactsOwner:
    """Probe composed infrastructure without treating health as execution authority."""

    def __init__(
        self,
        workspace: Path,
        sessions: object,
        evidence_backend: object,
        *,
        image_probe: Callable[[str], bool] | None = None,
        temporal_probe: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        self._workspace = workspace.resolve()
        self._sessions = sessions
        self._evidence_backend = evidence_backend
        self._image_probe = image_probe or self._locked_images_ready
        self._temporal_probe = temporal_probe or _temporal_unavailable

    async def read(
        self,
        *,
        tenant_id: str,
        capability_id: str,
        now: datetime,
    ) -> ExecutionReadinessFacts:
        del tenant_id
        try:
            closed_execution_binding_for(capability_id)
        except ValueError as exc:
            raise ValueError("r123_readiness_capability_denied") from exc
        database_ready = False
        try:
            async with self._sessions() as session:
                database_ready = (await session.scalar(select(1))) == 1
        except Exception:  # noqa: BLE001
            database_ready = False
        try:
            # CRITICAL: a configured endpoint is not live Temporal readiness.
            temporal_ready = await self._temporal_probe() is True
        except Exception:  # noqa: BLE001
            temporal_ready = False
        zap_promotion, nuclei_promotion = local_campaign_promotion_readiness(
            self._workspace,
            now=now,
        )
        evidence_ready = (
            isinstance(self._evidence_backend, LocalAppendOnlyBackend)
            or all(
                hasattr(self._evidence_backend, name)
                for name in ("put", "get_exact", "verify_exact")
            )
        )
        return ExecutionReadinessFacts(
            database_ready=database_ready,
            temporal_ready=temporal_ready,
            resolver_ready=database_ready,
            policy_ready=database_ready,
            quota_ready=database_ready,
            runner_ready=database_ready,
            evidence_ready=evidence_ready,
            finding_import_ready=database_ready,
            kill_switch_ready=database_ready,
            zap_adapter_ready=zap_promotion and self._image_probe("zap"),
            nuclei_adapter_ready=nuclei_promotion and self._image_probe("nuclei"),
            artifact_adapter_ready=local_artifact_promotion_readiness(
                self._workspace, now=now
            ),
        )

    def _locked_images_ready(self, adapter: str) -> bool:
        try:
            name = {
                "zap": "config/r104-zap-runtime-v2.json",
                "nuclei": "config/r105-nuclei-runtime-v2.json",
            }[adapter]
            lock = json.loads((self._workspace / name).read_text(encoding="utf-8"))
            pairs = (
                (
                    (lock["engine_local_tag"], lock["engine_image_id"]),
                    (lock["target_local_tag"], lock["target_image_id"]),
                    (lock["gateway_local_tag"], lock["gateway_image_id"]),
                )
                if adapter == "zap"
                else (
                    (lock["engine_local_tag"], lock["engine_image_id"]),
                    (lock["target_local_tag"], lock["target_image_id"]),
                    (lock["gateway_local_tag"], lock["gateway_image_id"]),
                )
            )
            for tag, expected in pairs:
                completed = subprocess.run(
                    ["docker", "image", "inspect", str(tag), "--format", "{{.Id}}"],
                    cwd=self._workspace,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if completed.returncode or completed.stdout.strip() != expected:
                    return False
            return True
        except (KeyError, OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return False


class _CampaignApiReadinessFactsOwner:
    def __init__(self, owner: CampaignWorkerReadinessFactsOwner) -> None:
        self._owner = owner

    async def read(self, *, now: datetime) -> ExecutionReadinessFacts:
        return await self._owner.read(
            tenant_id="r123-api-readiness",
            capability_id="zap-controlled-runtime",
            now=now,
        )


@dataclass(frozen=True, slots=True)
class CampaignApiRuntimeServices:
    qualification_service: CampaignQualificationService
    status_service: CampaignStatusService
    campaign_status_owner: CampaignStatusOwner
    campaign_core_service: CampaignCoreService


def load_campaign_signing_identity(
    workspace: Path,
    env: Mapping[str, str],
) -> tuple[Ed25519PrivateKey, str]:
    """Load the dedicated repo-local signing identity without accepting inline key material."""
    path_value = env.get("REDAGENT_R123_SIGNING_KEY_FILE", "").strip()
    key_id = env.get("REDAGENT_R123_SIGNING_KEY_ID", "").strip()
    if not path_value or not key_id:
        raise ValueError("r123_signing_configuration_incomplete")
    if (
        len(key_id) > 100
        or not key_id[0].isalnum()
        or any(character not in _KEY_ID_ALPHABET for character in key_id)
    ):
        raise ValueError("r123_signing_key_id_invalid")
    root = workspace.resolve()
    source = Path(path_value)
    if not source.is_absolute():
        source = root / source
    resolved = source.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("r123_signing_key_outside_workspace") from exc
    if source.is_symlink():
        raise ValueError("r123_signing_key_symlink_forbidden")
    if not resolved.is_file() or resolved.stat().st_size > 4096:
        raise ValueError("r123_signing_key_unavailable")
    try:
        loaded = serialization.load_pem_private_key(
            resolved.read_bytes(),
            password=None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("r123_signing_key_invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("r123_signing_key_invalid")
    return loaded, key_id


def build_stock_campaign_coordinator_factory(
    workspace: Path,
    env: Mapping[str, str],
):
    """Build the stock worker factory only for explicitly enabled compat_123 mode."""
    mode = load_strategy_loop_mode(env)
    if mode is StrategyLoopMode.DISABLED:
        return None
    signing_key, signing_key_id = load_campaign_signing_identity(workspace, env)
    evidence_settings = load_evidence_settings(workspace, env)
    evidence_backend = build_evidence_backend(evidence_settings, env)
    kms_reference = evidence_settings.kms_reference or "kms:redagent:r123-local"

    async def factory(
        sessions: object,
        temporal_gateway: TemporalOrchestrationGateway,
    ) -> CampaignActivityCoordinator:
        if not isinstance(temporal_gateway, TemporalOrchestrationGateway):
            raise ValueError("r123_temporal_readiness_owner_required")
        readiness_owner = CampaignWorkerReadinessFactsOwner(
            workspace,
            sessions,
            evidence_backend,
            temporal_probe=temporal_gateway.health,
        )
        facts = await readiness_owner.read(
            tenant_id="r123-worker-readiness",
            capability_id="zap-controlled-runtime",
            now=datetime.now(timezone.utc),
        )
        readiness = evaluate_strategy_loop_readiness(mode, facts)
        if not readiness.ready or not readiness.execution_enabled:
            raise ValueError(readiness.reason)
        return build_stock_campaign_activity_coordinator(
            workspace,
            sessions,
            readiness_facts_owner=readiness_owner,
            evidence_service=EvidenceService(sessions, evidence_backend),
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            kms_reference=kms_reference,
        )

    setattr(factory, "_redagent_temporal_readiness_factory", True)
    return factory


def build_stock_campaign_relay_factory(env: Mapping[str, str]):
    """Compose the mandatory tenant-partitioned relay beside an enabled stock worker."""
    mode = load_strategy_loop_mode(env)
    if mode is StrategyLoopMode.DISABLED:
        return None
    instance_id = uuid4().hex[:12]

    def factory(sessions: object, client: object, settings: object) -> CampaignRelayPump:
        task_queue = getattr(settings, "task_queue", None)
        if not isinstance(task_queue, str):
            raise ValueError("r123_relay_temporal_settings_invalid")
        return CampaignRelayPump(
            tenant_source=PostgresRelayTenantSource(sessions),
            repository_factory=postgres_relay_repository_factory(
                sessions,
                instance_id=instance_id,
            ),
            resolver=CampaignContextResolver(PostgresCanonicalAuthorityProvider(sessions)),
            gateway=ClosedLoopTemporalStartGateway(client, task_queue=task_queue),
            claim_owner=f"r123-relay-{instance_id}",
        )

    return factory


def build_stock_campaign_api_service_factory(
    workspace: Path,
    env: Mapping[str, str],
    *,
    evidence_backend: object | None = None,
):
    """Build tenant-dynamic API services for the explicitly enabled compat_123 mode."""
    mode = load_strategy_loop_mode(env)
    if mode is not StrategyLoopMode.TWO_CAPABILITY:
        raise ValueError("r123_api_factory_requires_enabled_mode")
    signing_key, signing_key_id = load_campaign_signing_identity(workspace, env)
    if evidence_backend is None:
        evidence_settings = load_evidence_settings(workspace, env)
        evidence_backend = build_evidence_backend(evidence_settings, env)

    def factory(
        sessions: object,
        temporal_gateway: TemporalOrchestrationGateway | None = None,
    ) -> CampaignApiRuntimeServices:
        resolver = CampaignContextResolver(PostgresCanonicalAuthorityProvider(sessions))
        starter = CampaignStartService(
            resolver,
            DeterministicCampaignStartPlanner(
                LocalCampaignPlanningFactsOwner(workspace),
                PolicyBoundCampaignAuthorizationOwner(
                    signing_key,
                    signing_key_id=signing_key_id,
                ),
            ),
            PostgresCampaignStartStore(sessions),
        )
        readiness_owner = CampaignWorkerReadinessFactsOwner(
            workspace,
            sessions,
            evidence_backend,
            temporal_probe=(
                temporal_gateway.health
                if isinstance(temporal_gateway, TemporalOrchestrationGateway)
                else None
            ),
        )
        recovery_state_owner = PostgresCampaignActivityStateOwner(
            sessions,
            safety_gate=ResolverActivitySafetyGate(resolver, readiness_owner),
            containment_owner=PostgresActivityContainmentOwner(sessions),
            actor_user_id="redagent-r124-api",
        )
        return CampaignApiRuntimeServices(
            qualification_service=CampaignQualificationService(
                PostgresQualificationFixtureOwner(sessions),
                starter,
            ),
            status_service=CampaignStatusService(
                mode,
                _CampaignApiReadinessFactsOwner(readiness_owner),
            ),
            campaign_status_owner=PostgresCampaignStatusOwner(sessions),
            campaign_core_service=CampaignCoreService(
                PostgresCampaignCoreAuthorizedOptionOwner(sessions),
                starter,
                presentation=PostgresCampaignCorePresentationOwner(sessions),
                recovery=PostgresCampaignCoreRecoveryOwner(
                    sessions,
                    recovery_state_owner,
                ),
                create_enabled=_campaign_core_create_enabled(env),
            ),
        )

    setattr(factory, "_redagent_temporal_readiness_factory", True)
    return factory


def _campaign_core_create_enabled(env: Mapping[str, str]) -> bool:
    value = env.get("REDAGENT_R124_CAMPAIGN_CORE_ENABLED", "true").strip().lower()
    if value not in {"true", "false"}:
        raise ValueError("r124_campaign_core_flag_invalid")
    return value == "true"


def build_campaign_activity_coordinator(
    workspace: Path,
    sessions: object,
    *,
    resolver: CampaignContextResolver,
    readiness_facts_owner: ActivityReadinessFactsOwner,
    envelope_verifier: EnvelopeAuthorityVerifier,
    runner_identity_owner: RunnerIdentityOwner,
    evidence_service: object,
    signing_key: Ed25519PrivateKey,
    signing_key_id: str,
    actor_user_id: str = "redagent-r123-worker",
    kms_reference: str = "kms:redagent:r123",
) -> CampaignActivityCoordinator:
    """Build the only enabled-mode compat_123 path; all dynamic tenant scope comes from owner reads."""
    result_writer = PostgresAdapterResultWriter(
        sessions,
        evidence_service,
        actor_user_id=actor_user_id,
        kms_reference=kms_reference,
    )
    closed = ClosedCampaignDispatcher(
        (
            ArtifactCampaignAdapter(workspace, result_writer),
            ZapCampaignAdapter(ZapDockerTransport(workspace), result_writer),
            NucleiCampaignAdapter(NucleiDockerTransport(workspace), result_writer),
        )
    )
    dispatcher = RunnerOwnedCampaignDispatcher(
        closed,
        PostgresRunnerLifecycleOwner(
            sessions,
            runner_identity_owner,
            actor_user_id=actor_user_id,
        ),
    )
    effect = CampaignEffectCoordinator(
        ResolverAuthorityGate(resolver, envelope_verifier),
        PostgresEffectTransitionStore(
            sessions,
            actor_user_id=actor_user_id,
            correlation_prefix="r123-effect",
        ),
        PostgresManifestV2Issuer(
            sessions,
            resolver=resolver,
            actor_user_id=actor_user_id,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
        ),
        dispatcher,
        PostgresEffectResultOwner(
            sessions,
            actor_user_id=actor_user_id,
            correlation_prefix="r123-result",
        ),
    )
    state = PostgresCampaignActivityStateOwner(
        sessions,
        safety_gate=ResolverActivitySafetyGate(resolver, readiness_facts_owner),
        containment_owner=PostgresActivityContainmentOwner(sessions),
        actor_user_id=actor_user_id,
    )
    return CampaignActivityCoordinator(state, effect)


def build_stock_campaign_activity_coordinator(
    workspace: Path,
    sessions: object,
    *,
    readiness_facts_owner: ActivityReadinessFactsOwner,
    evidence_service: object,
    signing_key: Ed25519PrivateKey,
    signing_key_id: str,
    actor_user_id: str = "redagent-r123-worker",
    kms_reference: str = "kms:redagent:r123",
) -> CampaignActivityCoordinator:
    """Compose canonical relational authority owners for the stock worker path."""
    resolver = CampaignContextResolver(PostgresCanonicalAuthorityProvider(sessions))
    return build_campaign_activity_coordinator(
        workspace,
        sessions,
        resolver=resolver,
        readiness_facts_owner=readiness_facts_owner,
        envelope_verifier=PostgresEnvelopeAuthorityVerifier(sessions),
        runner_identity_owner=PostgresRunnerIdentityOwner(sessions),
        evidence_service=evidence_service,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        actor_user_id=actor_user_id,
        kms_reference=kms_reference,
    )
