"""Single-writer compat_123 application coordination for one external effect boundary."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
from typing import Callable, Protocol
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.agent_kernel.contracts import ProjectedTool
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    DecisionContextSnapshotV1,
    PlanRevisionV1,
    StrategyBudgetV1,
    StrategyDecisionReceiptV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    StrategyOutcome,
    StrategySignalsV1,
    TypedReferenceV1,
    canonical_sha256 as canonical_campaign_sha256,
)
from redagent_platform.campaign_service.execution import (
    ApprovalReceiptV1,
    ApprovalTier,
    EffectReceiptV1,
    ProposalSafetyCeilingV1,
    ReconciliationState,
    SafetyEnvelopeV1,
)
from redagent_platform.campaign_service import detection_feedback as detection_feedback_contracts
from redagent_platform.campaign_service.strategy import decide_strategy
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.repository import (
    CampaignTransitionResult,
    CampaignRepository,
    StartCampaignCommand,
)
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)
from redagent_platform.runner_service.contracts import (
    JobManifestDraft,
    JobManifestDraftV2,
    ResourceLimits,
    SignedJobManifestV2,
    parse_signed_job_manifest_v2,
    sign_job_manifest_v2,
    verify_job_manifest_v2_binding,
    verify_signed_job_manifest_v2,
)
from redagent_platform.runner_service.repository import RunnerRepository
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository, IdempotencyConflict
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ClosedLoopCampaignWorkflowInput,
    deterministic_closed_loop_campaign_workflow_id,
    closed_loop_workflow_request_sha256,
)


@dataclass(frozen=True, slots=True)
class AuthorityRecheck:
    allowed: bool
    reason: str
    runner_id: str
    workload_identity: str
    policy_decision_id: str | None = None
    policy_bundle_revision: str | None = None
    policy_input_sha256: str | None = None
    policy_valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("effect_authority_decision_invalid")
        for name, value in (
            ("effect_authority_reason", self.reason),
            ("effect_runner_id", self.runner_id),
            ("effect_workload_identity", self.workload_identity),
        ):
            _required(name, value, 300)
        optional = (
            self.policy_decision_id,
            self.policy_bundle_revision,
            self.policy_input_sha256,
            self.policy_valid_until,
        )
        if any(value is not None for value in optional):
            if any(value is None for value in optional):
                raise ValueError("effect_authority_policy_binding_incomplete")
            assert self.policy_decision_id is not None
            assert self.policy_bundle_revision is not None
            assert self.policy_input_sha256 is not None
            assert self.policy_valid_until is not None
            _required("effect_authority_policy_decision", self.policy_decision_id, 100)
            _required("effect_authority_policy_revision", self.policy_bundle_revision, 100)
            _sha256("effect_authority_policy_input", self.policy_input_sha256)
            _aware(self.policy_valid_until)


@dataclass(frozen=True, slots=True)
class EffectDispatchCommand:
    tenant_id: str
    principal_id: str
    engagement_id: str
    target_id: str
    effect_id: str
    invocation_id: str
    effect_intent_sha256: str
    envelope_sha256: str
    expected_claim_version: int
    expected_dispatch_attempt: int
    expected_dispatch_generation: int
    claim_owner: str
    binding: CapabilityBindingKeyV1

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "principal_id", "engagement_id", "target_id", "effect_id",
            "invocation_id", "claim_owner",
        ):
            _required(name, getattr(self, name), 128)
        _sha256("effect_envelope_sha256", self.envelope_sha256)
        _sha256("effect_intent_sha256", self.effect_intent_sha256)
        if (
            isinstance(self.expected_claim_version, bool)
            or not 0 <= self.expected_claim_version <= 2_147_483_647
        ):
            raise ValueError("effect_expected_claim_version_invalid")
        if (
            isinstance(self.expected_dispatch_attempt, bool)
            or not 0 <= self.expected_dispatch_attempt <= 2
        ):
            raise ValueError("effect_expected_dispatch_attempt_invalid")
        if (
            isinstance(self.expected_dispatch_generation, bool)
            or not 0 <= self.expected_dispatch_generation <= 2
        ):
            raise ValueError("effect_expected_dispatch_generation_invalid")
        if not isinstance(self.binding, CapabilityBindingKeyV1):
            raise ValueError("effect_capability_binding_invalid")
        _validate_closed_binding(self.binding)


@dataclass(frozen=True, slots=True)
class EffectReconciliationCommand:
    effect_command: EffectDispatchCommand
    request: CampaignAdapterRequest
    request_sha256: str
    runner_id: str
    workload_identity: str
    started_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.effect_command, EffectDispatchCommand):
            raise ValueError("effect_reconciliation_command_invalid")
        if not isinstance(self.request, CampaignAdapterRequest):
            raise ValueError("effect_reconciliation_request_invalid")
        _sha256("effect_reconciliation_request_sha256", self.request_sha256)
        _required("effect_reconciliation_runner_id", self.runner_id, 100)
        _required(
            "effect_reconciliation_workload_identity",
            self.workload_identity,
            300,
        )
        _aware(self.started_at)
        command = self.effect_command
        binding = command.binding
        request = self.request
        if (
            command.expected_dispatch_attempt not in {1, 2}
            or command.expected_dispatch_generation not in {1, 2}
            or request.tenant_id != command.tenant_id
            or request.invocation_id != command.invocation_id
            or request.effect_id != command.effect_id
            or request.envelope_sha256 != command.envelope_sha256
            or (
                request.capability_id,
                request.capability_revision,
                request.adapter_id,
                request.adapter_version,
                request.profile_id,
                request.profile_revision,
                request.profile_sha256,
                request.bundle_id,
                request.bundle_revision,
                request.bundle_sha256,
            )
            != (
                binding.capability_id,
                binding.capability_revision,
                binding.adapter_id,
                binding.adapter_version,
                binding.profile_id,
                binding.profile_revision,
                binding.profile_sha256,
                binding.bundle_id,
                binding.bundle_revision,
                binding.bundle_sha256,
            )
            or _canonical_sha256(asdict(request)) != self.request_sha256
        ):
            raise ValueError("effect_reconciliation_binding_invalid")


class EffectAuthorityGate(Protocol):
    async def recheck(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> AuthorityRecheck: ...


class EffectTransitionStore(Protocol):
    async def claim(self, command: EffectDispatchCommand, *, now: datetime) -> int: ...

    async def mark_dispatching(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        request_sha256: str,
        runner_id: str,
        workload_identity: str,
        now: datetime,
    ) -> int: ...

    async def confirm(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object: ...

    async def ambiguity(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> None: ...

    async def not_applied(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object: ...

    async def lookup_unavailable(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> object: ...


class ManifestV2Issuer(Protocol):
    async def issue(
        self,
        command: EffectDispatchCommand,
        *,
        authority: AuthorityRecheck,
        now: datetime,
    ) -> SignedJobManifestV2: ...


@dataclass(frozen=True, slots=True)
class ManifestLineageContext:
    campaign_id: str
    engagement_id: str
    roe_id: str
    job_id: str
    manifest_namespace: str


class ManifestLineageOwner(Protocol):
    async def prepare(
        self,
        session: AsyncSession,
        command: EffectDispatchCommand,
        *,
        actor_user_id: str,
        stable: str,
        now: datetime,
    ) -> ManifestLineageContext: ...


class EffectDispatcher(Protocol):
    async def dispatch(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt: ...

    async def lookup(
        self, request: CampaignAdapterRequest
    ) -> AdapterTerminalReceipt | None: ...


class EffectResultOwner(Protocol):
    async def finalize(
        self,
        command: EffectDispatchCommand,
        receipt: AdapterTerminalReceipt,
        *,
        now: datetime,
        reconciliation: bool = False,
    ) -> AdapterTerminalReceipt: ...


class EnvelopeAuthorityVerifier(Protocol):
    async def verify_current_envelope(
        self,
        command: EffectDispatchCommand,
        snapshot: CanonicalAuthoritySnapshot,
        *,
        now: datetime,
    ) -> str | None: ...


class ResolverAuthorityGate:
    """Adapts the read-only canonical resolver plus exact envelope verification."""

    def __init__(
        self,
        resolver: CampaignContextResolver,
        envelope_verifier: EnvelopeAuthorityVerifier,
    ) -> None:
        self._resolver = resolver
        self._envelope_verifier = envelope_verifier

    async def recheck(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> AuthorityRecheck:
        result = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=command.tenant_id,
                principal_id=command.principal_id,
                engagement_id=command.engagement_id,
                target_id=command.target_id,
            ),
            now=now,
        )
        if not result.allowed or result.bindings is None:
            return AuthorityRecheck(
                False, result.reason, "unresolved-runner", "unresolved-workload"
            )
        reason = await self._envelope_verifier.verify_current_envelope(
            command, result.bindings, now=now
        )
        if reason is not None:
            return AuthorityRecheck(
                False,
                reason,
                result.bindings.runner_id,
                result.bindings.runner_workload_identity,
            )
        return AuthorityRecheck(
            True,
            "allowed",
            result.bindings.runner_id,
            result.bindings.runner_workload_identity,
        )


class PostgresEffectTransitionStore:
    """Transaction-owning adapter over the tenant-scoped compat_123 repository."""

    def __init__(
        self,
        session_factory: object,
        *,
        tenant_id: str | None = None,
        actor_user_id: str,
        correlation_prefix: str,
        lease_seconds: int = 30,
    ) -> None:
        self._sessions = session_factory
        self._tenant_id = (
            None
            if tenant_id is None
            else _required_value("effect_store_tenant", tenant_id, 64)
        )
        self._actor_user_id = actor_user_id
        self._correlation_prefix = _required_value(
            "effect_correlation_prefix", correlation_prefix, 40
        )
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise ValueError("effect_lease_seconds_invalid")
        self._lease_seconds = lease_seconds

    async def claim(self, command: EffectDispatchCommand, *, now: datetime) -> int:
        async with self._sessions() as session, session.begin():
            result = await self._repository(session, command, "claim").claim_effect(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=command.expected_claim_version,
                now=now,
                lease_seconds=self._lease_seconds,
            )
        return result.claim_version

    async def mark_dispatching(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        request_sha256: str,
        runner_id: str,
        workload_identity: str,
        now: datetime,
    ) -> int:
        async with self._sessions() as session, session.begin():
            result = await self._repository(session, command, "dispatch").mark_effect_dispatching(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                request_sha256=request_sha256,
                runner_id=runner_id,
                workload_identity=workload_identity,
                occurred_at=now,
            )
        return result.claim_version

    async def confirm(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            return await self._repository(session, command, "confirm").record_effect_receipt(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=now,
            )

    async def ambiguity(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(session, command, "ambiguity").record_effect_ambiguity(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                failure_code=failure_code,
                occurred_at=now,
            )

    async def not_applied(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            return await self._repository(
                session, command, "not-applied"
            ).record_effect_not_applied(
                effect_id=command.effect_id,
                expected_claim_version=expected_claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=now,
            )

    async def lookup_unavailable(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            return await self._repository(
                session, command, "lookup"
            ).record_effect_lookup_unavailable(
                effect_id=command.effect_id,
                expected_claim_version=expected_claim_version,
                failure_code=failure_code,
                occurred_at=now,
            )

    def _repository(
        self, session: object, command: EffectDispatchCommand, phase: str
    ) -> CampaignRepository:
        if self._tenant_id is not None and command.tenant_id != self._tenant_id:
            raise ValueError("effect_store_tenant_mismatch")
        suffix = hashlib.sha256(command.effect_id.encode()).hexdigest()[:12]
        return CampaignRepository(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=self._actor_user_id,
            correlation_id=f"{self._correlation_prefix}-{phase}-{suffix}",
        )


class PostgresEffectResultOwner:
    """Fail closed until runner, evidence, finding, and retest owners agree."""

    def __init__(
        self,
        session_factory: object,
        *,
        tenant_id: str | None = None,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self._sessions = session_factory
        self._tenant_id = (
            None
            if tenant_id is None
            else _required_value("result_owner_tenant", tenant_id, 64)
        )
        self._actor_user_id = _required_value(
            "result_owner_actor", actor_user_id, 64
        )
        self._correlation_prefix = _required_value(
            "result_owner_correlation", correlation_prefix, 40
        )

    async def finalize(
        self,
        command: EffectDispatchCommand,
        receipt: AdapterTerminalReceipt,
        *,
        now: datetime,
        reconciliation: bool = False,
    ) -> AdapterTerminalReceipt:
        _aware(now)
        if not isinstance(reconciliation, bool):
            raise ValueError("effect_result_owner_reconciliation_invalid")
        if self._tenant_id is not None and command.tenant_id != self._tenant_id:
            raise ValueError("effect_result_owner_tenant_mismatch")
        if (
            receipt.invocation_id != command.invocation_id
            or receipt.effect_id != command.effect_id
            or receipt.state != "confirmed"
            or receipt.external_receipt_id is None
            or receipt.cleanup_receipt_id is None
        ):
            raise ValueError("effect_result_owner_receipt_invalid")
        suffix = hashlib.sha256(command.effect_id.encode()).hexdigest()[:12]
        async with self._sessions() as session, session.begin():
            await CampaignRepository(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-{suffix}",
            ).validate_trusted_effect_owners(
                effect_id=command.effect_id,
                external_receipt_id=receipt.external_receipt_id,
                evidence_ids=receipt.evidence_ids,
                cleanup_receipt_id=receipt.cleanup_receipt_id,
                require_complete_coverage=False,
                require_retest=False,
                allow_reconciliation_required=reconciliation,
            )
        return receipt


class StrategyManifestLineageOwner:
    """Default lineage adapter preserving the accepted strategy-revision path."""

    async def prepare(
        self,
        session: AsyncSession,
        command: EffectDispatchCommand,
        *,
        actor_user_id: str,
        stable: str,
        now: datetime,
    ) -> ManifestLineageContext:
        campaign_repo = CampaignRepository(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=f"r123-manifest-context-{stable[:12]}",
        )
        context = await campaign_repo.read_effect_manifest_context(
            effect_id=command.effect_id,
            claim_owner=command.claim_owner,
            now=now,
        )
        if (
            context.engagement_id != command.engagement_id
            or context.envelope_sha256 != command.envelope_sha256
        ):
            raise ValueError("r123_manifest_effect_context_mismatch")
        job = await ControlPlaneRepository(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=f"r123-manifest-job-{stable[:12]}",
        ).create_runner_job(
            campaign_id=context.campaign_id,
            strategy_revision_id=context.strategy_revision_id,
            effect_id=command.effect_id,
            claim_owner=command.claim_owner,
            capability_id=command.binding.capability_id,
            envelope_sha256=command.envelope_sha256,
            occurred_at=now,
        )
        return ManifestLineageContext(
            campaign_id=context.campaign_id,
            engagement_id=context.engagement_id,
            roe_id=context.roe_id,
            job_id=str(job.resource["job_id"]),
            manifest_namespace="r123",
        )


class PostgresManifestV2Issuer:
    """Compose, sign, and persist one exact v2 manifest from canonical owners."""

    def __init__(
        self,
        sessions: object,
        *,
        resolver: CampaignContextResolver,
        tenant_id: str | None = None,
        actor_user_id: str,
        signing_key: Ed25519PrivateKey,
        signing_key_id: str,
        lineage_owner: ManifestLineageOwner | None = None,
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ValueError("r123_manifest_signing_key_invalid")
        self._sessions = sessions
        self._resolver = resolver
        self._tenant_id = (
            None
            if tenant_id is None
            else _required_value("r123_manifest_tenant", tenant_id, 64)
        )
        self._actor_user_id = _required_value(
            "r123_manifest_actor", actor_user_id, 64
        )
        self._signing_key = signing_key
        self._signing_key_id = _required_value(
            "r123_manifest_signing_key_id", signing_key_id, 100
        )
        self._lineage_owner = lineage_owner or StrategyManifestLineageOwner()

    async def issue(
        self,
        command: EffectDispatchCommand,
        *,
        authority: AuthorityRecheck,
        now: datetime,
    ) -> SignedJobManifestV2:
        _aware_start(now)
        if self._tenant_id is not None and command.tenant_id != self._tenant_id:
            raise ValueError("r123_manifest_tenant_mismatch")
        tenant_id = command.tenant_id
        resolved = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=command.tenant_id,
                principal_id=command.principal_id,
                engagement_id=command.engagement_id,
                target_id=command.target_id,
            ),
            now=now,
        )
        snapshot = resolved.bindings
        if (
            not resolved.allowed
            or snapshot is None
            or not authority.allowed
            or snapshot.runner_id != authority.runner_id
            or snapshot.runner_workload_identity != authority.workload_identity
        ):
            raise RuntimeError("r123_manifest_current_authority_denied")
        stable = hashlib.sha256(
            f"{tenant_id}\0{command.effect_id}".encode("utf-8")
        ).hexdigest()[:32]
        async with self._sessions() as session, session.begin():
            context = await self._lineage_owner.prepare(
                session,
                command,
                actor_user_id=self._actor_user_id,
                stable=stable,
                now=now,
            )
            if (
                context.engagement_id != command.engagement_id
            ):
                raise ValueError("r123_manifest_effect_context_mismatch")
            namespace = _required_value(
                "manifest_lineage_namespace", context.manifest_namespace, 32
            )
            idempotency_key = f"{namespace}-manifest-{stable}"
            job_id = context.job_id
            manifests = metadata.tables["runner_job_manifests"]
            existing = await session.scalar(
                select(manifests.c.manifest_document).where(
                    manifests.c.tenant_id == tenant_id,
                    manifests.c.job_id == job_id,
                    manifests.c.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                parsed = parse_signed_job_manifest_v2(existing)
                verify_signed_job_manifest_v2(
                    parsed, self._signing_key.public_key(), now=now
                )
                verify_job_manifest_v2_binding(parsed.manifest, command.binding)
                return parsed

            registrations = metadata.tables["runner_registrations"]
            classes = metadata.tables["runner_classes"]
            registration_rows = (
                await session.execute(
                    select(registrations, classes.c.class_id)
                    .join(
                        classes,
                        classes.c.id == registrations.c.runner_class_record_id,
                    )
                    .where(
                        registrations.c.tenant_id == tenant_id,
                        registrations.c.runner_id == authority.runner_id,
                        registrations.c.spiffe_id == authority.workload_identity,
                        registrations.c.registration_state == "active",
                        registrations.c.revoked_at.is_(None),
                        registrations.c.expires_at > now,
                    )
                    .order_by(registrations.c.generation.desc())
                    .limit(2)
                )
            ).mappings().all()
            if len(registration_rows) != 1:
                raise RuntimeError("r123_manifest_runner_registration_ambiguous")
            registration = registration_rows[0]
            capabilities = metadata.tables["execution_capability_manifests"]
            capability = (
                await session.execute(
                    select(capabilities).where(
                        capabilities.c.tenant_id == tenant_id,
                        capabilities.c.capability_id
                        == command.binding.capability_id,
                        capabilities.c.capability_revision
                        == command.binding.capability_revision,
                        capabilities.c.capability_status == "certified",
                    )
                )
            ).mappings().one_or_none()
            if capability is None or (
                capability["manifest_sha256"]
                != command.binding.execution_manifest_sha256
                or capability["adapter_id"] != command.binding.adapter_id
                or capability["adapter_version"] != command.binding.adapter_version
            ):
                raise RuntimeError("r123_manifest_capability_not_current")
            limits = ResourceLimits(**dict(capability["resource_limits"]))
            expiry_candidates = [
                snapshot.expires_at,
                snapshot.lease_expires_at,
                now + timedelta(minutes=5),
            ]
            if authority.policy_valid_until is not None:
                expiry_candidates.append(authority.policy_valid_until)
            expires_at = min(expiry_candidates)
            v1 = JobManifestDraft(
                schema_version=CONTRACT_SCHEMA_VERSION,
                manifest_id=f"manifest-{namespace}-{stable}",
                job_id=job_id,
                tenant_id=tenant_id,
                engagement_id=context.engagement_id,
                roe_version_id=context.roe_id,
                environment=str(registration["environment"]),
                runner_class_id=str(registration["class_id"]),
                network_plane=str(registration["network_plane"]),
                adapter_id=command.binding.adapter_id,
                adapter_version=command.binding.adapter_version,
                capability_digest=command.binding.execution_manifest_sha256,
                image_digest=str(capability["image_digest"]),
                artifact_receipt_id=str(capability["artifact_receipt_id"]),
                policy_revision=(
                    authority.policy_bundle_revision or snapshot.policy_revision
                ),
                policy_decision_id=(
                    authority.policy_decision_id or snapshot.policy_decision_id
                ),
                target_ids=(command.target_id,),
                target_hashes=(snapshot.target_sha256,),
                limits=limits,
                egress_profile="target-allowlist",
                evidence_schema=tuple(capability["evidence_schema"]),
                secret_reference_ids=(),
                issued_at=now,
                expires_at=expires_at,
                nonce=f"nonce-{namespace}-{stable}",
            )
            draft = JobManifestDraftV2(
                v1=v1,
                capability_id=command.binding.capability_id,
                capability_revision=command.binding.capability_revision,
                execution_manifest_sha256=command.binding.execution_manifest_sha256,
                profile_id=command.binding.profile_id,
                profile_revision=command.binding.profile_revision,
                profile_sha256=command.binding.profile_sha256,
                bundle_id=command.binding.bundle_id,
                bundle_revision=command.binding.bundle_revision,
                bundle_sha256=command.binding.bundle_sha256,
            )
            signed = sign_job_manifest_v2(
                draft, self._signing_key, key_id=self._signing_key_id
            )
            await RunnerRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"r123-manifest-persist-{stable[:12]}",
            ).issue_manifest_v2(
                signed,
                runner_registration_id=str(registration["id"]),
                binding=command.binding,
                idempotency_key=idempotency_key,
                occurred_at=now,
            )
            return signed


class EffectAmbiguityPersistenceError(RuntimeError):
    """Primary ambiguity owner failed; the Activity owner must persist the fallback."""


class CampaignEffectCoordinator:
    """Coordinates one effect while PostgreSQL remains the only transition writer."""

    def __init__(
        self,
        authority: EffectAuthorityGate,
        store: EffectTransitionStore,
        manifest_issuer: ManifestV2Issuer,
        dispatcher: EffectDispatcher,
        result_owner: EffectResultOwner,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._authority = authority
        self._store = store
        self._manifest_issuer = manifest_issuer
        self._dispatcher = dispatcher
        self._result_owner = result_owner
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def _record_ambiguity(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
        preserve: BaseException | None = None,
    ) -> None:
        try:
            await self._store.ambiguity(
                command,
                expected_claim_version=expected_claim_version,
                failure_code=failure_code,
                now=now,
            )
        except BaseException as persistence_error:
            # CRITICAL: preserve cancellation, but expose persistence loss so the
            # Activity state owner can make the independent durable transition.
            if isinstance(preserve, asyncio.CancelledError):
                preserve.add_note("effect_ambiguity_persistence_failed")
                return
            if isinstance(persistence_error, asyncio.CancelledError):
                raise
            raise EffectAmbiguityPersistenceError(
                "effect_ambiguity_persistence_failed"
            ) from persistence_error

    async def reconcile(
        self,
        reconciliation: EffectReconciliationCommand,
        *,
        now: datetime,
    ) -> object:
        if not isinstance(reconciliation, EffectReconciliationCommand):
            raise ValueError("effect_reconciliation_command_invalid")
        _aware(now)
        if now < reconciliation.started_at:
            raise ValueError("effect_reconciliation_time_invalid")
        command = reconciliation.effect_command
        try:
            receipt = await self._dispatcher.lookup(reconciliation.request)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            receipt = None
        if receipt is None:
            return await self._store.lookup_unavailable(
                command,
                expected_claim_version=command.expected_claim_version,
                failure_code="adapter_status_lookup_unavailable",
                now=now,
            )
        if (
            not isinstance(receipt, AdapterTerminalReceipt)
            or receipt.invocation_id != command.invocation_id
            or receipt.effect_id != command.effect_id
        ):
            raise ValueError("effect_reconciliation_receipt_binding_invalid")
        if receipt.state == "not_applied":
            if (
                not receipt.output_complete
                or receipt.external_receipt_id is None
                or not receipt.evidence_ids
                or receipt.failure_code is not None
            ):
                raise ValueError("effect_not_applied_receipt_incomplete")
            not_applied_receipt = EffectReceiptV1(
                schema_version="redagent.r123-effect-receipt/v1",
                effect_id=command.effect_id,
                effect_intent_sha256=command.effect_intent_sha256,
                envelope_sha256=command.envelope_sha256,
                dispatch_attempt=command.expected_dispatch_attempt,
                dispatch_generation=command.expected_dispatch_generation,
                runner_id=reconciliation.runner_id,
                workload_identity=reconciliation.workload_identity,
                request_sha256=reconciliation.request_sha256,
                started_at=reconciliation.started_at,
                completed_at=now,
                adapter_accepted=False,
                external_status="not_applied",
                external_receipt_id=receipt.external_receipt_id,
                evidence_ids=receipt.evidence_ids,
                cleanup_receipt_id=receipt.cleanup_receipt_id,
                output_complete=receipt.output_complete,
                external_contact_count=receipt.external_contact_count,
                reconciliation_state=ReconciliationState.NOT_APPLIED,
                reconciliation_evidence_ids=receipt.evidence_ids,
                redispatch_permitted=True,
                failure_code=None,
            )
            return await self._store.not_applied(
                command,
                expected_claim_version=command.expected_claim_version,
                receipt_sha256=not_applied_receipt.receipt_sha256,
                receipt_payload=not_applied_receipt.canonical_payload,
                now=now,
            )
        if receipt.state != "confirmed":
            return await self._store.lookup_unavailable(
                command,
                expected_claim_version=command.expected_claim_version,
                failure_code="adapter_status_lookup_unavailable",
                now=now,
            )
        owned = await self._result_owner.finalize(
            command,
            receipt,
            now=now,
            reconciliation=True,
        )
        if (
            not isinstance(owned, AdapterTerminalReceipt)
            or owned != receipt
            or owned.state != "confirmed"
        ):
            raise ValueError("effect_reconciliation_trusted_result_invalid")
        effect_receipt = EffectReceiptV1(
            schema_version="redagent.r123-effect-receipt/v1",
            effect_id=command.effect_id,
            effect_intent_sha256=command.effect_intent_sha256,
            envelope_sha256=command.envelope_sha256,
            dispatch_attempt=command.expected_dispatch_attempt,
            dispatch_generation=command.expected_dispatch_generation,
            runner_id=reconciliation.runner_id,
            workload_identity=reconciliation.workload_identity,
            request_sha256=reconciliation.request_sha256,
            started_at=reconciliation.started_at,
            completed_at=now,
            adapter_accepted=True,
            external_status="confirmed",
            external_receipt_id=owned.external_receipt_id,
            evidence_ids=owned.evidence_ids,
            cleanup_receipt_id=owned.cleanup_receipt_id,
            output_complete=owned.output_complete,
            external_contact_count=owned.external_contact_count,
            reconciliation_state=ReconciliationState.CONFIRMED,
            reconciliation_evidence_ids=owned.evidence_ids,
            redispatch_permitted=False,
            failure_code=None,
        )
        async def confirm_exact_receipt() -> object:
            return await self._store.confirm(
                command,
                expected_claim_version=command.expected_claim_version,
                receipt_sha256=effect_receipt.receipt_sha256,
                receipt_payload=effect_receipt.canonical_payload,
                now=now,
            )

        async def schedule_lookup_retry() -> object:
            return await self._store.lookup_unavailable(
                command,
                expected_claim_version=command.expected_claim_version,
                failure_code="effect_receipt_commit_unknown",
                now=now,
            )

        try:
            return await confirm_exact_receipt()
        except asyncio.CancelledError:
            try:
                # CRITICAL: replay only the same receipt; reconciliation never redispatches.
                await asyncio.shield(confirm_exact_receipt())
            except BaseException:  # noqa: BLE001
                try:
                    await asyncio.shield(schedule_lookup_retry())
                except BaseException:  # noqa: BLE001
                    pass
            raise
        except Exception:  # noqa: BLE001
            try:
                # IMPORTANT: one exact replay resolves confirmation response loss.
                return await confirm_exact_receipt()
            except asyncio.CancelledError:
                try:
                    await asyncio.shield(schedule_lookup_retry())
                except BaseException:  # noqa: BLE001
                    pass
                raise
            except Exception:  # noqa: BLE001
                return await schedule_lookup_retry()

    async def dispatch(self, command: EffectDispatchCommand, *, now: datetime) -> object:
        _aware(now)
        first = await self._authority.recheck(command, now=now)
        if not first.allowed:
            raise RuntimeError(f"effect_authority_denied:{first.reason}")

        claimed_version = await self._store.claim(command, now=now)
        signed = await self._manifest_issuer.issue(command, authority=first, now=now)
        if not isinstance(signed, SignedJobManifestV2):
            raise ValueError("effect_manifest_v2_required")
        verify_job_manifest_v2_binding(signed.manifest, command.binding)
        request = _adapter_request(command, signed)
        request_sha256 = _canonical_sha256(asdict(request))
        dispatching_version = await self._store.mark_dispatching(
            command,
            expected_claim_version=claimed_version,
            request_sha256=request_sha256,
            runner_id=first.runner_id,
            workload_identity=first.workload_identity,
            now=now,
        )

        # CRITICAL: outbox/claim/manifest state is not authority; recheck immediately before I/O.
        try:
            pre_io_at = self._clock()
            _aware(pre_io_at)
            if pre_io_at < now:
                raise RuntimeError("effect_pre_io_time_invalid")
        except BaseException as exc:
            await self._record_ambiguity(
                command,
                expected_claim_version=dispatching_version,
                failure_code="pre_io_authority_time_unknown",
                now=now,
                preserve=exc,
            )
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("effect_dispatch_reconciliation_required") from exc
        try:
            current = await self._authority.recheck(command, now=pre_io_at)
        except BaseException as exc:
            # CRITICAL: dispatching means later code may have observed the request; an aborted
            # current-authority check must leave durable ambiguity, never a retryable claim.
            await self._record_ambiguity(
                command,
                expected_claim_version=dispatching_version,
                failure_code="pre_io_authority_recheck_unknown",
                now=pre_io_at,
                preserve=exc,
            )
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("effect_dispatch_reconciliation_required") from exc
        if (
            not current.allowed
            or current.runner_id != first.runner_id
            or current.workload_identity != first.workload_identity
        ):
            await self._record_ambiguity(
                command,
                expected_claim_version=dispatching_version,
                failure_code="authority_drift_before_dispatch",
                now=pre_io_at,
            )
            raise RuntimeError("effect_dispatch_reconciliation_required")
        receipt_failure = "adapter_receipt_commit_unknown"
        try:
            receipt = await self._dispatcher.dispatch(request)
            if receipt.state != "confirmed":
                # IMPORTANT: preserve explicit cleanup/evidence loss for operator attention;
                # generic commit ambiguity must not hide an observed incomplete result.
                if receipt.failure_code in {"cleanup_receipt_missing", "cleanup_failed", "evidence_output_incomplete", "evidence_persistence_failed"}:
                    receipt_failure = receipt.failure_code
                raise RuntimeError("adapter_terminal_receipt_unconfirmed")
            receipt = await self._result_owner.finalize(command, receipt, now=pre_io_at)
            if (
                not isinstance(receipt, AdapterTerminalReceipt)
                or receipt.invocation_id != command.invocation_id
                or receipt.effect_id != command.effect_id
                or receipt.state != "confirmed"
            ):
                raise ValueError("effect_trusted_result_binding_invalid")
        except BaseException as exc:
            # CRITICAL: adapter acceptance or owner persistence may have happened; never auto-resend.
            await self._record_ambiguity(
                command,
                expected_claim_version=dispatching_version,
                failure_code=receipt_failure,
                now=pre_io_at,
                preserve=exc,
            )
            # CRITICAL: durable ambiguity and task cancellation are both true; preserve both.
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("effect_dispatch_reconciliation_required") from exc
        try:
            completed_at = self._clock()
            _aware(completed_at)
            if completed_at < pre_io_at:
                raise RuntimeError("effect_completion_time_invalid")
            effect_receipt = EffectReceiptV1(
                schema_version="redagent.r123-effect-receipt/v1",
                effect_id=command.effect_id,
                effect_intent_sha256=command.effect_intent_sha256,
                envelope_sha256=command.envelope_sha256,
                dispatch_attempt=command.expected_dispatch_attempt + 1,
                dispatch_generation=command.expected_dispatch_generation + 1,
                runner_id=current.runner_id,
                workload_identity=current.workload_identity,
                request_sha256=request_sha256,
                # CRITICAL: confirmation binds the persisted dispatch timestamp exactly;
                # the later fresh authority check must not rewrite that durable identity.
                started_at=now,
                completed_at=completed_at,
                adapter_accepted=True,
                external_status="confirmed",
                external_receipt_id=receipt.external_receipt_id,
                evidence_ids=receipt.evidence_ids,
                cleanup_receipt_id=receipt.cleanup_receipt_id,
                output_complete=receipt.output_complete,
                external_contact_count=receipt.external_contact_count,
                reconciliation_state=ReconciliationState.CONFIRMED,
                reconciliation_evidence_ids=receipt.evidence_ids,
                redispatch_permitted=False,
                failure_code=None,
            )
            payload = effect_receipt.canonical_payload
            receipt_sha256 = effect_receipt.receipt_sha256
        except BaseException as exc:
            await self._record_ambiguity(
                command,
                expected_claim_version=dispatching_version,
                failure_code="adapter_receipt_commit_unknown",
                now=pre_io_at,
                preserve=exc,
            )
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("effect_dispatch_reconciliation_required") from exc

        async def confirm_exact_receipt() -> object:
            return await self._store.confirm(
                command,
                expected_claim_version=dispatching_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=payload,
                now=completed_at,
            )

        try:
            return await confirm_exact_receipt()
        except asyncio.CancelledError as exc:
            try:
                # CRITICAL: replay only the same receipt; never redispatch after adapter acceptance.
                await asyncio.shield(confirm_exact_receipt())
            except BaseException:  # noqa: BLE001
                await self._record_ambiguity(
                    command,
                    expected_claim_version=dispatching_version,
                    failure_code="adapter_receipt_commit_unknown",
                    now=completed_at,
                    preserve=exc,
                )
            raise
        except Exception:  # noqa: BLE001
            try:
                # IMPORTANT: one exact replay resolves commit-response loss idempotently.
                return await confirm_exact_receipt()
            except asyncio.CancelledError as exc:
                await self._record_ambiguity(
                    command,
                    expected_claim_version=dispatching_version,
                    failure_code="adapter_receipt_commit_unknown",
                    now=completed_at,
                    preserve=exc,
                )
                raise
            except Exception as replay_error:
                await self._record_ambiguity(
                    command,
                    expected_claim_version=dispatching_version,
                    failure_code="adapter_receipt_commit_unknown",
                    now=completed_at,
                    preserve=replay_error,
                )
                raise RuntimeError(
                    "effect_dispatch_reconciliation_required"
                ) from replay_error


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignStartRequest:
    """Human-selectable start intent; runtime identities are deliberately absent."""

    tenant_id: str
    principal_id: str
    engagement_id: str
    target_id: str
    name: str
    objective_kind: str
    header_code: str | None
    require_corroboration: bool
    risk_profile: str

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "principal_id", "engagement_id", "target_id", "name",
        ):
            _required(f"campaign_start_{name}", getattr(self, name), 200)
        if self.objective_kind not in {
            "http_posture", "security_header_assertion", "repository_snapshot_posture",
        }:
            raise ValueError("campaign_start_objective_invalid")
        if self.objective_kind == "security_header_assertion":
            if self.header_code != "x-content-type-options":
                raise ValueError("campaign_start_header_invalid")
        elif self.header_code is not None:
            raise ValueError("campaign_start_header_forbidden")
        if not isinstance(self.require_corroboration, bool):
            raise ValueError("campaign_start_corroboration_invalid")
        if self.risk_profile != "tier1_passive":
            raise ValueError("campaign_start_risk_profile_denied")
        if self.objective_kind == "repository_snapshot_posture" and self.require_corroboration:
            raise ValueError("campaign_start_artifact_corroboration_forbidden")


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignCoreAuthorizedResource:
    """Canonical resource projected as a non-identifying operator selection."""

    resource_id: str
    label: str
    revision: str
    freshness: str
    eligible: bool
    unavailable_reason: str | None
    parent_id: str | None = None
    target_class: str = "owned-http"

    def __post_init__(self) -> None:
        _required("r124_resource_id", self.resource_id, 200)
        _required("r124_resource_label", self.label, 200)
        _required("r124_resource_revision", self.revision, 100)
        if self.freshness not in {"current", "stale"}:
            raise ValueError("r124_resource_freshness_invalid")
        if not isinstance(self.eligible, bool):
            raise ValueError("r124_resource_eligibility_invalid")
        if self.unavailable_reason is not None:
            _required("r124_resource_unavailable_reason", self.unavailable_reason, 200)
        if self.eligible and self.unavailable_reason is not None:
            raise ValueError("r124_resource_eligible_reason_conflict")
        if not self.eligible and self.unavailable_reason is None:
            raise ValueError("r124_resource_ineligible_reason_required")
        if self.parent_id is not None:
            _required("r124_resource_parent", self.parent_id, 200)
        if self.target_class not in {"owned-http", "repository-snapshot"}:
            raise ValueError("r124_resource_target_class_invalid")


class CampaignCoreAuthorizedOptionOwner(Protocol):
    async def list_engagements(
        self, *, tenant_id: str, principal_id: str, now: datetime
    ) -> tuple[CampaignCoreAuthorizedResource, ...]: ...

    async def list_targets(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_id: str,
        now: datetime,
    ) -> tuple[CampaignCoreAuthorizedResource, ...]: ...


@dataclass(frozen=True, slots=True)
class CampaignCoreResolvedIntent:
    """Current native selections retained for canonical intent source binding."""

    engagement: CampaignCoreAuthorizedResource
    target: CampaignCoreAuthorizedResource
    request: CampaignStartRequest


class CampaignCoreStarter(Protocol):
    async def replay(self, **values: object) -> object | None: ...

    async def start(
        self,
        request: CampaignStartRequest,
        *,
        now: datetime,
        idempotency_key: str,
        request_sha256: str,
    ) -> object: ...


class CampaignCorePresentationOwner(Protocol):
    async def list_campaigns(self, **values: object) -> dict[str, object]: ...

    async def read_campaign(self, **values: object) -> dict[str, object]: ...

    async def inspect_campaign(self, **values: object) -> dict[str, object]: ...

    async def list_attention(self, **values: object) -> dict[str, object]: ...


class CampaignCoreEtagConflict(RuntimeError):
    """The recovery mutation no longer targets the current aggregate revision."""


class CampaignCoreCreateDisabled(RuntimeError):
    """Normal campaign creation is disabled while recovery/read paths remain active."""


class CampaignCoreRecoveryOwner(Protocol):
    async def recover(self, **values: object) -> object: ...


class CampaignCoreService:
    """Resolve operator selections and delegate once to the canonical compat_123 start owner."""

    _OBJECTIVES = {
        "Assess HTTP security posture": ("http_posture", None, False),
        "Verify X-Content-Type-Options": (
            "security_header_assertion",
            "x-content-type-options",
            True,
        ),
        "Assess repository snapshot posture": (
            "repository_snapshot_posture",
            None,
            False,
        ),
    }

    def __init__(
        self,
        options: CampaignCoreAuthorizedOptionOwner,
        starter: CampaignCoreStarter,
        *,
        presentation: CampaignCorePresentationOwner | None = None,
        recovery: CampaignCoreRecoveryOwner | None = None,
        create_enabled: bool = True,
    ) -> None:
        self._options = options
        self._starter = starter
        self._presentation = presentation
        self._recovery = recovery
        self._create_enabled = create_enabled

    @property
    def creation_enabled(self) -> bool:
        return self._create_enabled

    async def resolve_application_scope(
        self, *, tenant_id: str, principal_id: str, engagement_id: str, target_id: str,
        now: datetime, require_eligible: bool,
    ) -> tuple[CampaignCoreAuthorizedResource, CampaignCoreAuthorizedResource]:
        if type(require_eligible) is not bool:
            raise ValueError("operator_scope_eligibility_invalid")
        engagements = await self._options.list_engagements(
            tenant_id=tenant_id, principal_id=principal_id, now=now,
        )
        matches = [resource for resource in engagements if resource.resource_id == engagement_id]
        if len(matches) != 1:
            raise ValueError("operator_application_scope_denied")
        engagement = matches[0]
        targets = await self._options.list_targets(
            tenant_id=tenant_id, principal_id=principal_id, engagement_id=engagement_id, now=now,
        )
        matches = [resource for resource in targets if resource.resource_id == target_id]
        if len(matches) != 1 or matches[0].parent_id != engagement_id:
            raise ValueError("operator_application_scope_denied")
        target = matches[0]
        # CRITICAL: recovery reads need current principal/ownership, not fresh execution eligibility.
        if require_eligible:
            if not engagement.eligible:
                raise ValueError("engagement_binding_ineligible")
            if not target.eligible:
                raise ValueError("target_binding_ineligible")
        return engagement, target

    async def list_engagement_options(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        limit: int,
        cursor: str | None,
        now: datetime,
    ) -> dict[str, object]:
        resources = await self._options.list_engagements(
            tenant_id=tenant_id,
            principal_id=principal_id,
            now=now,
        )
        return self._page(
            resources,
            tenant_id=tenant_id,
            kind="engagement",
            limit=limit,
            cursor=cursor,
        )

    async def list_target_options(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_binding: str,
        limit: int,
        cursor: str | None,
        now: datetime,
    ) -> dict[str, object]:
        engagement = await self._resolve_engagement(
            tenant_id=tenant_id,
            principal_id=principal_id,
            binding=engagement_binding,
            now=now,
        )
        if not engagement.eligible:
            raise ValueError("engagement_binding_ineligible")
        resources = await self._options.list_targets(
            tenant_id=tenant_id,
            principal_id=principal_id,
            engagement_id=engagement.resource_id,
            now=now,
        )
        return self._page(
            resources,
            tenant_id=tenant_id,
            kind="target",
            limit=limit,
            cursor=cursor,
        )

    async def list_risk_profile_options(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_binding: str,
        target_binding: str,
        limit: int,
        cursor: str | None,
        now: datetime,
    ) -> dict[str, object]:
        engagement, target = await self._resolve_pair(
            tenant_id=tenant_id,
            principal_id=principal_id,
            engagement_binding=engagement_binding,
            target_binding=target_binding,
            now=now,
        )
        del engagement, target
        resource = CampaignCoreAuthorizedResource(
            resource_id="tier1_passive",
            label="Tier 1 passive",
            revision="1",
            freshness="current",
            eligible=True,
            unavailable_reason=None,
        )
        return self._page(
            (resource,), tenant_id=tenant_id, kind="risk", limit=limit, cursor=cursor
        )

    async def start_campaign(
        self,
        intent: object,
        *,
        tenant_id: str,
        principal_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> dict[str, object]:
        key = _required_value("r124_transport_idempotency", idempotency_key, 200)
        request_sha256 = canonical_campaign_sha256({
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "engagement_binding": str(getattr(intent, "engagement_binding", "")),
            "target_binding": str(getattr(intent, "target_binding", "")),
            "objective": str(getattr(intent, "objective", "")),
            "risk_profile": str(getattr(intent, "risk_profile", "")),
        })
        replay = await self._starter.replay(
            tenant_id=tenant_id,
            actor_user_id=principal_id,
            idempotency_key=key,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return self._start_response(replay)
        if not self._create_enabled:
            raise CampaignCoreCreateDisabled("r124_campaign_create_disabled")
        resolved = await self.resolve_operator_intent(
            intent, tenant_id=tenant_id, principal_id=principal_id, now=now,
        )
        receipt = await self._starter.start(
            resolved.request,
            now=now,
            idempotency_key=key,
            request_sha256=request_sha256,
        )
        return self._start_response(receipt)

    async def resolve_operator_intent(
        self,
        intent: object,
        *,
        tenant_id: str,
        principal_id: str,
        now: datetime,
    ) -> CampaignCoreResolvedIntent:
        """Resolve current opaque selections without replaying or starting execution."""
        engagement, target = await self._resolve_pair(
            tenant_id=tenant_id,
            principal_id=principal_id,
            engagement_binding=str(getattr(intent, "engagement_binding", "")),
            target_binding=str(getattr(intent, "target_binding", "")),
            now=now,
        )
        objective = str(getattr(intent, "objective", ""))
        objective_contract = self._OBJECTIVES.get(objective)
        if objective_contract is None:
            raise ValueError("objective_unsupported")
        risk_resource = CampaignCoreAuthorizedResource(
            resource_id="tier1_passive",
            label="Tier 1 passive",
            revision="1",
            freshness="current",
            eligible=True,
            unavailable_reason=None,
        )
        if getattr(intent, "risk_profile", None) != _campaign_core_binding(
            tenant_id, "risk", risk_resource
        ):
            raise ValueError("risk_profile_unsupported")
        objective_kind, header_code, corroboration = objective_contract
        artifact_objective = objective_kind == "repository_snapshot_posture"
        if artifact_objective != (target.target_class == "repository-snapshot"):
            raise ValueError("objective_target_class_mismatch")
        # IMPORTANT: resolution has no dispatch owner; intent creation must remain effect-free.
        return CampaignCoreResolvedIntent(
            engagement=engagement,
            target=target,
            request=CampaignStartRequest(
                tenant_id=tenant_id,
                principal_id=principal_id,
                engagement_id=engagement.resource_id,
                target_id=target.resource_id,
                name=objective,
                objective_kind=objective_kind,
                header_code=header_code,
                require_corroboration=corroboration,
                risk_profile="tier1_passive",
            ),
        )

    @staticmethod
    def _start_response(receipt: object) -> dict[str, object]:
        campaign_id = _required_value(
            "r124_start_campaign", getattr(receipt, "campaign_id", None), 64
        )
        sequence = getattr(receipt, "aggregate_sequence", None)
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError("r124_start_sequence_invalid")
        return {
            "data": {
                "campaign_id": campaign_id,
                "status": str(getattr(receipt, "status", "dispatch_pending")),
                "aggregate_sequence": sequence,
                "etag": f'"{campaign_id}:{sequence}"',
                "replayed": bool(getattr(receipt, "replayed", False)),
            }
        }

    async def list_campaigns(self, **values: object) -> dict[str, object]:
        return await self._presentation_owner().list_campaigns(**values)

    async def read_campaign(self, **values: object) -> dict[str, object]:
        return await self._presentation_owner().read_campaign(**values)

    async def inspect_campaign(self, **values: object) -> dict[str, object]:
        return await self._presentation_owner().inspect_campaign(**values)

    async def list_attention(self, **values: object) -> dict[str, object]:
        return await self._presentation_owner().list_attention(**values)

    async def recover_campaign(
        self,
        *,
        action: str,
        reason: str,
        tenant_id: str,
        principal_id: str,
        campaign_id: str,
        expected_etag: str,
        idempotency_key: str,
        now: datetime,
    ) -> dict[str, object]:
        if action not in {"stop", "revoke"}:
            raise ValueError("r124_recovery_action_invalid")
        if len(reason) < 10 or len(reason) > 500:
            raise ValueError("r124_recovery_reason_invalid")
        sequence = _campaign_core_etag_revision(campaign_id, expected_etag)
        key = _required_value("r124_recovery_idempotency", idempotency_key, 200)
        stable = hashlib.sha256(
            f"{tenant_id}\x1f{campaign_id}\x1f{action}\x1f{key}".encode()
        ).hexdigest()[:32]
        request_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "action": action,
                    "campaign_id": campaign_id,
                    "expected_revision": sequence,
                    "reason_sha256": hashlib.sha256(reason.encode()).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        recovery = self._recovery
        if recovery is None:
            raise RuntimeError("r124_campaign_recovery_unavailable")
        commit = await recovery.recover(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            signal_id=f"r124-{action}-{stable}",
            actor_user_id=principal_id,
            reason_sha256=hashlib.sha256(reason.encode()).hexdigest(),
            expected_revision=sequence,
            idempotency_key=key,
            request_sha256=request_sha256,
            now=now,
            correlation_id=f"r124-{action}-{stable}",
        )
        state = getattr(commit, "state", None)
        next_sequence = getattr(commit, "revision", None)
        replayed = getattr(commit, "replayed", False)
        if (
            not isinstance(state, str)
            or isinstance(next_sequence, bool)
            or not isinstance(next_sequence, int)
            or next_sequence < 1
            or not isinstance(replayed, bool)
        ):
            raise ValueError("r124_recovery_commit_invalid")
        return {
            "data": {
                "campaign_id": campaign_id,
                "status": state,
                "aggregate_sequence": next_sequence,
                "etag": f'"{campaign_id}:{next_sequence}"',
                "replayed": replayed,
            }
        }

    def _presentation_owner(self) -> CampaignCorePresentationOwner:
        if self._presentation is None:
            raise RuntimeError("r124_campaign_presentation_unavailable")
        return self._presentation

    async def _resolve_pair(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_binding: str,
        target_binding: str,
        now: datetime,
    ) -> tuple[CampaignCoreAuthorizedResource, CampaignCoreAuthorizedResource]:
        engagement = await self._resolve_engagement(
            tenant_id=tenant_id,
            principal_id=principal_id,
            binding=engagement_binding,
            now=now,
        )
        if not engagement.eligible:
            raise ValueError("engagement_binding_ineligible")
        targets = await self._options.list_targets(
            tenant_id=tenant_id,
            principal_id=principal_id,
            engagement_id=engagement.resource_id,
            now=now,
        )
        target = self._resolve(
            targets,
            tenant_id=tenant_id,
            kind="target",
            binding=target_binding,
            error="target_binding_invalid",
        )
        if target.parent_id != engagement.resource_id:
            raise ValueError("target_binding_parent_mismatch")
        if not target.eligible:
            raise ValueError("target_binding_ineligible")
        return engagement, target

    async def _resolve_engagement(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        binding: str,
        now: datetime,
    ) -> CampaignCoreAuthorizedResource:
        resources = await self._options.list_engagements(
            tenant_id=tenant_id,
            principal_id=principal_id,
            now=now,
        )
        return self._resolve(
            resources,
            tenant_id=tenant_id,
            kind="engagement",
            binding=binding,
            error="engagement_binding_invalid",
        )

    @staticmethod
    def _resolve(
        resources: tuple[CampaignCoreAuthorizedResource, ...],
        *,
        tenant_id: str,
        kind: str,
        binding: str,
        error: str,
    ) -> CampaignCoreAuthorizedResource:
        matches = [
            resource for resource in resources
            if _campaign_core_binding(tenant_id, kind, resource) == binding
        ]
        if len(matches) != 1:
            raise ValueError(error)
        return matches[0]

    @staticmethod
    def _page(
        resources: tuple[CampaignCoreAuthorizedResource, ...],
        *,
        tenant_id: str,
        kind: str,
        limit: int,
        cursor: str | None,
    ) -> dict[str, object]:
        if isinstance(limit, bool) or not 1 <= limit <= 50:
            raise ValueError("r124_page_limit_invalid")
        offset = 0
        if cursor is not None:
            prefix = "r124-cursor-"
            if not cursor.startswith(prefix) or not cursor[len(prefix):].isdigit():
                raise ValueError("r124_cursor_invalid")
            offset = int(cursor[len(prefix):])
        selected = resources[offset:offset + limit]
        next_offset = offset + len(selected)
        next_cursor = (
            f"r124-cursor-{next_offset}" if next_offset < len(resources) else None
        )
        return {
            "data": [
                {
                    "binding": _campaign_core_binding(tenant_id, kind, resource),
                    "label": resource.label,
                    "revision": resource.revision,
                    "freshness": resource.freshness,
                    "eligible": resource.eligible,
                    "unavailable_reason": resource.unavailable_reason,
                }
                for resource in selected
            ],
            "page": {"limit": limit, "next_cursor": next_cursor},
        }


def _campaign_core_binding(
    tenant_id: str, kind: str, resource: CampaignCoreAuthorizedResource
) -> str:
    material = "\x1f".join((
        _required_value("r124_binding_tenant", tenant_id, 64),
        _required_value("r124_binding_kind", kind, 32),
        resource.resource_id,
        resource.parent_id or "",
        resource.revision,
    ))
    return f"r124-{kind}-{hashlib.sha256(material.encode()).hexdigest()[:32]}"


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignStartMaterial:
    """Canonical compat_119/compat_121/envelope-owner output consumed by the single writer."""

    tenant_id: str
    engagement_id: str
    target_id: str
    target_sha256: str
    objective_sha256: str
    context_schema: str
    context_sha256: str
    context_payload: dict[str, object]
    decision_schema: str
    decision_sha256: str
    decision_payload: dict[str, object]
    plan_revision_id: str
    plan_revision: int
    plan_sha256: str
    plan_payload: dict[str, object]
    proposal_ceiling_sha256: str
    approval_receipt_id: str
    approval_receipt_revision: int
    approval_receipt_sha256: str
    envelope_core_sha256: str
    envelope_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "engagement_id", "target_id", "plan_revision_id",
            "approval_receipt_id",
        ):
            _required(f"campaign_start_material_{name}", getattr(self, name), 100)
        if self.context_schema == "redagent.r119-decision-context/v1":
            if self.decision_schema != "redagent.r121-strategy-receipt/v1":
                raise ValueError("campaign_start_decision_schema_invalid")
        elif (
            self.context_schema,
            self.decision_schema,
        ) == (
            "redagent.artifact-posture-decision-context/v2",
            "redagent.artifact-posture-strategy-receipt/v2",
        ):
            pass
        elif not detection_feedback_contracts.detection_campaign_schema_pair_is_valid(
            self.context_schema, self.decision_schema
        ):
            raise ValueError("campaign_start_context_schema_invalid")
        for name in (
            "target_sha256", "objective_sha256", "context_sha256", "decision_sha256",
            "plan_sha256", "proposal_ceiling_sha256", "approval_receipt_sha256",
            "envelope_core_sha256", "envelope_sha256",
        ):
            _sha256(f"campaign_start_{name}", getattr(self, name))
        for name in ("context_payload", "decision_payload", "plan_payload"):
            value = getattr(self, name)
            if not isinstance(value, dict):
                raise ValueError(f"campaign_start_{name}_invalid")
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 2 * 1024 * 1024:
                raise ValueError(f"campaign_start_{name}_invalid")
        if self.plan_revision != 1 or self.approval_receipt_revision < 1:
            raise ValueError("campaign_start_revision_invalid")


@dataclass(frozen=True, slots=True)
class CampaignPlanningFacts:
    snapshot: DecisionContextSnapshotV1
    authority: AuthorityContextV1
    projections: tuple[ProjectedTool, ...]
    detection_adaptation: detection_feedback_contracts.DetectionAdaptationRequestV1 | None = None
    artifact_receipt: TypedReferenceV1 | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.snapshot, DecisionContextSnapshotV1)
            or not isinstance(self.authority, AuthorityContextV1)
            or not isinstance(self.projections, tuple)
            or not self.projections
            or not all(isinstance(item, ProjectedTool) for item in self.projections)
            or (
                self.artifact_receipt is not None
                and (
                    not isinstance(self.artifact_receipt, TypedReferenceV1)
                    or self.artifact_receipt.kind != "artifact-receipt"
                )
            )
            or (
                self.detection_adaptation is not None
                and not isinstance(
                    self.detection_adaptation,
                    detection_feedback_contracts.DetectionAdaptationRequestV1,
                )
            )
        ):
            raise ValueError("campaign_planning_facts_invalid")


@dataclass(frozen=True, slots=True)
class CampaignAuthorizationMaterial:
    ceiling: ProposalSafetyCeilingV1
    approval: ApprovalReceiptV1
    envelope: SafetyEnvelopeV1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.ceiling, ProposalSafetyCeilingV1)
            or not isinstance(self.approval, ApprovalReceiptV1)
            or not isinstance(self.envelope, SafetyEnvelopeV1)
        ):
            raise ValueError("campaign_authorization_material_invalid")


class CampaignPlanningFactsOwner(Protocol):
    async def read(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        *,
        now: datetime,
    ) -> CampaignPlanningFacts: ...


class CampaignAuthorizationOwner(Protocol):
    async def authorize(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        objective: StrategyObjectiveV1,
        receipt: StrategyDecisionReceiptV1,
        plan: PlanRevisionV1,
        *,
        now: datetime,
    ) -> CampaignAuthorizationMaterial: ...


class DeterministicCampaignStartPlanner:
    """Run the accepted compat_119/compat_121 decision and bind its output to the envelope owner."""

    def __init__(
        self,
        facts_owner: CampaignPlanningFactsOwner,
        authorization_owner: CampaignAuthorizationOwner,
    ) -> None:
        self._facts_owner = facts_owner
        self._authorization_owner = authorization_owner

    async def prepare(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        *,
        campaign_id: str,
        now: datetime,
    ) -> CampaignStartMaterial:
        _aware_start(now)
        facts = await self._facts_owner.read(request, authority, now=now)
        if not isinstance(facts, CampaignPlanningFacts):
            raise ValueError("campaign_planning_facts_invalid")
        r119 = facts.authority
        if (
            r119.tenant_id != request.tenant_id
            or r119.principal_id != request.principal_id
            or r119.engagement_id != request.engagement_id
            or r119.target.reference_id != request.target_id
            or r119.target.sha256 != authority.target_sha256
            or r119.roe_version_id != authority.roe_version_id
            or r119.roe_sha256 != authority.roe_sha256
            or r119.policy_decision_id != authority.policy_decision_id
            or r119.policy_revision != authority.policy_revision
            or r119.policy_sha256 != authority.policy_sha256
            or facts.snapshot.authority_sha256 != canonical_campaign_sha256(r119)
            or facts.snapshot.target_mapping_sha256 != r119.target_mapping_sha256
        ):
            raise ValueError("campaign_planning_authority_mismatch")
        artifact_objective = (
            request.objective_kind == StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE.value
        )
        objective = StrategyObjectiveV1(
            schema_version=(
                "redagent.artifact-posture-objective/v2"
                if artifact_objective
                else "redagent.r121-objective/v1"
            ),
            objective_id=(
                "objective-"
                + hashlib.sha256(campaign_id.encode("utf-8")).hexdigest()[:24]
            ),
            tenant_id=request.tenant_id,
            engagement_id=request.engagement_id,
            target=TypedReferenceV1(
                kind="target",
                reference_id=request.target_id,
                sha256=authority.target_sha256,
            ),
            kind=StrategyObjectiveKind(request.objective_kind),
            header_code=request.header_code,
            require_corroboration=request.require_corroboration,
            artifact_receipt=facts.artifact_receipt if artifact_objective else None,
        )
        receipt, plan = decide_strategy(
            objective=objective,
            snapshot=facts.snapshot,
            authority=r119,
            projections=facts.projections,
            budget=StrategyBudgetV1(
                max_elapsed_seconds=60,
                max_operations=1 if artifact_objective else 2,
                max_targets=1,
                max_evidence_bytes=1_048_576,
                max_depth=1 if artifact_objective else 2,
            ),
            signals=StrategySignalsV1(),
            model_proposal=None,
            now=now,
            detection_adaptation=facts.detection_adaptation,
        )
        if receipt.outcome is not StrategyOutcome.SELECT or plan is None:
            raise RuntimeError(f"campaign_strategy_not_executable:{receipt.reason}")
        authorization = await self._authorization_owner.authorize(
            request, authority, objective, receipt, plan, now=now
        )
        if not isinstance(authorization, CampaignAuthorizationMaterial):
            raise ValueError("campaign_authorization_material_invalid")
        ceiling = authorization.ceiling
        approval = authorization.approval
        envelope = authorization.envelope
        expected_capabilities = {
            (
                item.binding_key.capability_id,
                item.binding_key.capability_revision,
                item.binding_key.execution_manifest_sha256,
                item.binding_key.profile_sha256,
                item.binding_key.bundle_sha256,
            )
            for item in facts.snapshot.semantics
        }
        actual_capabilities = {
            (
                item.capability_id,
                item.capability_revision,
                item.execution_manifest_sha256,
                item.profile_sha256,
                item.bundle_sha256,
            )
            for item in ceiling.allowed_capabilities
        }
        core = envelope.core
        if (
            ceiling.tenant_id != request.tenant_id
            or ceiling.engagement_id != request.engagement_id
            or ceiling.actor_id != request.principal_id
            or ceiling.workload_identity != authority.runner_workload_identity
            or ceiling.objective_sha256 != receipt.objective_sha256
            or ceiling.target_revision != authority.target_revision
            or ceiling.target_sha256 != authority.target_sha256
            or ceiling.target_resolution_mode != authority.target_resolution_mode
            or ceiling.policy_sha256 != authority.policy_sha256
            or ceiling.policy_revocation_epoch != authority.policy_revocation_epoch
            or ceiling.roe_sha256 != authority.roe_sha256
            or ceiling.roe_revocation_epoch != authority.roe_revocation_epoch
            or ceiling.credential_class != "none"
            or ceiling.credential_reference_id is not None
            or ceiling.destination != authority.target_value
            or ceiling.approval_tier is not ApprovalTier.TIER_1
            or ceiling.risk_ceiling != "tier1-passive-read-only"
            or actual_capabilities != expected_capabilities
            or core.tenant_id != request.tenant_id
            or core.proposal_ceiling_sha256 != ceiling.proposal_ceiling_sha256
            or core.plan_sha256 != plan.plan_sha256
            or core.workload_identity != authority.runner_workload_identity
            or core.target_sha256 != authority.target_sha256
            or core.destination != authority.target_value
            or core.reservation_id != authority.reservation_id
            or core.lease_id != authority.lease_id
            or approval.core_sha256 != core.core_sha256
            or approval.tenant_id != request.tenant_id
            or approval.workload_identity != authority.runner_workload_identity
            or envelope.approval_receipt_id != approval.approval_id
            or envelope.approval_receipt_revision != approval.approval_revision
            or envelope.approval_receipt_sha256 != approval.receipt_sha256
        ):
            raise ValueError("campaign_authorization_binding_mismatch")
        bindings = tuple(item.binding_key for item in facts.snapshot.semantics)
        return CampaignStartMaterial(
            tenant_id=request.tenant_id,
            engagement_id=request.engagement_id,
            target_id=request.target_id,
            target_sha256=authority.target_sha256,
            objective_sha256=receipt.objective_sha256,
            context_schema=facts.snapshot.schema_version,
            context_sha256=facts.snapshot.snapshot_sha256,
            context_payload={
                "tenant_id": request.tenant_id,
                "target_id": request.target_id,
                "bindings": _json_safe(bindings),
                "snapshot": _json_safe(facts.snapshot),
            },
            decision_schema=receipt.schema_version,
            decision_sha256=receipt.receipt_sha256,
            decision_payload=_json_safe(receipt),
            plan_revision_id=plan.plan_id,
            plan_revision=plan.revision,
            plan_sha256=plan.plan_sha256,
            plan_payload=_json_safe(plan),
            proposal_ceiling_sha256=ceiling.proposal_ceiling_sha256,
            approval_receipt_id=approval.approval_id,
            approval_receipt_revision=approval.approval_revision,
            approval_receipt_sha256=approval.receipt_sha256,
            envelope_core_sha256=core.core_sha256,
            envelope_sha256=envelope.envelope_sha256,
        )


class CampaignStartPlanner(Protocol):
    async def prepare(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        *,
        campaign_id: str,
        now: datetime,
    ) -> CampaignStartMaterial: ...


class CampaignStartIdentitySource(Protocol):
    def new_campaign_id(self) -> str: ...

    def new_strategy_record_id(self) -> str: ...


class CampaignStartStore(Protocol):
    async def replay(self, **values: object) -> object | None: ...

    async def start(
        self,
        command: StartCampaignCommand,
        *,
        tenant_id: str,
        actor_user_id: str,
        occurred_at: datetime,
        idempotency_key: str | None = None,
        request_sha256: str | None = None,
    ) -> object: ...


class UuidCampaignStartIdentitySource:
    def new_campaign_id(self) -> str:
        return f"campaign-{uuid4().hex}"

    def new_strategy_record_id(self) -> str:
        return f"strategy-{uuid4().hex}"


class PostgresCampaignStartStore:
    def __init__(
        self,
        sessions: object,
        *,
        correlation_prefix: str = "r123-start",
    ) -> None:
        self._sessions = sessions
        self._correlation_prefix = _required_value(
            "campaign_start_store_correlation", correlation_prefix, 40
        )

    async def start(
        self,
        command: StartCampaignCommand,
        *,
        tenant_id: str,
        actor_user_id: str,
        occurred_at: datetime,
        idempotency_key: str | None = None,
        request_sha256: str | None = None,
    ) -> CampaignTransitionResult:
        tenant_key = _required_value("campaign_start_store_tenant", tenant_id, 64)
        actor_key = _required_value("campaign_start_store_actor", actor_user_id, 64)
        suffix = hashlib.sha256(command.campaign_id.encode()).hexdigest()[:12]
        async with self._sessions() as session, session.begin():
            if (idempotency_key is None) != (request_sha256 is None):
                raise ValueError("r124_start_idempotency_pair_required")
            if idempotency_key is not None and request_sha256 is not None:
                key = _required_value("r124_start_idempotency", idempotency_key, 200)
                _sha256("r124_start_request_sha256", request_sha256)
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": _campaign_core_idempotency_lock(tenant_key, key)},
                )
                records = metadata.tables["idempotency_records"]
                prior = (
                    await session.execute(
                        select(
                            records.c.request_hash,
                            records.c.response_body,
                        ).where(
                            records.c.tenant_id == tenant_key,
                            records.c.operation == "campaign.r124.start",
                            records.c.idempotency_key == key,
                        )
                    )
                ).mappings().one_or_none()
                if prior is not None:
                    return _campaign_core_start_replay(prior, request_sha256=request_sha256)
            result = await CampaignRepository(
                session,
                tenant_id=tenant_key,
                actor_user_id=actor_key,
                correlation_id=f"{self._correlation_prefix}-{suffix}",
            ).start_campaign(command, occurred_at=occurred_at)
            if idempotency_key is not None and request_sha256 is not None:
                records = metadata.tables["idempotency_records"]
                await session.execute(
                    insert(records).values(
                        id=f"idem-{uuid4().hex}",
                        tenant_id=tenant_key,
                        operation="campaign.r124.start",
                        idempotency_key=idempotency_key,
                        request_hash=request_sha256,
                        response_status=202,
                        response_body={
                            "campaign_id": result.campaign_id,
                            "workflow_id": result.workflow_id,
                            "aggregate_sequence": result.aggregate_sequence,
                            "audit_id": result.audit_id,
                            "outbox_id": result.outbox_id,
                        },
                        version=1,
                        created_at=occurred_at,
                        updated_at=occurred_at,
                    )
                )
            return result

    async def replay(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> CampaignTransitionResult | None:
        del actor_user_id
        tenant_key = _required_value("campaign_start_store_tenant", tenant_id, 64)
        key = _required_value("r124_start_idempotency", idempotency_key, 200)
        _sha256("r124_start_request_sha256", request_sha256)
        records = metadata.tables["idempotency_records"]
        async with self._sessions() as session, session.begin():
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _campaign_core_idempotency_lock(tenant_key, key)},
            )
            prior = (
                await session.execute(
                    select(records.c.request_hash, records.c.response_body).where(
                        records.c.tenant_id == tenant_key,
                        records.c.operation == "campaign.r124.start",
                        records.c.idempotency_key == key,
                    )
                )
            ).mappings().one_or_none()
        return None if prior is None else _campaign_core_start_replay(
            prior, request_sha256=request_sha256
        )


class CampaignStartService:
    def __init__(
        self,
        resolver: CampaignContextResolver,
        planner: CampaignStartPlanner,
        store: CampaignStartStore,
        identities: CampaignStartIdentitySource | None = None,
    ) -> None:
        self._resolver = resolver
        self._planner = planner
        self._store = store
        self._identities = identities or UuidCampaignStartIdentitySource()

    async def start(
        self,
        request: CampaignStartRequest,
        *,
        now: datetime,
        idempotency_key: str | None = None,
        request_sha256: str | None = None,
    ) -> object:
        if not isinstance(request, CampaignStartRequest):
            raise ValueError("campaign_start_request_invalid")
        if request_sha256 is not None and idempotency_key is None:
            raise ValueError("r124_start_idempotency_pair_required")
        _aware_start(now)
        resolution = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=request.tenant_id,
                principal_id=request.principal_id,
                engagement_id=request.engagement_id,
                target_id=request.target_id,
            ),
            now=now,
        )
        if not resolution.allowed or resolution.bindings is None:
            raise RuntimeError(f"campaign_start_denied:{resolution.reason}")
        authority = resolution.bindings
        # IMPORTANT: only this server-side source creates campaign/strategy identities.
        campaign_id = self._identities.new_campaign_id()
        strategy_record_id = self._identities.new_strategy_record_id()
        _required("campaign_start_generated_campaign", campaign_id, 64)
        _required("campaign_start_generated_strategy", strategy_record_id, 64)
        material = await self._planner.prepare(
            request, authority, campaign_id=campaign_id, now=now
        )
        if not isinstance(material, CampaignStartMaterial) or (
            material.tenant_id != request.tenant_id
            or material.engagement_id != request.engagement_id
            or material.target_id != request.target_id
            or material.target_sha256 != authority.target_sha256
            or material.context_payload.get("tenant_id") != request.tenant_id
            or material.context_payload.get("target_id") != request.target_id
            or material.decision_payload.get("objective_sha256")
            != material.objective_sha256
        ):
            raise ValueError("campaign_start_material_authority_mismatch")
        workflow_id = deterministic_closed_loop_campaign_workflow_id(
            request.tenant_id, campaign_id
        )
        workflow_request = ClosedLoopCampaignWorkflowInput(
            CONTRACT_SCHEMA_VERSION,
            request.tenant_id,
            campaign_id,
            material.plan_revision_id,
            material.envelope_sha256,
            2,
            1,
            3,
        )
        command = StartCampaignCommand(
            campaign_id=campaign_id,
            engagement_id=request.engagement_id,
            target_id=request.target_id,
            roe_id=authority.roe_version_id,
            strategy_record_id=strategy_record_id,
            strategy_revision_id=material.plan_revision_id,
            workflow_id=workflow_id,
            name=request.name,
            intent_sha256=material.objective_sha256,
            context_schema=material.context_schema,
            context_sha256=material.context_sha256,
            context_payload=material.context_payload,
            decision_schema=material.decision_schema,
            decision_sha256=material.decision_sha256,
            decision_payload=material.decision_payload,
            plan_revision=material.plan_revision,
            replan_count=0,
            plan_sha256=material.plan_sha256,
            plan_payload=material.plan_payload,
            proposal_ceiling_sha256=material.proposal_ceiling_sha256,
            approval_receipt_id=material.approval_receipt_id,
            approval_receipt_revision=material.approval_receipt_revision,
            approval_receipt_sha256=material.approval_receipt_sha256,
            envelope_core_sha256=material.envelope_core_sha256,
            envelope_sha256=material.envelope_sha256,
            workflow_request_sha256=closed_loop_workflow_request_sha256(workflow_request),
        )
        store_values: dict[str, object] = {
            "tenant_id": request.tenant_id,
            "actor_user_id": request.principal_id,
            "occurred_at": now,
        }
        if idempotency_key is not None:
            store_values.update({
                "idempotency_key": idempotency_key,
                "request_sha256": request_sha256 or canonical_campaign_sha256({
                    "tenant_id": request.tenant_id,
                    "principal_id": request.principal_id,
                    "engagement_id": request.engagement_id,
                    "target_id": request.target_id,
                    "name": request.name,
                    "objective_kind": request.objective_kind,
                    "header_code": request.header_code,
                    "require_corroboration": request.require_corroboration,
                    "risk_profile": request.risk_profile,
                }),
            })
        return await self._store.start(command, **store_values)

    async def replay(self, **values: object) -> object | None:
        return await self._store.replay(**values)


def _campaign_core_idempotency_lock(tenant_id: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(
        f"{tenant_id}\x1fcampaign.r124.start\x1f{idempotency_key}".encode()
    ).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _campaign_core_start_replay(
    prior: object, *, request_sha256: str
) -> CampaignTransitionResult:
    if prior["request_hash"] != request_sha256:
        raise IdempotencyConflict("idempotency_key_request_mismatch")
    body = prior["response_body"]
    if not isinstance(body, dict):
        raise ValueError("r124_start_replay_invalid")
    return CampaignTransitionResult(
        campaign_id=str(body["campaign_id"]),
        workflow_id=str(body["workflow_id"]),
        aggregate_sequence=int(body["aggregate_sequence"]),
        audit_id=str(body["audit_id"]),
        outbox_id=str(body["outbox_id"]),
        replayed=True,
    )


def _campaign_core_etag_revision(campaign_id: str, etag: str) -> int:
    prefix = f'"{campaign_id}:'
    if not etag.startswith(prefix) or not etag.endswith('"'):
        raise CampaignCoreEtagConflict("r124_etag_conflict")
    raw_revision = etag[len(prefix):-1]
    if not raw_revision.isdigit():
        raise CampaignCoreEtagConflict("r124_etag_conflict")
    revision = int(raw_revision)
    if revision < 1:
        raise CampaignCoreEtagConflict("r124_etag_conflict")
    return revision


def _adapter_request(
    command: EffectDispatchCommand, signed: SignedJobManifestV2
) -> CampaignAdapterRequest:
    manifest = signed.manifest
    return CampaignAdapterRequest(
        tenant_id=command.tenant_id,
        capability_id=manifest.capability_id,
        capability_revision=manifest.capability_revision,
        adapter_id=manifest.v1.adapter_id,
        adapter_version=manifest.v1.adapter_version,
        profile_id=manifest.profile_id,
        profile_revision=manifest.profile_revision,
        profile_sha256=manifest.profile_sha256,
        bundle_id=manifest.bundle_id,
        bundle_revision=manifest.bundle_revision,
        bundle_sha256=manifest.bundle_sha256,
        invocation_id=command.invocation_id,
        effect_id=command.effect_id,
        envelope_sha256=command.envelope_sha256,
        manifest_v2_sha256=signed.manifest_sha256,
    )


def _validate_closed_binding(binding: CapabilityBindingKeyV1) -> None:
    closed = closed_execution_registry().get(
        f"{binding.capability_id}@{binding.capability_revision}"
    )
    if closed is None or (
        binding.adapter_id,
        binding.adapter_version,
        binding.profile_id,
        binding.profile_revision,
        binding.profile_sha256,
        binding.bundle_id,
        binding.bundle_revision,
        binding.bundle_sha256,
    ) != (
        closed.adapter_id,
        closed.adapter_version,
        closed.profile_id,
        closed.profile_revision,
        closed.profile_sha256,
        closed.bundle_id,
        closed.bundle_revision,
        closed.bundle_sha256,
    ):
        raise ValueError("effect_capability_binding_not_closed")


def binding_from_campaign_context(
    context_payload: dict[str, object], capability_id: str
) -> CapabilityBindingKeyV1:
    """Rehydrate one exact binding from immutable persisted compat_119 material."""
    if not isinstance(context_payload, dict):
        raise ValueError("campaign_context_binding_inventory_invalid")
    raw_bindings = context_payload.get("bindings")
    if not isinstance(raw_bindings, list) or len(raw_bindings) not in {2, 3}:
        raise ValueError("campaign_context_binding_inventory_invalid")
    try:
        bindings = tuple(
            CapabilityBindingKeyV1(**item)
            for item in raw_bindings
            if isinstance(item, dict)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("campaign_context_binding_inventory_invalid") from exc
    capability_ids = {item.capability_id for item in bindings}
    expected_ids = (
        {"zap-controlled-runtime", "nuclei-trusted-runtime"}
        if len(bindings) == 2
        else {"artifact-posture", "zap-controlled-runtime", "nuclei-trusted-runtime"}
    )
    if len(bindings) != len(raw_bindings) or capability_ids != expected_ids:
        raise ValueError("campaign_context_binding_inventory_invalid")
    selected = tuple(item for item in bindings if item.capability_id == capability_id)
    if len(selected) != 1:
        raise ValueError("campaign_context_binding_not_found")
    _validate_closed_binding(selected[0])
    return selected[0]


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_safe(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _json_safe(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(item) for item in value]
    return value


def _required(name: str, value: object, maximum: int) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _required_value(name: str, value: object, maximum: int) -> str:
    _required(name, value, maximum)
    return value


def _sha256(name: str, value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name}_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("effect_dispatch_time_timezone_required")


def _aware_start(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("campaign_start_time_timezone_required")
