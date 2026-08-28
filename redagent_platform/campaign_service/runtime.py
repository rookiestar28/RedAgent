"""Concrete read-only PostgreSQL owners used by the compat_123 runtime boundary."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import and_, func, select

from redagent_platform.agent_kernel.qualification import build_projection_catalog
from redagent_platform.artifact_pipeline.capability import build_artifact_capability
from redagent_platform.artifact_pipeline.profiles import certified_profiles as certified_artifact_profiles
from redagent_platform.artifact_pipeline.promotion import verify_current_artifact_promotion
from redagent_platform.campaign_service.context import (
    build_artifact_posture_target_mapping,
    build_decision_context_snapshot,
    build_first_slice_semantics,
    build_first_slice_target_mapping,
    canonical_sha256,
    promote_artifact_posture_semantics,
)
from redagent_platform.campaign_service.contracts import (
    AuthorityContextV1,
    CollectionState,
    PlanRevisionV1,
    StrategyDecisionReceiptV1,
    StrategyObjectiveKind,
    StrategyObjectiveV1,
    TypedReferenceV1,
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
from redagent_platform.campaign_service.qualification import QualificationFixtureBinding
from redagent_platform.campaign_service.resolver import (
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.repository import campaign_core_principal_is_active
from redagent_platform.campaign_service.service import (
    CampaignAuthorizationMaterial,
    CampaignPlanningFacts,
    CampaignStartRequest,
)
from redagent_platform.nuclei_service.artifact_promotion import (
    verify_current_nuclei_artifact_promotion,
)
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
)
from redagent_platform.nuclei_service.promotion import (
    verify_current_nuclei_bundle_promotion,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.contracts import (
    ExecutionCapabilityManifest,
    canonical_capability_sha256,
)
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.zap_service.contracts import CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM
from redagent_platform.zap_service.promotion import verify_current_zap_promotion


_FIXTURE_ID = "owned-loopback-http-first-slice"
_LAB_BUNDLE_ID = "r123-owned-loopback-http-first-slice"
_MAX_MEMBERSHIP_AGE = timedelta(minutes=5)
_EXPECTED_ADAPTERS = frozenset({
    "zap-service:2.17.0-r104.2",
    "nuclei-service:3.11.1-r105.2",
})
_EXPECTED_ARTIFACT_ADAPTERS = frozenset({
    *_EXPECTED_ADAPTERS,
    "redagent-canonical-artifact:1.0.0-r110.1",
})
_EXPECTED_IMAGES = frozenset({
    CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
})


def local_campaign_promotion_readiness(
    workspace: Path,
    *,
    now: datetime,
) -> tuple[bool, bool]:
    """Verify current signed ZAP and Nuclei promotion evidence without runtime I/O."""
    _aware(now)
    root = workspace.resolve()
    try:
        _verify_current_zap(root, now=now)
        zap_ready = True
    except (OSError, ValueError):
        zap_ready = False
    try:
        _verify_current_nuclei(root, now=now)
        nuclei_ready = True
    except (OSError, ValueError):
        nuclei_ready = False
    return zap_ready, nuclei_ready


def local_artifact_promotion_readiness(workspace: Path, *, now: datetime) -> bool:
    """Verify the exact current-source artifact promotion without runtime I/O."""
    _aware(now)
    try:
        verify_current_artifact_promotion(workspace.resolve(), now=now)
        return True
    except (OSError, ValueError):
        return False


def _verify_current_zap(root: Path, *, now: datetime):
    attestations = root / "runtime-assets" / "attestations"
    return verify_current_zap_promotion(
        promotion_bytes=(
            attestations / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.json"
        ).read_bytes(),
        bundle_bytes=(
            attestations / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.sigstore.json"
        ).read_bytes(),
        public_key_bytes=(
            attestations / "260824-R104_ZAP_ARTIFACT_PROMOTION_V2.pub"
        ).read_bytes(),
        runtime_lock_bytes=(root / "config/r104-zap-runtime-v2.json").read_bytes(),
        qualification_bytes=(
            attestations / "260824-R104_ZAP_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes(),
        now=now,
    )


def _verify_current_nuclei(root: Path, *, now: datetime):
    attestations = root / "runtime-assets" / "attestations"
    qualification = (
        attestations / "260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
    ).read_bytes()
    artifact, signature_sha256 = verify_current_nuclei_artifact_promotion(
        promotion_bytes=(
            attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.json"
        ).read_bytes(),
        signature_bundle_bytes=(
            attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.sigstore.json"
        ).read_bytes(),
        public_key_bytes=(
            attestations / "260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.pub"
        ).read_bytes(),
        runtime_lock_bytes=(root / "config/r105-nuclei-runtime-v2.json").read_bytes(),
        qualification_bytes=qualification,
        now=now,
    )
    bundle = verify_current_nuclei_bundle_promotion(
        manifest_bytes=(root / "bundles/r105-nuclei/bundle-manifest-v2.json").read_bytes(),
        signature_bundle_bytes=(
            attestations / "260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.sigstore.json"
        ).read_bytes(),
        public_key_bytes=(
            attestations / "260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.pub"
        ).read_bytes(),
        template_bytes=(
            root / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml"
        ).read_bytes(),
        certificate_bytes=(root / "config/trust/r105-nuclei-user.crt").read_bytes(),
        qualification_bytes=qualification,
        now=now,
    )
    return artifact, signature_sha256, bundle


class LocalCampaignPlanningFactsOwner:
    """Build the initial compat_119 facts only from the exact signed first-slice artifacts."""

    def __init__(self, workspace: Path) -> None:
        root = workspace.resolve()
        if not root.is_dir():
            raise ValueError("r123_planning_workspace_invalid")
        self._workspace = root

    async def read(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        *,
        now: datetime,
    ) -> CampaignPlanningFacts:
        if not isinstance(request, CampaignStartRequest):
            raise ValueError("r123_planning_request_invalid")
        if not isinstance(authority, CanonicalAuthoritySnapshot):
            raise ValueError("r123_planning_authority_invalid")
        _aware(now)
        zap, _ = _verify_current_zap(self._workspace, now=now)
        nuclei, _, bundle = _verify_current_nuclei(self._workspace, now=now)
        zap_capability = build_zap_capability_manifest(
            platform="linux/amd64",
            artifact_receipt_id=zap.receipt_id,
        )
        nuclei_capability = build_nuclei_capability_manifest(
            platform="linux/amd64",
            artifact_receipt_id=nuclei.receipt_id,
        )
        artifact_objective = request.objective_kind == StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE.value
        artifact_promotion = None
        artifact_capability = None
        capabilities: tuple[ExecutionCapabilityManifest, ...] = (
            zap_capability,
            nuclei_capability,
        )
        if artifact_objective:
            if authority.target_resolution_mode != "canonical-artifact-binding":
                raise ValueError("artifact_campaign_target_resolution_denied")
            artifact_promotion = verify_current_artifact_promotion(self._workspace, now=now)
            artifact_capability = build_artifact_capability(
                artifact_receipt_id=artifact_promotion.receipt.receipt_id,
                source_digest=artifact_promotion.receipt.image_digest,
            )
            capabilities = (*capabilities, artifact_capability)
        projections = build_projection_catalog(capabilities)
        projection_by_capability = {
            item.source_capability_id: item for item in projections
        }
        promoted_at = max(zap.verified_at, nuclei.verified_at, bundle.promoted_at)
        expires_at = min(zap.expires_at, nuclei.expires_at, bundle.expires_at)
        first_slice_semantics = build_first_slice_semantics(
            zap_capability=zap_capability,
            nuclei_capability=nuclei_capability,
            nuclei_bundle=bundle,
            zap_projection=projection_by_capability["zap-controlled-runtime"],
            nuclei_projection=projection_by_capability["nuclei-trusted-runtime"],
            promoted_at=promoted_at,
            expires_at=expires_at,
        )
        semantics = first_slice_semantics
        mapping = build_first_slice_target_mapping(semantics)
        target_classes = (
            "owned-http-application",
            "synthetic-security-header-fixture",
            "owned-loopback-lab",
            "owned-loopback-gateway",
        )
        artifact_receipt = None
        if artifact_objective:
            assert artifact_capability is not None and artifact_promotion is not None
            expires_at = min(expires_at, artifact_promotion.receipt.expires_at)
            semantics = promote_artifact_posture_semantics(
                first_slice_semantics=first_slice_semantics,
                artifact_capability=artifact_capability,
                artifact_projection=projection_by_capability["artifact-posture"],
                profile=certified_artifact_profiles()["r110-repository-snapshot-v1"],
                promoted_at=artifact_promotion.receipt.verified_at,
                expires_at=artifact_promotion.receipt.expires_at,
            )
            mapping = build_artifact_posture_target_mapping(semantics)
            target_classes = (
                "repository-snapshot",
                "canonical-artifact-binding",
                "data-only-sandbox",
                "no-url",
            )
            artifact_receipt = TypedReferenceV1(
                kind="artifact-receipt",
                reference_id=artifact_promotion.receipt.receipt_id,
                sha256=canonical_capability_sha256(artifact_capability),
            )
        r119_authority = AuthorityContextV1(
            schema_version="redagent.r119-authority-context/v1",
            tenant_id=request.tenant_id,
            engagement_id=request.engagement_id,
            principal_id=request.principal_id,
            target=TypedReferenceV1(
                kind="target",
                reference_id=request.target_id,
                sha256=authority.target_sha256,
            ),
            target_mapping_sha256=mapping.mapping_sha256,
            target_class=target_classes[0],
            application_class=target_classes[1],
            environment_class=target_classes[2],
            url_class=target_classes[3],
            roe_version_id=authority.roe_version_id,
            roe_sha256=authority.roe_sha256,
            roe_status=authority.roe_status,
            policy_decision_id=authority.policy_decision_id,
            policy_revision=authority.policy_revision,
            policy_sha256=authority.policy_sha256,
            policy_status=authority.policy_status,
            issued_at=authority.observed_at,
            expires_at=min(
                authority.expires_at,
                authority.lease_expires_at,
                expires_at,
            ),
        )
        snapshot = build_decision_context_snapshot(
            semantics=semantics,
            target_mapping=mapping,
            authority=r119_authority,
            collection_state=CollectionState.COMPLETE,
            current_observations=(),
            current_evidence_facts=(),
            current_finding_facts=(),
            prior_complete_snapshot=None,
            snapshot_at=now,
        )
        return CampaignPlanningFacts(
            snapshot,
            r119_authority,
            projections,
            artifact_receipt=artifact_receipt,
        )


class PolicyBoundCampaignAuthorizationOwner:
    """Sign one deterministic Tier-1 envelope bound to the current policy decision."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        *,
        signing_key_id: str,
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ValueError("r123_authorization_signing_key_invalid")
        _identifier("r123_authorization_signing_key_id", signing_key_id, 100)
        self._signing_key = signing_key
        self._signing_key_id = signing_key_id

    async def authorize(
        self,
        request: CampaignStartRequest,
        authority: CanonicalAuthoritySnapshot,
        objective: StrategyObjectiveV1,
        receipt: StrategyDecisionReceiptV1,
        plan: PlanRevisionV1,
        *,
        now: datetime,
    ) -> CampaignAuthorizationMaterial:
        _aware(now)
        expiry = min(
            now + timedelta(minutes=2),
            authority.expires_at,
            authority.lease_expires_at,
        )
        if expiry <= now:
            raise ValueError("r123_authorization_expired")
        artifact_objective = objective.kind is StrategyObjectiveKind.REPOSITORY_SNAPSHOT_POSTURE
        target_resolution_mode = (
            "canonical-artifact-binding" if artifact_objective else "owned-loopback"
        )
        execution_mode = "data-only-zero-execution" if artifact_objective else "passive-read-only"
        egress_profile = "none" if artifact_objective else "owned-loopback-only"
        sandbox_class = "artifact-r110-data-only" if artifact_objective else "container-non-root-read-only"
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
                execution_mode=execution_mode,
                arguments_schema_sha256=canonical_sha256({
                    "schema": "redagent.r123-closed-adapter-arguments/v1",
                    "capability_id": item.binding_key.capability_id,
                }),
                arguments_ceiling_sha256=canonical_sha256({
                    "target_resolution_mode": target_resolution_mode,
                    "credential_class": "none",
                    "width": 1,
                }),
                arguments_max_bytes=4096,
            )
            for item in receipt.snapshot.semantics
        )
        budget = EffectBudgetV1(
            duration_seconds=60,
            request_count=1 if artifact_objective else 60,
            concurrency=1,
            data_bytes=1024 * 1024,
            evidence_bytes=1024 * 1024,
            impact_count=0,
            replan_count=1,
            plan_depth=1 if artifact_objective else 2,
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
        stable = canonical_sha256({
            "policy_decision_id": authority.policy_decision_id,
            "objective_sha256": receipt.objective_sha256,
            "plan_sha256": plan.plan_sha256,
        })
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
            egress_profile=egress_profile,
            sandbox_class=sandbox_class,
            runner_class="r123-closed-runner",
            risk_ceiling="tier1-passive-read-only",
            budget=budget,
            observation_freshness_seconds=300,
            obligations=obligations,
            approval_tier=ApprovalTier.TIER_1,
            expires_at=expiry,
            nonce=f"ceiling-{stable[:32]}",
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
            sandbox_class=sandbox_class,
            runner_class="r123-closed-runner",
            reservation_id=authority.reservation_id,
            lease_id=authority.lease_id,
            arguments_sha256=canonical_sha256({
                "primary": plan.primary,
                "successor": plan.successor,
            }),
            effect_sha256=canonical_sha256({
                "objective_sha256": receipt.objective_sha256,
                "plan_sha256": plan.plan_sha256,
            }),
            effective_budget=budget,
            policy_revocation_epoch=authority.policy_revocation_epoch,
            roe_revocation_epoch=authority.roe_revocation_epoch,
            issued_at=now,
            expires_at=expiry,
            nonce=f"envelope-{stable[32:]}",
        )
        approval = sign_approval_receipt(
            core,
            self._signing_key,
            approval_id=authority.policy_decision_id,
            approval_revision=authority.policy_revocation_epoch + 1,
            approver_id="redagent-policy-boundary",
            key_id=self._signing_key_id,
            approved_at=now,
            expires_at=expiry,
        )
        return CampaignAuthorizationMaterial(
            ceiling,
            approval,
            build_safety_envelope(
                core,
                approval,
                self._signing_key.public_key(),
                now=now,
            ),
        )


class PostgresEnvelopeAuthorityVerifier:
    """Re-read the exact current strategy/effect envelope immediately before dispatch."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def verify_current_envelope(
        self,
        command: object,
        snapshot: CanonicalAuthoritySnapshot,
        *,
        now: datetime,
    ) -> str | None:
        from redagent_platform.campaign_service.service import EffectDispatchCommand

        if not isinstance(command, EffectDispatchCommand):
            raise ValueError("r123_envelope_command_invalid")
        if not isinstance(snapshot, CanonicalAuthoritySnapshot):
            raise ValueError("r123_envelope_authority_invalid")
        _aware(now)
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, command.tenant_id)
            campaigns = metadata.tables["campaigns"]
            strategies = metadata.tables["campaign_strategy_revisions"]
            effects = metadata.tables["campaign_effects"]
            row = (
                await session.execute(
                    select(
                        campaigns.c.engagement_id,
                        campaigns.c.current_strategy_revision_id,
                        strategies.c.id.label("strategy_record_id"),
                        strategies.c.context_payload,
                        strategies.c.decision_payload,
                        strategies.c.approval_receipt_id,
                        strategies.c.envelope_sha256.label("strategy_envelope_sha256"),
                        strategies.c.created_by_user_id,
                        effects.c.invocation_id,
                        effects.c.strategy_revision_id.label("effect_strategy_record_id"),
                        effects.c.effect_intent_payload,
                        effects.c.envelope_sha256.label("effect_envelope_sha256"),
                        effects.c.effect_state,
                        effects.c.claim_owner,
                        effects.c.claim_expires_at,
                        effects.c.claim_version,
                    )
                    .select_from(
                        effects.join(
                            campaigns,
                            and_(
                                campaigns.c.tenant_id == effects.c.tenant_id,
                                campaigns.c.id == effects.c.campaign_id,
                            ),
                        ).join(
                            strategies,
                            and_(
                                strategies.c.tenant_id == effects.c.tenant_id,
                                strategies.c.id == effects.c.strategy_revision_id,
                            ),
                        )
                    )
                    .where(
                        effects.c.tenant_id == command.tenant_id,
                        effects.c.effect_id == command.effect_id,
                    )
                    .limit(2)
                )
            ).mappings().all()
        if len(row) != 1:
            return "r123_envelope_persisted_state_not_unique"
        persisted = row[0]
        if (
            persisted["current_strategy_revision_id"]
            != persisted["strategy_record_id"]
            or persisted["effect_strategy_record_id"]
            != persisted["strategy_record_id"]
            or persisted["invocation_id"] != command.invocation_id
        ):
            return "r123_envelope_strategy_drift"
        if (
            persisted["effect_state"] not in {"claimed", "dispatching"}
            or persisted["claim_owner"] != command.claim_owner
            or int(persisted["claim_version"]) != command.expected_claim_version
            or persisted["claim_expires_at"] is None
            or persisted["claim_expires_at"] <= now
        ):
            return "r123_envelope_claim_drift"
        if (
            snapshot.tenant_id != command.tenant_id
            or snapshot.principal_id != command.principal_id
            or snapshot.engagement_id != command.engagement_id
            or snapshot.target_id != command.target_id
            or persisted["engagement_id"] != command.engagement_id
            or persisted["created_by_user_id"] != command.principal_id
        ):
            return "r123_envelope_authority_scope_drift"
        if (
            persisted["strategy_envelope_sha256"] != command.envelope_sha256
            or persisted["effect_envelope_sha256"] != command.envelope_sha256
            or persisted["approval_receipt_id"] != snapshot.policy_decision_id
        ):
            return "r123_envelope_digest_drift"
        decision = persisted["decision_payload"]
        if not isinstance(decision, dict):
            return "r123_envelope_decision_invalid"
        if (
            decision.get("policy_revision") != snapshot.policy_revision
            or decision.get("policy_sha256") != snapshot.policy_sha256
        ):
            return "r123_envelope_policy_drift"
        if (
            decision.get("roe_version_id") != snapshot.roe_version_id
            or decision.get("roe_sha256") != snapshot.roe_sha256
        ):
            return "r123_envelope_roe_drift"
        objective = decision.get("objective")
        target = objective.get("target") if isinstance(objective, dict) else None
        if not isinstance(target, dict) or (
            target.get("reference_id") != snapshot.target_id
            or target.get("sha256") != snapshot.target_sha256
        ):
            return "r123_envelope_target_drift"
        binding = asdict(command.binding)
        context = persisted["context_payload"]
        effect_intent = persisted["effect_intent_payload"]
        if (
            not isinstance(context, dict)
            or context.get("bindings") is None
            or not isinstance(context["bindings"], list)
            or sum(item == binding for item in context["bindings"]) != 1
            or not isinstance(effect_intent, dict)
            or effect_intent.get("binding") != binding
        ):
            return "r123_envelope_binding_drift"
        return None


class PostgresCanonicalAuthorityProvider:
    """Rehydrate current compat_123 authority exclusively from accepted relational owners."""

    def __init__(
        self,
        sessions: object,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._sessions = sessions
        self._clock = clock

    async def read_current_authority(
        self, request: ResolutionRequest
    ) -> CanonicalAuthoritySnapshot | None:
        if not isinstance(request, ResolutionRequest):
            raise ValueError("r123_runtime_resolution_request_invalid")
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, request.tenant_id)
            observed_at = (
                self._clock() if self._clock is not None else await session.scalar(select(func.now()))
            )
            _aware(observed_at)
            base = await _read_base_authority(session, request, observed_at)
            if base is None:
                return None
            roe = await _read_current_roe(
                session,
                tenant_id=request.tenant_id,
                engagement_id=request.engagement_id,
            )
            if roe is None or not _roe_covers_target(roe, str(base["target_value"])):
                return None
            policy = await _read_current_policy(
                session,
                request=request,
                target_revision=int(base["target_revision"]),
                now=observed_at,
            )
            if policy is None:
                return None
            artifact_target = base["target_type"] == "repository_snapshot"
            lab = None
            if not artifact_target:
                lab = await _read_current_lab_lease(
                    session,
                    tenant_id=request.tenant_id,
                    target_id=request.target_id,
                    target_value=str(base["target_value"]),
                    roe_id=str(roe["roe_id"]),
                    policy_decision_id=str(policy["policy_decision_id"]),
                    now=observed_at,
                )
                if lab is None:
                    return None
            quota = await _read_current_quota(
                session,
                tenant_id=request.tenant_id,
                now=observed_at,
            )
            if quota is None or _quota_remaining(quota) <= 0:
                return None
            runner_id = None
            if not artifact_target:
                assert lab is not None
                runner_id = str(lab["runner_id"])
            runner = await _read_current_runner(
                session,
                tenant_id=request.tenant_id,
                runner_id=runner_id,
                policy_revision=str(policy["policy_revision"]),
                now=observed_at,
                artifact_target=artifact_target,
            )
            if runner is None or not _runner_row_exact(runner, artifact_target=artifact_target):
                return None
            stop_requested = await _read_stop_requested(
                session,
                tenant_id=request.tenant_id,
            )
        authority_expiries = [
            policy["valid_until"],
            quota["reservation_expires_at"],
            quota["policy_active_until"],
            quota["window_end"],
            runner["registration_expires_at"],
            runner["identity_not_after"],
        ]
        if artifact_target:
            authority_expiries.append(base["binding_expires_at"])
            lease_id = request.target_id
            lease_expires_at = base["binding_expires_at"]
        else:
            assert lab is not None
            authority_expiries.extend((
                lab["lease_expires_at"],
                lab["attestation_expires_at"],
                lab["bundle_expires_at"],
            ))
            lease_id = str(lab["lease_id"])
            lease_expires_at = lab["lease_expires_at"]
        expires_at = min(authority_expiries)
        return CanonicalAuthoritySnapshot(
            tenant_id=request.tenant_id,
            principal_id=request.principal_id,
            engagement_id=request.engagement_id,
            engagement_version=int(base["engagement_version"]),
            roe_version_id=str(roe["roe_id"]),
            roe_revision=int(roe["roe_revision"]),
            roe_sha256=_digest(roe["roe_document"]),
            roe_status="approved",
            roe_revocation_epoch=int(roe["roe_version"]),
            policy_decision_id=str(policy["policy_decision_id"]),
            policy_revision=str(policy["policy_revision"]),
            policy_sha256=_digest({
                "decision_id": policy["policy_decision_id"],
                "revision": policy["policy_revision"],
                "input_sha256": policy["input_hash"],
                "action": policy["action"],
                "subject_id": policy["subject_id"],
                "resource_type": policy["resource_type"],
                "resource_id": policy["resource_id"],
                "resource_version": policy["resource_version"],
                "obligations": policy["obligations"],
                "valid_until": policy["valid_until"],
            }),
            policy_status="allowed",
            policy_revocation_epoch=int(policy["policy_version"]),
            target_id=request.target_id,
            target_revision=int(base["target_revision"]),
            target_sha256=_digest({
                "target_id": request.target_id,
                "revision": base["target_revision"],
                "target_type": "repository" if artifact_target else base["target_type"],
                "normalized_value": base["target_value"],
            }),
            target_value=str(base["target_value"]),
            target_resolution_mode=(
                "canonical-artifact-binding" if artifact_target else "owned-loopback"
            ),
            credential_class="none",
            credential_reference=None,
            quota_reference=str(quota["quota_policy_id"]),
            quota_available=True,
            runner_id=str(runner["runner_id"]),
            runner_workload_identity=str(runner["spiffe_id"]),
            runner_ready=True,
            reservation_id=str(quota["reservation_id"]),
            lease_id=lease_id,
            lease_expires_at=lease_expires_at,
            stop_requested=stop_requested,
            observed_at=observed_at,
            expires_at=expires_at,
        )


class PostgresQualificationFixtureOwner:
    """Resolve the sole fixture from current canonical compat_093/compat_103 owners without minting IDs."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def read_owned_loopback_fixture(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        fixture_id: str,
        now: datetime,
    ) -> QualificationFixtureBinding:
        _identifier("r123_runtime_tenant", tenant_id, 64)
        _identifier("r123_runtime_principal", principal_id, 64)
        _aware(now)
        if fixture_id != _FIXTURE_ID:
            raise ValueError("r123_qualification_fixture_invalid")
        users = metadata.tables["users"]
        memberships = metadata.tables["tenant_memberships"]
        engagements = metadata.tables["engagements"]
        targets = metadata.tables["targets"]
        roe = metadata.tables["roe_versions"]
        approvals = metadata.tables["approvals"]
        bundles = metadata.tables["lab_bundles"]
        attestations = metadata.tables["lab_target_attestations"]
        leases = metadata.tables["lab_target_leases"]
        statement = (
            select(
                engagements.c.id.label("engagement_id"),
                targets.c.id.label("target_id"),
                targets.c.normalized_value.label("target_value"),
                roe.c.id.label("roe_id"),
                bundles.c.network_id,
                attestations.c.endpoint.label("attestation_endpoint"),
                attestations.c.attestation_sha256,
                attestations.c.allowed_test_classes,
                leases.c.endpoint.label("lease_endpoint"),
                leases.c.attestation_sha256.label("lease_attestation_sha256"),
                leases.c.roe_version_id.label("lease_roe_id"),
            )
            .select_from(
                users.join(
                    memberships,
                    and_(
                        memberships.c.tenant_id == users.c.tenant_id,
                        memberships.c.user_id == users.c.id,
                    ),
                )
                .join(
                    engagements,
                    and_(
                        engagements.c.tenant_id == users.c.tenant_id,
                        engagements.c.owner_user_id == users.c.id,
                    ),
                )
                .join(
                    targets,
                    and_(
                        targets.c.tenant_id == engagements.c.tenant_id,
                        targets.c.engagement_id == engagements.c.id,
                    ),
                )
                .join(
                    roe,
                    and_(
                        roe.c.tenant_id == engagements.c.tenant_id,
                        roe.c.engagement_id == engagements.c.id,
                    ),
                )
                .join(
                    approvals,
                    and_(
                        approvals.c.tenant_id == roe.c.tenant_id,
                        approvals.c.roe_version_id == roe.c.id,
                    ),
                )
                .join(
                    attestations,
                    and_(
                        attestations.c.tenant_id == targets.c.tenant_id,
                        attestations.c.target_id == targets.c.id,
                    ),
                )
                .join(
                    bundles,
                    and_(
                        bundles.c.tenant_id == attestations.c.tenant_id,
                        bundles.c.id == attestations.c.bundle_record_id,
                    ),
                )
                .join(
                    leases,
                    and_(
                        leases.c.tenant_id == attestations.c.tenant_id,
                        leases.c.attestation_record_id == attestations.c.id,
                        leases.c.target_id == targets.c.id,
                    ),
                )
            )
            .where(
                users.c.tenant_id == tenant_id,
                users.c.id == principal_id,
                memberships.c.status == "active",
                memberships.c.last_validated_at >= now - _MAX_MEMBERSHIP_AGE,
                memberships.c.last_validated_at <= now,
                roe.c.status == "approved",
                bundles.c.bundle_id == _LAB_BUNDLE_ID,
                bundles.c.bundle_state == "active",
                bundles.c.activated_at <= now,
                bundles.c.expires_at > now,
                attestations.c.fixture_kind == "web",
                attestations.c.non_production.is_(True),
                attestations.c.attestation_state == "active",
                attestations.c.issued_at <= now,
                attestations.c.expires_at > now,
                leases.c.test_class == "finding_mapping",
                leases.c.lease_state == "active",
                leases.c.issued_at <= now,
                leases.c.expires_at > now,
                leases.c.revoked_at.is_(None),
            )
            .order_by(engagements.c.id, targets.c.id, roe.c.revision.desc())
            .limit(3)
        )
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            rows = (await session.execute(statement)).mappings().all()
        valid = [row for row in rows if _fixture_row_valid(row)]
        if len(valid) != 1:
            raise RuntimeError("r123_qualification_fixture_not_current")
        row = valid[0]
        return QualificationFixtureBinding(
            fixture_id=_FIXTURE_ID,
            engagement_id=str(row["engagement_id"]),
            target_id=str(row["target_id"]),
            campaign_name="R123 owned-loopback qualification",
        )


class PostgresRunnerIdentityOwner:
    """Read one current exact compat_100 registered and observed runner identity."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def read_current_identity(
        self,
        *,
        tenant_id: str,
        runner_id: str,
        now: datetime,
    ) -> PeerCertificateIdentity:
        _identifier("r123_runtime_tenant", tenant_id, 64)
        _identifier("r123_runtime_runner", runner_id, 100)
        _aware(now)
        registrations = metadata.tables["runner_registrations"]
        identities = metadata.tables["runner_identities"]
        async with self._sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            rows = (
                await session.execute(
                    select(
                        registrations.c.runner_id,
                        registrations.c.spiffe_id.label("registered_spiffe_id"),
                        registrations.c.certificate_fingerprint.label(
                            "registered_fingerprint"
                        ),
                        registrations.c.certificate_serial.label("registered_serial"),
                        identities.c.spiffe_id,
                        identities.c.certificate_fingerprint,
                        identities.c.certificate_serial,
                        identities.c.not_before,
                        identities.c.not_after,
                    )
                    .select_from(
                        registrations.join(
                            identities,
                            and_(
                                identities.c.tenant_id == registrations.c.tenant_id,
                                identities.c.registration_id == registrations.c.id,
                            ),
                        )
                    )
                    .where(
                        registrations.c.tenant_id == tenant_id,
                        registrations.c.runner_id == runner_id,
                        registrations.c.registration_state == "active",
                        registrations.c.registered_at <= now,
                        registrations.c.expires_at > now,
                        registrations.c.revoked_at.is_(None),
                        identities.c.identity_state == "observed",
                        identities.c.not_before <= now,
                        identities.c.not_after > now,
                    )
                    .order_by(registrations.c.generation.desc())
                    .limit(2)
                )
            ).mappings().all()
        if len(rows) != 1 or not _identity_row_exact(rows[0]):
            raise RuntimeError("r123_runner_identity_not_current")
        row = rows[0]
        return PeerCertificateIdentity(
            runner_id=str(row["runner_id"]),
            spiffe_id=str(row["spiffe_id"]),
            certificate_fingerprint=str(row["certificate_fingerprint"]),
            certificate_serial=str(row["certificate_serial"]),
            not_before=row["not_before"],
            not_after=row["not_after"],
        )


def _fixture_row_valid(row: object) -> bool:
    classes = row["allowed_test_classes"]
    return (
        row["network_id"] == "redagent-r103-lab"
        and isinstance(classes, list)
        and "finding_mapping" in classes
        and row["target_value"] == row["attestation_endpoint"] == row["lease_endpoint"]
        and row["attestation_sha256"] == row["lease_attestation_sha256"]
        and row["roe_id"] == row["lease_roe_id"]
    )


def _identity_row_exact(row: object) -> bool:
    return (
        row["registered_spiffe_id"] == row["spiffe_id"]
        and row["registered_fingerprint"] == row["certificate_fingerprint"]
        and row["registered_serial"] == row["certificate_serial"]
    )


async def _read_base_authority(session: object, request: ResolutionRequest, now: datetime):
    engagements = metadata.tables["engagements"]
    targets = metadata.tables["targets"]
    if not await campaign_core_principal_is_active(
        session,
        tenant_id=request.tenant_id,
        principal_id=request.principal_id,
        now=now,
    ):
        return None
    rows = (
        await session.execute(
            select(
                engagements.c.version.label("engagement_version"),
                targets.c.version.label("target_revision"),
                targets.c.target_type,
                targets.c.normalized_value.label("target_value"),
            )
            .select_from(
                engagements.join(
                    targets,
                    and_(
                        targets.c.tenant_id == engagements.c.tenant_id,
                        targets.c.engagement_id == engagements.c.id,
                    ),
                )
            )
            .where(
                engagements.c.tenant_id == request.tenant_id,
                engagements.c.id == request.engagement_id,
                targets.c.id == request.target_id,
                targets.c.target_type == "url",
            )
            .limit(2)
        )
    ).mappings().all()
    if len(rows) == 1:
        return rows[0]
    if rows:
        return None
    artifact_bindings = metadata.tables["artifact_bindings"]
    artifact_rows = (
        await cast(Any, session).execute(
            select(
                engagements.c.version.label("engagement_version"),
                artifact_bindings.c.version.label("target_revision"),
                artifact_bindings.c.artifact_kind.label("target_type"),
                artifact_bindings.c.binding_id.label("target_value"),
                artifact_bindings.c.expires_at.label("binding_expires_at"),
            )
            .select_from(engagements.join(
                artifact_bindings,
                artifact_bindings.c.tenant_id == engagements.c.tenant_id,
            ))
            .where(
                engagements.c.tenant_id == request.tenant_id,
                engagements.c.id == request.engagement_id,
                artifact_bindings.c.binding_id == request.target_id,
                artifact_bindings.c.artifact_kind == "repository_snapshot",
                artifact_bindings.c.binding_state == "active-canonical-fixture",
                artifact_bindings.c.expires_at > now,
            )
            .limit(2)
        )
    ).mappings().all()
    return artifact_rows[0] if len(artifact_rows) == 1 else None


async def _read_current_roe(session: object, *, tenant_id: str, engagement_id: str):
    roe = metadata.tables["roe_versions"]
    approvals = metadata.tables["approvals"]
    policy_references = metadata.tables["policy_references"]
    rows = (
        await session.execute(
            select(
                roe.c.id.label("roe_id"),
                roe.c.revision.label("roe_revision"),
                roe.c.document.label("roe_document"),
                roe.c.version.label("roe_version"),
                policy_references.c.policy_name,
                policy_references.c.policy_version,
            )
            .select_from(
                roe.join(
                    approvals,
                    and_(
                        approvals.c.tenant_id == roe.c.tenant_id,
                        approvals.c.roe_version_id == roe.c.id,
                    ),
                ).join(
                    policy_references,
                    and_(
                        policy_references.c.tenant_id == roe.c.tenant_id,
                        policy_references.c.roe_version_id == roe.c.id,
                    ),
                )
            )
            .where(
                roe.c.tenant_id == tenant_id,
                roe.c.engagement_id == engagement_id,
                roe.c.status == "approved",
            )
            .order_by(roe.c.revision.desc())
            .limit(2)
        )
    ).mappings().all()
    if not rows:
        return None
    if len(rows) == 2 and rows[0]["roe_revision"] == rows[1]["roe_revision"]:
        return None
    return rows[0]


async def _read_current_policy(
    session: object,
    *,
    request: ResolutionRequest,
    target_revision: int,
    now: datetime,
):
    table = metadata.tables["policy_decisions"]
    rows = (
        await session.execute(
            select(
                table.c.opa_decision_id.label("policy_decision_id"),
                table.c.bundle_revision.label("policy_revision"),
                table.c.input_hash,
                table.c.action,
                table.c.subject_id,
                table.c.resource_type,
                table.c.resource_id,
                table.c.resource_version,
                table.c.obligations,
                table.c.valid_until,
                table.c.version.label("policy_version"),
                table.c.issued_at,
            )
            .where(
                table.c.tenant_id == request.tenant_id,
                table.c.action == "campaign:execute",
                table.c.subject_id == request.principal_id,
                table.c.resource_type == "target",
                table.c.resource_id == request.target_id,
                table.c.resource_version == target_revision,
                table.c.allowed.is_(True),
                table.c.issued_at <= now,
                table.c.valid_until > now,
            )
            .order_by(table.c.issued_at.desc(), table.c.id.desc())
            .limit(2)
        )
    ).mappings().all()
    if not rows:
        return None
    if len(rows) == 2 and rows[0]["issued_at"] == rows[1]["issued_at"]:
        return None
    return rows[0]


async def _read_current_lab_lease(
    session: object,
    *,
    tenant_id: str,
    target_id: str,
    target_value: str,
    roe_id: str,
    policy_decision_id: str,
    now: datetime,
):
    bundles = metadata.tables["lab_bundles"]
    attestations = metadata.tables["lab_target_attestations"]
    leases = metadata.tables["lab_target_leases"]
    rows = (
        await session.execute(
            select(
                leases.c.lease_id,
                leases.c.runner_id,
                leases.c.endpoint.label("lease_endpoint"),
                leases.c.expires_at.label("lease_expires_at"),
                leases.c.attestation_sha256.label("lease_attestation_sha256"),
                attestations.c.endpoint.label("attestation_endpoint"),
                attestations.c.attestation_sha256,
                attestations.c.expires_at.label("attestation_expires_at"),
                attestations.c.allowed_test_classes,
                bundles.c.expires_at.label("bundle_expires_at"),
                bundles.c.network_id,
            )
            .select_from(
                leases.join(
                    attestations,
                    and_(
                        attestations.c.tenant_id == leases.c.tenant_id,
                        attestations.c.id == leases.c.attestation_record_id,
                    ),
                ).join(
                    bundles,
                    and_(
                        bundles.c.tenant_id == attestations.c.tenant_id,
                        bundles.c.id == attestations.c.bundle_record_id,
                    ),
                )
            )
            .where(
                leases.c.tenant_id == tenant_id,
                leases.c.target_id == target_id,
                leases.c.roe_version_id == roe_id,
                leases.c.policy_reference == policy_decision_id,
                leases.c.test_class == "finding_mapping",
                leases.c.lease_state == "active",
                leases.c.issued_at <= now,
                leases.c.expires_at > now,
                leases.c.revoked_at.is_(None),
                attestations.c.target_id == target_id,
                attestations.c.fixture_kind == "web",
                attestations.c.non_production.is_(True),
                attestations.c.attestation_state == "active",
                attestations.c.issued_at <= now,
                attestations.c.expires_at > now,
                bundles.c.bundle_id == _LAB_BUNDLE_ID,
                bundles.c.bundle_state == "active",
                bundles.c.activated_at <= now,
                bundles.c.expires_at > now,
            )
            .order_by(leases.c.issued_at.desc())
            .limit(2)
        )
    ).mappings().all()
    if len(rows) != 1:
        return None
    row = rows[0]
    classes = row["allowed_test_classes"]
    if (
        row["network_id"] != "redagent-r103-lab"
        or not isinstance(classes, list)
        or "finding_mapping" not in classes
        or row["lease_endpoint"] != row["attestation_endpoint"]
        or row["lease_endpoint"] != target_value
        or row["lease_attestation_sha256"] != row["attestation_sha256"]
    ):
        return None
    return row


async def _read_current_quota(session: object, *, tenant_id: str, now: datetime):
    policies = metadata.tables["quota_policies"]
    usage = metadata.tables["quota_usage"]
    reservations = metadata.tables["quota_reservations"]
    rows = (
        await session.execute(
            select(
                policies.c.policy_id.label("quota_policy_id"),
                policies.c.active_until.label("policy_active_until"),
                usage.c.window_end,
                reservations.c.reservation_id,
                reservations.c.reserved_amount,
                reservations.c.consumed_amount,
                reservations.c.released_amount,
                reservations.c.expires_at.label("reservation_expires_at"),
            )
            .select_from(
                reservations.join(
                    policies,
                    and_(
                        policies.c.tenant_id == reservations.c.tenant_id,
                        policies.c.id == reservations.c.policy_record_id,
                    ),
                ).join(
                    usage,
                    and_(
                        usage.c.tenant_id == reservations.c.tenant_id,
                        usage.c.id == reservations.c.usage_id,
                        usage.c.policy_record_id == policies.c.id,
                    ),
                )
            )
            .where(
                reservations.c.tenant_id == tenant_id,
                reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
                reservations.c.expires_at > now,
                policies.c.dimension == "operations",
                policies.c.scope_kind == "tenant",
                policies.c.scope_id == tenant_id,
                policies.c.policy_state == "active",
                policies.c.active_from <= now,
                policies.c.active_until > now,
                usage.c.window_start <= now,
                usage.c.window_end > now,
            )
            .order_by(reservations.c.created_at.desc())
            .limit(2)
        )
    ).mappings().all()
    return rows[0] if len(rows) == 1 else None


async def _read_current_runner(
    session: object,
    *,
    tenant_id: str,
    runner_id: str | None,
    policy_revision: str,
    now: datetime,
    artifact_target: bool = False,
):
    classes = metadata.tables["runner_classes"]
    registrations = metadata.tables["runner_registrations"]
    identities = metadata.tables["runner_identities"]
    conditions = [
        registrations.c.tenant_id == tenant_id,
        registrations.c.environment == "local-conformance",
        registrations.c.network_plane == "owned-loopback",
        registrations.c.required_policy_revision == policy_revision,
        registrations.c.registration_state == "active",
        registrations.c.registered_at <= now,
        registrations.c.expires_at > now,
        registrations.c.revoked_at.is_(None),
        registrations.c.last_seen_at >= now - _MAX_MEMBERSHIP_AGE,
        classes.c.class_id == "r123-closed-runner",
        classes.c.class_status == "active",
        identities.c.identity_state == "observed",
        identities.c.not_before <= now,
        identities.c.not_after > now,
    ]
    if runner_id is not None:
        conditions.append(registrations.c.runner_id == runner_id)
    rows = (
        await session.execute(
            select(
                registrations.c.runner_id,
                registrations.c.spiffe_id,
                registrations.c.certificate_fingerprint,
                registrations.c.certificate_serial,
                registrations.c.adapter_allowlist,
                registrations.c.image_allowlist,
                registrations.c.expires_at.label("registration_expires_at"),
                identities.c.spiffe_id.label("identity_spiffe_id"),
                identities.c.certificate_fingerprint.label("identity_fingerprint"),
                identities.c.certificate_serial.label("identity_serial"),
                identities.c.not_after.label("identity_not_after"),
                classes.c.credential_classes,
            )
            .select_from(
                registrations.join(
                    classes,
                    and_(
                        classes.c.tenant_id == registrations.c.tenant_id,
                        classes.c.id == registrations.c.runner_class_record_id,
                    ),
                ).join(
                    identities,
                    and_(
                        identities.c.tenant_id == registrations.c.tenant_id,
                        identities.c.registration_id == registrations.c.id,
                    ),
                )
            )
            .where(*conditions)
            .order_by(registrations.c.generation.desc())
            .limit(2)
        )
    ).mappings().all()
    exact = tuple(
        row for row in rows if _runner_row_exact(row, artifact_target=artifact_target)
    )
    return exact[0] if len(exact) == 1 else None


async def _read_stop_requested(session: object, *, tenant_id: str) -> bool:
    table = metadata.tables["containment_controls"]
    capability_ids = tuple(item.partition("@")[0] for item in closed_execution_registry())
    value = await session.scalar(
        select(func.count()).select_from(table).where(
            table.c.tenant_id == tenant_id,
            table.c.control_state.in_(("pending_approval", "active")),
            (
                ((table.c.scope_kind == "tenant") & (table.c.scope_id == tenant_id))
                | (table.c.scope_kind == "global")
                | (
                    (table.c.scope_kind == "capability")
                    & table.c.scope_id.in_(capability_ids)
                )
            ),
        )
    )
    return bool(value)


def _roe_covers_target(row: object, target_value: str) -> bool:
    document = row["roe_document"]
    return (
        isinstance(document, dict)
        and document.get("active_testing") is True
        and isinstance(document.get("scope"), list)
        and target_value in document["scope"]
    )


def _quota_remaining(row: object) -> int:
    return (
        int(row["reserved_amount"])
        - int(row["consumed_amount"])
        - int(row["released_amount"])
    )


def _runner_row_exact(row: object, *, artifact_target: bool = False) -> bool:
    return (
        row["spiffe_id"] == row["identity_spiffe_id"]
        and row["certificate_fingerprint"] == row["identity_fingerprint"]
        and row["certificate_serial"] == row["identity_serial"]
        and set(row["adapter_allowlist"] or ()) == (
            _EXPECTED_ARTIFACT_ADAPTERS if artifact_target else _EXPECTED_ADAPTERS
        )
        and set(row["image_allowlist"] or ()) == _EXPECTED_IMAGES
        and row["credential_classes"] == ["none"]
    )


def _digest(value: object) -> str:
    normalized = _normalize(value)
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


async def _set_tenant(session: object, tenant_id: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant_id, True)))


def _identifier(name: str, value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("r123_runtime_time_timezone_required")
