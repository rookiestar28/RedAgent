"""Fail-closed pure preparation and current-policy boundary for plan admission."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Mapping

from redagent_platform.campaign_service.admission_contracts import (
    PLAN_ENVELOPE_SUBSET_DIMENSIONS,
    PLAN_ENVELOPE_SUBSET_PROOF_SCHEMA_VERSION,
    CampaignBudgetVectorV1,
    PlanEnvelopeSubsetProofV1,
)
from redagent_platform.campaign_service.admission_repository import AdmissionReservationCommandV1
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityEnvelopeV2,
    CampaignAuthorityLifecycleV2,
    SignedCampaignAuthorityEnvelopeV2,
    TrustedCampaignApproverKeyV2,
    verify_signed_campaign_authority,
)
from redagent_platform.campaign_service.planning.contracts import (
    CleanupMode,
    PlanValidationCertificateV1,
    PlanningDomainV1,
    ValidationLimitsV1,
    ValidationResult,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
)


def calculate_plan_budget(
    revision: AttackPathDagRevisionV1,
    domain: PlanningDomainV1,
) -> CampaignBudgetVectorV1:
    if not isinstance(revision, AttackPathDagRevisionV1) or not isinstance(domain, PlanningDomainV1):
        raise ValueError("plan_admission_budget_input_invalid")
    if (
        revision.width != 1
        or revision.depth != revision.node_count
        or revision.node_count != len(revision.candidate_plan.nodes)
    ):
        # CRITICAL: branch discounting needs mechanically proven exclusivity; unknown topology must deny.
        raise ValueError("plan_admission_topology_unsupported")
    if revision.domain_sha256 != domain.domain_sha256:
        raise ValueError("plan_admission_domain_mismatch")
    operators = {operator.operator_id: operator for operator in domain.operators}
    total = CampaignBudgetVectorV1(0, 0, 0, 0, 0, 0, 0, 0)
    for node in revision.candidate_plan.nodes:
        operator = operators.get(node.operator_id)
        if operator is None:
            raise ValueError("plan_admission_operator_unknown")
        if not operator.executable or operator.cleanup_mode is CleanupMode.NONE:
            raise ValueError("plan_admission_cleanup_contract_missing")
        attempts = 1 + operator.max_retries
        additive = CampaignBudgetVectorV1(
            duration_seconds=_checked_multiply(operator.max_duration_seconds, attempts),
            requests=_checked_multiply(operator.max_requests, attempts),
            rate_per_minute=operator.max_rate_per_minute,
            concurrency=operator.concurrency_weight,
            risk_micropoints=_checked_multiply(operator.max_risk_micropoints, attempts),
            cost_microunits=_checked_multiply(operator.max_cost_microunits, attempts),
            evidence_bytes=_checked_multiply(operator.max_evidence_bytes, attempts),
            data_bytes=_checked_multiply(operator.max_data_bytes, attempts),
        )
        total = CampaignBudgetVectorV1(
            duration_seconds=total.duration_seconds + additive.duration_seconds,
            requests=total.requests + additive.requests,
            rate_per_minute=max(total.rate_per_minute, additive.rate_per_minute),
            concurrency=max(total.concurrency, additive.concurrency),
            risk_micropoints=total.risk_micropoints + additive.risk_micropoints,
            cost_microunits=total.cost_microunits + additive.cost_microunits,
            evidence_bytes=total.evidence_bytes + additive.evidence_bytes,
            data_bytes=total.data_bytes + additive.data_bytes,
        )
    return total


def build_plan_admission_policy_input(
    *,
    authority: CampaignAuthorityEnvelopeV2,
    revision: AttackPathDagRevisionV1,
    certificate: PlanValidationCertificateV1,
    subset_proof_sha256: str,
    residual_budget: CampaignBudgetVectorV1,
    campaign_id: str,
    subject_id: str,
    roles: tuple[str, ...],
    permissions: tuple[str, ...],
    correlation_id: str,
    requested_at: datetime,
) -> PolicyDecisionInput:
    if revision.authority_sha256 != authority.authority_sha256:
        raise ValueError("plan_admission_authority_mismatch")
    if (
        certificate.authority_sha256 != authority.authority_sha256
        or certificate.domain_sha256 != revision.domain_sha256
        or certificate.plan_sha256 != revision.candidate_plan.plan_sha256
    ):
        raise ValueError("plan_admission_certificate_binding_mismatch")
    return PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign.plan.admit",
        tenant_id=authority.tenant_id,
        subject_id=subject_id,
        roles=roles,
        permissions=permissions,
        resource_type="campaign_plan",
        resource_id=campaign_id,
        policy_reference=authority.policy_revision,
        roe_version_id=authority.engagement_id,
        correlation_id=correlation_id,
        requested_at=requested_at,
        attributes={
            "campaign_authority_sha256": authority.authority_sha256,
            "campaign_policy_bundle_sha256": authority.policy_bundle_sha256,
            "campaign_domain_sha256": revision.domain_sha256,
            "campaign_plan_sha256": revision.candidate_plan.plan_sha256,
            "campaign_certificate_sha256": certificate.certificate_sha256,
            "campaign_subset_proof_sha256": subset_proof_sha256,
            "campaign_residual_budget_sha256": residual_budget.budget_sha256,
            "campaign_lifecycle_epoch": authority.lifecycle_epoch,
            "campaign_policy_revocation_epoch": authority.policy_revocation_epoch,
            "campaign_roe_revocation_epoch": authority.roe_revocation_epoch,
            "campaign_kill_switch_epoch": authority.kill_switch_epoch,
        },
    )


class AdmissionPolicyAdapter:
    def __init__(self, provider: Any, *, required_revision: str, trusted_bundle_sha256: str) -> None:
        if not required_revision or len(required_revision) > 100:
            raise ValueError("plan_admission_policy_revision_invalid")
        if len(trusted_bundle_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in trusted_bundle_sha256
        ):
            raise ValueError("plan_admission_policy_bundle_sha256_invalid")
        self.provider = provider
        self.required_revision = required_revision
        self.trusted_bundle_sha256 = trusted_bundle_sha256

    async def decide(self, request: PolicyDecisionInput, *, now: datetime) -> PolicyDecision:
        if request.attributes.get("campaign_policy_bundle_sha256") != self.trusted_bundle_sha256:
            raise ValueError("plan_admission_policy_bundle_mismatch")
        # CRITICAL: admission must use current readiness and a fresh decision; cached allow is not authority.
        readiness = await self.provider.assess_readiness(required_revision=self.required_revision)
        if (
            not readiness.ready
            or readiness.active_revision != self.required_revision
            or readiness.bundle_plugin_state != "OK"
        ):
            raise ValueError("plan_admission_policy_not_ready")
        decision = await self.provider.decide(request, required_revision=self.required_revision, now=now)
        decision.assert_current(request, required_revision=self.required_revision, now=now)
        return decision


def authority_budget(authority: CampaignAuthorityEnvelopeV2) -> CampaignBudgetVectorV1:
    if not isinstance(authority, CampaignAuthorityEnvelopeV2):
        raise ValueError("plan_admission_authority_invalid")
    bounds = authority.bounds
    return CampaignBudgetVectorV1(
        duration_seconds=bounds.max_duration_seconds,
        requests=bounds.max_requests,
        rate_per_minute=bounds.max_rate_per_minute,
        concurrency=bounds.max_concurrency,
        risk_micropoints=bounds.max_risk_micropoints,
        cost_microunits=bounds.max_cost_microunits,
        evidence_bytes=bounds.max_evidence_bytes,
        data_bytes=bounds.max_data_bytes,
    )


def build_plan_envelope_subset_proof(
    *,
    authority: CampaignAuthorityEnvelopeV2,
    revision: AttackPathDagRevisionV1,
    certificate: PlanValidationCertificateV1,
) -> PlanEnvelopeSubsetProofV1:
    if (
        not isinstance(authority, CampaignAuthorityEnvelopeV2)
        or not isinstance(revision, AttackPathDagRevisionV1)
        or not isinstance(certificate, PlanValidationCertificateV1)
    ):
        raise ValueError("plan_envelope_subset_proof_input_invalid")
    return PlanEnvelopeSubsetProofV1(
        schema_version=PLAN_ENVELOPE_SUBSET_PROOF_SCHEMA_VERSION,
        authority_sha256=authority.authority_sha256,
        domain_sha256=revision.domain_sha256,
        plan_sha256=revision.candidate_plan.plan_sha256,
        certificate_sha256=certificate.certificate_sha256,
        validator_version=certificate.validator_version,
        validator_sha256=certificate.validator_sha256,
        validation_result=certificate.result,
        checked_dimensions=PLAN_ENVELOPE_SUBSET_DIMENSIONS,
    )


class CampaignPlanAdmissionService:
    def __init__(
        self,
        *,
        policy: AdmissionPolicyAdapter,
        store: Any,
        trusted_keys: Mapping[str, TrustedCampaignApproverKeyV2],
        validation_limits: ValidationLimitsV1,
        trusted_validator_version: str,
        trusted_validator_sha256: str,
        lease_seconds: int = 60,
        owned_sequential: bool = False,
    ) -> None:
        if not isinstance(policy, AdmissionPolicyAdapter) or not isinstance(validation_limits, ValidationLimitsV1):
            raise ValueError("plan_admission_service_dependency_invalid")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("plan_admission_lease_seconds_invalid")
        if type(owned_sequential) is not bool:
            raise ValueError("plan_admission_profile_invalid")
        self.policy = policy
        self.store = store
        self.trusted_keys = dict(trusted_keys)
        self.validation_limits = validation_limits
        self.trusted_validator_version = trusted_validator_version
        self.trusted_validator_sha256 = trusted_validator_sha256
        self.lease_seconds = lease_seconds
        self.owned_sequential = owned_sequential

    async def admit_plan(
        self,
        *,
        signed_authority: SignedCampaignAuthorityEnvelopeV2,
        lifecycle: CampaignAuthorityLifecycleV2,
        revision: AttackPathDagRevisionV1,
        domain: PlanningDomainV1,
        certificate: PlanValidationCertificateV1,
        campaign_id: str,
        subject_id: str,
        roles: tuple[str, ...],
        permissions: tuple[str, ...],
        correlation_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> object:
        authority = signed_authority.authority
        subset_proof = build_plan_envelope_subset_proof(
            authority=authority,
            revision=revision,
            certificate=certificate,
        )
        subset_proof_sha256 = subset_proof.proof_sha256
        request_sha256 = canonical_planning_sha256(
            {
                "schema_version": "redagent.plan-admission-request/v1",
                "tenant_id": authority.tenant_id,
                "campaign_id": campaign_id,
                "engagement_id": authority.engagement_id,
                "signed_authority_sha256": signed_authority.signed_authority_sha256,
                "authority_sha256": authority.authority_sha256,
                "domain_sha256": revision.domain_sha256,
                "plan_sha256": revision.candidate_plan.plan_sha256,
                "certificate_sha256": certificate.certificate_sha256,
                "subset_proof_sha256": subset_proof_sha256,
                "subject_id": subject_id,
                "roles": tuple(sorted(roles)),
                "permissions": tuple(sorted(permissions)),
                "correlation_id": correlation_id,
                "idempotency_key": idempotency_key,
            }
        )
        denial_context = {
            "tenant_id": authority.tenant_id,
            "engagement_id": authority.engagement_id,
            "signed_authority_sha256": signed_authority.signed_authority_sha256,
            "authority_sha256": authority.authority_sha256,
            "domain_sha256": revision.domain_sha256,
            "plan_sha256": revision.candidate_plan.plan_sha256,
            "certificate_sha256": certificate.certificate_sha256,
            "validator_version": certificate.validator_version,
            "validator_sha256": certificate.validator_sha256,
            "subset_proof_sha256": subset_proof_sha256,
            "policy_bundle_sha256": authority.policy_bundle_sha256,
            "lifecycle_epoch": lifecycle.lifecycle_epoch,
            "policy_revocation_epoch": lifecycle.policy_revocation_epoch,
            "roe_revocation_epoch": lifecycle.roe_revocation_epoch,
            "kill_switch_epoch": lifecycle.kill_switch_epoch,
            "issued_at": now,
        }
        replay = await self.store.replay(
            tenant_id=authority.tenant_id,
            campaign_id=campaign_id,
            idempotency_key=idempotency_key,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return replay

        try:
            verify_signed_campaign_authority(
                signed_authority,
                lifecycle,
                trusted_keys=self.trusted_keys,
                now=now,
            )
        except ValueError as exc:
            return await self._deny(
                denial_stage="authority",
                reason_code=str(exc),
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        if (
            revision.tenant_id != authority.tenant_id
            or revision.engagement_id != authority.engagement_id
            or revision.authority_sha256 != authority.authority_sha256
            or revision.domain_sha256 != domain.domain_sha256
            or certificate.tenant_id != authority.tenant_id
            or certificate.engagement_id != authority.engagement_id
            or certificate.authority_sha256 != authority.authority_sha256
            or certificate.domain_sha256 != domain.domain_sha256
            or certificate.plan_sha256 != revision.candidate_plan.plan_sha256
        ):
            return await self._deny(
                denial_stage="binding",
                reason_code="plan_admission_binding_mismatch",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        if (
            certificate.validator_version != self.trusted_validator_version
            or certificate.validator_sha256 != self.trusted_validator_sha256
            or certificate.result is not ValidationResult.VALID
        ):
            # CRITICAL: INVALID and UNKNOWN are both non-authority and must stop before policy evaluation.
            return await self._deny(
                denial_stage="certificate",
                reason_code="plan_validation_not_valid",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        # CRITICAL: only the server-selected closed mode may use peak accounting; certificate labels do not select semantics.
        from redagent_platform.campaign_service.planning.owned_sequential import validate_owned_sequential_candidate_plan
        validator = validate_owned_sequential_candidate_plan if self.owned_sequential else validate_candidate_plan
        recomputed = validator(
            revision.candidate_plan,
            domain,
            authority,
            limits=self.validation_limits,
            validated_at=certificate.validated_at,
        )
        if recomputed.certificate_sha256 != certificate.certificate_sha256:
            return await self._deny(
                denial_stage="certificate",
                reason_code="plan_validation_recompute_mismatch",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        recomputed_subset_proof = build_plan_envelope_subset_proof(
            authority=authority,
            revision=revision,
            certificate=recomputed,
        )
        if not recomputed_subset_proof.admissible or recomputed_subset_proof.proof_sha256 != subset_proof_sha256:
            return await self._deny(
                denial_stage="subset",
                reason_code="plan_envelope_subset_proof_invalid",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        try:
            reserved = calculate_plan_budget(revision, domain)
        except ValueError as exc:
            return await self._deny(
                denial_stage="budget",
                reason_code=str(exc),
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        authorized = authority_budget(authority)
        if not reserved.fits_within(authorized):
            return await self._deny(
                denial_stage="budget",
                reason_code="campaign_budget_exhausted",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
            )
        residual = await self.store.preview_residual(
            tenant_id=authority.tenant_id,
            campaign_id=campaign_id,
            envelope_sha256=authority.authority_sha256,
            authorized_budget=authorized,
        )
        policy_request = build_plan_admission_policy_input(
            authority=authority,
            revision=revision,
            certificate=certificate,
            subset_proof_sha256=subset_proof_sha256,
            residual_budget=residual,
            campaign_id=campaign_id,
            subject_id=subject_id,
            roles=tuple(sorted(roles)),
            permissions=tuple(sorted(permissions)),
            correlation_id=correlation_id,
            requested_at=now,
        )
        try:
            decision = await self.policy.decide(policy_request, now=now)
        except (RuntimeError, ValueError):
            return await self._deny(
                denial_stage="policy",
                reason_code="policy_unavailable_or_invalid",
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                context=denial_context,
                policy_request=policy_request,
            )
        if not decision.allowed:
            return await self._deny(
                denial_stage="policy",
                reason_code=decision.reason_code,
                request_sha256=request_sha256,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                policy_request=policy_request,
                policy_decision=decision,
                context=denial_context,
            )
        lease_expires_at = min(
            now + timedelta(seconds=self.lease_seconds),
            authority.expires_at,
            lifecycle.valid_until,
            decision.valid_until,
        )
        command = AdmissionReservationCommandV1(
            campaign_id=campaign_id,
            engagement_id=authority.engagement_id,
            signed_authority_sha256=signed_authority.signed_authority_sha256,
            authority_sha256=authority.authority_sha256,
            domain_sha256=domain.domain_sha256,
            plan_sha256=revision.candidate_plan.plan_sha256,
            certificate_sha256=certificate.certificate_sha256,
            validator_version=certificate.validator_version,
            validator_sha256=certificate.validator_sha256,
            subset_proof_sha256=subset_proof_sha256,
            policy_bundle_sha256=authority.policy_bundle_sha256,
            authorized_budget=authorized,
            reserved_budget=reserved,
            policy_request=policy_request,
            policy_decision=decision,
            idempotency_key=idempotency_key,
            request_sha256=request_sha256,
            lifecycle_epoch=lifecycle.lifecycle_epoch,
            policy_revocation_epoch=lifecycle.policy_revocation_epoch,
            roe_revocation_epoch=lifecycle.roe_revocation_epoch,
            kill_switch_epoch=lifecycle.kill_switch_epoch,
            issued_at=now,
            lease_expires_at=lease_expires_at,
        )
        return await self.store.admit(command)

    async def _deny(self, **values: object) -> object:
        return await self.store.deny(**values)


def _checked_multiply(value: int, multiplier: int) -> int:
    result = value * multiplier
    if result > 10**18:
        raise ValueError("campaign_budget_overflow")
    return result
