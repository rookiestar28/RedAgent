"""Current-approval boundary for atomic R173 admission and durable start intent."""

from __future__ import annotations

from typing import Any, Mapping

from redagent_platform.campaign_service.admission import (
    AdmissionPolicyAdapter,
    CampaignPlanAdmissionService,
)
from redagent_platform.campaign_service.admission_start_contracts import (
    AutonomousCampaignAdmissionContextProvider,
    AutonomousCampaignAdmissionContextV1,
    AutonomousCampaignAdmissionStartCommandV1,
    AutonomousCampaignApprovalBundleV1,
)
from redagent_platform.campaign_service.application_contracts import (
    ApplicationApprovalExpired,
    ApplicationApprovalForbidden,
    ApplicationPlanInvalid,
    ApplicationPlanUnavailable,
    ApplicationRevisionConflict,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.approval_contracts import (
    AutonomousCampaignApprovalDecision,
)
from redagent_platform.campaign_service.authority_envelope import TrustedCampaignApproverKeyV2
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1


class AutonomousCampaignAdmissionStartService:
    def __init__(
        self,
        *,
        source: Any,
        context_provider: AutonomousCampaignAdmissionContextProvider,
        store_factory: Any,
        policy: AdmissionPolicyAdapter,
        trusted_keys: Mapping[str, TrustedCampaignApproverKeyV2],
        validation_limits: ValidationLimitsV1,
        trusted_validator_version: str,
        trusted_validator_sha256: str,
        lease_seconds: int = 60,
    ) -> None:
        if (
            not callable(getattr(source, "read_current_approval_bundle", None))
            or not callable(getattr(context_provider, "read_current_admission_context", None))
            or not callable(store_factory)
            or not isinstance(policy, AdmissionPolicyAdapter)
            or not isinstance(validation_limits, ValidationLimitsV1)
            or not trusted_keys
            or not trusted_validator_version
            or not trusted_validator_sha256
        ):
            raise ValueError("admission_start_service_dependency_invalid")
        self._source = source
        self._context_provider = context_provider
        self._store_factory = store_factory
        self._policy = policy
        self._trusted_keys = dict(trusted_keys)
        self._validation_limits = validation_limits
        self._trusted_validator_version = trusted_validator_version
        self._trusted_validator_sha256 = trusted_validator_sha256
        self._lease_seconds = lease_seconds

    async def admit_and_queue(self, command: AutonomousCampaignAdmissionStartCommandV1) -> object:
        if not isinstance(command, AutonomousCampaignAdmissionStartCommandV1):
            raise ValueError("admission_start_command_invalid")
        if "campaign:admit" not in command.actor_permissions:
            raise ApplicationApprovalForbidden("admission_permission_required")
        bundle = await self._source.read_current_approval_bundle(
            tenant_id=command.tenant_id,
            campaign_id=command.campaign_id,
            approval_receipt_id=command.approval_receipt_id,
        )
        if not isinstance(bundle, AutonomousCampaignApprovalBundleV1):
            raise ApplicationPlanUnavailable("current_approval_bundle_unavailable")
        self._verify_bundle(command, bundle)
        context = await self._context_provider.read_current_admission_context(
            tenant_id=command.tenant_id,
            campaign_id=command.campaign_id,
        )
        if not isinstance(context, AutonomousCampaignAdmissionContextV1):
            raise ApplicationPlanUnavailable("current_admission_context_unavailable")
        self._verify_context(bundle, context)
        store = self._store_factory(command, bundle, context)
        admission = CampaignPlanAdmissionService(
            policy=self._policy,
            store=store,
            trusted_keys=self._trusted_keys,
            validation_limits=self._validation_limits,
            trusted_validator_version=self._trusted_validator_version,
            trusted_validator_sha256=self._trusted_validator_sha256,
            lease_seconds=self._lease_seconds,
        )
        return await admission.admit_plan(
            signed_authority=context.signed_authority,
            lifecycle=context.authority_lifecycle,
            revision=context.revision,
            domain=context.domain,
            certificate=context.certificate,
            campaign_id=command.campaign_id,
            subject_id=command.actor_user_id,
            roles=command.actor_roles,
            permissions=("campaign:admit",),
            correlation_id=command.correlation_id,
            idempotency_key=command.idempotency_key,
            now=command.occurred_at,
        )

    @staticmethod
    def _verify_bundle(
        command: AutonomousCampaignAdmissionStartCommandV1,
        bundle: AutonomousCampaignApprovalBundleV1,
    ) -> None:
        application = bundle.application
        preview = bundle.preview
        receipt = bundle.approval_receipt
        initial = (
            application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
            and application.aggregate_revision == command.expected_revision
        )
        replay = (
            application.lifecycle_state
            in {
                AutonomousCampaignLifecycle.ADMITTED,
                AutonomousCampaignLifecycle.EXECUTION_QUEUED,
                AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
                AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                AutonomousCampaignLifecycle.FAILED_CONTAINED,
                AutonomousCampaignLifecycle.DENIED,
                AutonomousCampaignLifecycle.EXPIRED,
                AutonomousCampaignLifecycle.REVOKED,
            }
            and receipt.application_revision == command.expected_revision
            and application.aggregate_revision >= command.expected_revision + 1
        )
        if not initial and not replay:
            if application.aggregate_revision == command.expected_revision:
                raise ApplicationPlanInvalid("admission_application_not_approved")
            raise ApplicationRevisionConflict("application_revision_conflict")
        if (
            application.tenant_id != command.tenant_id
            or application.campaign_id != command.campaign_id
            or preview.tenant_id != command.tenant_id
            or preview.campaign_id != command.campaign_id
            or receipt.tenant_id != command.tenant_id
            or receipt.campaign_id != command.campaign_id
            or receipt.decision is not AutonomousCampaignApprovalDecision.APPROVED
            or receipt.receipt_id != command.approval_receipt_id
            or receipt.receipt_sha256 != command.approval_receipt_sha256
            or receipt.application_revision != command.expected_revision
            or receipt.preview_id != preview.preview_id
            or receipt.preview_sha256 != preview.preview_sha256
            or receipt.engagement_id != application.engagement_id
            or receipt.target_id != application.target_id
            or receipt.signed_authority_sha256 != preview.signed_authority_sha256
            or receipt.authority_sha256 != preview.authority_sha256
            or receipt.domain_sha256 != preview.domain_sha256
            or receipt.plan_revision_id != preview.plan_revision_id
            or receipt.plan_revision_sha256 != preview.plan_revision_sha256
            or receipt.plan_sha256 != preview.plan_sha256
            or receipt.certificate_sha256 != preview.certificate_sha256
            or receipt.validator_version != preview.validator_version
            or receipt.validator_sha256 != preview.validator_sha256
            or receipt.capability_set_sha256 != preview.capability_set_sha256
            or receipt.authorized_budget_sha256 != preview.authorized_budget.budget_sha256
            or receipt.plan_budget_sha256 != preview.plan_budget.budget_sha256
            or receipt.policy_revision != preview.policy_revision
            or receipt.policy_bundle_sha256 != preview.policy_bundle_sha256
            or receipt.policy_reference != command.policy_reference
            or receipt.lifecycle_epoch != preview.lifecycle_epoch
            or receipt.policy_revocation_epoch != preview.policy_revocation_epoch
            or receipt.roe_revocation_epoch != preview.roe_revocation_epoch
            or receipt.kill_switch_epoch != preview.kill_switch_epoch
        ):
            raise ApplicationPlanInvalid("admission_approval_bundle_mismatch")
        if initial and command.occurred_at >= receipt.expires_at:
            raise ApplicationApprovalExpired("admission_approval_expired")

    @staticmethod
    def _verify_context(
        bundle: AutonomousCampaignApprovalBundleV1,
        context: AutonomousCampaignAdmissionContextV1,
    ) -> None:
        application = bundle.application
        receipt = bundle.approval_receipt
        authority = context.signed_authority.authority
        revision = context.revision
        certificate = context.certificate
        if (
            context.tenant_id != application.tenant_id
            or context.campaign_id != application.campaign_id
            or authority.engagement_id != application.engagement_id
            or application.target_id not in authority.target_ids
            or context.signed_authority.signed_authority_sha256 != receipt.signed_authority_sha256
            or authority.authority_sha256 != receipt.authority_sha256
            or authority.policy_revision != receipt.policy_revision
            or authority.policy_bundle_sha256 != receipt.policy_bundle_sha256
            or context.domain.domain_sha256 != receipt.domain_sha256
            or revision.revision_id != receipt.plan_revision_id
            or revision.revision_sha256 != receipt.plan_revision_sha256
            or revision.candidate_plan.plan_sha256 != receipt.plan_sha256
            or certificate.certificate_sha256 != receipt.certificate_sha256
            or certificate.validator_version != receipt.validator_version
            or certificate.validator_sha256 != receipt.validator_sha256
            or authority.lifecycle_epoch != receipt.lifecycle_epoch
            or authority.policy_revocation_epoch != receipt.policy_revocation_epoch
            or authority.roe_revocation_epoch != receipt.roe_revocation_epoch
            or authority.kill_switch_epoch != receipt.kill_switch_epoch
        ):
            raise ApplicationPlanInvalid("admission_approval_context_mismatch")
