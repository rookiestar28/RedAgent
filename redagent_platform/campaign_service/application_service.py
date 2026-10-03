"""Canonical Phase 26 application-service boundary for autonomous campaign lifecycle state."""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime
from typing import Mapping, TypeVar, cast

from redagent_platform.campaign_service.application_contracts import (
    is_owned_execution_mode,
    ApplicationDependencyUnavailable,
    ApplicationModeDisabled,
    ApplicationNotFound,
    ApplicationOutcomeError,
    ApplicationApprovalExpired,
    ApplicationApprovalForbidden,
    ApplicationPlanInvalid,
    ApplicationPlanUnavailable,
    ApplicationRevisionConflict,
    AutonomousCampaignApplicationRepository,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
    AutonomousCampaignMutationResultV1,
    AutonomousCampaignReadinessV1,
    CreateAutonomousCampaignIntentV1,
    PrepareAutonomousCampaignRootV1,
    RevokeAutonomousCampaignIntentV1,
)
from redagent_platform.campaign_service.admission import authority_budget, calculate_plan_budget
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.approval_contracts import (
    APPROVAL_RECEIPT_SCHEMA_VERSION,
    PLAN_PREVIEW_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
    AutonomousCampaignApprovalContextProvider,
    AutonomousCampaignApprovalContextV1,
    AutonomousCampaignApprovalDecision,
    AutonomousCampaignApprovalDecisionResultV1,
    AutonomousCampaignApprovalReceiptV1,
    AutonomousCampaignPlanActionV1,
    AutonomousCampaignPlanApproverV1,
    AutonomousCampaignPlanPreviewResultV1,
    AutonomousCampaignPlanPreviewV1,
    DenyAutonomousCampaignPlanV1,
    StageAutonomousCampaignPlanV1,
    canonical_approval_decision_request_sha256,
)
from redagent_platform.campaign_service.authority_envelope import (
    TrustedCampaignApproverKeyV2,
    verify_signed_campaign_authority,
)
from redagent_platform.campaign_service.planning.contracts import (
    ValidationLimitsV1,
    ValidationResult,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.campaign_service.planning.owned_sequential import validate_owned_sequential_candidate_plan
from redagent_platform.campaign_service.child_lineage import ChildLineageConflict, ChildLineageVerifier
from redagent_platform.campaign_service.child_replan_contracts import CanonicalChildReplanStore, PrepareAutonomousCampaignChildV1


_T = TypeVar("_T")


class AutonomousCampaignApplicationService:
    """Own application commands; execution remains in the admitted worker graph."""

    def __init__(
        self,
        repository: AutonomousCampaignApplicationRepository,
        *,
        mode: AutonomousCampaignMode = AutonomousCampaignMode.PLAN_ONLY,
        approval_context_provider: AutonomousCampaignApprovalContextProvider | None = None,
        trusted_approval_keys: Mapping[str, TrustedCampaignApproverKeyV2] | None = None,
        validation_limits: ValidationLimitsV1 | None = None,
        trusted_validator_version: str | None = None,
        trusted_validator_sha256: str | None = None,
        child_lineage_verifier: ChildLineageVerifier | None = None,
        canonical_child_store: CanonicalChildReplanStore | None = None,
    ) -> None:
        if not isinstance(mode, AutonomousCampaignMode):
            raise ValueError("autonomous_campaign_mode_invalid")
        self._repository = repository
        self._mode = mode
        self._approval_context_provider = approval_context_provider
        self._trusted_approval_keys = None if trusted_approval_keys is None else dict(trusted_approval_keys)
        self._validation_limits = validation_limits
        self._trusted_validator_version = trusted_validator_version
        self._trusted_validator_sha256 = trusted_validator_sha256
        self._child_lineage_verifier = child_lineage_verifier
        self._canonical_child_store = canonical_child_store

    @property
    def mode(self) -> AutonomousCampaignMode:
        return self._mode

    async def create_intent(self, command: CreateAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        self._require_enabled()
        if not isinstance(command, CreateAutonomousCampaignIntentV1):
            raise ValueError("create_intent_command_invalid")
        # CRITICAL: mode is server-owned; a client command must never enable effects.
        return await _await_repository(self._repository.create_intent(replace(command, mode=self._mode)))

    async def read(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignReadinessV1:
        self._require_enabled()
        return self.project(await self.read_current_state(tenant_id=tenant_id, campaign_id=campaign_id))

    async def read_current_state(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignApplicationStateV1:
        # IMPORTANT: creation rollback must leave native state readable for authorized containment.
        state = await _await_repository(self._repository.read(tenant_id=tenant_id, campaign_id=campaign_id))
        if state is None:
            raise ApplicationNotFound("autonomous_campaign_not_found")
        return state

    async def read_operator_plan_replay(
        self, command: PrepareAutonomousCampaignRootV1,
    ) -> AutonomousCampaignPlanPreviewResultV1 | None:
        self._require_enabled()
        if not isinstance(command, PrepareAutonomousCampaignRootV1):
            raise ValueError("operator_preparation_command_invalid")
        read = getattr(self._repository, "read_operator_plan_replay", None)
        if not callable(read):
            raise ApplicationDependencyUnavailable("operator_preparation_replay_owner_unavailable")
        return await _await_repository(read(command))

    async def revoke_intent(self, command: RevokeAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        self._require_enabled()
        if not isinstance(command, RevokeAutonomousCampaignIntentV1):
            raise ValueError("revoke_intent_command_invalid")
        return await _await_repository(self._repository.revoke_intent(command))

    async def stage_plan(
        self, command: StageAutonomousCampaignPlanV1, *,
        operator_request: PrepareAutonomousCampaignRootV1 | None = None,
    ) -> AutonomousCampaignPlanPreviewResultV1:
        self._require_enabled()
        self._require_plan_staging_configured()
        if not isinstance(command, StageAutonomousCampaignPlanV1):
            raise ValueError("stage_plan_command_invalid")
        if operator_request is not None:
            if not isinstance(operator_request, PrepareAutonomousCampaignRootV1) or any(
                getattr(operator_request, field) != getattr(command, field) for field in (
                    "tenant_id", "campaign_id", "actor_user_id", "expected_revision",
                    "idempotency_key", "correlation_id", "occurred_at",
                )
            ):
                raise ApplicationPlanInvalid("operator_preparation_stage_binding_mismatch")
            replay = await self.read_operator_plan_replay(operator_request)
            if replay is not None:
                return replay
        context = await self._read_current_approval_context(
            tenant_id=command.tenant_id,
            campaign_id=command.campaign_id,
        )
        state = await _await_repository(
            self._repository.read(tenant_id=command.tenant_id, campaign_id=command.campaign_id)
        )
        if state is None:
            raise ApplicationNotFound("autonomous_campaign_not_found")
        if state.aggregate_revision != command.expected_revision:
            if operator_request is not None:
                replay = await self.read_operator_plan_replay(operator_request)
                if replay is not None:
                    return replay
            raise ApplicationRevisionConflict("application_revision_conflict")
        if state.lifecycle_state not in {
            AutonomousCampaignLifecycle.INTENT_CREATED,
            AutonomousCampaignLifecycle.AWAITING_APPROVAL,
            AutonomousCampaignLifecycle.APPROVED,
        }:
            raise ApplicationPlanInvalid("plan_staging_state_invalid")
        preview = self._build_preview(command, state, context)
        repository = cast(object, self._repository)
        stage = getattr(repository, "stage_plan", None)
        if not callable(stage):
            raise ApplicationDependencyUnavailable("application_dependency_unavailable")
        if operator_request is not None:
            return await _await_repository(stage(command, preview, operator_request=operator_request))
        return await _await_repository(stage(command, preview))

    async def prepare_child(self, command: PrepareAutonomousCampaignChildV1) -> AutonomousCampaignPlanPreviewResultV1:
        self._require_enabled()
        if self._mode is not AutonomousCampaignMode.BOUNDED_REPLAN:
            raise ApplicationModeDisabled("bounded_child_mode_required")
        if self._canonical_child_store is None:
            raise ApplicationDependencyUnavailable("canonical_child_store_unavailable")
        try:
            self._require_plan_staging_configured()
        except ApplicationPlanUnavailable as exc:
            raise ApplicationDependencyUnavailable("canonical_child_current_dependencies_unavailable") from exc
        if not isinstance(command, PrepareAutonomousCampaignChildV1):
            raise ValueError("canonical_child_command_invalid")
        from redagent_platform.campaign_service.child_replan_service import CanonicalChildReplanService
        from redagent_platform.campaign_service.child_replan_store import ChildParentConflict

        service = CanonicalChildReplanService(self._canonical_child_store, application_service=self,
            context_provider=self._approval_context_provider, trusted_keys=self._trusted_approval_keys)

        async def prepare_owned() -> AutonomousCampaignPlanPreviewResultV1:
            try:
                return await service.prepare_child(command)
            except (ChildParentConflict, ValueError) as exc:
                raise ApplicationPlanInvalid("canonical_child_preparation_denied") from exc

        return await _await_repository(prepare_owned())

    async def read_plan_preview(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignPlanPreviewV1:
        self._require_enabled()
        repository = cast(object, self._repository)
        read_preview = getattr(repository, "read_plan_preview", None)
        if not callable(read_preview):
            raise ApplicationDependencyUnavailable("application_dependency_unavailable")
        preview = await _await_repository(read_preview(tenant_id=tenant_id, campaign_id=campaign_id))
        if preview is None:
            raise ApplicationPlanUnavailable("plan_preview_not_found")
        if not isinstance(preview, AutonomousCampaignPlanPreviewV1):
            raise ApplicationPlanInvalid("plan_preview_invalid")
        return preview

    async def approve_plan(
        self, command: ApproveAutonomousCampaignPlanV1
    ) -> AutonomousCampaignApprovalDecisionResultV1:
        if not isinstance(command, ApproveAutonomousCampaignPlanV1):
            raise ValueError("approve_plan_command_invalid")
        return await self._decide_plan(command, AutonomousCampaignApprovalDecision.APPROVED, "approved")

    async def deny_plan(
        self, command: DenyAutonomousCampaignPlanV1
    ) -> AutonomousCampaignApprovalDecisionResultV1:
        if not isinstance(command, DenyAutonomousCampaignPlanV1):
            raise ValueError("deny_plan_command_invalid")
        return await self._decide_plan(command, AutonomousCampaignApprovalDecision.DENIED, command.reason_code)

    @staticmethod
    def project(
        state: AutonomousCampaignApplicationStateV1,
        *,
        admission_start_available: bool = False,
    ) -> AutonomousCampaignReadinessV1:
        if not isinstance(state, AutonomousCampaignApplicationStateV1):
            raise ValueError("autonomous_campaign_state_invalid")
        if type(admission_start_available) is not bool:
            raise ValueError("autonomous_campaign_admission_availability_invalid")
        plan_ready = state.lifecycle_state in {
            AutonomousCampaignLifecycle.PLAN_VALIDATED,
            AutonomousCampaignLifecycle.AWAITING_APPROVAL,
            AutonomousCampaignLifecycle.APPROVED,
        }
        approval_ready = state.lifecycle_state in {
            AutonomousCampaignLifecycle.AWAITING_APPROVAL,
            AutonomousCampaignLifecycle.APPROVED,
        }
        if state.lifecycle_state is AutonomousCampaignLifecycle.AWAITING_APPROVAL:
            unavailable_reason = "human_approval_required"
        elif state.lifecycle_state is AutonomousCampaignLifecycle.APPROVED:
            unavailable_reason = (
                "ready_for_admission_start"
                if admission_start_available
                else "admission_start_not_configured"
            )
        elif state.lifecycle_state is AutonomousCampaignLifecycle.PLAN_VALIDATED:
            unavailable_reason = "plan_preview_transition_pending"
        else:
            unavailable_reason = "plan_not_prepared"
        return AutonomousCampaignReadinessV1(
            application=state,
            mode=state.mode,
            plan_ready=plan_ready,
            approval_ready=approval_ready,
            admission_ready=(
                state.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
                and admission_start_available
            ),
            start_ready=(
                state.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
                and admission_start_available
            ),
            unavailable_reason=unavailable_reason,
        )

    def _build_preview(
        self,
        command: StageAutonomousCampaignPlanV1,
        state: AutonomousCampaignApplicationStateV1,
        context: AutonomousCampaignApprovalContextV1,
    ) -> AutonomousCampaignPlanPreviewV1:
        if (
            command.signed_authority != context.signed_authority
            or command.authority_lifecycle != context.authority_lifecycle
        ):
            raise ApplicationPlanInvalid("plan_approval_context_mismatch")
        signed = context.signed_authority
        authority = signed.authority
        lifecycle = context.authority_lifecycle
        revision = command.revision
        certificate = command.certificate
        domain = command.domain
        try:
            verify_signed_campaign_authority(
                signed,
                lifecycle,
                trusted_keys=self._trusted_approval_keys or {},
                now=command.occurred_at,
            )
        except ValueError as exc:
            raise ApplicationPlanInvalid(str(exc)) from exc
        if (
            command.tenant_id != state.tenant_id
            or command.campaign_id != state.campaign_id
            or authority.tenant_id != state.tenant_id
            or authority.engagement_id != state.engagement_id
            or state.target_id not in authority.target_ids
            or revision.tenant_id != state.tenant_id
            or revision.engagement_id != state.engagement_id
            or revision.authority_sha256 != authority.authority_sha256
            or revision.domain_sha256 != domain.domain_sha256
            or revision.candidate_plan.objective_id != domain.objective.objective_id
            or any(node.target_id != state.target_id for node in revision.candidate_plan.nodes)
        ):
            raise ApplicationPlanInvalid("plan_preview_binding_mismatch")
        if certificate.result is not ValidationResult.VALID:
            raise ApplicationPlanInvalid("plan_validation_not_valid")
        if (
            certificate.validator_version != self._trusted_validator_version
            or certificate.validator_sha256 != self._trusted_validator_sha256
        ):
            raise ApplicationPlanInvalid("plan_validation_certificate_mismatch")
        validator = (validate_owned_sequential_candidate_plan
                     if self._mode is AutonomousCampaignMode.BOUNDED_REPLAN and state.mode is AutonomousCampaignMode.BOUNDED_REPLAN
                     else validate_candidate_plan)
        recomputed = validator(
            revision.candidate_plan,
            domain,
            authority,
            limits=cast(ValidationLimitsV1, self._validation_limits),
            validated_at=certificate.validated_at,
        )
        if recomputed.certificate_sha256 != certificate.certificate_sha256:
            raise ApplicationPlanInvalid("plan_validation_certificate_mismatch")
        operators = {item.operator_id: item for item in domain.operators}
        try:
            actions = tuple(
                AutonomousCampaignPlanActionV1(
                    node_id=node.node_id,
                    order=node.order,
                    operator_id=node.operator_id,
                    target_id=node.target_id,
                    capability_id=operators[node.operator_id].capability.capability_id,
                    capability_revision=operators[node.operator_id].capability.capability_revision,
                    effect_class=operators[node.operator_id].effect_class.value,
                    executable=operators[node.operator_id].executable,
                    max_duration_seconds=operators[node.operator_id].max_duration_seconds,
                    max_requests=operators[node.operator_id].max_requests,
                    max_rate_per_minute=operators[node.operator_id].max_rate_per_minute,
                    concurrency_weight=operators[node.operator_id].concurrency_weight,
                    max_retries=operators[node.operator_id].max_retries,
                    max_risk_micropoints=operators[node.operator_id].max_risk_micropoints,
                    max_cost_microunits=operators[node.operator_id].max_cost_microunits,
                    max_evidence_bytes=operators[node.operator_id].max_evidence_bytes,
                    max_data_bytes=operators[node.operator_id].max_data_bytes,
                    cleanup_mode=operators[node.operator_id].cleanup_mode,
                )
                for node in revision.candidate_plan.nodes
            )
            plan_budget = calculate_plan_budget(revision, domain)
        except (KeyError, ValueError) as exc:
            raise ApplicationPlanInvalid("plan_preview_budget_invalid") from exc
        authorized = authority_budget(authority)
        if not plan_budget.fits_within(authorized):
            raise ApplicationPlanInvalid("plan_preview_budget_exceeded")
        # CRITICAL: preview approval cannot outlive any signature that made the authority acceptable.
        expires_at = min(
            authority.expires_at,
            lifecycle.valid_until,
            *(approval.expires_at for approval in signed.approvals),
        )
        if command.occurred_at >= expires_at:
            raise ApplicationApprovalExpired("plan_preview_expired")
        capability_ids = tuple(sorted({item.capability_id for item in actions}))
        execution_bindings: tuple[CapabilityBindingKeyV1, ...] = ()
        if is_owned_execution_mode(state.mode):
            execution_bindings = tuple(sorted(context.execution_bindings, key=lambda item: item.capability_id))
            if tuple(item.capability_id for item in execution_bindings) != capability_ids:
                raise ApplicationPlanInvalid("auto_execution_bindings_missing")
            for binding in execution_bindings:
                capability = next(item.capability for item in domain.operators if item.capability.capability_id == binding.capability_id)
                if any(getattr(binding, field) != getattr(capability, field) for field in (
                    "capability_revision", "execution_manifest_sha256", "adapter_id", "adapter_version",
                    "profile_id", "profile_revision", "profile_sha256", "bundle_id", "bundle_revision", "bundle_sha256"
                )):
                    raise ApplicationPlanInvalid("auto_execution_binding_mismatch")
        effect_classes = tuple(sorted({item.effect_class for item in actions}))
        application_revision = command.expected_revision + 2
        preview_identity = canonical_planning_sha256(
            {
                "schema_version": PLAN_PREVIEW_SCHEMA_VERSION,
                "tenant_id": state.tenant_id,
                "campaign_id": state.campaign_id,
                "application_revision": application_revision,
                "signed_authority_sha256": signed.signed_authority_sha256,
                "plan_revision_sha256": revision.revision_sha256,
                "certificate_sha256": certificate.certificate_sha256,
            }
        )
        return AutonomousCampaignPlanPreviewV1(
            execution_mode=state.mode,
            execution_bindings=execution_bindings,
            schema_version=PLAN_PREVIEW_SCHEMA_VERSION,
            preview_id=f"preview-{preview_identity[:24]}",
            tenant_id=state.tenant_id,
            campaign_id=state.campaign_id,
            engagement_id=state.engagement_id,
            application_revision=application_revision,
            application_intent_sha256=state.intent_sha256,
            source_binding_sha256=state.source_binding_sha256,
            signed_authority_sha256=signed.signed_authority_sha256,
            authority_sha256=authority.authority_sha256,
            domain_sha256=domain.domain_sha256,
            plan_revision_id=revision.revision_id,
            plan_revision_sha256=revision.revision_sha256,
            plan_sha256=revision.candidate_plan.plan_sha256,
            objective_id=domain.objective.objective_id,
            objective_sha256=revision.objective_sha256,
            target_id=state.target_id,
            capability_ids=capability_ids,
            capability_set_sha256=canonical_planning_sha256(capability_ids),
            effect_classes=effect_classes,
            actions=actions,
            authorized_budget=authorized,
            plan_budget=plan_budget,
            certificate_sha256=certificate.certificate_sha256,
            validator_version=certificate.validator_version,
            validator_sha256=certificate.validator_sha256,
            validation_result=certificate.result,
            policy_revision=authority.policy_revision,
            policy_bundle_sha256=authority.policy_bundle_sha256,
            lifecycle_epoch=lifecycle.lifecycle_epoch,
            policy_revocation_epoch=lifecycle.policy_revocation_epoch,
            roe_revocation_epoch=lifecycle.roe_revocation_epoch,
            kill_switch_epoch=lifecycle.kill_switch_epoch,
            required_approvers=tuple(
                AutonomousCampaignPlanApproverV1(item.principal_id, item.role_id)
                for item in authority.required_approvers
            ),
            issued_at=command.occurred_at,
            expires_at=expires_at,
        )

    async def _decide_plan(
        self,
        command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
        decision: AutonomousCampaignApprovalDecision,
        reason_code: str,
    ) -> AutonomousCampaignApprovalDecisionResultV1:
        self._require_enabled()
        preview = await self.read_plan_preview(tenant_id=command.tenant_id, campaign_id=command.campaign_id)
        if command.preview_id != preview.preview_id or command.preview_sha256 != preview.preview_sha256:
            raise ApplicationPlanInvalid("approval_preview_mismatch")
        if command.expected_revision != preview.application_revision:
            raise ApplicationRevisionConflict("application_revision_conflict")
        if command.occurred_at >= preview.expires_at:
            raise ApplicationApprovalExpired("plan_approval_expired")
        if "campaign:approve" not in command.actor_permissions:
            raise ApplicationApprovalForbidden("approval_permission_required")
        matches = tuple(
            item for item in preview.required_approvers if item.principal_id == command.actor_user_id
        )
        if len(matches) != 1:
            raise ApplicationApprovalForbidden("approval_actor_not_required")
        context = await self._read_current_approval_context(
            tenant_id=command.tenant_id,
            campaign_id=command.campaign_id,
        )
        child_verified = False
        if preview.child_lineage_sha256 is not None:
            if self._child_lineage_verifier is None:
                raise ApplicationDependencyUnavailable("child_lineage_verifier_unavailable")
            try:
                await self._child_lineage_verifier.verify(tenant_id=command.tenant_id, campaign_id=command.campaign_id,
                    preview=preview, now=command.occurred_at)
            except (ChildLineageConflict, ValueError) as exc:
                raise ApplicationPlanInvalid("child_lineage_not_current") from exc
            child_verified = True
        self._verify_current_approval_context(context, preview=preview, now=command.occurred_at, child_verified=child_verified)
        request_sha256 = canonical_approval_decision_request_sha256(command)
        receipt_identity = canonical_planning_sha256(
            {"request_sha256": request_sha256, "idempotency_key": command.idempotency_key}
        )
        receipt = AutonomousCampaignApprovalReceiptV1(
            schema_version=APPROVAL_RECEIPT_SCHEMA_VERSION,
            receipt_id=f"approval-{receipt_identity[:24]}",
            decision=decision,
            reason_code=reason_code,
            tenant_id=preview.tenant_id,
            campaign_id=preview.campaign_id,
            engagement_id=preview.engagement_id,
            application_revision=command.expected_revision + 1,
            preview_id=preview.preview_id,
            preview_sha256=preview.preview_sha256,
            signed_authority_sha256=preview.signed_authority_sha256,
            authority_sha256=preview.authority_sha256,
            domain_sha256=preview.domain_sha256,
            plan_revision_id=preview.plan_revision_id,
            plan_revision_sha256=preview.plan_revision_sha256,
            plan_sha256=preview.plan_sha256,
            certificate_sha256=preview.certificate_sha256,
            validator_version=preview.validator_version,
            validator_sha256=preview.validator_sha256,
            target_id=preview.target_id,
            capability_set_sha256=preview.capability_set_sha256,
            authorized_budget_sha256=preview.authorized_budget.budget_sha256,
            plan_budget_sha256=preview.plan_budget.budget_sha256,
            policy_revision=preview.policy_revision,
            policy_bundle_sha256=preview.policy_bundle_sha256,
            lifecycle_epoch=preview.lifecycle_epoch,
            policy_revocation_epoch=preview.policy_revocation_epoch,
            roe_revocation_epoch=preview.roe_revocation_epoch,
            kill_switch_epoch=preview.kill_switch_epoch,
            approver_user_id=command.actor_user_id,
            approver_role=matches[0].role_id,
            permission_set_sha256=canonical_planning_sha256(command.actor_permissions),
            policy_reference=command.policy_reference,
            idempotency_key=command.idempotency_key,
            request_sha256=request_sha256,
            decided_at=command.occurred_at,
            expires_at=preview.expires_at,
        )
        decide = getattr(cast(object, self._repository), "decide_plan", None)
        if not callable(decide):
            raise ApplicationDependencyUnavailable("application_dependency_unavailable")
        return await _await_repository(decide(command, receipt))

    def _require_plan_staging_configured(self) -> None:
        if (
            self._approval_context_provider is None
            or not self._trusted_approval_keys
            or self._validation_limits is None
            or not self._trusted_validator_version
            or not self._trusted_validator_sha256
        ):
            raise ApplicationPlanUnavailable("r172_plan_validation_not_configured")

    async def _read_current_approval_context(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
    ) -> AutonomousCampaignApprovalContextV1:
        provider = self._approval_context_provider
        if provider is None:
            raise ApplicationPlanUnavailable("r172_approval_context_not_configured")
        read = getattr(cast(object, provider), "read_current_approval_context", None)
        if not callable(read):
            raise ApplicationDependencyUnavailable("application_dependency_unavailable")
        context = await _await_repository(read(tenant_id=tenant_id, campaign_id=campaign_id))
        if context is None:
            raise ApplicationPlanUnavailable("current_approval_context_unavailable")
        if (
            not isinstance(context, AutonomousCampaignApprovalContextV1)
            or context.tenant_id != tenant_id
            or context.campaign_id != campaign_id
        ):
            raise ApplicationPlanInvalid("current_approval_context_binding_mismatch")
        return context

    def _verify_current_approval_context(
        self,
        context: AutonomousCampaignApprovalContextV1,
        *,
        preview: AutonomousCampaignPlanPreviewV1,
        now: datetime,
        child_verified: bool = False,
    ) -> None:
        signed = context.signed_authority
        authority = signed.authority
        lifecycle = context.authority_lifecycle
        try:
            verify_signed_campaign_authority(
                signed,
                lifecycle,
                trusted_keys=self._trusted_approval_keys or {},
                now=now,
            )
        except ValueError as exc:
            raise ApplicationPlanInvalid(str(exc)) from exc
        current_expires_at = min(
            authority.expires_at,
            lifecycle.valid_until,
            *(approval.expires_at for approval in signed.approvals),
        )
        current_bindings = context.execution_bindings
        if child_verified and preview.child_lineage_sha256 is not None:
            # CRITICAL: only freshly proved strict-subset children may project the root capability catalog to remaining actions.
            required_capabilities = {action.capability_id for action in preview.actions}
            current_bindings = tuple(binding for binding in current_bindings if binding.capability_id in required_capabilities)
        if (
            context.tenant_id != preview.tenant_id
            or context.campaign_id != preview.campaign_id
            or authority.engagement_id != preview.engagement_id
            or preview.target_id not in authority.target_ids
            or signed.signed_authority_sha256 != preview.signed_authority_sha256
            or authority.authority_sha256 != preview.authority_sha256
            or authority.policy_revision != preview.policy_revision
            or authority.policy_bundle_sha256 != preview.policy_bundle_sha256
            or lifecycle.lifecycle_epoch != preview.lifecycle_epoch
            or lifecycle.policy_revocation_epoch != preview.policy_revocation_epoch
            or lifecycle.roe_revocation_epoch != preview.roe_revocation_epoch
            or lifecycle.kill_switch_epoch != preview.kill_switch_epoch
            or current_expires_at != preview.expires_at
            or (is_owned_execution_mode(preview.execution_mode) and
                tuple(sorted(current_bindings, key=lambda item: item.capability_id)) != preview.execution_bindings)
        ):
            # CRITICAL: a persisted preview is evidence, never current authority for a later decision.
            raise ApplicationPlanInvalid("approval_authority_context_drift")

    def _require_enabled(self) -> None:
        # CRITICAL: creation/planning/decision entry points reject DISABLED before repository access.
        # Explicit authorized operator state/recovery reads remain available during rollback.
        if self._mode is AutonomousCampaignMode.DISABLED:
            raise ApplicationModeDisabled("autonomous_campaign_disabled")


async def _await_repository(operation: Awaitable[_T]) -> _T:
    try:
        return await operation
    except ApplicationOutcomeError:
        raise
    except Exception as exc:
        # CRITICAL: never expose driver-specific failures; callers require one closed dependency outcome.
        raise ApplicationDependencyUnavailable("application_dependency_unavailable") from exc
