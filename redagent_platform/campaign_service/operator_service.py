"""Normal operator adapters; authoritative decisions remain in canonical owners."""

from __future__ import annotations

from datetime import datetime
import hashlib

from redagent_platform.campaign_service.application_contracts import (
    APPLICATION_CONTRACT_VERSION, ApplicationBindingConflict, ApplicationDependencyUnavailable,
    ApplicationPlanUnavailable, ApplicationPlanInvalid, ApplicationRevisionConflict,
    AutonomousCampaignLifecycle, AutonomousCampaignMode, AutonomousCampaignMutationResultV1,
    AutonomousCampaignNativeRootV1, CreateAutonomousCampaignIntentV1, PrepareAutonomousCampaignRootV1,
    is_owned_execution_mode,
)
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService, _await_repository
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_STAGE_SCHEMA_VERSION, StageAutonomousCampaignPlanV1, AutonomousCampaignPlanPreviewResultV1,
)
from redagent_platform.campaign_service.operator_contracts import (
    AutonomousCampaignRootPlanSource, AutonomousCampaignRootPlanMaterialV1,
    AutonomousCampaignOperatorRecoveryV1, AutonomousCampaignOperatorStopCommitV1,
)
from redagent_platform.campaign_service.planning.contracts import (
    ValidationLimitsV1, ValidationResult, canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan
from redagent_platform.campaign_service.planning.owned_sequential import (
    derive_owned_sequential_search_limits, plan_owned_sequential_attack_path,
    validate_owned_sequential_candidate_plan,
)
from redagent_platform.campaign_service.service import CampaignCoreService
from redagent_platform.campaign_service.dag_execution_contracts import DAG_EXECUTION_SCHEMA_VERSION, DagStopSignalV1
from redagent_platform.orchestration.gateway import OrchestrationUnavailable


class AutonomousCampaignOperatorService:
    def __init__(
        self, selections: CampaignCoreService, application: AutonomousCampaignApplicationService,
        *, root_plan_source: AutonomousCampaignRootPlanSource | None = None,
        validation_limits: ValidationLimitsV1 | None = None,
        native_owner: object | None = None, stop_gateway: object | None = None,
        create_enabled: bool = True,
    ) -> None:
        if not isinstance(selections, CampaignCoreService) or not isinstance(application, AutonomousCampaignApplicationService):
            raise ValueError("operator_application_configuration_invalid")
        if type(create_enabled) is not bool:
            raise ValueError("operator_creation_configuration_invalid")
        if root_plan_source is not None and not callable(getattr(root_plan_source, "read_root_plan", None)):
            raise ValueError("operator_root_source_configuration_invalid")
        if validation_limits is not None and not isinstance(validation_limits, ValidationLimitsV1):
            raise ValueError("operator_validation_configuration_invalid")
        if native_owner is not None and not all(callable(getattr(native_owner, name, None)) for name in (
            "read_status", "request_stop", "request_revoke",
        )):
            raise ValueError("operator_native_owner_configuration_incomplete")
        if stop_gateway is not None and not callable(getattr(stop_gateway, "stop_campaign_dag", None)):
            raise ValueError("operator_stop_gateway_configuration_invalid")
        self._selections = selections
        self._application = application
        self._root_plan_source = root_plan_source
        self._validation_limits = validation_limits
        self._create_enabled = create_enabled
        self._native_owner = native_owner
        self._stop_gateway = stop_gateway

    @property
    def creation_available(self) -> bool:
        return (
            self._create_enabled and self._root_plan_source is not None and self._validation_limits is not None
            and self._application.mode is not AutonomousCampaignMode.DISABLED
            and self._native_owner is not None
            and (not is_owned_execution_mode(self._application.mode) or self._stop_gateway is not None)
        )

    @property
    def creation_requested(self) -> bool:
        return self._create_enabled and self.mode is not AutonomousCampaignMode.DISABLED

    @property
    def mode(self) -> AutonomousCampaignMode:
        return self._application.mode

    @property
    def application_service(self) -> AutonomousCampaignApplicationService:
        return self._application

    @property
    def selection_service(self) -> CampaignCoreService:
        return self._selections

    @property
    def preparation_available(self) -> bool:
        return self.creation_available and self._validation_limits is not None

    @property
    def status_available(self) -> bool:
        return self._native_owner is not None

    @property
    def stop_available(self) -> bool:
        return self._native_owner is not None and self._stop_gateway is not None

    @property
    def revoke_available(self) -> bool:
        return self._native_owner is not None

    async def read_status(self, *, tenant_id: str, campaign_id: str, principal_id: str, now: datetime):
        if self._native_owner is None:
            raise ApplicationDependencyUnavailable("operator_status_owner_unavailable")
        return await _await_repository(self._native_owner.read_status(
            tenant_id=tenant_id, campaign_id=campaign_id, principal_id=principal_id, now=now,
        ))

    async def recover(
        self, *, action: str, reason: str, tenant_id: str, campaign_id: str, principal_id: str,
        expected_revision: int, idempotency_key: str, correlation_id: str, now: datetime,
    ) -> dict[str, object]:
        if self._native_owner is None or (action == "stop" and self._stop_gateway is None):
            raise ApplicationDependencyUnavailable("operator_recovery_owner_unavailable")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise ValueError("operator_recovery_reason_invalid")
        command = AutonomousCampaignOperatorRecoveryV1(
            action=action, tenant_id=tenant_id, campaign_id=campaign_id, actor_user_id=principal_id,
            expected_revision=expected_revision, reason_sha256=hashlib.sha256(reason.strip().encode()).hexdigest(),
            idempotency_key=idempotency_key, correlation_id=correlation_id, occurred_at=now,
        )
        signal_status = "not_requested"
        execution_run_id = None
        if action == "revoke":
            mutation = await _await_repository(self._native_owner.request_revoke(command))
        else:
            commit = await _await_repository(self._native_owner.request_stop(command))
            if not isinstance(commit, AutonomousCampaignOperatorStopCommitV1):
                raise ApplicationDependencyUnavailable("operator_stop_commit_invalid")
            mutation, execution_run_id = commit.mutation, commit.execution_run_id
            signal_status = "not_repeated"
            if not mutation.replayed:
                # CRITICAL: commit the durable pre-I/O stop flag before signaling. Unknown delivery
                # must leave stop visible and must never imply containment or complete cleanup.
                try:
                    await self._stop_gateway.stop_campaign_dag(commit.workflow_id, DagStopSignalV1(
                        DAG_EXECUTION_SCHEMA_VERSION, commit.signal_id, principal_id, command.reason_sha256,
                    ), run_id=commit.workflow_run_id)
                    signal_status = "acknowledged"
                except OrchestrationUnavailable:
                    signal_status = "unknown"
        if not isinstance(mutation, AutonomousCampaignMutationResultV1):
            raise ApplicationDependencyUnavailable("operator_recovery_commit_invalid")
        state = mutation.application
        return {
            "campaign_id": campaign_id, "mode": state.mode.value, "lifecycle_state": state.lifecycle_state.value,
            "aggregate_revision": state.aggregate_revision,
            "etag": f'"autonomous-{campaign_id}:{state.aggregate_revision}"',
            "replayed": mutation.replayed, "action": action, "stop_requested": action == "stop",
            "signal_status": signal_status, "execution_run_id": execution_run_id,
        }

    async def prepare_plan(
        self, *, tenant_id: str, campaign_id: str, principal_id: str, expected_revision: int,
        idempotency_key: str, correlation_id: str, now: datetime,
    ) -> AutonomousCampaignPlanPreviewResultV1:
        if not self.creation_available or self._validation_limits is None:
            raise ApplicationPlanUnavailable("operator_preparation_unavailable")
        request = PrepareAutonomousCampaignRootV1(
            tenant_id=tenant_id, campaign_id=campaign_id, actor_user_id=principal_id,
            expected_revision=expected_revision, idempotency_key=idempotency_key,
            correlation_id=correlation_id, occurred_at=now,
        )
        state = await self._application.read_current_state(tenant_id=tenant_id, campaign_id=campaign_id)
        engagement, target = await self._selections.resolve_application_scope(
            tenant_id=tenant_id, principal_id=principal_id,
            engagement_id=state.engagement_id, target_id=state.target_id,
            now=now, require_eligible=False,
        )
        # CRITICAL: current principal/ownership precedes native replay; refresh never restages a preview.
        replay = await self._application.read_operator_plan_replay(request)
        if replay is not None:
            return replay
        if state.aggregate_revision != expected_revision:
            raise ApplicationRevisionConflict("application_revision_conflict")
        if state.lifecycle_state is not AutonomousCampaignLifecycle.INTENT_CREATED:
            raise ApplicationPlanInvalid("operator_root_already_prepared")
        if not engagement.eligible or not target.eligible:
            raise ApplicationBindingConflict("operator_execution_scope_ineligible")
        source = self._root_plan_source
        if source is None:
            raise ApplicationPlanUnavailable("operator_root_source_unavailable")
        material = await source.read_root_plan(application=state, now=now)
        if material is None:
            raise ApplicationPlanUnavailable("operator_root_source_unavailable")
        if not isinstance(material, AutonomousCampaignRootPlanMaterialV1):
            raise ValueError("operator_root_plan_material_invalid")
        context = material.context
        authority = context.signed_authority.authority
        if context.tenant_id != tenant_id or context.campaign_id != campaign_id or authority.engagement_id != state.engagement_id:
            raise ValueError("operator_root_source_binding_mismatch")
        if state.mode is AutonomousCampaignMode.BOUNDED_REPLAN:
            search = derive_owned_sequential_search_limits(material.domain, authority)
            planned = plan_owned_sequential_attack_path(material.domain, authority, material.initial_state, search)
            validator = validate_owned_sequential_candidate_plan
        else:
            planned = plan_attack_path(material.domain, authority, material.initial_state, material.search_limits)
            validator = validate_candidate_plan
        if planned.revision is None:
            raise ApplicationPlanInvalid("operator_root_plan_unavailable")
        certificate = validator(
            planned.revision.candidate_plan, material.domain, authority,
            limits=self._validation_limits, validated_at=now,
        )
        if certificate.result is not ValidationResult.VALID:
            raise ApplicationPlanInvalid("operator_root_plan_invalid")
        return await self._application.stage_plan(StageAutonomousCampaignPlanV1(
            schema_version=PLAN_STAGE_SCHEMA_VERSION, tenant_id=tenant_id, campaign_id=campaign_id,
            actor_user_id=principal_id, expected_revision=expected_revision,
            signed_authority=context.signed_authority, authority_lifecycle=context.authority_lifecycle,
            domain=material.domain, revision=planned.revision, certificate=certificate,
            idempotency_key=idempotency_key, correlation_id=correlation_id, occurred_at=now,
        ), operator_request=request)

    async def create_intent(
        self, intent: object, *, tenant_id: str, principal_id: str, idempotency_key: str,
        correlation_id: str, now: datetime,
    ) -> AutonomousCampaignMutationResultV1:
        if not self.creation_available:
            raise ApplicationDependencyUnavailable("operator_creation_unavailable")
        if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 200:
            raise ValueError("operator_idempotency_key_invalid")
        resolved = await self._selections.resolve_operator_intent(
            intent, tenant_id=tenant_id, principal_id=principal_id, now=now,
        )
        if resolved.target.target_class != "owned-http":
            raise ApplicationBindingConflict("operator_target_class_unavailable")
        parts = resolved.target.revision.split(":")
        try:
            if len(parts) != 2:
                raise ValueError("operator_target_revision_invalid")
            native_root = AutonomousCampaignNativeRootV1(
                name=resolved.request.name, engagement_revision=int(resolved.engagement.revision),
                target_revision=int(parts[0]), roe_revision=int(parts[1]),
            )
        except ValueError as exc:
            raise ApplicationBindingConflict("operator_native_source_invalid") from exc
        campaign_id = "campaign-" + canonical_planning_sha256({
            "schema": "redagent.operator-intent-identity/v1", "tenant_id": tenant_id,
            "principal_id": principal_id, "idempotency_key": idempotency_key,
        })[:48]
        intent_sha256 = canonical_planning_sha256({
            "schema": "redagent.operator-intent/v1", "tenant_id": tenant_id,
            # CRITICAL: native intent digests are unique per tenant. Bind the server-owned request
            # identity so a deliberate new campaign can reuse selections without colliding with history.
            "principal_id": principal_id, "campaign_id": campaign_id,
            **{field: getattr(intent, field) for field in (
                "engagement_binding", "target_binding", "objective", "risk_profile",
            )},
        })
        source_sha256 = canonical_planning_sha256({
            "schema": "redagent.operator-native-source/v1", "tenant_id": tenant_id,
            "engagement_id": resolved.engagement.resource_id,
            "engagement_revision": native_root.engagement_revision,
            "target_id": resolved.target.resource_id, "target_revision": native_root.target_revision,
            "roe_revision": native_root.roe_revision, "target_class": resolved.target.target_class,
            "objective_kind": resolved.request.objective_kind,
            "header_code": resolved.request.header_code,
            "require_corroboration": resolved.request.require_corroboration,
            "risk_profile": resolved.request.risk_profile,
        })
        # CRITICAL: create only the native intent; preparation, approval and admission are separate mutations.
        return await self._application.create_intent(CreateAutonomousCampaignIntentV1(
            schema_version=APPLICATION_CONTRACT_VERSION, tenant_id=tenant_id, campaign_id=campaign_id,
            engagement_id=resolved.engagement.resource_id, target_id=resolved.target.resource_id,
            actor_user_id=principal_id, intent_sha256=intent_sha256, source_binding_sha256=source_sha256,
            expected_revision=0, idempotency_key=idempotency_key,
            correlation_id=correlation_id, occurred_at=now, native_root=native_root,
        ))
