"""Immutable compat_123 safety, effect, and pure level-reconciliation contracts."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ApprovalTier(str, Enum):
    TIER_1 = "tier1"
    TIER_2 = "tier2"
    TIER_3 = "tier3"


class ReconciliationState(str, Enum):
    RECONCILIATION_REQUIRED = "reconciliation_required"
    CONFIRMED = "confirmed"
    NOT_APPLIED = "not_applied"
    COMPENSATED = "compensated"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class ReconcileOutcome(str, Enum):
    SETTLED = "settled"
    DISPATCH_ONCE = "dispatch_once"
    RETRY_AT = "retry_at"
    BLOCKED = "blocked"
    CONTAINED = "contained"
    TERMINAL_FAILURE = "terminal_failure"


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectBudgetV1:
    duration_seconds: int
    request_count: int
    concurrency: int
    data_bytes: int
    evidence_bytes: int
    impact_count: int
    replan_count: int
    plan_depth: int

    def __post_init__(self) -> None:
        _integer("effect_budget_duration_seconds", self.duration_seconds, 1, 3600)
        _integer("effect_budget_request_count", self.request_count, 1, 1000)
        _integer("effect_budget_concurrency", self.concurrency, 1, 1)
        _integer("effect_budget_data_bytes", self.data_bytes, 1, 64 * 1024 * 1024)
        _integer("effect_budget_evidence_bytes", self.evidence_bytes, 1, 32 * 1024 * 1024)
        _integer("effect_budget_impact_count", self.impact_count, 0, 0)
        _integer("effect_budget_replan_count", self.replan_count, 0, 1)
        _integer("effect_budget_plan_depth", self.plan_depth, 1, 2)

    @property
    def budget_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SafetyObligationsV1:
    evidence_required: bool
    report_safe_evidence_required: bool
    cleanup_required: bool
    compensation_required: bool
    reconciliation_required: bool
    secret_revocation_required: bool
    containment_required: bool
    residual_risk_required: bool
    finding_or_coverage_required: bool
    retest_required: bool
    stop_on_authority_drift: bool

    def __post_init__(self) -> None:
        if not all(isinstance(value, bool) for value in asdict(self).values()):
            raise ValueError("safety_obligations_invalid")
        if not all(asdict(self).values()):
            raise ValueError("safety_obligations_required")


@dataclass(frozen=True, slots=True, kw_only=True)
class CapabilityExecutionCeilingV1:
    capability_id: str
    capability_revision: int
    execution_manifest_sha256: str
    adapter_id: str
    adapter_version: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None
    semantics_sha256: str
    execution_mode: str
    arguments_schema_sha256: str
    arguments_ceiling_sha256: str
    arguments_max_bytes: int

    def __post_init__(self) -> None:
        for name in ("capability_id", "adapter_id", "adapter_version", "profile_id", "execution_mode"):
            _identifier(f"proposal_{name}", getattr(self, name))
        _integer("proposal_capability_revision", self.capability_revision, 1, 9999)
        _integer("proposal_profile_revision", self.profile_revision, 1, 9999)
        for name in (
            "execution_manifest_sha256",
            "profile_sha256",
            "semantics_sha256",
            "arguments_schema_sha256",
            "arguments_ceiling_sha256",
        ):
            _sha256(f"proposal_{name}", getattr(self, name))
        bundle = (self.bundle_id, self.bundle_revision, self.bundle_sha256)
        if any(value is None for value in bundle) and any(value is not None for value in bundle):
            raise ValueError("proposal_bundle_identity_incomplete")
        if self.bundle_id is not None:
            _identifier("proposal_bundle_id", self.bundle_id)
            _integer("proposal_bundle_revision", self.bundle_revision, 1, 9999)
            _sha256("proposal_bundle_sha256", self.bundle_sha256)
        _integer("proposal_arguments_max_bytes", self.arguments_max_bytes, 1, 16_384)

    @property
    def capability_ceiling_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProposalSafetyCeilingV1:
    schema_version: str
    tenant_id: str
    engagement_id: str
    actor_id: str
    workload_identity: str
    objective_sha256: str
    target_revision: int
    target_sha256: str
    target_resolution_mode: str
    allowed_capabilities: tuple[CapabilityExecutionCeilingV1, ...]
    policy_sha256: str
    policy_revocation_epoch: int
    roe_sha256: str
    roe_revocation_epoch: int
    credential_class: str
    credential_reference_id: str | None
    destination: str
    egress_profile: str
    sandbox_class: str
    runner_class: str
    risk_ceiling: str
    budget: EffectBudgetV1
    observation_freshness_seconds: int
    obligations: SafetyObligationsV1
    approval_tier: ApprovalTier
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-proposal-safety-ceiling/v1")
        for name in ("tenant_id", "engagement_id", "actor_id", "target_resolution_mode", "credential_class"):
            _identifier(f"proposal_{name}", getattr(self, name))
        for name in ("destination", "egress_profile", "sandbox_class", "runner_class", "risk_ceiling", "nonce"):
            _reference(f"proposal_{name}", getattr(self, name))
        _reference("proposal_workload_identity", self.workload_identity)
        for name in ("objective_sha256", "target_sha256", "policy_sha256", "roe_sha256"):
            _sha256(f"proposal_{name}", getattr(self, name))
        _integer("proposal_target_revision", self.target_revision, 1, 2_147_483_647)
        _integer("proposal_policy_revocation_epoch", self.policy_revocation_epoch, 0, 2_147_483_647)
        _integer("proposal_roe_revocation_epoch", self.roe_revocation_epoch, 0, 2_147_483_647)
        if (
            not isinstance(self.allowed_capabilities, tuple)
            or not 1 <= len(self.allowed_capabilities) <= 3
            or not all(isinstance(value, CapabilityExecutionCeilingV1) for value in self.allowed_capabilities)
            or len({value.capability_id for value in self.allowed_capabilities}) != len(self.allowed_capabilities)
        ):
            raise ValueError("proposal_capabilities_invalid")
        if self.credential_class == "none":
            if self.credential_reference_id is not None:
                raise ValueError("proposal_credential_reference_invalid")
        elif self.credential_reference_id is None:
            raise ValueError("proposal_credential_reference_required")
        else:
            _identifier("proposal_credential_reference_id", self.credential_reference_id)
        if not isinstance(self.budget, EffectBudgetV1) or not isinstance(self.obligations, SafetyObligationsV1):
            raise ValueError("proposal_safety_components_invalid")
        _integer("proposal_observation_freshness_seconds", self.observation_freshness_seconds, 1, 3600)
        if self.approval_tier is not ApprovalTier.TIER_1:
            raise ValueError("proposal_first_slice_tier_invalid")
        _aware("proposal_expires_at", self.expires_at)

    @property
    def proposal_ceiling_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutableEnvelopeCoreV1:
    schema_version: str
    tenant_id: str
    proposal_ceiling_sha256: str
    plan_sha256: str
    approver_requirement: str
    workload_identity: str
    target_sha256: str
    destination: str
    sandbox_class: str
    runner_class: str
    reservation_id: str
    lease_id: str
    arguments_sha256: str
    effect_sha256: str
    effective_budget: EffectBudgetV1
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-executable-envelope-core/v1")
        _identifier("envelope_tenant_id", self.tenant_id)
        for name in ("approver_requirement", "workload_identity", "destination", "sandbox_class", "runner_class", "nonce"):
            _reference(f"envelope_{name}", getattr(self, name))
        for name in ("reservation_id", "lease_id"):
            _identifier(f"envelope_{name}", getattr(self, name))
        for name in (
            "proposal_ceiling_sha256", "plan_sha256", "target_sha256", "arguments_sha256", "effect_sha256"
        ):
            _sha256(f"envelope_{name}", getattr(self, name))
        if not isinstance(self.effective_budget, EffectBudgetV1):
            raise ValueError("envelope_budget_invalid")
        _integer("envelope_policy_revocation_epoch", self.policy_revocation_epoch, 0, 2_147_483_647)
        _integer("envelope_roe_revocation_epoch", self.roe_revocation_epoch, 0, 2_147_483_647)
        _window("envelope", self.issued_at, self.expires_at, 300)

    @property
    def core_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalReceiptV1:
    schema_version: str
    approval_id: str
    approval_revision: int
    tenant_id: str
    approver_id: str
    workload_identity: str
    core_sha256: str
    decision: str
    approved_at: datetime
    expires_at: datetime
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-approval-receipt/v1")
        for name in ("approval_id", "tenant_id", "approver_id", "key_id"):
            _identifier(f"approval_{name}", getattr(self, name))
        _reference("approval_workload_identity", self.workload_identity)
        _integer("approval_revision", self.approval_revision, 1, 2_147_483_647)
        _sha256("approval_core_sha256", self.core_sha256)
        if self.decision != "approved":
            raise ValueError("approval_decision_invalid")
        _window("approval", self.approved_at, self.expires_at, 300)
        try:
            value = base64.urlsafe_b64decode(self.signature.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("approval_signature_invalid") from exc
        if len(value) != 64:
            raise ValueError("approval_signature_invalid")

    @property
    def receipt_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class SafetyEnvelopeV1:
    schema_version: str
    core: ExecutableEnvelopeCoreV1
    approval_receipt_id: str
    approval_receipt_revision: int
    approval_receipt_sha256: str

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-safety-envelope/v1")
        if not isinstance(self.core, ExecutableEnvelopeCoreV1):
            raise ValueError("safety_envelope_core_invalid")
        _identifier("safety_envelope_approval_id", self.approval_receipt_id)
        _integer("safety_envelope_approval_revision", self.approval_receipt_revision, 1, 2_147_483_647)
        _sha256("safety_envelope_approval_sha256", self.approval_receipt_sha256)

    @property
    def envelope_sha256(self) -> str:
        # IMPORTANT: the final digest covers the independently signed core plus receipt identity;
        # it is never included in the approval signature input and therefore cannot recurse.
        return _canonical_sha256(self)


def sign_approval_receipt(
    core: ExecutableEnvelopeCoreV1,
    private_key: Ed25519PrivateKey,
    *,
    approval_id: str,
    approval_revision: int,
    approver_id: str,
    key_id: str,
    approved_at: datetime,
    expires_at: datetime,
) -> ApprovalReceiptV1:
    if not isinstance(core, ExecutableEnvelopeCoreV1) or not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("approval_signing_input_invalid")
    unsigned = _approval_unsigned_payload(
        approval_id=approval_id,
        approval_revision=approval_revision,
        tenant_id=core.tenant_id,
        approver_id=approver_id,
        workload_identity=core.workload_identity,
        core_sha256=core.core_sha256,
        decision="approved",
        approved_at=approved_at,
        expires_at=expires_at,
        key_id=key_id,
    )
    signature = base64.urlsafe_b64encode(private_key.sign(_canonical_bytes(unsigned))).decode("ascii")
    return ApprovalReceiptV1(signature=signature, **unsigned)


def build_safety_envelope(
    core: ExecutableEnvelopeCoreV1,
    receipt: ApprovalReceiptV1,
    public_key: Ed25519PublicKey,
    *,
    now: datetime,
) -> SafetyEnvelopeV1:
    if receipt.core_sha256 != core.core_sha256:
        raise ValueError("approval_core_mismatch")
    if receipt.tenant_id != core.tenant_id or receipt.workload_identity != core.workload_identity:
        raise ValueError("approval_scope_mismatch")
    _aware("approval_verification_now", now)
    if not receipt.approved_at <= now < receipt.expires_at or not core.issued_at <= now < core.expires_at:
        raise ValueError("approval_expired")
    unsigned = _approval_unsigned_payload(
        approval_id=receipt.approval_id,
        approval_revision=receipt.approval_revision,
        tenant_id=receipt.tenant_id,
        approver_id=receipt.approver_id,
        workload_identity=receipt.workload_identity,
        core_sha256=receipt.core_sha256,
        decision=receipt.decision,
        approved_at=receipt.approved_at,
        expires_at=receipt.expires_at,
        key_id=receipt.key_id,
    )
    try:
        public_key.verify(base64.urlsafe_b64decode(receipt.signature.encode("ascii")), _canonical_bytes(unsigned))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("approval_signature_invalid") from exc
    return SafetyEnvelopeV1(
        schema_version="redagent.r123-safety-envelope/v1",
        core=core,
        approval_receipt_id=receipt.approval_id,
        approval_receipt_revision=receipt.approval_revision,
        approval_receipt_sha256=receipt.receipt_sha256,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectIntentV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    plan_revision_id: str
    node_id: str
    invocation_id: str
    effect_id: str
    envelope_sha256: str
    arguments_sha256: str
    target_sha256: str
    current_authority_sha256: str
    outbox_sequence: int
    created_at: datetime

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-effect-intent/v1")
        for name in ("tenant_id", "campaign_id", "plan_revision_id", "node_id", "invocation_id", "effect_id"):
            _identifier(f"effect_intent_{name}", getattr(self, name))
        for name in ("envelope_sha256", "arguments_sha256", "target_sha256", "current_authority_sha256"):
            _sha256(f"effect_intent_{name}", getattr(self, name))
        _integer("effect_intent_outbox_sequence", self.outbox_sequence, 1, 2_147_483_647)
        _aware("effect_intent_created_at", self.created_at)

    @property
    def effect_intent_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectReceiptV1:
    schema_version: str
    effect_id: str
    effect_intent_sha256: str
    envelope_sha256: str
    dispatch_attempt: int
    dispatch_generation: int
    runner_id: str
    workload_identity: str
    request_sha256: str
    started_at: datetime
    completed_at: datetime | None
    adapter_accepted: bool
    external_status: str
    external_receipt_id: str | None
    evidence_ids: tuple[str, ...]
    cleanup_receipt_id: str | None
    output_complete: bool
    external_contact_count: int
    reconciliation_state: ReconciliationState
    reconciliation_evidence_ids: tuple[str, ...]
    redispatch_permitted: bool
    failure_code: str | None

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-effect-receipt/v1")
        for name in ("effect_id", "runner_id"):
            _identifier(f"effect_receipt_{name}", getattr(self, name))
        _reference("effect_receipt_workload_identity", self.workload_identity)
        for name in ("effect_intent_sha256", "envelope_sha256", "request_sha256"):
            _sha256(f"effect_receipt_{name}", getattr(self, name))
        _integer("effect_receipt_dispatch_attempt", self.dispatch_attempt, 1, 5)
        _integer("effect_receipt_dispatch_generation", self.dispatch_generation, 1, 2_147_483_647)
        _aware("effect_receipt_started_at", self.started_at)
        if self.completed_at is not None:
            _aware("effect_receipt_completed_at", self.completed_at)
            if self.completed_at < self.started_at:
                raise ValueError("effect_receipt_time_invalid")
        if not isinstance(self.adapter_accepted, bool) or not isinstance(self.redispatch_permitted, bool):
            raise ValueError("effect_receipt_boolean_invalid")
        _reference("effect_receipt_external_status", self.external_status)
        if self.external_receipt_id is not None:
            _identifier("effect_receipt_external_receipt_id", self.external_receipt_id)
        _closed_ids("effect_receipt_evidence_ids", self.evidence_ids, maximum=16)
        _closed_ids("effect_receipt_reconciliation_evidence_ids", self.reconciliation_evidence_ids, maximum=16)
        if self.cleanup_receipt_id is not None:
            _identifier("effect_receipt_cleanup_receipt_id", self.cleanup_receipt_id)
        if not isinstance(self.output_complete, bool):
            raise ValueError("effect_receipt_output_complete_invalid")
        _integer(
            "effect_receipt_external_contact_count",
            self.external_contact_count,
            0,
            1000,
        )
        if self.failure_code is not None:
            _reference("effect_receipt_failure_code", self.failure_code)
        if self.reconciliation_state is ReconciliationState.RECONCILIATION_REQUIRED:
            if self.redispatch_permitted:
                raise ValueError("effect_ambiguous_redispatch_forbidden")
            if not self.adapter_accepted or self.completed_at is not None:
                raise ValueError("effect_ambiguous_receipt_invalid")
        elif self.reconciliation_state is ReconciliationState.NOT_APPLIED:
            if (
                self.adapter_accepted
                or self.completed_at is None
                or self.external_status != "not_applied"
                or self.external_receipt_id is None
                or not self.evidence_ids
                or self.cleanup_receipt_id is None
                or not self.output_complete
                or self.external_contact_count != 0
                or not self.reconciliation_evidence_ids
                or not self.redispatch_permitted
                or self.failure_code is not None
            ):
                raise ValueError("effect_not_applied_receipt_incomplete")
        elif self.reconciliation_state is ReconciliationState.CONFIRMED:
            if (
                not self.adapter_accepted
                or self.completed_at is None
                or self.external_receipt_id is None
                or not self.evidence_ids
                or self.cleanup_receipt_id is None
                or not self.output_complete
                or self.external_contact_count != 0
                or not self.reconciliation_evidence_ids
                or self.failure_code is not None
                or self.redispatch_permitted
            ):
                raise ValueError("effect_confirmed_receipt_incomplete")
        elif self.redispatch_permitted:
            raise ValueError("effect_terminal_redispatch_forbidden")

    @property
    def receipt_sha256(self) -> str:
        return _canonical_sha256(self)

    @property
    def canonical_payload(self) -> dict[str, object]:
        payload = _normalize(self)
        if not isinstance(payload, dict):  # pragma: no cover - dataclass invariant
            raise RuntimeError("effect_receipt_payload_invalid")
        return payload


@dataclass(frozen=True, slots=True, kw_only=True)
class NodeDesiredV1:
    schema_version: str
    tenant_id: str
    plan_revision_id: str
    node_id: str
    effect_intent_sha256: str
    max_attempts: int
    stop_requested: bool
    authority_current: bool
    budget_available: bool
    successor_allowed: bool
    obligations: SafetyObligationsV1

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-node-desired/v1")
        for name in ("tenant_id", "plan_revision_id", "node_id"):
            _identifier(f"node_desired_{name}", getattr(self, name))
        _sha256("node_desired_effect_intent_sha256", self.effect_intent_sha256)
        _integer("node_desired_max_attempts", self.max_attempts, 1, 2)
        if not all(
            isinstance(value, bool)
            for value in (self.stop_requested, self.authority_current, self.budget_available, self.successor_allowed)
        ):
            raise ValueError("node_desired_boolean_invalid")
        if not isinstance(self.obligations, SafetyObligationsV1):
            raise ValueError("node_desired_obligations_invalid")

    @property
    def desired_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class NodeObservedV1:
    schema_version: str
    effect_state: str
    attempt_count: int
    next_retry_at: datetime | None
    receipt_state: ReconciliationState | None
    effect_receipt_sha256: str | None
    evidence_complete: bool
    report_safe_evidence_complete: bool
    finding_or_coverage_complete: bool
    retest_complete: bool
    secret_revocation_complete: bool
    containment_complete: bool
    cleanup_complete: bool
    reconciliation_complete: bool
    residual_risk_complete: bool
    infrastructure_available: bool

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-node-observed/v1")
        if self.effect_state not in {
            "absent", "claimed", "dispatching", "reconciliation_required", "not_applied",
            "confirmed", "compensated", "manual_review_required", "failed",
        }:
            raise ValueError("node_observed_effect_state_invalid")
        _integer("node_observed_attempt_count", self.attempt_count, 0, 2)
        if self.next_retry_at is not None:
            _aware("node_observed_next_retry_at", self.next_retry_at)
        if self.effect_receipt_sha256 is not None:
            _sha256("node_observed_effect_receipt_sha256", self.effect_receipt_sha256)
        if self.receipt_state is None and self.effect_receipt_sha256 is not None:
            raise ValueError("node_observed_receipt_state_required")
        values = (
            self.evidence_complete,
            self.report_safe_evidence_complete,
            self.finding_or_coverage_complete,
            self.retest_complete,
            self.secret_revocation_complete,
            self.containment_complete,
            self.cleanup_complete,
            self.reconciliation_complete,
            self.residual_risk_complete,
            self.infrastructure_available,
        )
        if not all(isinstance(value, bool) for value in values):
            raise ValueError("node_observed_boolean_invalid")
        if self.effect_state == "not_applied" and (
            self.receipt_state is not ReconciliationState.NOT_APPLIED
            or self.effect_receipt_sha256 is None
            or not self.evidence_complete
            or not self.report_safe_evidence_complete
            or not self.cleanup_complete
            or not self.reconciliation_complete
        ):
            # CRITICAL: an unproved observation can never mint redispatch authority.
            raise ValueError("node_observed_not_applied_proof_required")

    @property
    def observed_sha256(self) -> str:
        return _canonical_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReconcileResultV1:
    schema_version: str
    desired_sha256: str
    observed_sha256: str
    outcome: ReconcileOutcome
    reason_code: str
    retry_at: datetime | None
    redispatch_permitted: bool

    def __post_init__(self) -> None:
        _schema(self.schema_version, "redagent.r123-reconcile-result/v1")
        _sha256("reconcile_desired_sha256", self.desired_sha256)
        _sha256("reconcile_observed_sha256", self.observed_sha256)
        _reference("reconcile_reason_code", self.reason_code)
        if self.retry_at is not None:
            _aware("reconcile_retry_at", self.retry_at)
        if self.outcome is ReconcileOutcome.RETRY_AT and self.retry_at is None:
            raise ValueError("reconcile_retry_at_required")
        if self.outcome is not ReconcileOutcome.RETRY_AT and self.retry_at is not None:
            raise ValueError("reconcile_retry_at_forbidden")
        if self.redispatch_permitted and self.outcome not in {
            ReconcileOutcome.DISPATCH_ONCE,
            ReconcileOutcome.RETRY_AT,
        }:
            raise ValueError("reconcile_redispatch_invalid")

    @property
    def reconcile_sha256(self) -> str:
        return _canonical_sha256(self)


def reconcile_node(desired: NodeDesiredV1, observed: NodeObservedV1, *, now: datetime) -> ReconcileResultV1:
    """Return a pure level decision; callers alone own persistence and side effects."""
    if not isinstance(desired, NodeDesiredV1) or not isinstance(observed, NodeObservedV1):
        raise ValueError("reconcile_input_invalid")
    _aware("reconcile_now", now)

    def result(
        outcome: ReconcileOutcome,
        reason: str,
        *,
        retry_at: datetime | None = None,
        redispatch: bool = False,
    ) -> ReconcileResultV1:
        return ReconcileResultV1(
            schema_version="redagent.r123-reconcile-result/v1",
            desired_sha256=desired.desired_sha256,
            observed_sha256=observed.observed_sha256,
            outcome=outcome,
            reason_code=reason,
            retry_at=retry_at,
            redispatch_permitted=redispatch,
        )

    if desired.stop_requested:
        return result(ReconcileOutcome.CONTAINED, "stop_requested_containment_required")
    if not desired.authority_current:
        return result(ReconcileOutcome.BLOCKED, "current_authority_denied")
    if not desired.budget_available:
        return result(ReconcileOutcome.BLOCKED, "effect_budget_unavailable")
    if not observed.infrastructure_available:
        return result(ReconcileOutcome.BLOCKED, "infrastructure_unavailable")
    if observed.effect_state == "absent":
        return result(ReconcileOutcome.DISPATCH_ONCE, "effect_absent_dispatch_once", redispatch=True)
    if observed.effect_state in {"claimed", "dispatching"}:
        return result(ReconcileOutcome.BLOCKED, "effect_in_flight")
    if observed.effect_state == "reconciliation_required":
        if observed.next_retry_at is not None:
            return result(
                ReconcileOutcome.RETRY_AT,
                "status_lookup_retry_scheduled",
                retry_at=observed.next_retry_at,
            )
        return result(ReconcileOutcome.BLOCKED, "adapter_acceptance_ambiguous")
    if observed.effect_state == "not_applied":
        if observed.attempt_count >= desired.max_attempts:
            return result(ReconcileOutcome.TERMINAL_FAILURE, "effect_attempt_budget_exhausted")
        if observed.next_retry_at is None:
            return result(ReconcileOutcome.BLOCKED, "effect_retry_schedule_missing")
        return result(
            ReconcileOutcome.RETRY_AT,
            "status_proved_not_applied_retry_scheduled",
            retry_at=observed.next_retry_at,
            redispatch=True,
        )
    if observed.effect_state == "failed":
        return result(ReconcileOutcome.TERMINAL_FAILURE, "effect_terminal_failure")
    if observed.effect_state == "manual_review_required":
        return result(ReconcileOutcome.BLOCKED, "manual_review_required")
    if observed.effect_state == "compensated":
        return result(ReconcileOutcome.SETTLED, "effect_compensated_terminal")
    if observed.effect_state != "confirmed":
        return result(ReconcileOutcome.BLOCKED, "effect_state_unrecognized")

    finalizer_checks = (
        ("evidence_complete", "evidence_incomplete"),
        ("report_safe_evidence_complete", "report_safe_evidence_incomplete"),
        ("finding_or_coverage_complete", "finding_or_coverage_incomplete"),
        ("retest_complete", "retest_incomplete"),
        ("secret_revocation_complete", "secret_revocation_incomplete"),
        ("containment_complete", "containment_incomplete"),
        ("cleanup_complete", "cleanup_incomplete"),
        ("reconciliation_complete", "reconciliation_incomplete"),
        ("residual_risk_complete", "residual_risk_incomplete"),
    )
    for field, reason in finalizer_checks:
        if getattr(desired.obligations, _obligation_field(field)) and not getattr(observed, field):
            return result(ReconcileOutcome.BLOCKED, reason)
    return result(ReconcileOutcome.SETTLED, "all_terminal_obligations_complete")


def _obligation_field(observed_field: str) -> str:
    return {
        "evidence_complete": "evidence_required",
        "report_safe_evidence_complete": "report_safe_evidence_required",
        "finding_or_coverage_complete": "finding_or_coverage_required",
        "retest_complete": "retest_required",
        "secret_revocation_complete": "secret_revocation_required",  # pragma: allowlist secret
        "containment_complete": "containment_required",
        "cleanup_complete": "cleanup_required",
        "reconciliation_complete": "reconciliation_required",
        "residual_risk_complete": "residual_risk_required",
    }[observed_field]


def _approval_unsigned_payload(**values: object) -> dict[str, object]:
    return {"schema_version": "redagent.r123-approval-receipt/v1", **values}


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _normalize(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return _normalize(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        _aware("canonical_datetime", value)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    return value


def _schema(value: object, expected: str) -> None:
    if value != expected:
        raise ValueError("r123_schema_version_unsupported")


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reference(name: str, value: object) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _integer(name: str, value: object, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")


def _window(name: str, start: datetime, end: datetime, maximum_seconds: int) -> None:
    _aware(f"{name}_start", start)
    _aware(f"{name}_end", end)
    if not start < end or (end - start).total_seconds() > maximum_seconds:
        raise ValueError(f"{name}_window_invalid")


def _closed_ids(name: str, values: tuple[str, ...], *, maximum: int) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > maximum
        or len(set(values)) != len(values)
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)
