"""Closed contracts for fail-closed plan admission and campaign budget accounting."""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from enum import Enum
import re

from redagent_platform.campaign_service.planning.contracts import ValidationResult, canonical_planning_sha256


CAMPAIGN_BUDGET_VECTOR_SCHEMA_VERSION = "redagent.campaign-budget-vector/v1"
PLAN_ENVELOPE_SUBSET_PROOF_SCHEMA_VERSION = "redagent.plan-envelope-subset-proof/v1"
PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION = "redagent.plan-admission-receipt/v1"
_MAX_BUDGET_VALUE = 10**18
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_REASON = re.compile(r"^[a-z][a-z0-9_:]{0,149}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PLAN_ENVELOPE_SUBSET_DIMENSIONS = (
    "tenant",
    "engagement",
    "objective",
    "success_conditions",
    "targets",
    "capabilities",
    "effects",
    "data_access",
    "credentials",
    "environment",
    "graph_bounds",
    "resource_bounds",
    "operator_arguments",
    "time_window",
)


class AdmissionOutcome(str, Enum):
    ADMITTED = "admitted"
    DENIED = "denied"


class CampaignReservationState(str, Enum):
    RESERVED = "reserved"
    HELD = "held"
    CONSUMED = "consumed"
    RELEASED = "released"
    EXPIRED = "expired"


def assert_campaign_reservation_transition(
    current: CampaignReservationState,
    target: CampaignReservationState,
    *,
    effect_started: bool,
    reconciliation_code: str | None,
    now: datetime,
    lease_expires_at: datetime,
) -> None:
    if not isinstance(current, CampaignReservationState) or not isinstance(target, CampaignReservationState):
        raise ValueError("campaign_reservation_state_invalid")
    if type(effect_started) is not bool:
        raise ValueError("campaign_reservation_effect_flag_invalid")
    _aware("campaign_reservation_now", now)
    _aware("campaign_reservation_lease_expires_at", lease_expires_at)
    if reconciliation_code is not None:
        _reason("campaign_reservation_reconciliation", reconciliation_code)
    if current in {
        CampaignReservationState.CONSUMED,
        CampaignReservationState.RELEASED,
        CampaignReservationState.EXPIRED,
    }:
        raise ValueError("campaign_reservation_terminal")
    if current is CampaignReservationState.HELD:
        if target is CampaignReservationState.CONSUMED and reconciliation_code == "applied":
            return
        if target is CampaignReservationState.RELEASED and reconciliation_code == "not_applied":
            return
        # CRITICAL: elapsed time is never proof that an ambiguous effect was not applied.
        raise ValueError("campaign_reservation_held_requires_reconciliation")
    if target is CampaignReservationState.HELD:
        if effect_started and reconciliation_code in {"effect_started", "effect_ambiguous"}:
            return
        raise ValueError("campaign_reservation_hold_requires_effect")
    if target is CampaignReservationState.CONSUMED:
        if effect_started and reconciliation_code == "applied":
            return
        raise ValueError("campaign_reservation_consumption_proof_required")
    if target is CampaignReservationState.RELEASED:
        if effect_started:
            raise ValueError("campaign_reservation_effect_release_forbidden")
        if reconciliation_code in {"not_started", "not_applied"}:
            return
        raise ValueError("campaign_reservation_release_proof_required")
    if target is CampaignReservationState.EXPIRED:
        if effect_started:
            raise ValueError("campaign_reservation_effect_expiry_forbidden")
        if now >= lease_expires_at:
            return
        raise ValueError("campaign_reservation_lease_active")
    raise ValueError("campaign_reservation_transition_invalid")


@dataclass(frozen=True, slots=True)
class CampaignBudgetVectorV1:
    duration_seconds: int
    requests: int
    rate_per_minute: int
    concurrency: int
    risk_micropoints: int
    cost_microunits: int
    evidence_bytes: int
    data_bytes: int
    schema_version: str = CAMPAIGN_BUDGET_VECTOR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CAMPAIGN_BUDGET_VECTOR_SCHEMA_VERSION:
            raise ValueError("campaign_budget_schema_unsupported")
        for field in fields(self):
            if field.name == "schema_version":
                continue
            value = getattr(self, field.name)
            if type(value) is not int or not 0 <= value <= _MAX_BUDGET_VALUE:
                raise ValueError(f"campaign_budget_{field.name}_invalid")

    @property
    def budget_sha256(self) -> str:
        return canonical_planning_sha256(self)

    def add(self, other: CampaignBudgetVectorV1) -> CampaignBudgetVectorV1:
        _budget(other)
        values: dict[str, int] = {}
        for field in fields(self):
            if field.name == "schema_version":
                continue
            value = getattr(self, field.name) + getattr(other, field.name)
            if value > _MAX_BUDGET_VALUE:
                raise ValueError("campaign_budget_overflow")
            values[field.name] = value
        return _budget_from_values(values)

    def subtract(self, other: CampaignBudgetVectorV1) -> CampaignBudgetVectorV1:
        _budget(other)
        values: dict[str, int] = {}
        for field in fields(self):
            if field.name == "schema_version":
                continue
            value = getattr(self, field.name) - getattr(other, field.name)
            if value < 0:
                raise ValueError("campaign_budget_underflow")
            values[field.name] = value
        return _budget_from_values(values)

    def fits_within(self, available: CampaignBudgetVectorV1) -> bool:
        _budget(available)
        return all(
            getattr(self, field.name) <= getattr(available, field.name)
            for field in fields(self)
            if field.name != "schema_version"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanEnvelopeSubsetProofV1:
    schema_version: str
    authority_sha256: str
    domain_sha256: str
    plan_sha256: str
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    validation_result: ValidationResult
    checked_dimensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_ENVELOPE_SUBSET_PROOF_SCHEMA_VERSION:
            raise ValueError("plan_envelope_subset_proof_schema_unsupported")
        for name in (
            "authority_sha256",
            "domain_sha256",
            "plan_sha256",
            "certificate_sha256",
            "validator_sha256",
        ):
            _sha256(f"plan_envelope_subset_proof_{name}", getattr(self, name))
        _identifier("plan_envelope_subset_proof_validator_version", self.validator_version)
        if not isinstance(self.validation_result, ValidationResult):
            raise ValueError("plan_envelope_subset_proof_result_invalid")
        # CRITICAL: this exact closed list prevents a new authority dimension from being silently omitted.
        if self.checked_dimensions != PLAN_ENVELOPE_SUBSET_DIMENSIONS:
            raise ValueError("plan_envelope_subset_proof_incomplete")

    @property
    def admissible(self) -> bool:
        return self.validation_result is ValidationResult.VALID

    @property
    def proof_sha256(self) -> str:
        return canonical_planning_sha256(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanAdmissionReceiptV1:
    schema_version: str
    receipt_id: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_sha256: str
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    subset_proof_sha256: str
    policy_decision_id: str | None
    policy_input_sha256: str | None
    policy_bundle_revision: str | None
    policy_bundle_sha256: str | None
    pre_residual_budget_sha256: str | None
    post_residual_budget_sha256: str | None
    reserved_budget: CampaignBudgetVectorV1 | None
    reservation_id: str | None
    idempotency_key: str
    request_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    issued_at: datetime
    expires_at: datetime
    outcome: AdmissionOutcome
    denial_stage: str | None
    reason_code: str
    audit_id: str
    outbox_id: str

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION:
            raise ValueError("plan_admission_receipt_schema_unsupported")
        for name in (
            "receipt_id",
            "tenant_id",
            "campaign_id",
            "engagement_id",
            "validator_version",
            "idempotency_key",
            "audit_id",
            "outbox_id",
        ):
            _identifier(f"plan_admission_{name}", getattr(self, name))
        for name in (
            "signed_authority_sha256",
            "authority_sha256",
            "domain_sha256",
            "plan_sha256",
            "certificate_sha256",
            "validator_sha256",
            "subset_proof_sha256",
            "request_sha256",
        ):
            _sha256(f"plan_admission_{name}", getattr(self, name))
        for name in (
            "policy_input_sha256",
            "policy_bundle_sha256",
            "pre_residual_budget_sha256",
            "post_residual_budget_sha256",
        ):
            value = getattr(self, name)
            if value is not None:
                _sha256(f"plan_admission_{name}", value)
        for name in ("policy_decision_id", "policy_bundle_revision"):
            value = getattr(self, name)
            if value is not None:
                _identifier(f"plan_admission_{name}", value)
        for name in (
            "lifecycle_epoch",
            "policy_revocation_epoch",
            "roe_revocation_epoch",
            "kill_switch_epoch",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 2_147_483_647:
                raise ValueError(f"plan_admission_{name}_invalid")
        _aware("plan_admission_issued_at", self.issued_at)
        _aware("plan_admission_expires_at", self.expires_at)
        if not self.issued_at < self.expires_at:
            raise ValueError("plan_admission_receipt_window_invalid")
        if not isinstance(self.outcome, AdmissionOutcome):
            raise ValueError("plan_admission_outcome_invalid")
        _reason("plan_admission_reason", self.reason_code)
        if self.denial_stage is not None:
            _reason("plan_admission_denial_stage", self.denial_stage)
        success_fields = (
            self.policy_decision_id,
            self.policy_input_sha256,
            self.policy_bundle_revision,
            self.policy_bundle_sha256,
            self.pre_residual_budget_sha256,
            self.post_residual_budget_sha256,
            self.reserved_budget,
            self.reservation_id,
        )
        if self.outcome is AdmissionOutcome.ADMITTED:
            if self.denial_stage is not None or any(value is None for value in success_fields):
                raise ValueError("plan_admission_success_fields_required")
            if self.reason_code != "admitted":
                raise ValueError("plan_admission_success_reason_invalid")
        else:
            if self.denial_stage is None:
                raise ValueError("plan_admission_denial_stage_required")
            if any(
                value is not None
                for value in (self.post_residual_budget_sha256, self.reserved_budget, self.reservation_id)
            ):
                raise ValueError("plan_admission_denial_fields_forbidden")

    @property
    def receipt_sha256(self) -> str:
        return canonical_planning_sha256(self)


def _budget(value: object) -> None:
    if not isinstance(value, CampaignBudgetVectorV1):
        raise ValueError("campaign_budget_vector_invalid")


def _budget_from_values(values: dict[str, int]) -> CampaignBudgetVectorV1:
    return CampaignBudgetVectorV1(
        duration_seconds=values["duration_seconds"],
        requests=values["requests"],
        rate_per_minute=values["rate_per_minute"],
        concurrency=values["concurrency"],
        risk_micropoints=values["risk_micropoints"],
        cost_microunits=values["cost_microunits"],
        evidence_bytes=values["evidence_bytes"],
        data_bytes=values["data_bytes"],
    )


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reason(name: str, value: object) -> None:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
