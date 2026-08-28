"""Immutable campaign authority, lifecycle, and subset contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


CAMPAIGN_AUTHORITY_SCHEMA_VERSION = "redagent.campaign-authority-envelope/v2"
CAMPAIGN_AUTHORITY_CANONICALIZATION_VERSION = "redagent.canonical-json/v1"
CAMPAIGN_AUTHORITY_APPROVAL_SCHEMA_VERSION = "redagent.campaign-authority-approval/v2"
CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION = "redagent.campaign-authority-lifecycle/v2"
CAMPAIGN_AUTHORITY_MAX_LIFECYCLE_OBSERVATION_SECONDS = 300

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,99}$")


class CampaignEffectClass(str, Enum):
    READ_ONLY_OBSERVATION = "read_only_observation"
    NETWORK_REQUEST = "network_request"
    AUTHENTICATED_QUERY = "authenticated_query"
    CONTROLLED_STATE_CHANGE = "controlled_state_change"
    DISRUPTIVE = "disruptive"


class CampaignDataAccessClass(str, Enum):
    METADATA_ONLY = "metadata_only"
    REPORT_SAFE = "report_safe"
    SENSITIVE = "sensitive"


class CampaignCredentialClass(str, Enum):
    NONE = "none"
    SCOPED_READ = "scoped_read"
    SCOPED_WRITE = "scoped_write"


class CampaignEnvironmentClass(str, Enum):
    SYNTHETIC_LOOPBACK = "synthetic_loopback"
    OWNED_DISPOSABLE_LAB = "owned_disposable_lab"
    OWNED_STAGING = "owned_staging"


class CampaignAuthorityLifecycleState(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AuthoritySubsetClassification(str, Enum):
    SUBSET = "subset"
    EXPANSION = "expansion"
    INCOMPARABLE = "incomparable"


@dataclass(frozen=True, slots=True)
class CampaignApproverRequirementV2:
    principal_id: str
    role_id: str

    def __post_init__(self) -> None:
        _identifier("campaign_approver_principal", self.principal_id)
        _identifier("campaign_approver_role", self.role_id)


@dataclass(frozen=True, slots=True)
class CampaignAuthorityBoundsV2:
    max_duration_seconds: int
    max_search_seconds: int
    max_depth: int
    max_width: int
    max_nodes: int
    max_frontier: int
    max_replans: int
    max_retries_per_node: int
    max_requests: int
    max_rate_per_minute: int
    max_concurrency: int
    max_risk_micropoints: int
    max_cost_microunits: int
    max_evidence_bytes: int
    max_data_bytes: int

    def __post_init__(self) -> None:
        limits = {
            "max_duration_seconds": (1, 86_400),
            "max_search_seconds": (1, 3_600),
            "max_depth": (1, 1_024),
            "max_width": (1, 1_024),
            "max_nodes": (1, 100_000),
            "max_frontier": (1, 100_000),
            "max_replans": (0, 10_000),
            "max_retries_per_node": (0, 100),
            "max_requests": (1, 10_000_000),
            "max_rate_per_minute": (1, 1_000_000),
            "max_concurrency": (1, 10_000),
            "max_risk_micropoints": (0, 1_000_000_000),
            "max_cost_microunits": (0, 1_000_000_000_000),
            "max_evidence_bytes": (1, 1_099_511_627_776),
            "max_data_bytes": (1, 1_099_511_627_776),
        }
        for name, (minimum, maximum) in limits.items():
            _integer(f"campaign_authority_{name}", getattr(self, name), minimum, maximum)
        if self.max_frontier < self.max_width or self.max_frontier > self.max_nodes:
            raise ValueError("campaign_authority_frontier_invalid")
        if self.max_nodes < self.max_depth or self.max_nodes < self.max_width:
            raise ValueError("campaign_authority_graph_bounds_inconsistent")
        if self.max_concurrency > self.max_width:
            raise ValueError("campaign_authority_concurrency_above_width")
        if self.max_rate_per_minute < self.max_concurrency:
            raise ValueError("campaign_authority_rate_below_concurrency")


@dataclass(frozen=True, slots=True)
class CampaignSafetyRequirementsV2:
    evidence_required: bool
    report_safe_redaction_required: bool
    cleanup_required: bool
    containment_required: bool
    terminal_receipt_required: bool
    stop_on_authority_drift: bool

    def __post_init__(self) -> None:
        if any(not isinstance(getattr(self, field.name), bool) for field in fields(self)):
            raise ValueError("campaign_authority_safety_requirement_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignAuthorityEnvelopeV2:
    schema_version: str
    canonicalization_version: str
    envelope_id: str
    tenant_id: str
    engagement_id: str
    target_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    objective_ids: tuple[str, ...]
    success_condition_ids: tuple[str, ...]
    allowed_effect_classes: tuple[CampaignEffectClass, ...]
    forbidden_effect_classes: tuple[CampaignEffectClass, ...]
    allowed_data_access_classes: tuple[CampaignDataAccessClass, ...]
    allowed_credential_classes: tuple[CampaignCredentialClass, ...]
    allowed_environment_classes: tuple[CampaignEnvironmentClass, ...]
    valid_from: datetime
    expires_at: datetime
    bounds: CampaignAuthorityBoundsV2
    required_approvers: tuple[CampaignApproverRequirementV2, ...]
    safety_requirements: CampaignSafetyRequirementsV2
    policy_bundle_sha256: str
    policy_revision: str
    policy_revocation_epoch: int
    roe_sha256: str
    roe_revocation_epoch: int
    lifecycle_epoch: int
    kill_switch_epoch: int
    nonce: str
    parent_authority_sha256: str | None
    expansion_requires_new_approval: bool

    def __post_init__(self) -> None:
        if self.schema_version != CAMPAIGN_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("campaign_authority_schema_unsupported")
        if self.canonicalization_version != CAMPAIGN_AUTHORITY_CANONICALIZATION_VERSION:
            raise ValueError("campaign_authority_canonicalization_unsupported")
        for name in ("envelope_id", "tenant_id", "engagement_id", "policy_revision", "nonce"):
            _identifier(f"campaign_authority_{name}", getattr(self, name))
        _closed_ids("campaign_authority_targets", self.target_ids, maximum=1_024)
        _closed_ids("campaign_authority_capabilities", self.capability_ids, maximum=512)
        _closed_ids("campaign_authority_objectives", self.objective_ids, maximum=256)
        _closed_ids("campaign_authority_success_conditions", self.success_condition_ids, maximum=256)
        _closed_enums(
            "campaign_authority_effect_class",
            self.allowed_effect_classes,
            CampaignEffectClass,
            maximum=len(CampaignEffectClass),
            allow_empty=False,
        )
        _closed_enums(
            "campaign_authority_forbidden_effect_class",
            self.forbidden_effect_classes,
            CampaignEffectClass,
            maximum=len(CampaignEffectClass),
            allow_empty=True,
        )
        if set(self.allowed_effect_classes) & set(self.forbidden_effect_classes):
            raise ValueError("campaign_authority_effect_class_conflict")
        _closed_enums(
            "campaign_authority_data_access_class",
            self.allowed_data_access_classes,
            CampaignDataAccessClass,
            maximum=len(CampaignDataAccessClass),
            allow_empty=False,
        )
        _closed_enums(
            "campaign_authority_credential_class",
            self.allowed_credential_classes,
            CampaignCredentialClass,
            maximum=len(CampaignCredentialClass),
            allow_empty=False,
        )
        _closed_enums(
            "campaign_authority_environment_class",
            self.allowed_environment_classes,
            CampaignEnvironmentClass,
            maximum=len(CampaignEnvironmentClass),
            allow_empty=False,
        )
        _aware("campaign_authority_valid_from", self.valid_from)
        _aware("campaign_authority_expires_at", self.expires_at)
        if not self.valid_from < self.expires_at:
            raise ValueError("campaign_authority_window_invalid")
        if (self.expires_at - self.valid_from).total_seconds() > self.bounds.max_duration_seconds:
            raise ValueError("campaign_authority_duration_exceeds_bound")
        if (
            not isinstance(self.required_approvers, tuple)
            or not self.required_approvers
            or len(self.required_approvers) > 16
            or any(not isinstance(item, CampaignApproverRequirementV2) for item in self.required_approvers)
            or len(set(self.required_approvers)) != len(self.required_approvers)
            or tuple(sorted(self.required_approvers, key=lambda item: (item.principal_id, item.role_id)))
            != self.required_approvers
        ):
            raise ValueError("campaign_authority_approver_requirements_invalid")
        if not isinstance(self.bounds, CampaignAuthorityBoundsV2):
            raise ValueError("campaign_authority_bounds_invalid")
        if not isinstance(self.safety_requirements, CampaignSafetyRequirementsV2):
            raise ValueError("campaign_authority_safety_requirements_invalid")
        _sha256("campaign_authority_policy_bundle_sha256", self.policy_bundle_sha256)
        _sha256("campaign_authority_roe_sha256", self.roe_sha256)
        for name in ("policy_revocation_epoch", "roe_revocation_epoch", "lifecycle_epoch", "kill_switch_epoch"):
            _integer(f"campaign_authority_{name}", getattr(self, name), 0, 2_147_483_647)
        if self.parent_authority_sha256 is not None:
            _sha256("campaign_authority_parent_sha256", self.parent_authority_sha256)
        if self.expansion_requires_new_approval is not True:
            raise ValueError("campaign_authority_expansion_approval_required")

    @property
    def authority_sha256(self) -> str:
        return hashlib.sha256(canonical_campaign_authority_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignAuthorityApprovalV2:
    schema_version: str
    authority_sha256: str
    approver_id: str
    approver_role: str
    key_id: str
    approved_at: datetime
    expires_at: datetime
    signature_hex: str

    def __post_init__(self) -> None:
        if self.schema_version != CAMPAIGN_AUTHORITY_APPROVAL_SCHEMA_VERSION:
            raise ValueError("campaign_approval_schema_unsupported")
        _sha256("campaign_approval_authority_sha256", self.authority_sha256)
        for name in ("approver_id", "approver_role", "key_id"):
            _identifier(f"campaign_approval_{name}", getattr(self, name))
        _aware("campaign_approval_approved_at", self.approved_at)
        _aware("campaign_approval_expires_at", self.expires_at)
        if not self.approved_at < self.expires_at:
            raise ValueError("campaign_approval_window_invalid")
        if not isinstance(self.signature_hex, str) or not _SIGNATURE.fullmatch(self.signature_hex):
            raise ValueError("campaign_approval_signature_invalid")


@dataclass(frozen=True, slots=True)
class SignedCampaignAuthorityEnvelopeV2:
    authority: CampaignAuthorityEnvelopeV2
    approvals: tuple[CampaignAuthorityApprovalV2, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.authority, CampaignAuthorityEnvelopeV2):
            raise ValueError("signed_campaign_authority_invalid")
        if (
            not isinstance(self.approvals, tuple)
            or not self.approvals
            or len(self.approvals) > 32
            or any(not isinstance(item, CampaignAuthorityApprovalV2) for item in self.approvals)
        ):
            raise ValueError("campaign_approvals_invalid")
        principals = tuple(item.approver_id for item in self.approvals)
        if len(set(principals)) != len(principals):
            raise ValueError("campaign_approval_principal_duplicate")
        ordering = tuple(sorted(self.approvals, key=lambda item: (item.approver_id, item.approver_role, item.key_id)))
        if ordering != self.approvals:
            raise ValueError("campaign_approvals_not_canonical")

    @property
    def signed_authority_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignAuthorityLifecycleV2:
    schema_version: str
    authority_sha256: str
    tenant_id: str
    engagement_id: str
    state: CampaignAuthorityLifecycleState
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    observed_at: datetime
    valid_until: datetime
    revoked_at: datetime | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if self.schema_version != CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION:
            raise ValueError("campaign_lifecycle_schema_unsupported")
        _sha256("campaign_lifecycle_authority_sha256", self.authority_sha256)
        _identifier("campaign_lifecycle_tenant", self.tenant_id)
        _identifier("campaign_lifecycle_engagement", self.engagement_id)
        if not isinstance(self.state, CampaignAuthorityLifecycleState):
            raise ValueError("campaign_lifecycle_state_invalid")
        for name in ("lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"):
            _integer(f"campaign_lifecycle_{name}", getattr(self, name), 0, 2_147_483_647)
        _aware("campaign_lifecycle_observed_at", self.observed_at)
        _aware("campaign_lifecycle_valid_until", self.valid_until)
        if not self.observed_at < self.valid_until or self.valid_until - self.observed_at > timedelta(
            seconds=CAMPAIGN_AUTHORITY_MAX_LIFECYCLE_OBSERVATION_SECONDS
        ):
            raise ValueError("campaign_lifecycle_observation_window_invalid")
        if self.state is CampaignAuthorityLifecycleState.ACTIVE:
            if self.revoked_at is not None or self.reason_code is not None:
                raise ValueError("campaign_active_lifecycle_revocation_metadata_forbidden")
        else:
            if self.revoked_at is None or self.reason_code is None:
                raise ValueError("campaign_inactive_lifecycle_reason_required")
            _aware("campaign_lifecycle_revoked_at", self.revoked_at)
            if self.revoked_at > self.observed_at:
                raise ValueError("campaign_lifecycle_revocation_after_observation")
            if not _REASON.fullmatch(self.reason_code):
                raise ValueError("campaign_lifecycle_reason_invalid")


@dataclass(frozen=True, slots=True)
class CampaignAuthorityVerificationV2:
    authority_sha256: str
    signed_authority_sha256: str
    approver_ids: tuple[str, ...]
    lifecycle_epoch: int


@dataclass(frozen=True, slots=True)
class CampaignAuthoritySubsetProofV2:
    classification: AuthoritySubsetClassification
    candidate_sha256: str
    parent_sha256: str
    reasons: tuple[str, ...]
    narrowed_dimensions: tuple[str, ...]


def canonical_campaign_authority_bytes(authority: CampaignAuthorityEnvelopeV2) -> bytes:
    if not isinstance(authority, CampaignAuthorityEnvelopeV2):
        raise ValueError("campaign_authority_invalid")
    # CRITICAL: signatures cover only this canonical immutable payload; never include signatures or mutable lifecycle facts.
    return _canonical_bytes(authority)


def sign_campaign_authority(
    authority: CampaignAuthorityEnvelopeV2,
    private_key: Ed25519PrivateKey,
    *,
    approver_id: str,
    approver_role: str,
    key_id: str,
    approved_at: datetime,
    expires_at: datetime,
) -> CampaignAuthorityApprovalV2:
    if not isinstance(authority, CampaignAuthorityEnvelopeV2) or not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("campaign_approval_signing_input_invalid")
    for name, value in (("approver_id", approver_id), ("approver_role", approver_role), ("key_id", key_id)):
        _identifier(f"campaign_approval_{name}", value)
    _aware("campaign_approval_approved_at", approved_at)
    _aware("campaign_approval_expires_at", expires_at)
    if not authority.valid_from <= approved_at < expires_at <= authority.expires_at:
        raise ValueError("campaign_approval_window_outside_authority")
    values = {
        "schema_version": CAMPAIGN_AUTHORITY_APPROVAL_SCHEMA_VERSION,
        "authority_sha256": authority.authority_sha256,
        "approver_id": approver_id,
        "approver_role": approver_role,
        "key_id": key_id,
        "approved_at": approved_at,
        "expires_at": expires_at,
    }
    signature = private_key.sign(_canonical_bytes(values)).hex()
    return CampaignAuthorityApprovalV2(
        schema_version=CAMPAIGN_AUTHORITY_APPROVAL_SCHEMA_VERSION,
        authority_sha256=authority.authority_sha256,
        approver_id=approver_id,
        approver_role=approver_role,
        key_id=key_id,
        approved_at=approved_at,
        expires_at=expires_at,
        signature_hex=signature,
    )


def verify_signed_campaign_authority(
    signed: SignedCampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2,
    *,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> CampaignAuthorityVerificationV2:
    if not isinstance(signed, SignedCampaignAuthorityEnvelopeV2) or not isinstance(public_keys, Mapping):
        raise ValueError("signed_campaign_authority_verification_input_invalid")
    _assert_current_lifecycle(signed.authority, lifecycle, now=now)
    if not signed.authority.valid_from <= now < signed.authority.expires_at:
        raise ValueError("campaign_authority_expired")
    verified_pairs: set[CampaignApproverRequirementV2] = set()
    for approval in signed.approvals:
        if approval.authority_sha256 != signed.authority.authority_sha256:
            raise ValueError("campaign_approval_authority_mismatch")
        if not (
            signed.authority.valid_from <= approval.approved_at < approval.expires_at <= signed.authority.expires_at
        ):
            raise ValueError("campaign_approval_window_outside_authority")
        if not approval.approved_at <= now < approval.expires_at:
            raise ValueError("campaign_approval_expired")
        key = public_keys.get(approval.key_id)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("campaign_approval_key_missing")
        try:
            # CRITICAL: verify the reconstructed detached statement, never caller-provided bytes.
            key.verify(bytes.fromhex(approval.signature_hex), _canonical_bytes(_approval_payload(approval)))
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("campaign_approval_signature_invalid") from exc
        verified_pairs.add(CampaignApproverRequirementV2(approval.approver_id, approval.approver_role))
    if not set(signed.authority.required_approvers).issubset(verified_pairs):
        raise ValueError("campaign_required_approval_missing")
    return CampaignAuthorityVerificationV2(
        authority_sha256=signed.authority.authority_sha256,
        signed_authority_sha256=signed.signed_authority_sha256,
        approver_ids=tuple(sorted(item.approver_id for item in signed.approvals)),
        lifecycle_epoch=lifecycle.lifecycle_epoch,
    )


def classify_campaign_authority_subset(
    candidate: CampaignAuthorityEnvelopeV2,
    parent: CampaignAuthorityEnvelopeV2,
) -> CampaignAuthoritySubsetProofV2:
    if not isinstance(candidate, CampaignAuthorityEnvelopeV2) or not isinstance(parent, CampaignAuthorityEnvelopeV2):
        raise ValueError("campaign_authority_subset_input_invalid")
    # CRITICAL: enumerate every authority-bearing dimension here; omission can silently mint authority.
    incomparable: list[str] = []
    for field_name in (
        "schema_version",
        "canonicalization_version",
        "tenant_id",
        "engagement_id",
        "policy_bundle_sha256",
        "policy_revision",
        "policy_revocation_epoch",
        "roe_sha256",
        "roe_revocation_epoch",
        "lifecycle_epoch",
        "kill_switch_epoch",
    ):
        if getattr(candidate, field_name) != getattr(parent, field_name):
            incomparable.append(f"binding_mismatch:{field_name}")
    if incomparable:
        return CampaignAuthoritySubsetProofV2(
            AuthoritySubsetClassification.INCOMPARABLE,
            candidate.authority_sha256,
            parent.authority_sha256,
            tuple(incomparable),
            (),
        )

    expanded: list[str] = []
    narrowed: list[str] = []
    _compare_subset("targets", candidate.target_ids, parent.target_ids, expanded, narrowed)
    _compare_subset("capabilities", candidate.capability_ids, parent.capability_ids, expanded, narrowed)
    _compare_subset("objectives", candidate.objective_ids, parent.objective_ids, expanded, narrowed)
    _compare_subset(
        "success_conditions", candidate.success_condition_ids, parent.success_condition_ids, expanded, narrowed
    )
    _compare_subset(
        "allowed_effects", candidate.allowed_effect_classes, parent.allowed_effect_classes, expanded, narrowed
    )
    _compare_superset(
        "forbidden_effects", candidate.forbidden_effect_classes, parent.forbidden_effect_classes, expanded, narrowed
    )
    _compare_subset(
        "data_access", candidate.allowed_data_access_classes, parent.allowed_data_access_classes, expanded, narrowed
    )
    _compare_subset(
        "credentials", candidate.allowed_credential_classes, parent.allowed_credential_classes, expanded, narrowed
    )
    _compare_subset(
        "environments", candidate.allowed_environment_classes, parent.allowed_environment_classes, expanded, narrowed
    )
    if candidate.valid_from < parent.valid_from or candidate.expires_at > parent.expires_at:
        expanded.append("expanded_time_window")
    elif candidate.valid_from > parent.valid_from or candidate.expires_at < parent.expires_at:
        narrowed.append("time_window")
    bounds_narrowed = False
    for field in fields(CampaignAuthorityBoundsV2):
        candidate_value = getattr(candidate.bounds, field.name)
        parent_value = getattr(parent.bounds, field.name)
        if candidate_value > parent_value:
            expanded.append(f"expanded_bound:{field.name}")
        elif candidate_value < parent_value:
            bounds_narrowed = True
    if bounds_narrowed:
        narrowed.append("bounds")
    _compare_superset("required_approvers", candidate.required_approvers, parent.required_approvers, expanded, narrowed)
    safety_narrowed = False
    for field in fields(CampaignSafetyRequirementsV2):
        candidate_value = getattr(candidate.safety_requirements, field.name)
        parent_value = getattr(parent.safety_requirements, field.name)
        if parent_value and not candidate_value:
            expanded.append(f"weakened_safety_requirement:{field.name}")
        elif candidate_value and not parent_value:
            safety_narrowed = True
    if safety_narrowed:
        narrowed.append("safety_requirements")
    classification = AuthoritySubsetClassification.EXPANSION if expanded else AuthoritySubsetClassification.SUBSET
    return CampaignAuthoritySubsetProofV2(
        classification,
        candidate.authority_sha256,
        parent.authority_sha256,
        tuple(expanded),
        tuple(narrowed),
    )


def campaign_authority_policy_attributes(
    authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2,
    *,
    target_id: str,
    capability_id: str,
    effect_class: CampaignEffectClass,
    data_access_class: CampaignDataAccessClass,
    credential_class: CampaignCredentialClass,
    environment_class: CampaignEnvironmentClass,
    residual_budget_sha256: str,
    now: datetime,
) -> Mapping[str, object]:
    _assert_current_lifecycle(authority, lifecycle, now=now)
    if target_id not in authority.target_ids:
        raise ValueError("campaign_policy_target_not_authorized")
    if capability_id not in authority.capability_ids:
        raise ValueError("campaign_policy_capability_not_authorized")
    if not isinstance(effect_class, CampaignEffectClass) or effect_class not in authority.allowed_effect_classes:
        raise ValueError("campaign_policy_effect_not_authorized")
    if (
        not isinstance(data_access_class, CampaignDataAccessClass)
        or data_access_class not in authority.allowed_data_access_classes
    ):
        raise ValueError("campaign_policy_data_access_not_authorized")
    if (
        not isinstance(credential_class, CampaignCredentialClass)
        or credential_class not in authority.allowed_credential_classes
    ):
        raise ValueError("campaign_policy_credential_not_authorized")
    if (
        not isinstance(environment_class, CampaignEnvironmentClass)
        or environment_class not in authority.allowed_environment_classes
    ):
        raise ValueError("campaign_policy_environment_not_authorized")
    _sha256("campaign_policy_residual_budget_sha256", residual_budget_sha256)
    # CRITICAL: policy receives only closed metadata; never project signatures, selectors, evidence, or credentials.
    return {
        "campaign_authority_sha256": authority.authority_sha256,
        "campaign_authority_version": "v2",
        "campaign_capability_id": capability_id,
        "campaign_credential_class": credential_class.value,
        "campaign_data_access_class": data_access_class.value,
        "campaign_effect_class": effect_class.value,
        "campaign_environment_class": environment_class.value,
        "campaign_kill_switch_epoch": lifecycle.kill_switch_epoch,
        "campaign_lifecycle_epoch": lifecycle.lifecycle_epoch,
        "campaign_lifecycle_state": lifecycle.state.value,
        "campaign_residual_budget_sha256": residual_budget_sha256,
        "campaign_target_id": target_id,
    }


def _assert_current_lifecycle(
    authority: CampaignAuthorityEnvelopeV2,
    lifecycle: CampaignAuthorityLifecycleV2,
    *,
    now: datetime,
) -> None:
    if not isinstance(authority, CampaignAuthorityEnvelopeV2) or not isinstance(
        lifecycle, CampaignAuthorityLifecycleV2
    ):
        raise ValueError("campaign_lifecycle_input_invalid")
    _aware("campaign_lifecycle_now", now)
    if lifecycle.authority_sha256 != authority.authority_sha256:
        raise ValueError("campaign_lifecycle_authority_mismatch")
    if lifecycle.tenant_id != authority.tenant_id:
        raise ValueError("campaign_lifecycle_tenant_mismatch")
    if lifecycle.engagement_id != authority.engagement_id:
        raise ValueError("campaign_lifecycle_engagement_mismatch")
    if lifecycle.state is not CampaignAuthorityLifecycleState.ACTIVE:
        raise ValueError("campaign_authority_not_active")
    if lifecycle.lifecycle_epoch != authority.lifecycle_epoch:
        raise ValueError("campaign_lifecycle_epoch_mismatch")
    if lifecycle.policy_revocation_epoch != authority.policy_revocation_epoch:
        raise ValueError("campaign_policy_epoch_mismatch")
    if lifecycle.roe_revocation_epoch != authority.roe_revocation_epoch:
        raise ValueError("campaign_roe_epoch_mismatch")
    if lifecycle.kill_switch_epoch != authority.kill_switch_epoch:
        raise ValueError("campaign_kill_switch_epoch_mismatch")
    # CRITICAL: a signed envelope never makes cached lifecycle state current; freshness is checked on every consumption.
    if not lifecycle.observed_at <= now < lifecycle.valid_until:
        raise ValueError("campaign_lifecycle_observation_expired")
    if not authority.valid_from <= now < authority.expires_at:
        raise ValueError("campaign_authority_expired")


def _approval_payload(approval: CampaignAuthorityApprovalV2) -> dict[str, object]:
    return {
        "schema_version": approval.schema_version,
        "authority_sha256": approval.authority_sha256,
        "approver_id": approval.approver_id,
        "approver_role": approval.approver_role,
        "key_id": approval.key_id,
        "approved_at": approval.approved_at,
        "expires_at": approval.expires_at,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _normalize(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return _normalize(asdict(cast(Any, value)))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        _aware("campaign_canonical_datetime", value)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    return value


def _compare_subset(
    name: str,
    candidate: tuple[object, ...],
    parent: tuple[object, ...],
    expanded: list[str],
    narrowed: list[str],
) -> None:
    if not set(candidate).issubset(parent):
        expanded.append(f"expanded_{name}")
    elif set(candidate) != set(parent):
        narrowed.append(name)


def _compare_superset(
    name: str,
    candidate: tuple[object, ...],
    parent: tuple[object, ...],
    expanded: list[str],
    narrowed: list[str],
) -> None:
    if not set(candidate).issuperset(parent):
        expanded.append(f"weakened_{name}")
    elif set(candidate) != set(parent):
        narrowed.append(name)


def _closed_ids(name: str, values: tuple[str, ...], *, maximum: int) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > maximum
        or len(set(values)) != len(values)
        or tuple(sorted(values)) != values
    ):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _closed_enums(
    name: str,
    values: tuple[object, ...],
    enum_type: type[Enum],
    *,
    maximum: int,
    allow_empty: bool,
) -> None:
    if (
        not isinstance(values, tuple)
        or (not values and not allow_empty)
        or len(values) > maximum
        or len(set(values)) != len(values)
        or any(not isinstance(item, enum_type) for item in values)
        or tuple(sorted(values, key=lambda item: str(cast(Enum, item).value))) != values
    ):
        raise ValueError(f"{name}_invalid")


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
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
