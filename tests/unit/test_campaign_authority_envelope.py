from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, strategies as st
import pytest

from redagent_platform.campaign_service.authority_envelope import (
    AuthoritySubsetClassification,
    CampaignApproverRequirementV2,
    CampaignAuthorityBoundsV2,
    CampaignAuthorityEnvelopeV2,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
    CampaignCredentialClass,
    CampaignDataAccessClass,
    CampaignEffectClass,
    CampaignEnvironmentClass,
    CampaignSafetyRequirementsV2,
    SignedCampaignAuthorityEnvelopeV2,
    canonical_campaign_authority_bytes,
    classify_campaign_authority_subset,
    sign_campaign_authority,
    verify_signed_campaign_authority,
)
from redagent_platform.campaign_service.execution import EffectBudgetV1


NOW = datetime(2026, 8, 29, 4, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def bounds(**overrides: int) -> CampaignAuthorityBoundsV2:
    values = {
        "max_duration_seconds": 1_800,
        "max_search_seconds": 30,
        "max_depth": 6,
        "max_width": 4,
        "max_nodes": 24,
        "max_frontier": 12,
        "max_replans": 3,
        "max_retries_per_node": 2,
        "max_requests": 120,
        "max_rate_per_minute": 30,
        "max_concurrency": 2,
        "max_risk_micropoints": 500_000,
        "max_cost_microunits": 2_000_000,
        "max_evidence_bytes": 20 * 1024 * 1024,
        "max_data_bytes": 10 * 1024 * 1024,
    }
    values.update(overrides)
    if "max_nodes" in overrides and "max_frontier" not in overrides:
        values["max_frontier"] = min(values["max_frontier"], values["max_nodes"])
    return CampaignAuthorityBoundsV2(**values)


def safety(**overrides: bool) -> CampaignSafetyRequirementsV2:
    values = {
        "evidence_required": True,
        "report_safe_redaction_required": True,
        "cleanup_required": True,
        "containment_required": True,
        "terminal_receipt_required": True,
        "stop_on_authority_drift": True,
    }
    values.update(overrides)
    return CampaignSafetyRequirementsV2(**values)


def envelope(**overrides: object) -> CampaignAuthorityEnvelopeV2:
    values: dict[str, object] = {
        "schema_version": "redagent.campaign-authority-envelope/v2",
        "canonicalization_version": "redagent.canonical-json/v1",
        "envelope_id": "authority-a",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-a",
        "target_ids": ("target-a", "target-b"),
        "capability_ids": ("artifact-posture", "nuclei-controlled-runtime"),
        "objective_ids": ("objective-a", "objective-b"),
        "success_condition_ids": ("success-a", "success-b"),
        "allowed_effect_classes": (
            CampaignEffectClass.NETWORK_REQUEST,
            CampaignEffectClass.READ_ONLY_OBSERVATION,
        ),
        "forbidden_effect_classes": (
            CampaignEffectClass.CONTROLLED_STATE_CHANGE,
            CampaignEffectClass.DISRUPTIVE,
        ),
        "allowed_data_access_classes": (
            CampaignDataAccessClass.METADATA_ONLY,
            CampaignDataAccessClass.REPORT_SAFE,
        ),
        "allowed_credential_classes": (CampaignCredentialClass.NONE,),
        "allowed_environment_classes": (
            CampaignEnvironmentClass.OWNED_DISPOSABLE_LAB,
            CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
        ),
        "valid_from": NOW,
        "expires_at": NOW + timedelta(minutes=20),
        "bounds": bounds(),
        "required_approvers": (CampaignApproverRequirementV2(principal_id="approver-a", role_id="campaign-owner"),),
        "safety_requirements": safety(),
        "policy_bundle_sha256": SHA_A,
        "policy_revision": "policy-revision-a",
        "policy_revocation_epoch": 7,
        "roe_sha256": SHA_B,
        "roe_revocation_epoch": 11,
        "lifecycle_epoch": 13,
        "kill_switch_epoch": 17,
        "nonce": "nonce-authority-a",
        "parent_authority_sha256": None,
        "expansion_requires_new_approval": True,
    }
    values.update(overrides)
    return CampaignAuthorityEnvelopeV2(**values)  # type: ignore[arg-type]


def lifecycle(authority: CampaignAuthorityEnvelopeV2, **overrides: object) -> CampaignAuthorityLifecycleV2:
    values: dict[str, object] = {
        "schema_version": "redagent.campaign-authority-lifecycle/v2",
        "authority_sha256": authority.authority_sha256,
        "tenant_id": authority.tenant_id,
        "engagement_id": authority.engagement_id,
        "state": CampaignAuthorityLifecycleState.ACTIVE,
        "lifecycle_epoch": authority.lifecycle_epoch,
        "policy_revocation_epoch": authority.policy_revocation_epoch,
        "roe_revocation_epoch": authority.roe_revocation_epoch,
        "kill_switch_epoch": authority.kill_switch_epoch,
        "observed_at": NOW + timedelta(seconds=1),
        "valid_until": NOW + timedelta(minutes=5),
        "revoked_at": None,
        "reason_code": None,
    }
    values.update(overrides)
    return CampaignAuthorityLifecycleV2(**values)  # type: ignore[arg-type]


def signed(authority: CampaignAuthorityEnvelopeV2 | None = None):
    authority = authority or envelope()
    key = Ed25519PrivateKey.generate()
    approval = sign_campaign_authority(
        authority,
        key,
        approver_id="approver-a",
        approver_role="campaign-owner",
        key_id="key-a",
        approved_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    return SignedCampaignAuthorityEnvelopeV2(authority=authority, approvals=(approval,)), key


def test_canonical_authority_is_stable_normalized_and_closed() -> None:
    first = envelope()
    repeated = envelope()
    assert canonical_campaign_authority_bytes(first) == canonical_campaign_authority_bytes(repeated)
    assert first.authority_sha256 == repeated.authority_sha256
    assert first.authority_sha256 == "099cdda294d7a11a510d317ab0d71f2354f116e95db669a74abe666dbf48c21a"
    assert b'"tenant_id":"tenant-a"' in canonical_campaign_authority_bytes(first)
    assert b'"valid_from":"2026-08-29T04:00:00Z"' in canonical_campaign_authority_bytes(first)

    with pytest.raises(ValueError, match="campaign_authority_schema_unsupported"):
        replace(first, schema_version="redagent.campaign-authority-envelope/v3")
    with pytest.raises(ValueError, match="campaign_authority_effect_class_invalid"):
        replace(first, allowed_effect_classes=("future-effect",))
    with pytest.raises(ValueError, match="campaign_authority_expansion_approval_required"):
        replace(first, expansion_requires_new_approval=False)


def test_signature_and_current_lifecycle_bind_exact_authority_and_approver() -> None:
    wrapped, key = signed()
    result = verify_signed_campaign_authority(
        wrapped,
        lifecycle(wrapped.authority),
        public_keys={"key-a": key.public_key()},
        now=NOW + timedelta(minutes=2),
    )
    assert result.authority_sha256 == wrapped.authority.authority_sha256
    assert result.approver_ids == ("approver-a",)

    tampered = replace(wrapped.authority, bounds=replace(wrapped.authority.bounds, max_nodes=23))
    with pytest.raises(ValueError, match="campaign_approval_authority_mismatch"):
        verify_signed_campaign_authority(
            replace(wrapped, authority=tampered),
            lifecycle(tampered),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=2),
        )

    wrong_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="campaign_approval_signature_invalid"):
        verify_signed_campaign_authority(
            wrapped,
            lifecycle(wrapped.authority),
            public_keys={"key-a": wrong_key.public_key()},
            now=NOW + timedelta(minutes=2),
        )

    signature = wrapped.approvals[0].signature_hex
    flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
    with pytest.raises(ValueError, match="campaign_approval_signature_invalid"):
        verify_signed_campaign_authority(
            replace(wrapped, approvals=(replace(wrapped.approvals[0], signature_hex=flipped),)),
            lifecycle(wrapped.authority),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=2),
        )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    (
        ({"tenant_id": "tenant-b"}, "campaign_lifecycle_tenant_mismatch"),
        ({"engagement_id": "engagement-b"}, "campaign_lifecycle_engagement_mismatch"),
        (
            {"state": CampaignAuthorityLifecycleState.REVOKED, "revoked_at": NOW, "reason_code": "operator_revoked"},
            "campaign_authority_not_active",
        ),
        ({"policy_revocation_epoch": 8}, "campaign_policy_epoch_mismatch"),
        ({"roe_revocation_epoch": 12}, "campaign_roe_epoch_mismatch"),
        ({"lifecycle_epoch": 14}, "campaign_lifecycle_epoch_mismatch"),
        ({"kill_switch_epoch": 18}, "campaign_kill_switch_epoch_mismatch"),
        ({"valid_until": NOW + timedelta(minutes=1)}, "campaign_lifecycle_observation_expired"),
    ),
)
def test_current_lifecycle_fails_closed_for_drift(overrides: dict[str, object], reason: str) -> None:
    wrapped, key = signed()
    with pytest.raises(ValueError, match=reason):
        verify_signed_campaign_authority(
            wrapped,
            lifecycle(wrapped.authority, **overrides),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=2),
        )


def test_expiry_and_duplicate_or_wrong_role_approvals_fail_closed() -> None:
    wrapped, key = signed()
    with pytest.raises(ValueError, match="campaign_authority_expired"):
        verify_signed_campaign_authority(
            wrapped,
            lifecycle(
                wrapped.authority,
                observed_at=NOW + timedelta(minutes=20),
                valid_until=NOW + timedelta(minutes=22),
            ),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=20, seconds=1),
        )

    wrong_role = sign_campaign_authority(
        wrapped.authority,
        key,
        approver_id="approver-a",
        approver_role="security-reviewer",
        key_id="key-a",
        approved_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=15),
    )
    with pytest.raises(ValueError, match="campaign_required_approval_missing"):
        verify_signed_campaign_authority(
            replace(wrapped, approvals=(wrong_role,)),
            lifecycle(wrapped.authority),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=2),
        )

    with pytest.raises(ValueError, match="campaign_approval_principal_duplicate"):
        SignedCampaignAuthorityEnvelopeV2(
            authority=wrapped.authority,
            approvals=(wrapped.approvals[0], wrapped.approvals[0]),
        )

    outside_window = replace(wrapped.approvals[0], approved_at=NOW - timedelta(seconds=1))
    with pytest.raises(ValueError, match="campaign_approval_window_outside_authority"):
        verify_signed_campaign_authority(
            replace(wrapped, approvals=(outside_window,)),
            lifecycle(wrapped.authority),
            public_keys={"key-a": key.public_key()},
            now=NOW + timedelta(minutes=2),
        )


def test_mechanical_subset_narrows_every_authority_dimension() -> None:
    parent = envelope()
    candidate = envelope(
        envelope_id="authority-b",
        target_ids=("target-a",),
        capability_ids=("artifact-posture",),
        objective_ids=("objective-a",),
        success_condition_ids=("success-a",),
        allowed_effect_classes=(CampaignEffectClass.READ_ONLY_OBSERVATION,),
        forbidden_effect_classes=(
            CampaignEffectClass.CONTROLLED_STATE_CHANGE,
            CampaignEffectClass.DISRUPTIVE,
            CampaignEffectClass.NETWORK_REQUEST,
        ),
        allowed_data_access_classes=(CampaignDataAccessClass.METADATA_ONLY,),
        allowed_environment_classes=(CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,),
        valid_from=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=10),
        bounds=bounds(max_nodes=12, max_requests=60, max_risk_micropoints=250_000),
        parent_authority_sha256=parent.authority_sha256,
    )
    proof = classify_campaign_authority_subset(candidate, parent)
    assert proof.classification is AuthoritySubsetClassification.SUBSET
    assert proof.reasons == ()
    assert {
        "targets",
        "capabilities",
        "objectives",
        "success_conditions",
        "allowed_effects",
        "forbidden_effects",
        "data_access",
        "environments",
        "time_window",
        "bounds",
    }.issubset(set(proof.narrowed_dimensions))


@pytest.mark.parametrize(
    "candidate",
    (
        envelope(envelope_id="scope-target", target_ids=("target-a", "target-b", "target-c")),
        envelope(
            envelope_id="scope-capability",
            capability_ids=("artifact-posture", "nuclei-controlled-runtime", "zap-controlled-runtime"),
        ),
        envelope(
            envelope_id="scope-effect",
            allowed_effect_classes=(
                CampaignEffectClass.CONTROLLED_STATE_CHANGE,
                CampaignEffectClass.NETWORK_REQUEST,
                CampaignEffectClass.READ_ONLY_OBSERVATION,
            ),
            forbidden_effect_classes=(CampaignEffectClass.DISRUPTIVE,),
        ),
        envelope(envelope_id="scope-forbidden", forbidden_effect_classes=(CampaignEffectClass.DISRUPTIVE,)),
        envelope(
            envelope_id="scope-data",
            allowed_data_access_classes=(
                CampaignDataAccessClass.METADATA_ONLY,
                CampaignDataAccessClass.REPORT_SAFE,
                CampaignDataAccessClass.SENSITIVE,
            ),
        ),
        envelope(
            envelope_id="scope-credential",
            allowed_credential_classes=(CampaignCredentialClass.NONE, CampaignCredentialClass.SCOPED_READ),
        ),
        envelope(
            envelope_id="scope-environment",
            allowed_environment_classes=(
                CampaignEnvironmentClass.OWNED_DISPOSABLE_LAB,
                CampaignEnvironmentClass.OWNED_STAGING,
                CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
            ),
        ),
        envelope(envelope_id="scope-time", expires_at=NOW + timedelta(minutes=21)),
        envelope(envelope_id="scope-budget", bounds=bounds(max_nodes=25)),
    ),
)
def test_each_widened_dimension_is_an_expansion(candidate: CampaignAuthorityEnvelopeV2) -> None:
    proof = classify_campaign_authority_subset(candidate, envelope())
    assert proof.classification is AuthoritySubsetClassification.EXPANSION
    assert proof.reasons


def test_objective_success_approver_and_safety_weakening_are_expansions() -> None:
    parent = envelope()
    objective = envelope(
        envelope_id="objective-expansion",
        objective_ids=("objective-a", "objective-b", "objective-c"),
    )
    success = envelope(
        envelope_id="success-expansion",
        success_condition_ids=("success-a", "success-b", "success-c"),
    )
    assert classify_campaign_authority_subset(objective, parent).reasons == ("expanded_objectives",)
    assert classify_campaign_authority_subset(success, parent).reasons == ("expanded_success_conditions",)

    stronger_approval_parent = envelope(
        required_approvers=(
            CampaignApproverRequirementV2("approver-a", "campaign-owner"),
            CampaignApproverRequirementV2("approver-b", "security-reviewer"),
        )
    )
    approver_weakening = envelope(envelope_id="approver-weakening")
    assert classify_campaign_authority_subset(approver_weakening, stronger_approval_parent).reasons == (
        "weakened_required_approvers",
    )

    safety_weakening = envelope(
        envelope_id="safety-weakening",
        safety_requirements=safety(cleanup_required=False),
    )
    assert classify_campaign_authority_subset(safety_weakening, parent).reasons == (
        "weakened_safety_requirement:cleanup_required",
    )


@pytest.mark.parametrize("field_name", tuple(field.name for field in fields(CampaignAuthorityBoundsV2)))
def test_each_widened_bound_is_an_expansion(field_name: str) -> None:
    parent = envelope()
    widened = replace(parent.bounds, **{field_name: getattr(parent.bounds, field_name) + 1})
    candidate = envelope(envelope_id=f"expanded-{field_name.replace('_', '-')}", bounds=widened)
    proof = classify_campaign_authority_subset(candidate, parent)
    assert proof.classification is AuthoritySubsetClassification.EXPANSION
    assert f"expanded_bound:{field_name}" in proof.reasons


@pytest.mark.parametrize("invalid", (True, 1.5))
def test_bounds_reject_boolean_or_fractional_units(invalid: object) -> None:
    with pytest.raises(ValueError, match="campaign_authority_max_risk_micropoints_invalid"):
        replace(bounds(), max_risk_micropoints=invalid)  # type: ignore[arg-type]


def test_cross_tenant_and_policy_bindings_are_incomparable() -> None:
    parent = envelope()
    for candidate in (
        envelope(envelope_id="cross-tenant", tenant_id="tenant-b"),
        envelope(envelope_id="cross-engagement", engagement_id="engagement-b"),
        envelope(envelope_id="cross-policy", policy_bundle_sha256=SHA_C),
        envelope(envelope_id="cross-roe", roe_sha256=SHA_C),
    ):
        assert (
            classify_campaign_authority_subset(candidate, parent).classification
            is AuthoritySubsetClassification.INCOMPARABLE
        )


@given(max_nodes=st.integers(min_value=6, max_value=24), max_requests=st.integers(min_value=1, max_value=120))
def test_generated_narrow_bounds_are_monotonic(max_nodes: int, max_requests: int) -> None:
    parent = envelope()
    candidate = envelope(
        envelope_id="generated-child",
        bounds=bounds(max_nodes=max_nodes, max_requests=max_requests),
    )
    assert classify_campaign_authority_subset(candidate, parent).classification is AuthoritySubsetClassification.SUBSET


def test_subset_relation_is_reflexive_and_transitive() -> None:
    broad = envelope()
    middle = envelope(envelope_id="middle", target_ids=("target-a",), bounds=bounds(max_nodes=12))
    narrow = envelope(
        envelope_id="narrow",
        target_ids=("target-a",),
        capability_ids=("artifact-posture",),
        bounds=bounds(max_nodes=6),
    )
    assert classify_campaign_authority_subset(broad, broad).classification is AuthoritySubsetClassification.SUBSET
    assert classify_campaign_authority_subset(middle, broad).classification is AuthoritySubsetClassification.SUBSET
    assert classify_campaign_authority_subset(narrow, middle).classification is AuthoritySubsetClassification.SUBSET
    assert classify_campaign_authority_subset(narrow, broad).classification is AuthoritySubsetClassification.SUBSET


def test_existing_v1_budget_digest_remains_frozen() -> None:
    existing = EffectBudgetV1(
        duration_seconds=180,
        request_count=60,
        concurrency=1,
        data_bytes=15 * 1024 * 1024,
        evidence_bytes=10 * 1024 * 1024,
        impact_count=0,
        replan_count=1,
        plan_depth=2,
    )
    assert existing.budget_sha256 == "87a8ed65c1ee758ff8cf02e95e88714d4f9a9d392d89755594037feb7c1474ac"
