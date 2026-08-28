from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, strategies as st

from redagent_platform.campaign_service.admission import (
    AdmissionPolicyAdapter,
    CampaignPlanAdmissionService,
    authority_budget,
    build_plan_envelope_subset_proof,
    build_plan_admission_policy_input,
    calculate_plan_budget,
)
from redagent_platform.campaign_service.admission_contracts import (
    CAMPAIGN_BUDGET_VECTOR_SCHEMA_VERSION,
    PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
    PLAN_ENVELOPE_SUBSET_DIMENSIONS,
    AdmissionOutcome,
    CampaignBudgetVectorV1,
    CampaignReservationState,
    PlanAdmissionReceiptV1,
    PlanEnvelopeSubsetProofV1,
    assert_campaign_reservation_transition,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
    SignedCampaignAuthorityEnvelopeV2,
    TrustedCampaignApproverKeyV2,
    sign_campaign_authority,
)
from redagent_platform.campaign_service.planning.contracts import ValidationResult
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.policy_service.contracts import PolicyBoundary
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import (
    NOW,
    authority,
    domain,
    limits,
    operator,
    world,
)
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan


def _revision(*, current_domain=None):
    current_domain = current_domain or domain()
    result = plan_attack_path(current_domain, authority(), world(), search_limits())
    assert result.revision is not None
    return result.revision


def _budget(**overrides: int) -> CampaignBudgetVectorV1:
    values = {
        "duration_seconds": 10,
        "requests": 2,
        "rate_per_minute": 3,
        "concurrency": 1,
        "risk_micropoints": 20,
        "cost_microunits": 30,
        "evidence_bytes": 40,
        "data_bytes": 50,
    }
    values.update(overrides)
    return CampaignBudgetVectorV1(**values)


def test_budget_vector_is_closed_immutable_canonical_and_checked() -> None:
    current = _budget()
    assert current.schema_version == CAMPAIGN_BUDGET_VECTOR_SCHEMA_VERSION
    assert current.budget_sha256 == _budget().budget_sha256
    assert current.add(_budget()).duration_seconds == 20
    assert current.fits_within(_budget(duration_seconds=9)) is False
    assert _budget(duration_seconds=11).subtract(current).duration_seconds == 1
    with pytest.raises(FrozenInstanceError):
        current.requests = 7  # type: ignore[misc]
    with pytest.raises(ValueError, match="campaign_budget_requests_invalid"):
        replace(current, requests=-1)
    with pytest.raises(ValueError, match="campaign_budget_overflow"):
        _budget(cost_microunits=10**18).add(_budget(cost_microunits=1))
    with pytest.raises(ValueError, match="campaign_budget_underflow"):
        current.subtract(_budget(requests=3))


def test_budget_calculation_reserves_every_attempt_and_path_peaks() -> None:
    retried = replace(
        operator(),
        max_duration_seconds=7,
        max_requests=2,
        max_rate_per_minute=9,
        concurrency_weight=2,
        max_retries=1,
        max_risk_micropoints=11,
        max_cost_microunits=13,
        max_evidence_bytes=17,
        max_data_bytes=19,
    )
    current_domain = domain(operators=(retried,))
    budget = calculate_plan_budget(_revision(current_domain=current_domain), current_domain)
    assert budget == CampaignBudgetVectorV1(
        duration_seconds=14,
        requests=4,
        rate_per_minute=9,
        concurrency=2,
        risk_micropoints=22,
        cost_microunits=26,
        evidence_bytes=34,
        data_bytes=38,
    )


def test_budget_calculation_denies_unknown_operator_and_non_width_one_shape() -> None:
    revision = _revision()
    unknown_domain = domain(operators=(replace(operator(), operator_id="different-operator"),))
    object.__setattr__(revision, "domain_sha256", unknown_domain.domain_sha256)
    with pytest.raises(ValueError, match="plan_admission_operator_unknown"):
        calculate_plan_budget(revision, unknown_domain)
    object.__setattr__(revision, "width", 2)
    with pytest.raises(ValueError, match="plan_admission_topology_unsupported"):
        calculate_plan_budget(revision, domain())


def test_receipt_success_and_denial_fields_are_stage_closed() -> None:
    admitted = PlanAdmissionReceiptV1(
        schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
        receipt_id="admission-a",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        engagement_id="engagement-a",
        signed_authority_sha256="a" * 64,
        authority_sha256="b" * 64,
        domain_sha256="c" * 64,
        plan_sha256="d" * 64,
        certificate_sha256="e" * 64,
        validator_version="validator-v1",
        validator_sha256="f" * 64,
        subset_proof_sha256="1" * 64,
        policy_decision_id="decision-a",
        policy_input_sha256="2" * 64,
        policy_bundle_revision="policy-a",
        policy_bundle_sha256="3" * 64,
        pre_residual_budget_sha256="4" * 64,
        post_residual_budget_sha256="5" * 64,
        reserved_budget=_budget(),
        reservation_id="reservation-a",
        idempotency_key="idempotency-a",
        request_sha256="6" * 64,
        lifecycle_epoch=1,
        policy_revocation_epoch=2,
        roe_revocation_epoch=3,
        kill_switch_epoch=4,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        outcome=AdmissionOutcome.ADMITTED,
        denial_stage=None,
        reason_code="admitted",
        audit_id="audit-a",
        outbox_id="outbox-a",
    )
    assert admitted.receipt_sha256 == replace(admitted).receipt_sha256
    with pytest.raises(ValueError, match="plan_admission_success_fields_required"):
        replace(admitted, reservation_id=None)
    with pytest.raises(ValueError, match="plan_admission_denial_fields_forbidden"):
        replace(admitted, outcome=AdmissionOutcome.DENIED, denial_stage="policy")


def test_subset_proof_is_typed_complete_and_bound_to_validation_certificate() -> None:
    current_authority = authority()
    revision = _revision()
    certificate = validate_candidate_plan(
        revision.candidate_plan,
        domain(),
        current_authority,
        limits=limits(),
        validated_at=NOW,
    )
    proof = build_plan_envelope_subset_proof(
        authority=current_authority,
        revision=revision,
        certificate=certificate,
    )
    assert proof.admissible is True
    assert proof.checked_dimensions == PLAN_ENVELOPE_SUBSET_DIMENSIONS
    assert proof.certificate_sha256 == certificate.certificate_sha256
    with pytest.raises(ValueError, match="plan_envelope_subset_proof_incomplete"):
        replace(proof, checked_dimensions=proof.checked_dimensions[:-1])
    with pytest.raises(ValueError, match="plan_envelope_subset_proof_result_invalid"):
        PlanEnvelopeSubsetProofV1(
            schema_version=proof.schema_version,
            authority_sha256=proof.authority_sha256,
            domain_sha256=proof.domain_sha256,
            plan_sha256=proof.plan_sha256,
            certificate_sha256=proof.certificate_sha256,
            validator_version=proof.validator_version,
            validator_sha256=proof.validator_sha256,
            validation_result="valid",  # type: ignore[arg-type]
            checked_dimensions=proof.checked_dimensions,
        )


def test_policy_input_binds_closed_admission_projection() -> None:
    current_authority = authority()
    revision = _revision()
    certificate = validate_candidate_plan(
        revision.candidate_plan,
        domain(),
        current_authority,
        limits=limits(),
        validated_at=NOW,
    )
    assert certificate.result is ValidationResult.VALID
    request = build_plan_admission_policy_input(
        authority=current_authority,
        revision=revision,
        certificate=certificate,
        subset_proof_sha256="1" * 64,
        residual_budget=_budget(),
        campaign_id="campaign-a",
        subject_id="operator-a",
        roles=("campaign-operator",),
        permissions=("campaign:admit",),
        correlation_id="correlation-a",
        requested_at=NOW,
    )
    assert request.boundary is PolicyBoundary.WORKFLOW
    assert request.action == "campaign.plan.admit"
    assert request.resource_type == "campaign_plan"
    assert request.attributes == {
        "campaign_authority_sha256": current_authority.authority_sha256,
        "campaign_policy_bundle_sha256": current_authority.policy_bundle_sha256,
        "campaign_domain_sha256": revision.domain_sha256,
        "campaign_plan_sha256": revision.candidate_plan.plan_sha256,
        "campaign_certificate_sha256": certificate.certificate_sha256,
        "campaign_subset_proof_sha256": "1" * 64,
        "campaign_residual_budget_sha256": _budget().budget_sha256,
        "campaign_lifecycle_epoch": current_authority.lifecycle_epoch,
        "campaign_policy_revocation_epoch": current_authority.policy_revocation_epoch,
        "campaign_roe_revocation_epoch": current_authority.roe_revocation_epoch,
        "campaign_kill_switch_epoch": current_authority.kill_switch_epoch,
    }


def test_policy_adapter_requires_readiness_revision_digest_and_current_allow() -> None:
    provider = DeterministicFakePolicyProvider(revision="policy-revision-a")
    adapter = AdmissionPolicyAdapter(
        provider,
        required_revision="policy-revision-a",
        trusted_bundle_sha256="a" * 64,
    )
    request = build_plan_admission_policy_input(
        authority=authority(),
        revision=_revision(),
        certificate=validate_candidate_plan(
            _revision().candidate_plan,
            domain(),
            authority(),
            limits=limits(),
            validated_at=NOW,
        ),
        subset_proof_sha256="1" * 64,
        residual_budget=_budget(),
        campaign_id="campaign-a",
        subject_id="operator-a",
        roles=("campaign-operator",),
        permissions=("campaign:admit",),
        correlation_id="correlation-a",
        requested_at=NOW,
    )
    decision = asyncio.run(adapter.decide(request, now=NOW))
    assert decision.allowed is True
    assert decision.bundle_revision == "policy-revision-a"


class _Store:
    def __init__(self) -> None:
        self.command = None
        self.denial = None

    async def replay(self, **values):
        return None

    async def preview_residual(self, **values):
        return values["authorized_budget"]

    async def admit(self, command):
        self.command = command
        return "admitted-result"

    async def deny(self, **values):
        self.denial = values
        return "denied-result"


class _CountingProvider(DeterministicFakePolicyProvider):
    def __init__(self) -> None:
        super().__init__(revision="policy-a")
        self.decisions = 0

    async def decide(self, *args, **kwargs):
        self.decisions += 1
        return await super().decide(*args, **kwargs)


def _signed_authority(current=None):
    current = current or authority()
    key = Ed25519PrivateKey.generate()
    approval = sign_campaign_authority(
        current,
        key,
        approver_id="approver-a",
        approver_role="campaign-owner",
        key_id="key-a",
        approved_at=NOW,
        expires_at=NOW + timedelta(seconds=55),
    )
    signed = SignedCampaignAuthorityEnvelopeV2(current, (approval,))
    trusted = {"key-a": TrustedCampaignApproverKeyV2("key-a", "approver-a", ("campaign-owner",), key.public_key())}
    lifecycle = CampaignAuthorityLifecycleV2(
        schema_version="redagent.campaign-authority-lifecycle/v2",
        authority_sha256=current.authority_sha256,
        tenant_id=current.tenant_id,
        engagement_id=current.engagement_id,
        state=CampaignAuthorityLifecycleState.ACTIVE,
        lifecycle_epoch=current.lifecycle_epoch,
        policy_revocation_epoch=current.policy_revocation_epoch,
        roe_revocation_epoch=current.roe_revocation_epoch,
        kill_switch_epoch=current.kill_switch_epoch,
        observed_at=NOW,
        valid_until=NOW + timedelta(seconds=30),
        revoked_at=None,
        reason_code=None,
    )
    return signed, lifecycle, trusted


def test_service_verifies_certificate_then_policy_and_builds_atomic_command() -> None:
    signed, lifecycle, trusted = _signed_authority()
    current_domain = domain()
    revision = _revision(current_domain=current_domain)
    certificate = validate_candidate_plan(
        revision.candidate_plan,
        current_domain,
        signed.authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=1),
    )
    store = _Store()
    provider = _CountingProvider()
    service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            provider,
            required_revision=signed.authority.policy_revision,
            trusted_bundle_sha256=signed.authority.policy_bundle_sha256,
        ),
        store=store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=certificate.validator_version,
        trusted_validator_sha256=certificate.validator_sha256,
        lease_seconds=20,
    )
    result = asyncio.run(
        service.admit_plan(
            signed_authority=signed,
            lifecycle=lifecycle,
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-a",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert result == "admitted-result"
    assert provider.decisions == 1
    assert store.command.authorized_budget == authority_budget(signed.authority)
    assert store.command.reserved_budget == calculate_plan_budget(revision, current_domain)
    assert store.command.policy_decision.allowed is True


def test_service_persists_unknown_certificate_denial_without_policy_call() -> None:
    signed, lifecycle, trusted = _signed_authority()
    current_domain = domain()
    revision = _revision(current_domain=current_domain)
    valid = validate_candidate_plan(
        revision.candidate_plan,
        current_domain,
        signed.authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=1),
    )
    unknown = replace(valid, result=ValidationResult.UNKNOWN, bounded_reason="validation_limit")
    store = _Store()
    provider = _CountingProvider()
    service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            provider,
            required_revision=signed.authority.policy_revision,
            trusted_bundle_sha256=signed.authority.policy_bundle_sha256,
        ),
        store=store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=valid.validator_version,
        trusted_validator_sha256=valid.validator_sha256,
    )
    result = asyncio.run(
        service.admit_plan(
            signed_authority=signed,
            lifecycle=lifecycle,
            revision=revision,
            domain=current_domain,
            certificate=unknown,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-unknown",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert result == "denied-result"
    assert store.denial["denial_stage"] == "certificate"
    assert store.denial["reason_code"] == "plan_validation_not_valid"
    assert provider.decisions == 0


def test_service_denies_lifecycle_drift_and_policy_unavailability_before_reservation() -> None:
    signed, lifecycle, trusted = _signed_authority()
    current_domain = domain()
    revision = _revision(current_domain=current_domain)
    certificate = validate_candidate_plan(
        revision.candidate_plan,
        current_domain,
        signed.authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=1),
    )
    store = _Store()
    provider = _CountingProvider()
    service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            provider,
            required_revision=signed.authority.policy_revision,
            trusted_bundle_sha256=signed.authority.policy_bundle_sha256,
        ),
        store=store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=certificate.validator_version,
        trusted_validator_sha256=certificate.validator_sha256,
    )
    stale = replace(lifecycle, kill_switch_epoch=lifecycle.kill_switch_epoch + 1)
    result = asyncio.run(
        service.admit_plan(
            signed_authority=signed,
            lifecycle=stale,
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-stale",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert result == "denied-result"
    assert store.denial["denial_stage"] == "authority"
    assert store.denial["reason_code"] == "campaign_kill_switch_epoch_mismatch"
    assert provider.decisions == 0

    class _UnavailableProvider:
        async def assess_readiness(self, **_values):
            raise RuntimeError("synthetic_policy_unavailable")

    store = _Store()
    unavailable_service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            _UnavailableProvider(),
            required_revision=signed.authority.policy_revision,
            trusted_bundle_sha256=signed.authority.policy_bundle_sha256,
        ),
        store=store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=certificate.validator_version,
        trusted_validator_sha256=certificate.validator_sha256,
    )
    result = asyncio.run(
        unavailable_service.admit_plan(
            signed_authority=signed,
            lifecycle=lifecycle,
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-policy-unavailable",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert result == "denied-result"
    assert store.denial["denial_stage"] == "policy"
    assert store.denial["reason_code"] == "policy_unavailable_or_invalid"
    assert store.command is None


def test_service_denies_retry_amplified_over_budget_and_exact_replay_skips_policy() -> None:
    retried = replace(operator(), max_requests=6, max_retries=1)
    current_domain = domain(operators=(retried,))
    current_authority = authority()
    signed, lifecycle, trusted = _signed_authority(current_authority)
    revision = _revision(current_domain=current_domain)
    certificate = validate_candidate_plan(
        revision.candidate_plan,
        current_domain,
        current_authority,
        limits=limits(),
        validated_at=NOW + timedelta(seconds=1),
    )
    assert certificate.result is ValidationResult.VALID
    store = _Store()
    provider = _CountingProvider()
    service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            provider,
            required_revision=current_authority.policy_revision,
            trusted_bundle_sha256=current_authority.policy_bundle_sha256,
        ),
        store=store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=certificate.validator_version,
        trusted_validator_sha256=certificate.validator_sha256,
    )
    result = asyncio.run(
        service.admit_plan(
            signed_authority=signed,
            lifecycle=lifecycle,
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-over-budget",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert result == "denied-result"
    assert store.denial["denial_stage"] == "budget"
    assert store.denial["reason_code"] == "campaign_budget_exhausted"
    assert provider.decisions == 0

    class _ReplayStore(_Store):
        async def replay(self, **_values):
            return "persisted-replay"

    replay_store = _ReplayStore()
    replay_provider = _CountingProvider()
    replay_service = CampaignPlanAdmissionService(
        policy=AdmissionPolicyAdapter(
            replay_provider,
            required_revision=current_authority.policy_revision,
            trusted_bundle_sha256=current_authority.policy_bundle_sha256,
        ),
        store=replay_store,
        trusted_keys=trusted,
        validation_limits=limits(),
        trusted_validator_version=certificate.validator_version,
        trusted_validator_sha256=certificate.validator_sha256,
    )
    replay = asyncio.run(
        replay_service.admit_plan(
            signed_authority=signed,
            lifecycle=lifecycle,
            revision=revision,
            domain=current_domain,
            certificate=certificate,
            campaign_id="campaign-a",
            subject_id="operator-a",
            roles=("campaign-operator",),
            permissions=("campaign:admit",),
            correlation_id="correlation-a",
            idempotency_key="admit-replay",
            now=NOW + timedelta(seconds=2),
        )
    )
    assert replay == "persisted-replay"
    assert replay_provider.decisions == 0
    assert replay_store.command is None


def test_reservation_state_machine_holds_ambiguity_and_requires_typed_reconciliation() -> None:
    assert_campaign_reservation_transition(
        CampaignReservationState.RESERVED,
        CampaignReservationState.HELD,
        effect_started=True,
        reconciliation_code="effect_ambiguous",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=1),
    )
    assert_campaign_reservation_transition(
        CampaignReservationState.HELD,
        CampaignReservationState.CONSUMED,
        effect_started=True,
        reconciliation_code="applied",
        now=NOW + timedelta(seconds=2),
        lease_expires_at=NOW + timedelta(seconds=1),
    )
    assert_campaign_reservation_transition(
        CampaignReservationState.HELD,
        CampaignReservationState.RELEASED,
        effect_started=True,
        reconciliation_code="not_applied",
        now=NOW + timedelta(seconds=2),
        lease_expires_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="campaign_reservation_held_requires_reconciliation"):
        assert_campaign_reservation_transition(
            CampaignReservationState.HELD,
            CampaignReservationState.EXPIRED,
            effect_started=True,
            reconciliation_code=None,
            now=NOW + timedelta(seconds=2),
            lease_expires_at=NOW + timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="campaign_reservation_effect_release_forbidden"):
        assert_campaign_reservation_transition(
            CampaignReservationState.RESERVED,
            CampaignReservationState.RELEASED,
            effect_started=True,
            reconciliation_code="not_started",
            now=NOW,
            lease_expires_at=NOW + timedelta(seconds=1),
        )


@given(
    total=st.integers(min_value=0, max_value=10**12),
    first=st.integers(min_value=0, max_value=10**12),
    second=st.integers(min_value=0, max_value=10**12),
)
def test_budget_property_never_accepts_more_than_residual(total: int, first: int, second: int) -> None:
    authorized = CampaignBudgetVectorV1(total, total, total, total, total, total, total, total)
    first_vector = CampaignBudgetVectorV1(first, first, first, first, first, first, first, first)
    if not first_vector.fits_within(authorized):
        return
    residual = authorized.subtract(first_vector)
    second_vector = CampaignBudgetVectorV1(second, second, second, second, second, second, second, second)
    assert second_vector.fits_within(residual) is (first + second <= total)
