from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.execution import (
    ApprovalTier,
    CapabilityExecutionCeilingV1,
    EffectBudgetV1,
    EffectIntentV1,
    EffectReceiptV1,
    ExecutableEnvelopeCoreV1,
    NodeDesiredV1,
    NodeObservedV1,
    ProposalSafetyCeilingV1,
    ReconcileOutcome,
    ReconciliationState,
    SafetyObligationsV1,
    build_safety_envelope,
    reconcile_node,
    sign_approval_receipt,
)


NOW = datetime(2026, 8, 24, 2, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def budget() -> EffectBudgetV1:
    return EffectBudgetV1(
        duration_seconds=180,
        request_count=60,
        concurrency=1,
        data_bytes=15 * 1024 * 1024,
        evidence_bytes=10 * 1024 * 1024,
        impact_count=0,
        replan_count=1,
        plan_depth=2,
    )


def capability() -> CapabilityExecutionCeilingV1:
    return CapabilityExecutionCeilingV1(
        capability_id="zap-controlled-runtime",
        capability_revision=2,
        execution_manifest_sha256=SHA_A,
        adapter_id="zap-service",
        adapter_version="2.17.0-r104.3",
        profile_id="zap-passive-v1",
        profile_revision=1,
        profile_sha256=SHA_B,
        bundle_id=None,
        bundle_revision=None,
        bundle_sha256=None,
        semantics_sha256=SHA_C,
        execution_mode="passive-read-only",
        arguments_schema_sha256=SHA_A,
        arguments_ceiling_sha256=SHA_B,
        arguments_max_bytes=4096,
    )


def obligations() -> SafetyObligationsV1:
    return SafetyObligationsV1(
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


def ceiling() -> ProposalSafetyCeilingV1:
    return ProposalSafetyCeilingV1(
        schema_version="redagent.r123-proposal-safety-ceiling/v1",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        actor_id="operator-a",
        workload_identity="spiffe://redagent.test/runner/runner-a",
        objective_sha256=SHA_A,
        target_revision=3,
        target_sha256=SHA_B,
        target_resolution_mode="registered-owned-loopback",
        allowed_capabilities=(capability(),),
        policy_sha256=SHA_C,
        policy_revocation_epoch=4,
        roe_sha256=SHA_A,
        roe_revocation_epoch=5,
        credential_class="none",
        credential_reference_id=None,
        destination="owned-loopback-gateway",
        egress_profile="owned-loopback-only",
        sandbox_class="container-non-root-read-only",
        runner_class="owned-loopback-runner",
        risk_ceiling="tier1-passive-read-only",
        budget=budget(),
        observation_freshness_seconds=3600,
        obligations=obligations(),
        approval_tier=ApprovalTier.TIER_1,
        expires_at=NOW + timedelta(minutes=5),
        nonce="ceiling-nonce-a",
    )


def core() -> ExecutableEnvelopeCoreV1:
    return ExecutableEnvelopeCoreV1(
        schema_version="redagent.r123-executable-envelope-core/v1",
        tenant_id="tenant-a",
        proposal_ceiling_sha256=ceiling().proposal_ceiling_sha256,
        plan_sha256=SHA_A,
        approver_requirement="standing-tier1-owned-loopback",
        workload_identity="spiffe://redagent.test/runner/runner-a",
        target_sha256=SHA_B,
        destination="owned-loopback-gateway",
        sandbox_class="container-non-root-read-only",
        runner_class="owned-loopback-runner",
        reservation_id="reservation-a",
        lease_id="lease-a",
        arguments_sha256=SHA_C,
        effect_sha256=SHA_A,
        effective_budget=budget(),
        policy_revocation_epoch=4,
        roe_revocation_epoch=5,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
        nonce="envelope-nonce-a",
    )


def test_non_recursive_approval_and_envelope_bind_exact_core_and_receipt() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = sign_approval_receipt(
        core(),
        key,
        approval_id="approval-a",
        approval_revision=2,
        approver_id="approver-a",
        key_id="approval-key-a",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )
    envelope = build_safety_envelope(core(), receipt, key.public_key(), now=NOW)

    assert receipt.core_sha256 == core().core_sha256
    assert envelope.core == core()
    assert envelope.approval_receipt_sha256 == receipt.receipt_sha256
    assert envelope.envelope_sha256 not in {core().core_sha256, receipt.receipt_sha256}

    tampered = replace(receipt, core_sha256=SHA_B)
    with pytest.raises(ValueError, match="approval_core_mismatch"):
        build_safety_envelope(core(), tampered, key.public_key(), now=NOW)


def test_ceiling_denies_secret_reference_for_passive_none_and_invalid_budget() -> None:
    with pytest.raises(ValueError, match="proposal_credential_reference_invalid"):
        replace(ceiling(), credential_reference_id="secret-ref-forbidden")
    with pytest.raises(ValueError, match="effect_budget_plan_depth_invalid"):
        replace(budget(), plan_depth=3)
    with pytest.raises(ValueError, match="effect_budget_replan_count_invalid"):
        replace(budget(), replan_count=2)


def effect_intent() -> EffectIntentV1:
    return EffectIntentV1(
        schema_version="redagent.r123-effect-intent/v1",
        tenant_id="tenant-a",
        campaign_id="campaign-a",
        plan_revision_id="strategy-revision-a",
        node_id="node-1",
        invocation_id="invocation-a",
        effect_id="effect-a",
        envelope_sha256=SHA_A,
        arguments_sha256=SHA_B,
        target_sha256=SHA_C,
        current_authority_sha256=SHA_A,
        outbox_sequence=3,
        created_at=NOW,
    )


def ambiguous_receipt() -> EffectReceiptV1:
    return EffectReceiptV1(
        schema_version="redagent.r123-effect-receipt/v1",
        effect_id="effect-a",
        effect_intent_sha256=effect_intent().effect_intent_sha256,
        envelope_sha256=SHA_A,
        dispatch_attempt=1,
        dispatch_generation=1,
        runner_id="runner-a",
        workload_identity="spiffe://redagent.test/runner/runner-a",
        request_sha256=SHA_B,
        started_at=NOW,
        completed_at=None,
        adapter_accepted=True,
        external_status="acceptance-possible",
        external_receipt_id=None,
        evidence_ids=(),
        cleanup_receipt_id=None,
        output_complete=False,
        external_contact_count=0,
        reconciliation_state=ReconciliationState.RECONCILIATION_REQUIRED,
        reconciliation_evidence_ids=(),
        redispatch_permitted=False,
        failure_code="receipt-commit-ambiguous",
    )


def test_possible_adapter_acceptance_never_allows_automatic_redispatch() -> None:
    receipt = ambiguous_receipt()
    assert receipt.reconciliation_state is ReconciliationState.RECONCILIATION_REQUIRED
    assert receipt.redispatch_permitted is False
    with pytest.raises(ValueError, match="effect_ambiguous_redispatch_forbidden"):
        replace(receipt, redispatch_permitted=True)


def test_confirmed_receipt_requires_terminal_evidence_and_cleanup() -> None:
    with pytest.raises(ValueError, match="effect_confirmed_receipt_incomplete"):
        replace(
            ambiguous_receipt(),
            reconciliation_state=ReconciliationState.CONFIRMED,
            completed_at=NOW + timedelta(seconds=1),
            external_status="succeeded",
            external_receipt_id="external-a",
            failure_code=None,
        )

    receipt = replace(
        ambiguous_receipt(),
        reconciliation_state=ReconciliationState.CONFIRMED,
        completed_at=NOW + timedelta(seconds=1),
        external_status="succeeded",
        external_receipt_id="external-a",
        evidence_ids=("evidence-a",),
        cleanup_receipt_id="cleanup-a",
        output_complete=True,
        reconciliation_evidence_ids=("reconciliation-evidence-a",),
        failure_code=None,
    )
    assert receipt.receipt_sha256 != effect_intent().effect_intent_sha256

    with pytest.raises(ValueError, match="effect_confirmed_receipt_incomplete"):
        replace(receipt, output_complete=False)
    with pytest.raises(ValueError, match="effect_confirmed_receipt_incomplete"):
        replace(receipt, external_contact_count=1)


@pytest.mark.parametrize(
    "overrides",
    (
        {"adapter_accepted": True},
        {"completed_at": None},
        {"external_receipt_id": None},
        {"evidence_ids": ()},
        {"cleanup_receipt_id": None},
        {"output_complete": False},
        {"external_contact_count": 1},
        {"reconciliation_evidence_ids": ()},
        {"redispatch_permitted": False},
        {"failure_code": "not-applied-proof-invalid"},
    ),
)
def test_not_applied_receipt_requires_complete_persistable_retry_authority(
    overrides,
) -> None:
    receipt = replace(
        ambiguous_receipt(),
        completed_at=NOW + timedelta(seconds=1),
        adapter_accepted=False,
        external_status="not_applied",
        external_receipt_id="status-not-applied-a",
        evidence_ids=("status-evidence-a",),
        cleanup_receipt_id="cleanup-a",
        output_complete=True,
        reconciliation_state=ReconciliationState.NOT_APPLIED,
        reconciliation_evidence_ids=("status-evidence-a",),
        redispatch_permitted=True,
        failure_code=None,
    )
    assert receipt.receipt_sha256

    with pytest.raises(ValueError, match="effect_not_applied_receipt_incomplete"):
        replace(receipt, **overrides)


def desired() -> NodeDesiredV1:
    return NodeDesiredV1(
        schema_version="redagent.r123-node-desired/v1",
        tenant_id="tenant-a",
        plan_revision_id="strategy-revision-a",
        node_id="node-1",
        effect_intent_sha256=effect_intent().effect_intent_sha256,
        max_attempts=2,
        stop_requested=False,
        authority_current=True,
        budget_available=True,
        successor_allowed=True,
        obligations=obligations(),
    )


def observed(**overrides: object) -> NodeObservedV1:
    values: dict[str, object] = {
        "schema_version": "redagent.r123-node-observed/v1",
        "effect_state": "absent",
        "attempt_count": 0,
        "next_retry_at": None,
        "receipt_state": None,
        "effect_receipt_sha256": None,
        "evidence_complete": False,
        "report_safe_evidence_complete": False,
        "finding_or_coverage_complete": False,
        "retest_complete": False,
        "secret_revocation_complete": False,
        "containment_complete": False,
        "cleanup_complete": False,
        "reconciliation_complete": False,
        "residual_risk_complete": False,
        "infrastructure_available": True,
    }
    values.update(overrides)
    return NodeObservedV1(**values)  # type: ignore[arg-type]


def test_level_reconciler_returns_only_closed_outcomes_and_stable_reasons() -> None:
    dispatch = reconcile_node(desired(), observed(), now=NOW)
    assert (dispatch.outcome, dispatch.reason_code) == (
        ReconcileOutcome.DISPATCH_ONCE,
        "effect_absent_dispatch_once",
    )

    blocked = reconcile_node(replace(desired(), authority_current=False), observed(), now=NOW)
    assert (blocked.outcome, blocked.reason_code) == (
        ReconcileOutcome.BLOCKED,
        "current_authority_denied",
    )

    contained = reconcile_node(replace(desired(), stop_requested=True), observed(), now=NOW)
    assert (contained.outcome, contained.reason_code) == (
        ReconcileOutcome.CONTAINED,
        "stop_requested_containment_required",
    )

    retry_at = NOW + timedelta(seconds=5)
    retry = reconcile_node(
        desired(),
        observed(
            effect_state="not_applied",
            attempt_count=1,
            next_retry_at=retry_at,
            receipt_state=ReconciliationState.NOT_APPLIED,
            effect_receipt_sha256=SHA_A,
            evidence_complete=True,
            report_safe_evidence_complete=True,
            cleanup_complete=True,
            reconciliation_complete=True,
        ),
        now=NOW,
    )
    assert retry.outcome is ReconcileOutcome.RETRY_AT and retry.retry_at == retry_at

    failed = reconcile_node(
        desired(),
        observed(
            effect_state="not_applied",
            attempt_count=2,
            receipt_state=ReconciliationState.NOT_APPLIED,
            effect_receipt_sha256=SHA_A,
            evidence_complete=True,
            report_safe_evidence_complete=True,
            cleanup_complete=True,
            reconciliation_complete=True,
        ),
        now=NOW,
    )
    assert (failed.outcome, failed.reason_code) == (
        ReconcileOutcome.TERMINAL_FAILURE,
        "effect_attempt_budget_exhausted",
    )
    assert {item.value for item in ReconcileOutcome} == {
        "settled",
        "dispatch_once",
        "retry_at",
        "blocked",
        "contained",
        "terminal_failure",
    }


@pytest.mark.parametrize(
    "overrides",
    (
        {},
        {"receipt_state": ReconciliationState.NOT_APPLIED},
        {
            "receipt_state": ReconciliationState.NOT_APPLIED,
            "effect_receipt_sha256": SHA_A,
        },
        {
            "receipt_state": ReconciliationState.CONFIRMED,
            "effect_receipt_sha256": SHA_A,
            "evidence_complete": True,
            "report_safe_evidence_complete": True,
            "cleanup_complete": True,
            "reconciliation_complete": True,
        },
    ),
)
def test_not_applied_observation_requires_exact_durable_retry_proof(overrides) -> None:
    with pytest.raises(ValueError, match="node_observed_not_applied_proof_required"):
        observed(effect_state="not_applied", attempt_count=1, **overrides)


def test_finalizer_blocks_success_until_every_obligation_is_terminal() -> None:
    confirmed = observed(
        effect_state="confirmed",
        attempt_count=1,
        receipt_state=ReconciliationState.CONFIRMED,
        effect_receipt_sha256=SHA_A,
        evidence_complete=True,
        report_safe_evidence_complete=True,
        finding_or_coverage_complete=True,
        retest_complete=True,
        secret_revocation_complete=True,
        containment_complete=True,
        cleanup_complete=True,
        reconciliation_complete=True,
        residual_risk_complete=True,
    )
    settled = reconcile_node(desired(), confirmed, now=NOW)
    assert (settled.outcome, settled.reason_code) == (
        ReconcileOutcome.SETTLED,
        "all_terminal_obligations_complete",
    )

    for field, reason in (
        ("evidence_complete", "evidence_incomplete"),
        ("report_safe_evidence_complete", "report_safe_evidence_incomplete"),
        ("finding_or_coverage_complete", "finding_or_coverage_incomplete"),
        ("retest_complete", "retest_incomplete"),
        ("secret_revocation_complete", "secret_revocation_incomplete"),
        ("containment_complete", "containment_incomplete"),
        ("cleanup_complete", "cleanup_incomplete"),
        ("reconciliation_complete", "reconciliation_incomplete"),
        ("residual_risk_complete", "residual_risk_incomplete"),
    ):
        result = reconcile_node(desired(), replace(confirmed, **{field: False}), now=NOW)
        assert (result.outcome, result.reason_code) == (ReconcileOutcome.BLOCKED, reason)


def test_ambiguous_effect_is_blocked_until_read_only_status_reconciliation() -> None:
    result = reconcile_node(
        desired(),
        observed(
            effect_state="reconciliation_required",
            attempt_count=1,
            receipt_state=ReconciliationState.RECONCILIATION_REQUIRED,
            effect_receipt_sha256=ambiguous_receipt().receipt_sha256,
        ),
        now=NOW,
    )
    assert (result.outcome, result.reason_code, result.redispatch_permitted) == (
        ReconcileOutcome.BLOCKED,
        "adapter_acceptance_ambiguous",
        False,
    )

    retry = reconcile_node(
        desired(),
        observed(
            effect_state="reconciliation_required",
            attempt_count=1,
            next_retry_at=NOW + timedelta(seconds=1),
            receipt_state=ReconciliationState.RECONCILIATION_REQUIRED,
            effect_receipt_sha256=ambiguous_receipt().receipt_sha256,
        ),
        now=NOW,
    )
    assert retry.outcome is ReconcileOutcome.RETRY_AT
    assert retry.reason_code == "status_lookup_retry_scheduled"
    assert retry.retry_at == NOW + timedelta(seconds=1)
    assert retry.redispatch_permitted is False
