from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import control_plane, domain, scope_roe_ledger
from redagent_platform.scope_authorization import JobScopeRequest, ScopeTarget


NOW = datetime(2026, 7, 9, 14, 30, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=10)
END = NOW + timedelta(hours=2)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")
API_TARGET = ScopeTarget(target_type=domain.TargetType.API_SPEC, value="openapi.yaml")


def roe(**overrides: object) -> control_plane.RoeVersionRecord:
    values = {
        "roe_version_id": "roe-1",
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "version": 1,
        "status": control_plane.RoeStatus.APPROVED,
        "allowed_targets": (TARGET,),
        "forbidden_targets": (),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
        "window_start": START,
        "window_end": END,
        "max_interactions": 50,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email:security@example.test",
        "created_by_user_id": "operator-1",
        "created_at": NOW,
        "approved_by_user_id": "approver-1",
        "approved_at": NOW + timedelta(minutes=1),
    }
    values.update(overrides)
    return control_plane.RoeVersionRecord(**values)  # type: ignore[arg-type]


def ownership(
    target: ScopeTarget = TARGET,
    *,
    expires_at: datetime = END + timedelta(days=1),
    evidence_id: str = "ownership-1",
) -> scope_roe_ledger.TargetOwnershipEvidence:
    return scope_roe_ledger.build_target_ownership_evidence(
        evidence_id=evidence_id,
        target=target,
        owner_label="Ray Chiu",
        verified_by_user_id="reviewer-1",
        verified_at=NOW,
        expires_at=expires_at,
        proof_reference="owner approval ticket #123",
    )


def ledger_version(
    source_roe: control_plane.RoeVersionRecord | None = None,
    parent: scope_roe_ledger.RoeLedgerVersion | None = None,
    evidence: tuple[scope_roe_ledger.TargetOwnershipEvidence, ...] | None = None,
) -> scope_roe_ledger.RoeLedgerVersion:
    source_roe = source_roe or roe()
    ownership_evidence = (ownership(),) if evidence is None else evidence
    return scope_roe_ledger.build_ledger_version(
        ledger_version_id=f"ledger-{source_roe.version}",
        roe=source_roe,
        parent=parent,
        ownership_evidence=ownership_evidence,
        approver_user_id="approver-1",
        approved_at=NOW + timedelta(minutes=2),
        reason="Approved scope version.",
    )


def policy_decision(**overrides: object) -> control_plane.PolicyDecisionRecord:
    values = {
        "decision_id": "decision-1",
        "roe_version_id": "roe-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "outcome": domain.PolicyDecisionOutcome.ALLOW,
        "reason": "scope_authorized",
        "decided_at": NOW + timedelta(minutes=5),
        "expires_at": NOW + timedelta(minutes=30),
        "target": TARGET,
        "mode": domain.TestMode.PASSIVE_SCAN,
        "projected_interactions": 10,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return control_plane.PolicyDecisionRecord(**values)  # type: ignore[arg-type]


def deviation(
    *,
    effective_from: datetime = NOW + timedelta(minutes=8),
    affected_targets: tuple[ScopeTarget, ...] = (TARGET,),
    affected_modes: tuple[domain.TestMode, ...] = (domain.TestMode.PASSIVE_SCAN,),
) -> scope_roe_ledger.RoeDeviationApproval:
    return scope_roe_ledger.RoeDeviationApproval(
        deviation_id="deviation-1",
        ledger_version_id="ledger-1",
        approved_by_user_id="approver-2",
        approved_at=NOW + timedelta(minutes=7),
        effective_from=effective_from,
        expires_at=NOW + timedelta(minutes=45),
        reason="Temporary time-window exception.",
        affected_targets=affected_targets,
        affected_modes=affected_modes,
        justification="Business owner approved the bounded deviation.",
        approval_hash="",
    )


def test_scope_version_requires_target_ownership_evidence() -> None:
    with pytest.raises(ValueError, match="target_ownership_evidence_missing"):
        ledger_version(evidence=())

    with pytest.raises(ValueError, match="target_ownership_evidence_expired"):
        ledger_version(evidence=(ownership(expires_at=NOW + timedelta(minutes=1)),))


def test_scope_diff_approval_records_targets_modes_window_and_hash() -> None:
    first = ledger_version()
    changed_roe = roe(
        roe_version_id="roe-2",
        version=2,
        allowed_targets=(TARGET, API_TARGET),
        allowed_modes=(domain.TestMode.PASSIVE_SCAN, domain.TestMode.ACTIVE_SCAN),
        window_end=END + timedelta(hours=1),
    )
    second = ledger_version(
        changed_roe,
        parent=first,
        evidence=(ownership(), ownership(API_TARGET, evidence_id="ownership-2")),
    )

    kinds = {entry.kind for entry in second.diff}
    assert scope_roe_ledger.ScopeDiffKind.TARGET_ADDED in kinds
    assert scope_roe_ledger.ScopeDiffKind.MODE_ADDED in kinds
    assert scope_roe_ledger.ScopeDiffKind.TIME_WINDOW_CHANGED in kinds
    assert second.approver_user_id == "approver-1"
    assert second.reason == "Approved scope version."
    assert second.expires_at == END + timedelta(hours=1)
    assert API_TARGET.normalized() in second.affected_targets
    assert domain.TestMode.ACTIVE_SCAN in second.affected_modes
    assert len(second.immutable_hash) == 64


def test_expired_roe_denies_version_and_dispatch() -> None:
    expired_roe = roe(window_end=NOW + timedelta(minutes=1))

    with pytest.raises(ValueError, match="expired_roe_denied"):
        ledger_version(expired_roe)

    version = ledger_version()
    decision = scope_roe_ledger.evaluate_dispatch_gate(
        ledger_version=version,
        revocations=(),
        target=TARGET,
        mode=domain.TestMode.PASSIVE_SCAN,
        requested_at=END + timedelta(seconds=1),
    )

    assert not decision.allowed
    assert decision.reason == "expired_roe_denied"


def test_deviation_requires_approval_and_is_not_retroactive_to_failed_decisions() -> None:
    version = ledger_version()
    failed = policy_decision(
        decision_id="failed-1",
        outcome=domain.PolicyDecisionOutcome.DENY,
        reason="outside_time_window",
        decided_at=NOW + timedelta(minutes=6),
    )

    with pytest.raises(ValueError, match="deviation_retroactive_to_failed_policy_decision"):
        scope_roe_ledger.approve_deviation(
            approval=deviation(effective_from=NOW + timedelta(minutes=8)),
            ledger_version=version,
            policy_decisions=(failed,),
        )

    approved = scope_roe_ledger.approve_deviation(
        approval=deviation(effective_from=NOW + timedelta(minutes=9), affected_targets=(API_TARGET,)),
        ledger_version=version,
        policy_decisions=(failed,),
    )

    assert approved.approved_by_user_id == "approver-2"
    assert len(approved.approval_hash) == 64


def test_revocation_blocks_future_dispatch_and_report_publication() -> None:
    version = ledger_version()
    revocation = scope_roe_ledger.build_revocation_entry(
        revocation_id="revocation-1",
        ledger_version_id=version.ledger_version_id,
        revoked_by_user_id="security-lead-1",
        revoked_at=NOW + timedelta(minutes=10),
        reason="Scope owner revoked authorization.",
        affected_targets=(TARGET,),
        affected_modes=(domain.TestMode.PASSIVE_SCAN,),
    )

    dispatch = scope_roe_ledger.evaluate_dispatch_gate(
        ledger_version=version,
        revocations=(revocation,),
        target=TARGET,
        mode=domain.TestMode.PASSIVE_SCAN,
        requested_at=NOW + timedelta(minutes=11),
    )
    publication = scope_roe_ledger.evaluate_report_publication_gate(
        ledger_version=version,
        revocations=(revocation,),
        report_id="report-1",
        requested_at=NOW + timedelta(minutes=11),
    )

    assert not dispatch.allowed
    assert dispatch.reason == "scope_revoked_for_dispatch"
    assert not publication.allowed
    assert publication.reason == "scope_revoked_for_publication"


def test_replayable_authorization_proof_is_deterministic() -> None:
    version = ledger_version()
    approved_deviation = scope_roe_ledger.approve_deviation(
        approval=deviation(affected_targets=(API_TARGET,)),
        ledger_version=version,
        policy_decisions=(),
    )
    revocation = scope_roe_ledger.build_revocation_entry(
        revocation_id="revocation-1",
        ledger_version_id=version.ledger_version_id,
        revoked_by_user_id="security-lead-1",
        revoked_at=NOW + timedelta(minutes=20),
        reason="Post-test closeout.",
        affected_targets=(TARGET,),
        affected_modes=(domain.TestMode.PASSIVE_SCAN,),
    )

    first = scope_roe_ledger.export_replayable_authorization_proof(
        proof_id="proof-1",
        ledger_version=version,
        policy_decision=policy_decision(),
        deviations=(approved_deviation,),
        revocations=(revocation,),
        generated_at=NOW + timedelta(minutes=21),
    )
    second = scope_roe_ledger.export_replayable_authorization_proof(
        proof_id="proof-1",
        ledger_version=version,
        policy_decision=policy_decision(),
        deviations=(approved_deviation,),
        revocations=(revocation,),
        generated_at=NOW + timedelta(minutes=21),
    )

    assert first.proof_hash == second.proof_hash
    assert first.scope_version_hash == version.immutable_hash
    assert first.deviation_hashes == (approved_deviation.approval_hash,)
    assert first.revocation_hashes == (revocation.revocation_hash,)
    assert len(first.policy_decision_hash) == 64


def test_replay_proof_requires_matching_roe_version() -> None:
    with pytest.raises(ValueError, match="policy_decision_roe_mismatch"):
        scope_roe_ledger.export_replayable_authorization_proof(
            proof_id="proof-bad",
            ledger_version=ledger_version(roe(roe_version_id="roe-2")),
            policy_decision=policy_decision(),
            deviations=(),
            revocations=(),
            generated_at=NOW + timedelta(minutes=21),
        )
