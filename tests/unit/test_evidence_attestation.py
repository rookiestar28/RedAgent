from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_attestation, evidence_chain, evidence_store, policy_simulator


NOW = datetime(2026, 7, 9, 15, 5, tzinfo=timezone.utc)


def write_request(**overrides: object) -> evidence_store.EvidenceArtifactWriteRequest:
    values = {
        "evidence_id": "evidence-1",
        "organization_id": "org-1",
        "source_job_id": "job-1",
        "kind": domain.EvidenceKind.COMMAND_LOG,
        "created_at": NOW,
        "redaction_status": evidence_chain.RedactionStatus.REDACTED,
        "retention_class": evidence_chain.RetentionClass.STANDARD,
        "access_policy": evidence_chain.EvidenceAccessPolicy.REVIEWERS_ONLY,
        "content": b"redacted command log",
        "contains_sensitive_capture": True,
        "artifact_metadata": {"source": "unit-test", "redaction": "applied"},
        "operator_user_id": "operator-1",
        "runner_id": "runner-1",
    }
    values.update(overrides)
    return evidence_store.EvidenceArtifactWriteRequest(**values)  # type: ignore[arg-type]


def policy_result() -> policy_simulator.PolicySimulationResult:
    pack = policy_simulator.build_default_assurance_policy_pack(
        pack_id="assurance-pack",
        version="2026.07.09",
        status=policy_simulator.PolicyPackStatus.REVIEWED,
        created_at=NOW,
        reviewed_by_user_id="reviewer-1",
        reviewed_at=NOW,
    )
    subject = policy_simulator.SimulationSubject(
        subject_id="subject-redaction",
        domain=policy_simulator.PolicyDomain.REDACTION,
        context={"redaction_passed": True},
    )
    return policy_simulator.simulate_policy(
        policy_simulator.PolicySimulationRequest(
            simulation_id="simulation-1",
            policy_pack=pack,
            subjects=(subject,),
            requested_at=NOW,
            actor_user_id="operator-1",
            dry_run=True,
        )
    )


def custody_events(evidence_id: str = "evidence-1") -> tuple[evidence_attestation.EvidenceCustodyEvent, ...]:
    events = []
    previous = None
    for index, kind in enumerate(evidence_attestation.CustodyEventKind, start=1):
        event = evidence_attestation.build_custody_event(
            event_id=f"custody-{index}",
            evidence_id=evidence_id,
            organization_id="org-1",
            kind=kind,
            actor_user_id="operator-1",
            occurred_at=NOW,
            details={"stage": kind.value, "raw": "fingerprinted only"},
            previous_event=previous,
        )
        events.append(event)
        previous = event
    return tuple(events)


def test_valid_attestation_includes_required_custody_and_policy_hash(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    write = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    verification = store.verify_artifact("evidence-1")

    attestation = evidence_attestation.build_evidence_package_attestation(
        attestation_id="attestation-1",
        organization_id="org-1",
        generated_by_user_id="reviewer-1",
        generated_at=NOW,
        manifests=(write.manifest,),
        custody_events=custody_events(),
        artifact_verifications=(verification,),
        policy_simulation=policy_result(),
    )

    assert attestation.evidence_ids == ("evidence-1",)
    assert len(attestation.custody_event_hashes) == len(evidence_attestation.CustodyEventKind)
    assert attestation.policy_simulation_hash == policy_result().result_hash
    assert attestation.attestation_hash


def test_missing_custody_event_is_denied(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    write = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    verification = store.verify_artifact("evidence-1")
    incomplete_events = tuple(
        event for event in custody_events() if event.kind is not evidence_attestation.CustodyEventKind.EXPORT
    )

    with pytest.raises(ValueError, match="missing_custody_event:evidence-1:export"):
        evidence_attestation.build_evidence_package_attestation(
            attestation_id="attestation-1",
            organization_id="org-1",
            generated_by_user_id="reviewer-1",
            generated_at=NOW,
            manifests=(write.manifest,),
            custody_events=incomplete_events,
            artifact_verifications=(verification,),
        )


def test_rehash_verification_detects_modified_artifact_and_records_audit(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    write = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    (tmp_path / write.manifest.artifact_path).write_bytes(b"tampered")

    report = evidence_attestation.run_rehash_verification(
        verification_id="rehash-1",
        organization_id="org-1",
        verified_by_user_id="reviewer-1",
        verified_at=NOW,
        store=store,
        evidence_ids=("evidence-1",),
        evidence_chain=evidence_chain.EvidenceChain(),
    )

    assert not report.all_ok
    assert report.entries[0].reason == "content_hash_mismatch"
    assert report.audit_chain.audit_events[-1].subject_type == "evidence_rehash_verification"
    assert report.audit_chain.audit_events[-1].event_hash


def test_rehash_verification_detects_missing_artifact_and_opens_tamper_review(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    write = store.write_artifact(write_request(), evidence_chain.EvidenceChain())
    (tmp_path / write.manifest.artifact_path).unlink()

    report = evidence_attestation.run_rehash_verification(
        verification_id="rehash-1",
        organization_id="org-1",
        verified_by_user_id="reviewer-1",
        verified_at=NOW,
        store=store,
        evidence_ids=("evidence-1",),
        evidence_chain=evidence_chain.EvidenceChain(),
    )
    review = evidence_attestation.open_tamper_review(
        review_id="tamper-review-1",
        verification_id=report.verification_id,
        entry=report.entries[0],
        opened_by_user_id="reviewer-1",
        opened_at=NOW,
        reason="missing artifact requires review",
    )

    assert report.entries[0].reason == "missing_artifact"
    assert review.status is evidence_attestation.TamperReviewStatus.OPEN
    assert review.source_verification_hash == report.entries[0].verification_hash


def test_legal_hold_and_legal_hold_retention_deny_disposition(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    explicit_hold = store.write_artifact(
        write_request(legal_hold=True),
        evidence_chain.EvidenceChain(),
    )
    retention_hold = store.write_artifact(
        write_request(evidence_id="evidence-2", retention_class=evidence_chain.RetentionClass.LEGAL_HOLD),
        explicit_hold.evidence_chain,
    )

    first = evidence_attestation.decide_retention_disposition(
        manifest=explicit_hold.manifest,
        action=evidence_attestation.RetentionAction.DISPOSE,
        requested_by_user_id="operator-1",
        requested_at=NOW,
        reason="routine cleanup",
    )
    second = evidence_attestation.decide_retention_disposition(
        manifest=retention_hold.manifest,
        action=evidence_attestation.RetentionAction.EXPIRE,
        requested_by_user_id="operator-1",
        requested_at=NOW,
        reason="retention expiry",
    )

    assert not first.allowed
    assert first.reason == "legal_hold_prevents_disposal"
    assert not second.allowed
    assert second.reason == "legal_hold_prevents_disposal"


def test_export_manifest_uses_hashes_not_raw_content(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    write = store.write_artifact(write_request(content=b"do not include this raw content"), evidence_chain.EvidenceChain())
    verification = store.verify_artifact("evidence-1")
    attestation = evidence_attestation.build_evidence_package_attestation(
        attestation_id="attestation-1",
        organization_id="org-1",
        generated_by_user_id="reviewer-1",
        generated_at=NOW,
        manifests=(write.manifest,),
        custody_events=custody_events(),
        artifact_verifications=(verification,),
    )

    manifest = evidence_attestation.build_export_manifest(
        export_manifest_id="export-manifest-1",
        attestation=attestation,
        manifests=(write.manifest,),
        artifact_verifications=(verification,),
        destination_label="customer-report",
        generated_by_user_id="reviewer-1",
        generated_at=NOW,
    )

    rendered = repr(manifest)
    assert manifest.export_manifest_hash
    assert manifest.attestation_hash == attestation.attestation_hash
    assert "do not include this raw content" not in rendered
    assert manifest.evidence_ids == ("evidence-1",)
