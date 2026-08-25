from datetime import datetime, timezone

from redagent_platform import adapter_certification, policy_simulator
from redagent_platform.release_gate import (
    BlockingItemDisposition,
    BlockingItemStatus,
    DependencyPostureEvidence,
    FullGateEvidence,
    MigrationPlanEvidence,
    ProvenanceAttestation,
    R089ReleaseCandidate,
    ReleaseArtifactInventoryItem,
    ReleaseArtifactKind,
    ReleaseGateChecklist,
    ReleaseNoteSection,
    ReleaseNotesCoverage,
    RollbackPlanEvidence,
    ReviewArea,
    ReviewRecord,
    UserDocTopic,
    UserDocumentationCoverage,
    build_r034_release_gate_checklist,
    validate_r089_release_candidate,
    validate_release_gate,
)


NOW = datetime(2026, 7, 9, 18, 30, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64


def test_r034_release_gate_baseline_is_accepted():
    checklist = build_r034_release_gate_checklist()

    validation = validate_release_gate(checklist)

    assert validation.accepted is True
    assert validation.reason == "release_gate_accepted"


def test_open_blocking_item_fails_release_gate():
    checklist = build_r034_release_gate_checklist()
    open_item = BlockingItemDisposition(item_id="compat_010", status=BlockingItemStatus.OPEN)
    changed = _replace_checklist(
        checklist,
        blocking_items=(open_item,) + tuple(item for item in checklist.blocking_items if item.item_id != "compat_010"),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "blocking_item_open:compat_010" in validation.gaps


def test_deferred_blocking_item_requires_owner_risk_and_deadline():
    checklist = build_r034_release_gate_checklist()
    deferred = BlockingItemDisposition(item_id="compat_011", status=BlockingItemStatus.DEFERRED, owner="", risk="", deadline="")
    changed = _replace_checklist(
        checklist,
        blocking_items=(deferred,) + tuple(item for item in checklist.blocking_items if item.item_id != "compat_011"),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "deferred_item_owner_required:compat_011" in validation.gaps
    assert "deferred_item_risk_required:compat_011" in validation.gaps
    assert "deferred_item_deadline_required:compat_011" in validation.gaps


def test_full_gate_evidence_is_required():
    checklist = build_r034_release_gate_checklist()
    changed = _replace_checklist(
        checklist,
        full_gate=FullGateEvidence(
            command_log_path="",
            sensitive_value_scan_passed=False,
            pre_commit_passed=False,
            backend_unit_tests_passed=False,
            frontend_e2e_passed=False,
        ),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "missing_full_gate_command_log_path" in validation.gaps
    assert "sensitive_value_scan_required" in validation.gaps
    assert "pre_commit_required" in validation.gaps
    assert "backend_unit_tests_required" in validation.gaps
    assert "frontend_e2e_required" in validation.gaps


def test_security_privacy_and_operations_reviews_are_required():
    checklist = build_r034_release_gate_checklist()
    incomplete = ReviewRecord(area=ReviewArea.PRIVACY, reviewer="", completed=False, evidence_refs=())
    changed = _replace_checklist(
        checklist,
        reviews=(incomplete,) + tuple(review for review in checklist.reviews if review.area is not ReviewArea.PRIVACY),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "missing_reviewer" in validation.gaps
    assert "review_incomplete:privacy" in validation.gaps
    assert "review_evidence_required:privacy" in validation.gaps


def test_user_documentation_requires_all_topics():
    checklist = build_r034_release_gate_checklist()
    changed = _replace_checklist(
        checklist,
        user_docs=tuple(doc for doc in checklist.user_docs if doc.topic is not UserDocTopic.EXECUTION_SAFETY),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "missing_user_doc:execution_safety" in validation.gaps


def test_incomplete_user_documentation_fails_release_gate():
    checklist = build_r034_release_gate_checklist()
    incomplete = UserDocumentationCoverage(topic=UserDocTopic.EVIDENCE_HANDLING, path="docs/sop/USER_OPERATION_GUIDE.md", complete=False)
    changed = _replace_checklist(
        checklist,
        user_docs=(incomplete,) + tuple(doc for doc in checklist.user_docs if doc.topic is not UserDocTopic.EVIDENCE_HANDLING),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "user_doc_incomplete:evidence_handling" in validation.gaps


def test_release_notes_require_all_sections():
    checklist = build_r034_release_gate_checklist()
    changed = _replace_checklist(
        checklist,
        release_notes=tuple(note for note in checklist.release_notes if note.section is not ReleaseNoteSection.NON_GOALS),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "missing_release_note:non_goals" in validation.gaps


def test_incomplete_release_notes_fail_release_gate():
    checklist = build_r034_release_gate_checklist()
    incomplete = ReleaseNotesCoverage(section=ReleaseNoteSection.KNOWN_LIMITATIONS, path="docs/sop/INITIAL_RELEASE_NOTES.md", complete=False)
    changed = _replace_checklist(
        checklist,
        release_notes=(incomplete,) + tuple(note for note in checklist.release_notes if note.section is not ReleaseNoteSection.KNOWN_LIMITATIONS),
    )

    validation = validate_release_gate(changed)

    assert validation.accepted is False
    assert "release_note_incomplete:known_limitations" in validation.gaps


def _replace_checklist(checklist: ReleaseGateChecklist, **changes):
    values = {
        "release_id": checklist.release_id,
        "blocking_items": checklist.blocking_items,
        "full_gate": checklist.full_gate,
        "reviews": checklist.reviews,
        "user_docs": checklist.user_docs,
        "release_notes": checklist.release_notes,
    }
    values.update(changes)
    return ReleaseGateChecklist(**values)


def test_r089_release_candidate_fails_when_full_gate_evidence_is_missing() -> None:
    candidate = r089_candidate(
        full_gate=FullGateEvidence(
            command_log_path="",
            sensitive_value_scan_passed=False,
            pre_commit_passed=False,
            backend_unit_tests_passed=False,
            frontend_e2e_passed=False,
        )
    )

    validation = validate_r089_release_candidate(candidate)

    assert not validation.accepted
    assert "missing_full_gate_command_log_path" in validation.gaps
    assert "sensitive_value_scan_required" in validation.gaps
    assert "pre_commit_required" in validation.gaps


def test_r089_release_candidate_blocks_provenance_mismatch() -> None:
    artifacts = release_artifacts()
    attestations = tuple(
        provenance_for_artifact(artifact, observed_sha256=HASH_B if artifact.kind is ReleaseArtifactKind.CODE else artifact.sha256)
        for artifact in artifacts
    )

    validation = validate_r089_release_candidate(
        r089_candidate(artifacts=artifacts, provenance_attestations=attestations)
    )

    assert not validation.accepted
    assert "provenance_observed_hash_mismatch:redagent_platform/release_gate.py" in validation.gaps


def test_r089_release_candidate_blocks_uncertified_adapter() -> None:
    validation = validate_r089_release_candidate(
        r089_candidate(adapter_certifications=(adapter_result(certified=False),))
    )

    assert not validation.accepted
    assert "adapter_not_certified:zap-passive:1.0.0" in validation.gaps
    assert "adapter_release_blocking:zap-passive:1.0.0" in validation.gaps


def test_r089_dependency_posture_warning_does_not_block_clean_release() -> None:
    validation = validate_r089_release_candidate(
        r089_candidate(
            dependency_posture=DependencyPostureEvidence(
                sbom_path=".tmp/sbom/redagent-sbom.json",
                dependency_scan_passed=True,
                secret_scan_passed=True,
                scorecard_score=6,
                warnings=("scorecard_branch_protection_not_detected",),
            )
        )
    )

    assert validation.accepted
    assert "dependency_posture_warning:scorecard:6" in validation.warnings
    assert "dependency_posture_warning:scorecard_branch_protection_not_detected" in validation.warnings


def test_r089_rollback_plan_requires_restore_compatibility_disabled_features_and_notifications() -> None:
    validation = validate_r089_release_candidate(
        r089_candidate(
            rollback_plan=RollbackPlanEvidence(
                plan_id="rollback-1",
                restore_path="",
                data_compatibility="",
                disabled_feature_handling="",
                operator_notification_plan="",
                validated_at=NOW,
                evidence_refs=(),
            )
        )
    )

    assert not validation.accepted
    assert "missing_rollback_restore_path" in validation.gaps
    assert "missing_rollback_data_compatibility" in validation.gaps
    assert "missing_rollback_disabled_feature_handling" in validation.gaps
    assert "missing_rollback_operator_notification_plan" in validation.gaps
    assert "rollback_evidence_refs_required" in validation.gaps


def test_r089_accepted_release_package_includes_inventory_and_deterministic_hash() -> None:
    candidate = r089_candidate()

    first = validate_r089_release_candidate(candidate)
    second = validate_r089_release_candidate(candidate)

    assert first.accepted
    assert first.reason == "release_readiness_accepted"
    assert first.package is not None
    assert second.package is not None
    assert first.package.package_hash == second.package.package_hash
    assert {artifact.kind for artifact in first.package.artifact_inventory} == set(ReleaseArtifactKind)
    assert first.package.policy_pack_versions == ("policy-pack:2026.07.09",)
    assert first.package.rollback_plan_id == "rollback-1"


def r089_candidate(**overrides: object) -> R089ReleaseCandidate:
    artifacts = release_artifacts()
    values = {
        "release_id": "release-r089",
        "full_gate": FullGateEvidence(
            command_log_path=".local/validation/260709-R089_RELEASE_READINESS_COMMAND_LOG.md",
            sensitive_value_scan_passed=True,
            pre_commit_passed=True,
            backend_unit_tests_passed=True,
            frontend_e2e_passed=True,
        ),
        "artifacts": artifacts,
        "adapter_certifications": (adapter_result(),),
        "policy_packs": (policy_pack(),),
        "provenance_attestations": tuple(provenance_for_artifact(artifact) for artifact in artifacts),
        "dependency_posture": DependencyPostureEvidence(
            sbom_path=".tmp/sbom/redagent-sbom.json",
            dependency_scan_passed=True,
            secret_scan_passed=True,
            scorecard_score=9,
        ),
        "migration_plan": MigrationPlanEvidence(
            plan_id="migration-1",
            evidence_migration_path="docs/release/evidence-migration.md",
            report_migration_path="docs/release/report-migration.md",
            backward_compatible=True,
            rollback_compatible=True,
            reviewed_by_user_id="release-reviewer",
            reviewed_at=NOW,
            artifact_refs=("migration-artifact",),
        ),
        "rollback_plan": RollbackPlanEvidence(
            plan_id="rollback-1",
            restore_path="docs/release/restore.md",
            data_compatibility="Backward-compatible schema; no destructive migration.",
            disabled_feature_handling="Disable new adapters and policy packs before restore.",
            operator_notification_plan="Notify operators through release channel and incident bridge.",
            validated_at=NOW,
            evidence_refs=("rollback-drill-1",),
        ),
        "audit_export_batch_hashes": (HASH_A,),
        "environment_baseline_hash": HASH_A,
        "current_environment_hash": HASH_A,
    }
    values.update(overrides)
    return R089ReleaseCandidate(**values)  # type: ignore[arg-type]


def release_artifacts() -> tuple[ReleaseArtifactInventoryItem, ...]:
    return (
        artifact("code", ReleaseArtifactKind.CODE, "redagent_platform/release_gate.py"),
        artifact("config", ReleaseArtifactKind.CONFIG, ".pre-commit-config.yaml"),
        artifact("policy-pack", ReleaseArtifactKind.POLICY_PACK, "docs/security/policy-pack.json"),
        artifact("adapter-manifest", ReleaseArtifactKind.ADAPTER_MANIFEST, "docs/release/adapter-manifest.json"),
        artifact("skill-package", ReleaseArtifactKind.SKILL_PACKAGE, "skills/codex/redagent-operator/SKILL.md"),
        artifact("documentation", ReleaseArtifactKind.DOCUMENTATION, "PUBLIC_RELEASE.md"),
        artifact("migration-artifact", ReleaseArtifactKind.MIGRATION_ARTIFACT, "docs/release/migration.md"),
    )


def artifact(artifact_id: str, kind: ReleaseArtifactKind, path: str) -> ReleaseArtifactInventoryItem:
    return ReleaseArtifactInventoryItem(
        artifact_id=artifact_id,
        kind=kind,
        relative_path=path,
        version="2026.07.09",
        sha256=HASH_A,
    )


def provenance_for_artifact(
    artifact_item: ReleaseArtifactInventoryItem,
    *,
    observed_sha256: str | None = None,
) -> ProvenanceAttestation:
    return ProvenanceAttestation(
        subject_path=artifact_item.relative_path,
        expected_sha256=artifact_item.sha256,
        observed_sha256=observed_sha256 or artifact_item.sha256,
        builder_id="local-release-builder",
        attestation_reference=f"attestation:{artifact_item.artifact_id}",
        signed=True,
    )


def adapter_result(*, certified: bool = True) -> adapter_certification.AdapterCertificationResult:
    return adapter_certification.AdapterCertificationResult(
        adapter_id="zap-passive",
        version="1.0.0",
        status=adapter_certification.AdapterCertificationStatus.CERTIFIED
        if certified
        else adapter_certification.AdapterCertificationStatus.FAILED,
        findings=(),
        release_blocking=not certified,
        result_hash=HASH_A,
        audit_event_hash=HASH_B,
    )


def policy_pack() -> policy_simulator.PolicyPack:
    return policy_simulator.build_default_assurance_policy_pack(
        pack_id="policy-pack",
        version="2026.07.09",
        status=policy_simulator.PolicyPackStatus.REVIEWED,
        created_at=NOW,
        reviewed_by_user_id="policy-reviewer",
        reviewed_at=NOW,
    )
