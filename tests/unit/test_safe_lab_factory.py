from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    adapter_certification,
    coverage_packs,
    domain,
    evidence_chain,
    lab_harness,
    safe_lab_factory,
    target_inventory,
    test_registry,
)


NOW = datetime(2026, 7, 9, 18, 0, tzinfo=timezone.utc)


def approval() -> lab_harness.SandboxApproval:
    return lab_harness.SandboxApproval(
        approval_id="approval-1",
        organization_id="org-1",
        approved_by_user_id="lead-1",
        approved_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        allowed_kinds=(lab_harness.LabTargetKind.JUICE_SHOP,),
        allowed_actions=(lab_harness.LabHarnessAction.CONNECT_EXISTING,),
        plan_reference="PUBLIC_RELEASE.md",
        emergency_contact_method="email",
    )


def lab_request() -> lab_harness.LabTargetRequest:
    return lab_harness.LabTargetRequest(
        target_id="lab-juice-local",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="Security Lab",
        kind=lab_harness.LabTargetKind.JUICE_SHOP,
        action=lab_harness.LabHarnessAction.CONNECT_EXISTING,
        base_url="http://localhost:3000",
        requested_at=NOW,
    )


def safe_request(**overrides: object) -> safe_lab_factory.SafeLabTargetRequest:
    values = {
        "factory_id": "factory-1",
        "lab_request": lab_request(),
        "allowed_categories": (
            safe_lab_factory.LabTestCategory.PASSIVE_WEB,
            safe_lab_factory.LabTestCategory.REDACTION,
            safe_lab_factory.LabTestCategory.REPORTING,
            safe_lab_factory.LabTestCategory.KILL_SWITCH,
            safe_lab_factory.LabTestCategory.ADAPTER_VALIDATION,
        ),
        "disposable": True,
        "non_production_attested": True,
        "requested_by_user_id": "operator-1",
    }
    values.update(overrides)
    return safe_lab_factory.SafeLabTargetRequest(**values)  # type: ignore[arg-type]


def safe_target(**overrides: object) -> safe_lab_factory.SafeLabTarget:
    return safe_lab_factory.register_safe_lab_target(safe_request(**overrides), approval())


def production_target() -> target_inventory.InventoryTarget:
    return target_inventory.build_inventory_target(
        target_inventory.TargetImportCandidate(
            id="prod-target",
            organization_id="org-1",
            engagement_id="eng-1",
            owner_label="Production",
            target_type=domain.TargetType.WEB_ORIGIN,
            value="https://prod.example.test",
            environment=target_inventory.EnvironmentType.PRODUCTION,
            data_sensitivity=target_inventory.DataSensitivity.CONFIDENTIAL,
            authorization_status=domain.AuthorizationStatus.APPROVED,
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            explicit_review=True,
            review_reason="unit-test",
        )
    )


def mapping() -> test_registry.TaxonomyMapping:
    return test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.OWASP_WSTG,
        identifier="WSTG-CONF-01",
        name="Configuration review",
    )


def adapter_registry() -> adapter_certification.AdapterCertificationRegistry:
    profile = coverage_packs.CoveragePackProfile(
        profile_id="safe-default",
        name="Safe default",
        safe_by_default=True,
        live_job_selectable=True,
        allowed_modes=(domain.TestMode.LAB_ONLY_RUN,),
    )
    imported = coverage_packs.import_coverage_pack(
        coverage_packs.CoveragePackImport(
            pack_id="pack-lab-validation",
            name="Lab validation pack",
            version="2026.07.09",
            owner_user_id="owner-1",
            source_references=("STD-WSTG",),
            risk_class=domain.TestRiskClass.LAB_ONLY,
            supported_adapters=("lab-adapter",),
            default_profile=profile,
            profiles=(profile,),
            deprecation_policy="Deprecate with reviewed replacement.",
            taxonomy_mappings=(mapping(),),
            tests=(
                coverage_packs.CoveragePackTest(
                    test_definition_id="test:lab-validation",
                    test_definition_version="1.0.0",
                    implementation_status=coverage_packs.CoverageImplementationStatus.IMPLEMENTED,
                    taxonomy_mappings=(mapping(),),
                ),
            ),
        )
    )
    approved = coverage_packs.approve_coverage_pack(imported, reviewer_user_id="reviewer-1", approved_at=NOW)
    coverage_registry = coverage_packs.CoveragePackRegistry().register(
        approved,
        event_id="audit-pack-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )
    manifest = adapter_certification.AdapterManifest(
        adapter_id="lab-adapter",
        version="1.0.0",
        display_name="Lab validation adapter",
        command_boundary="structured lab validation manifest only",
        supported_modes=(domain.TestMode.LAB_ONLY_RUN,),
        forbidden_modes=(domain.TestMode.ACTIVE_SCAN,),
        evidence_schema=(domain.EvidenceKind.COMMAND_LOG,),
        cleanup_required=True,
        cleanup_evidence_schema=("cleanup_callback",),
        timeout_seconds=60,
        cancellation_supported=True,
        declared_features=(
            adapter_certification.AdapterFeature.PASSIVE_RESULT_IMPORT,
            adapter_certification.AdapterFeature.CLEANUP,
            adapter_certification.AdapterFeature.CANCELLATION,
        ),
        allowed_surfaces=(adapter_certification.AdapterUseSurface.RUNNER_JOB,),
        coverage_pack_refs=(
            adapter_certification.AdapterCoveragePackRef(
                pack_id="pack-lab-validation",
                version="2026.07.09",
                adapter_id="lab-adapter",
                profile_id="safe-default",
            ),
        ),
        provenance=adapter_certification.AdapterProvenance(
            source_reference="internal:lab-adapter",
            expected_artifact_digest="sha256:lab123",
            observed_artifact_digest="sha256:lab123",
            sbom_reference="sbom:redagent:lab-adapter",
            attestation_reference="attestation:redagent:lab-adapter",
            reviewed_by_user_id="reviewer-1",
        ),
    )
    registry, result = adapter_certification.AdapterCertificationRegistry().certify(
        manifest,
        coverage_registry=coverage_registry,
        reviewer_user_id="reviewer-1",
        certified_at=NOW,
        event_id="audit-cert-1",
    )
    assert result.certified
    return registry


def test_safe_lab_target_registration_is_non_production_scoped_disposable_and_tagged() -> None:
    target = safe_target()

    assert target.non_production
    assert target.disposable
    assert target.registration.inventory_target.environment is target_inventory.EnvironmentType.LAB
    assert target.registration.inventory_target.target_type is domain.TargetType.LAB_TARGET
    assert target.registration.inventory_target.allowed_modes == (domain.TestMode.LAB_ONLY_RUN,)
    assert target.registration.labels == (lab_harness.LAB_ONLY_LABEL,)
    assert safe_lab_factory.LabTestCategory.ADAPTER_VALIDATION in target.allowed_categories


def test_production_and_non_disposable_lab_targets_are_denied() -> None:
    with pytest.raises(ValueError, match="production_target_forbidden"):
        safe_lab_factory.assert_non_production_lab_target(production_target())
    with pytest.raises(ValueError, match="lab_target_must_be_disposable"):
        safe_target(disposable=False)
    with pytest.raises(ValueError, match="non_production_attestation_required"):
        safe_target(non_production_attested=False)


def test_synthetic_dataset_contains_only_synthetic_records_and_canaries() -> None:
    dataset = safe_lab_factory.build_synthetic_dataset(
        dataset_id="dataset-1",
        generated_at=NOW,
        canary_seed="eng-1",
    )

    assert dataset.forbidden_real_data_classes == safe_lab_factory.FORBIDDEN_REAL_DATA_CLASSES
    assert all(record.classification.startswith("synthetic_") for record in dataset.records)
    assert all(value.startswith("canary-") for value in dataset.canary_values)
    assert all("example.invalid" in record.value or record.kind is not safe_lab_factory.SyntheticRecordKind.USER_ALIAS for record in dataset.records)
    assert dataset.dataset_hash


def test_golden_evidence_requires_findings_redaction_cleanup_and_report_snapshot() -> None:
    target = safe_target()
    dataset = safe_lab_factory.build_synthetic_dataset(dataset_id="dataset-1", generated_at=NOW, canary_seed="eng-1")
    corpus = safe_lab_factory.build_golden_evidence_corpus(
        corpus_id="corpus-1",
        target=target,
        dataset=dataset,
        expected_finding_ids=("finding-missing-header",),
        redaction_expectations=("canary values must be redacted",),
        cleanup_expectations=("teardown proof required",),
        report_snapshot_markdown="# Lab Report\n\nSynthetic results only.",
    )

    safe_lab_factory.verify_golden_evidence_corpus(corpus)
    assert corpus.lab_target_id == target.registration.target_id
    assert corpus.expectations[0].synthetic_dataset_hash == dataset.dataset_hash
    assert corpus.expectations[0].report_snapshot_hash

    broken = replace(corpus, corpus_hash="bad")
    with pytest.raises(ValueError, match="golden_corpus_hash_mismatch"):
        safe_lab_factory.verify_golden_evidence_corpus(broken)


def test_teardown_proof_requires_all_steps_and_records_audit_evidence() -> None:
    target = safe_target()
    expected_steps = tuple(step.order for step in target.registration.teardown_procedure.steps)
    chain, proof = safe_lab_factory.record_teardown_proof(
        proof_id="teardown-1",
        target=target,
        completed_step_orders=expected_steps,
        artifact_ids=("artifact-teardown-log",),
        disposable_removed=True,
        teardown_at=NOW,
        actor_user_id="operator-1",
        audit_event_id="audit-teardown-1",
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert proof.audit_event_hash == chain.audit_events[-1].event_hash
    assert proof.disposable_removed
    assert proof.completed_step_orders == expected_steps

    with pytest.raises(ValueError, match="teardown_steps_incomplete"):
        safe_lab_factory.record_teardown_proof(
            proof_id="teardown-2",
            target=target,
            completed_step_orders=expected_steps[:-1],
            artifact_ids=("artifact-teardown-log",),
            disposable_removed=True,
            teardown_at=NOW,
            actor_user_id="operator-1",
            audit_event_id="audit-teardown-2",
            audit_chain=evidence_chain.EvidenceChain(),
        )


def test_adapter_validation_requires_certified_adapter_and_lab_category() -> None:
    target = safe_target()
    certified = safe_lab_factory.validate_adapter_for_lab_target(
        adapter_registry=adapter_registry(),
        target=target,
        adapter_id="lab-adapter",
        version="1.0.0",
        mode=domain.TestMode.LAB_ONLY_RUN,
    )
    uncertified = safe_lab_factory.validate_adapter_for_lab_target(
        adapter_registry=adapter_certification.AdapterCertificationRegistry(),
        target=target,
        adapter_id="lab-adapter",
        version="1.0.0",
        mode=domain.TestMode.LAB_ONLY_RUN,
    )
    no_category = safe_lab_factory.validate_adapter_for_lab_target(
        adapter_registry=adapter_registry(),
        target=safe_target(allowed_categories=(safe_lab_factory.LabTestCategory.PASSIVE_WEB,)),
        adapter_id="lab-adapter",
        version="1.0.0",
        mode=domain.TestMode.LAB_ONLY_RUN,
    )

    assert certified.allowed
    assert certified.reason == "certified_adapter_allowed_for_lab_target"
    assert uncertified.reason == "adapter_not_certified"
    assert no_category.reason == "adapter_validation_category_required"
