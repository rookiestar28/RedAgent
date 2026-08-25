from datetime import datetime, timezone

import pytest

from redagent_platform import domain, evidence_chain, test_registry


NOW = datetime(2026, 7, 8, 13, 0, tzinfo=timezone.utc)


def mapping() -> test_registry.TaxonomyMapping:
    return test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.MITRE_ATTACK,
        identifier="T1595",
        name="Active Scanning",
    )


def metadata(**overrides: object) -> test_registry.MetadataImport:
    values = {
        "id": "test:def-1",
        "name": "Passive header review",
        "version": "1.0.0",
        "source": test_registry.TestDefinitionSource.INTERNAL,
        "source_reference": "internal:passive-header-review",
        "author": "Security Engineering",
        "target_types": (domain.TargetType.WEB_ORIGIN,),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "risk_class": domain.TestRiskClass.PASSIVE,
        "required_permissions": ("target:read",),
        "expected_evidence": (domain.EvidenceKind.HTTP_METADATA,),
        "cleanup_behavior": test_registry.CleanupBehavior.NONE,
        "taxonomy_mappings": (mapping(),),
    }
    values.update(overrides)
    return test_registry.MetadataImport(**values)  # type: ignore[arg-type]


def test_definition_metadata_contains_r009_required_fields() -> None:
    definition = test_registry.import_metadata_only(metadata())

    assert definition.id == "test:def-1"
    assert definition.name == "Passive header review"
    assert definition.version == "1.0.0"
    assert definition.source is test_registry.TestDefinitionSource.INTERNAL
    assert definition.author == "Security Engineering"
    assert definition.reviewer_user_id is None
    assert definition.target_types == (domain.TargetType.WEB_ORIGIN,)
    assert definition.risk_class is domain.TestRiskClass.PASSIVE
    assert definition.required_permissions == ("target:read",)
    assert definition.expected_evidence == (domain.EvidenceKind.HTTP_METADATA,)
    assert definition.cleanup_behavior is test_registry.CleanupBehavior.NONE
    assert definition.taxonomy_mappings == (mapping(),)


def test_import_supports_metadata_only_sources() -> None:
    sources = {
        test_registry.TestDefinitionSource.ATOMIC: "atomic:T1059.001",
        test_registry.TestDefinitionSource.NUCLEI: "nuclei:exposed-panels",
        test_registry.TestDefinitionSource.ZAP: "zap:10021",
        test_registry.TestDefinitionSource.INTERNAL: "internal:custom-check",
    }

    definitions = tuple(
        test_registry.import_metadata_only(
            metadata(
                id=f"test:{source.value}",
                source=source,
                source_reference=source_reference,
            )
        )
        for source, source_reference in sources.items()
    )

    assert {definition.source for definition in definitions} == set(sources)
    assert all(definition.metadata_only for definition in definitions)
    assert all(not definition.execution_enabled for definition in definitions)


def test_metadata_import_rejects_executable_content_boundary() -> None:
    with pytest.raises(ValueError, match="executable_content_forbidden_in_metadata_import"):
        test_registry.import_metadata_only(metadata(executable_content_present=True))


def test_high_risk_or_destructive_definitions_are_blocked_by_default() -> None:
    definition = test_registry.import_metadata_only(
        metadata(
            id="test:cloud-technique",
            mode=domain.TestMode.CLOUD_TECHNIQUE,
            risk_class=domain.TestRiskClass.DESTRUCTIVE,
            cleanup_behavior=test_registry.CleanupBehavior.MANUAL_REQUIRED,
        )
    )
    reviewed = test_registry.review_definition(
        definition,
        reviewer_user_id="reviewer-1",
        enable_execution=True,
    )

    assert reviewed.high_risk_or_destructive
    assert not reviewed.execution_enabled
    assert reviewed.execution_block_reason == "high_risk_or_destructive_blocked_by_default"


def test_registry_change_requires_review() -> None:
    registry = test_registry.TestDefinitionRegistry()
    definition = test_registry.import_metadata_only(metadata())

    with pytest.raises(ValueError, match="registry_change_requires_review"):
        registry.register(
            definition,
            event_id="audit-1",
            actor_user_id="operator-1",
            occurred_at=NOW,
        )


def test_reviewed_registry_change_produces_audit_event() -> None:
    registry = test_registry.TestDefinitionRegistry()
    reviewed = test_registry.review_definition(
        test_registry.import_metadata_only(metadata()),
        reviewer_user_id="reviewer-1",
    )

    registry = registry.register(
        reviewed,
        event_id="audit-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )

    assert registry.definitions == (reviewed,)
    assert registry.audit_chain.audit_events[0].action is evidence_chain.AuditAction.TEST_DEFINITION_CHANGE
    assert registry.audit_chain.audit_events[0].subject_id == "test:def-1:1.0.0"


def test_duplicate_definition_version_is_rejected() -> None:
    registry = test_registry.TestDefinitionRegistry()
    reviewed = test_registry.review_definition(
        test_registry.import_metadata_only(metadata()),
        reviewer_user_id="reviewer-1",
    )
    registry = registry.register(
        reviewed,
        event_id="audit-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )

    with pytest.raises(ValueError, match="test_definition_version_already_registered"):
        registry.register(
            reviewed,
            event_id="audit-2",
            actor_user_id="reviewer-1",
            occurred_at=NOW,
        )


def test_metadata_import_requires_taxonomy_mapping_and_expected_evidence() -> None:
    with pytest.raises(ValueError, match="missing_taxonomy_mappings"):
        test_registry.import_metadata_only(metadata(taxonomy_mappings=()))
    with pytest.raises(ValueError, match="missing_expected_evidence"):
        test_registry.import_metadata_only(metadata(expected_evidence=()))
