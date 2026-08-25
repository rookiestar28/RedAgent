from datetime import datetime, timezone

import pytest

from redagent_platform import coverage_packs, domain, evidence_chain, test_registry


NOW = datetime(2026, 7, 9, 16, 15, tzinfo=timezone.utc)


def attack_mapping() -> test_registry.TaxonomyMapping:
    return test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.MITRE_ATTACK,
        identifier="T1595",
        name="Active Scanning",
    )


def wstg_mapping() -> test_registry.TaxonomyMapping:
    return test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.OWASP_WSTG,
        identifier="WSTG-CONF-01",
        name="Configuration review",
    )


def safe_profile(**overrides: object) -> coverage_packs.CoveragePackProfile:
    values = {
        "profile_id": "safe-default",
        "name": "Safe default",
        "safe_by_default": True,
        "live_job_selectable": True,
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
    }
    values.update(overrides)
    return coverage_packs.CoveragePackProfile(**values)  # type: ignore[arg-type]


def unsafe_profile() -> coverage_packs.CoveragePackProfile:
    return coverage_packs.CoveragePackProfile(
        profile_id="unsafe-active",
        name="Unsafe active profile",
        safe_by_default=False,
        live_job_selectable=True,
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
    )


def pack_test(
    test_id: str,
    status: coverage_packs.CoverageImplementationStatus,
    *mappings: test_registry.TaxonomyMapping,
) -> coverage_packs.CoveragePackTest:
    return coverage_packs.CoveragePackTest(
        test_definition_id=test_id,
        test_definition_version="1.0.0",
        implementation_status=status,
        taxonomy_mappings=mappings or (attack_mapping(),),
    )


def pack_import(**overrides: object) -> coverage_packs.CoveragePackImport:
    values = {
        "pack_id": "pack-web-baseline",
        "name": "Web baseline coverage",
        "version": "2026.07.09",
        "owner_user_id": "owner-1",
        "source_references": ("STD-WSTG", "STD-ASVS", "STD-SARIF"),
        "risk_class": domain.TestRiskClass.PASSIVE,
        "supported_adapters": ("zap-passive", "nuclei-metadata"),
        "default_profile": safe_profile(),
        "profiles": (safe_profile(), unsafe_profile()),
        "deprecation_policy": "Deprecate with replacement pack or documented acceptance.",
        "taxonomy_mappings": (attack_mapping(), wstg_mapping()),
        "tests": (
            pack_test("test:implemented", coverage_packs.CoverageImplementationStatus.IMPLEMENTED, attack_mapping()),
            pack_test("test:planned", coverage_packs.CoverageImplementationStatus.PLANNED, wstg_mapping()),
        ),
    }
    values.update(overrides)
    return coverage_packs.CoveragePackImport(**values)  # type: ignore[arg-type]


def approved_pack(**overrides: object) -> coverage_packs.CoveragePack:
    imported = coverage_packs.import_coverage_pack(pack_import(**overrides))
    return coverage_packs.approve_coverage_pack(
        imported,
        reviewer_user_id="reviewer-1",
        approved_at=NOW,
    )


def registered_registry(**overrides: object) -> coverage_packs.CoveragePackRegistry:
    return coverage_packs.CoveragePackRegistry().register(
        approved_pack(**overrides),
        event_id="audit-pack-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )


def test_pack_import_requires_governance_fields_and_is_metadata_only() -> None:
    imported = coverage_packs.import_coverage_pack(pack_import())

    assert imported.pack_id == "pack-web-baseline"
    assert imported.owner_user_id == "owner-1"
    assert imported.version == "2026.07.09"
    assert imported.source_references == ("STD-WSTG", "STD-ASVS", "STD-SARIF")
    assert imported.risk_class is domain.TestRiskClass.PASSIVE
    assert imported.supported_adapters == ("zap-passive", "nuclei-metadata")
    assert imported.default_profile_id == "safe-default"
    assert imported.deprecation_policy
    assert imported.status is coverage_packs.CoveragePackStatus.DRAFT
    assert imported.metadata_only

    with pytest.raises(ValueError, match="coverage_pack_source_references_required"):
        coverage_packs.import_coverage_pack(pack_import(source_references=()))
    with pytest.raises(ValueError, match="coverage_pack_executable_content_forbidden"):
        coverage_packs.import_coverage_pack(pack_import(executable_content_present=True))


def test_approval_requires_independent_reviewer_and_audit_backed_registration() -> None:
    imported = coverage_packs.import_coverage_pack(pack_import())

    with pytest.raises(PermissionError, match="coverage_pack_approval_requires_independent_reviewer"):
        coverage_packs.approve_coverage_pack(imported, reviewer_user_id="owner-1", approved_at=NOW)

    approved = coverage_packs.approve_coverage_pack(imported, reviewer_user_id="reviewer-1", approved_at=NOW)
    registry = coverage_packs.CoveragePackRegistry().register(
        approved,
        event_id="audit-pack-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )

    assert approved.reviewer_user_id == "reviewer-1"
    assert approved.approved_at == NOW
    assert registry.packs == (approved,)
    assert registry.audit_chain.audit_events[0].action is evidence_chain.AuditAction.TEST_DEFINITION_CHANGE
    assert registry.audit_chain.audit_events[0].subject_id == "pack-web-baseline:2026.07.09"


def test_mapping_consistency_blocks_unmapped_pack_or_test_claims() -> None:
    undeclared_test_mapping = test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.OWASP_ASVS,
        identifier="V14.4",
        name="HTTP security headers",
    )
    with pytest.raises(ValueError, match="test_mapping_not_declared_by_pack"):
        approved_pack(
            taxonomy_mappings=(attack_mapping(),),
            tests=(
                pack_test(
                    "test:unexpected",
                    coverage_packs.CoverageImplementationStatus.IMPLEMENTED,
                    undeclared_test_mapping,
                ),
            ),
        )
    with pytest.raises(ValueError, match="pack_mapping_without_test"):
        approved_pack(
            taxonomy_mappings=(attack_mapping(), wstg_mapping()),
            tests=(pack_test("test:implemented", coverage_packs.CoverageImplementationStatus.IMPLEMENTED, attack_mapping()),),
        )


def test_deprecated_and_unsupported_packs_cannot_be_selected_for_live_jobs() -> None:
    registry = registered_registry()
    deprecated = registry.deprecate(
        pack_id="pack-web-baseline",
        version="2026.07.09",
        reviewer_user_id="reviewer-2",
        reason="Replaced by a reviewed 2026.07.10 pack.",
        deprecated_at=NOW,
        event_id="audit-pack-deprecated",
    )
    unsupported_registry = registered_registry(
        pack_id="pack-unsupported",
        tests=(pack_test("test:unsupported", coverage_packs.CoverageImplementationStatus.UNSUPPORTED, attack_mapping()),),
        taxonomy_mappings=(attack_mapping(),),
    )

    deprecated_decision = deprecated.select_for_live_job(
        pack_id="pack-web-baseline",
        version="2026.07.09",
        adapter_id="zap-passive",
        profile_id="safe-default",
    )
    unsupported_decision = unsupported_registry.select_for_live_job(
        pack_id="pack-unsupported",
        version="2026.07.09",
        adapter_id="zap-passive",
        profile_id="safe-default",
    )

    assert deprecated_decision.reason == "coverage_pack_deprecated"
    assert unsupported_decision.reason == "coverage_pack_unsupported"
    assert not deprecated_decision.allowed
    assert not unsupported_decision.allowed


def test_unsafe_profile_and_adapter_mismatch_are_denied_for_live_jobs() -> None:
    registry = registered_registry()

    unsafe = registry.select_for_live_job(
        pack_id="pack-web-baseline",
        version="2026.07.09",
        adapter_id="zap-passive",
        profile_id="unsafe-active",
    )
    adapter_mismatch = registry.select_for_live_job(
        pack_id="pack-web-baseline",
        version="2026.07.09",
        adapter_id="uncertified-adapter",
        profile_id="safe-default",
    )
    allowed = registry.select_for_live_job(
        pack_id="pack-web-baseline",
        version="2026.07.09",
        adapter_id="zap-passive",
        profile_id="safe-default",
    )

    assert unsafe.reason == "coverage_profile_not_safe_for_live_jobs"
    assert adapter_mismatch.reason == "adapter_not_supported_by_pack"
    assert allowed.allowed
    assert allowed.reason == "coverage_pack_selectable"


def test_coverage_report_distinguishes_all_required_statuses() -> None:
    registry = registered_registry(
        pack_id="pack-full-matrix",
        taxonomy_mappings=(attack_mapping(), wstg_mapping()),
        tests=(
            pack_test("test:implemented", coverage_packs.CoverageImplementationStatus.IMPLEMENTED, attack_mapping()),
            pack_test("test:planned", coverage_packs.CoverageImplementationStatus.PLANNED, wstg_mapping()),
            pack_test("test:disabled", coverage_packs.CoverageImplementationStatus.DISABLED, attack_mapping()),
            pack_test("test:lab", coverage_packs.CoverageImplementationStatus.LAB_ONLY, wstg_mapping()),
            pack_test("test:unsupported", coverage_packs.CoverageImplementationStatus.UNSUPPORTED, attack_mapping()),
        ),
    )

    report = registry.coverage_report()

    assert report.total_packs == 1
    assert len(report.rows) == 5
    assert report.implemented_count == 1
    assert report.planned_count == 1
    assert report.disabled_count == 1
    assert report.lab_only_count == 1
    assert report.unsupported_count == 1
