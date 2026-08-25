from datetime import datetime, timezone

from redagent_platform import adapter_certification, coverage_packs, domain, evidence_chain, test_registry


NOW = datetime(2026, 7, 9, 17, 0, tzinfo=timezone.utc)


def mapping() -> test_registry.TaxonomyMapping:
    return test_registry.TaxonomyMapping(
        kind=test_registry.TaxonomyKind.OWASP_WSTG,
        identifier="WSTG-CONF-01",
        name="Configuration review",
    )


def profile() -> coverage_packs.CoveragePackProfile:
    return coverage_packs.CoveragePackProfile(
        profile_id="safe-default",
        name="Safe default",
        safe_by_default=True,
        live_job_selectable=True,
        allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
    )


def pack_registry(adapter_id: str = "zap-passive") -> coverage_packs.CoveragePackRegistry:
    pack = coverage_packs.import_coverage_pack(
        coverage_packs.CoveragePackImport(
            pack_id="pack-web-baseline",
            name="Web baseline",
            version="2026.07.09",
            owner_user_id="owner-1",
            source_references=("STD-WSTG",),
            risk_class=domain.TestRiskClass.PASSIVE,
            supported_adapters=(adapter_id,),
            default_profile=profile(),
            profiles=(profile(),),
            deprecation_policy="Deprecate with reviewed replacement.",
            taxonomy_mappings=(mapping(),),
            tests=(
                coverage_packs.CoveragePackTest(
                    test_definition_id="test:header-review",
                    test_definition_version="1.0.0",
                    implementation_status=coverage_packs.CoverageImplementationStatus.IMPLEMENTED,
                    taxonomy_mappings=(mapping(),),
                ),
            ),
        )
    )
    approved = coverage_packs.approve_coverage_pack(pack, reviewer_user_id="reviewer-1", approved_at=NOW)
    return coverage_packs.CoveragePackRegistry().register(
        approved,
        event_id="audit-pack-1",
        actor_user_id="reviewer-1",
        occurred_at=NOW,
    )


def provenance(**overrides: object) -> adapter_certification.AdapterProvenance:
    values = {
        "source_reference": "internal:zap-passive-adapter",
        "expected_artifact_digest": "sha256:abc123",
        "observed_artifact_digest": "sha256:abc123",
        "sbom_reference": "sbom:redagent:zap-passive",
        "attestation_reference": "attestation:redagent:zap-passive",
        "reviewed_by_user_id": "reviewer-1",
    }
    values.update(overrides)
    return adapter_certification.AdapterProvenance(**values)  # type: ignore[arg-type]


def manifest(**overrides: object) -> adapter_certification.AdapterManifest:
    values = {
        "adapter_id": "zap-passive",
        "version": "1.0.0",
        "display_name": "ZAP passive import adapter",
        "command_boundary": "structured runner manifest only; no arbitrary commands",
        "supported_modes": (domain.TestMode.PASSIVE_SCAN,),
        "forbidden_modes": (domain.TestMode.ADVERSARY_EMULATION,),
        "evidence_schema": (domain.EvidenceKind.HTTP_METADATA, domain.EvidenceKind.COMMAND_LOG),
        "cleanup_required": True,
        "cleanup_evidence_schema": ("cleanup_callback", "artifact_manifest"),
        "timeout_seconds": 120,
        "cancellation_supported": True,
        "declared_features": (
            adapter_certification.AdapterFeature.PASSIVE_RESULT_IMPORT,
            adapter_certification.AdapterFeature.CANCELLATION,
            adapter_certification.AdapterFeature.CLEANUP,
        ),
        "allowed_surfaces": (
            adapter_certification.AdapterUseSurface.UI,
            adapter_certification.AdapterUseSurface.API,
            adapter_certification.AdapterUseSurface.SKILL,
            adapter_certification.AdapterUseSurface.RUNNER_JOB,
        ),
        "coverage_pack_refs": (
            adapter_certification.AdapterCoveragePackRef(
                pack_id="pack-web-baseline",
                version="2026.07.09",
                adapter_id="zap-passive",
                profile_id="safe-default",
            ),
        ),
        "provenance": provenance(),
    }
    values.update(overrides)
    return adapter_certification.AdapterManifest(**values)  # type: ignore[arg-type]


def certify(
    adapter_manifest: adapter_certification.AdapterManifest | None = None,
) -> tuple[adapter_certification.AdapterCertificationRegistry, adapter_certification.AdapterCertificationResult]:
    return adapter_certification.AdapterCertificationRegistry().certify(
        adapter_manifest or manifest(),
        coverage_registry=pack_registry(),
        reviewer_user_id="reviewer-1",
        certified_at=NOW,
        event_id="audit-cert-1",
    )


def test_certified_adapter_is_allowed_for_declared_surfaces_and_modes() -> None:
    registry, result = certify()

    decision = registry.authorize_use(
        adapter_id="zap-passive",
        version="1.0.0",
        surface=adapter_certification.AdapterUseSurface.RUNNER_JOB,
        mode=domain.TestMode.PASSIVE_SCAN,
    )

    assert result.certified
    assert not result.release_blocking
    assert registry.audit_chain.audit_events[0].action is evidence_chain.AuditAction.TEST_DEFINITION_CHANGE
    assert decision.allowed
    assert decision.reason == "adapter_certified_for_surface"


def test_uncertified_adapter_is_denied_for_ui_api_skill_and_runner_job_surfaces() -> None:
    registry = adapter_certification.AdapterCertificationRegistry()

    for surface in adapter_certification.AdapterUseSurface:
        decision = registry.authorize_use(
            adapter_id="zap-passive",
            version="1.0.0",
            surface=surface,
            mode=domain.TestMode.PASSIVE_SCAN,
        )
        assert not decision.allowed
        assert decision.reason == "adapter_not_certified"


def test_unsafe_features_are_release_blocking_and_not_registered() -> None:
    bad = manifest(
        declared_features=(
            adapter_certification.AdapterFeature.PASSIVE_RESULT_IMPORT,
            adapter_certification.AdapterFeature.ARBITRARY_COMMAND_EXECUTION,
            adapter_certification.AdapterFeature.PAYLOAD_EXECUTION,
        )
    )

    registry, result = certify(bad)
    gate = adapter_certification.evaluate_release_gate((result,))

    assert result.status is adapter_certification.AdapterCertificationStatus.FAILED
    assert result.release_blocking
    assert {finding.reason for finding in result.findings} == {
        "unsafe_feature_denied:arbitrary_command_execution",
        "unsafe_feature_denied:payload_execution",
    }
    assert registry.certified_adapters == ()
    assert not gate.allowed
    assert gate.reason == "adapter_certification_release_blocked"


def test_provenance_mismatch_fails_certification() -> None:
    _, result = certify(
        manifest(
            provenance=provenance(
                expected_artifact_digest="sha256:expected",
                observed_artifact_digest="sha256:observed",
            )
        )
    )

    assert result.status is adapter_certification.AdapterCertificationStatus.FAILED
    assert "adapter_provenance_mismatch" in {finding.reason for finding in result.findings}


def test_cleanup_evidence_and_cancellation_are_required() -> None:
    _, result = certify(
        manifest(
            cleanup_evidence_schema=(),
            cancellation_supported=False,
        )
    )

    reasons = {finding.reason for finding in result.findings}
    assert "cleanup_evidence_schema_required" in reasons
    assert "adapter_cancellation_required" in reasons
    assert result.release_blocking


def test_coverage_pack_incompatibility_fails_certification() -> None:
    adapter_manifest = manifest(
        coverage_pack_refs=(
            adapter_certification.AdapterCoveragePackRef(
                pack_id="pack-web-baseline",
                version="2026.07.09",
                adapter_id="zap-passive",
                profile_id="missing-profile",
            ),
        )
    )

    _, result = certify(adapter_manifest)

    assert result.status is adapter_certification.AdapterCertificationStatus.FAILED
    assert result.findings[0].reason == "coverage_pack_not_selectable:coverage_profile_not_found"


def test_surface_or_mode_not_declared_is_denied_after_certification() -> None:
    registry, _ = certify(
        manifest(
            allowed_surfaces=(adapter_certification.AdapterUseSurface.RUNNER_JOB,),
        )
    )

    surface_denied = registry.authorize_use(
        adapter_id="zap-passive",
        version="1.0.0",
        surface=adapter_certification.AdapterUseSurface.UI,
        mode=domain.TestMode.PASSIVE_SCAN,
    )
    mode_denied = registry.authorize_use(
        adapter_id="zap-passive",
        version="1.0.0",
        surface=adapter_certification.AdapterUseSurface.RUNNER_JOB,
        mode=domain.TestMode.ACTIVE_SCAN,
    )

    assert surface_denied.reason == "adapter_surface_not_certified"
    assert mode_denied.reason == "adapter_mode_not_certified"
