from datetime import datetime, timezone

import pytest

from redagent_platform import evidence_chain, supply_chain
from redagent_platform.findings import Severity


NOW = datetime(2026, 7, 8, 22, 0, tzinfo=timezone.utc)


def repository(**overrides: object) -> supply_chain.RepositoryAllowlistEntry:
    values = {
        "repository_id": "repo-1",
        "repository_path": "B:/owned/repo",
        "owner_user_id": "owner-1",
        "trusted": True,
    }
    values.update(overrides)
    return supply_chain.RepositoryAllowlistEntry(**values)  # type: ignore[arg-type]


def pipeline(**overrides: object) -> supply_chain.PipelineAllowlistEntry:
    values = {
        "pipeline_id": "pipeline-1",
        "repository_id": "repo-1",
        "owner_user_id": "owner-1",
    }
    values.update(overrides)
    return supply_chain.PipelineAllowlistEntry(**values)  # type: ignore[arg-type]


def scope(**overrides: object) -> supply_chain.SupplyChainScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "repositories": (repository(),),
        "pipelines": (pipeline(),),
        "external_verification_approved": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainScope(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> supply_chain.SupplyChainAssessmentRequest:
    values = {
        "job_id": "supply-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "repository_id": "repo-1",
        "pipeline_id": "pipeline-1",
        "check_kinds": (
            supply_chain.SupplyChainCheckKind.STATIC_ANALYSIS,
            supply_chain.SupplyChainCheckKind.DEPENDENCY_INVENTORY,
            supply_chain.SupplyChainCheckKind.SBOM_IMPORT,
            supply_chain.SupplyChainCheckKind.SENSITIVE_VALUE_SCAN,
            supply_chain.SupplyChainCheckKind.PROVENANCE_CHECK,
        ),
        "requested_at": NOW,
        "external_verification_requested": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainAssessmentRequest(**values)  # type: ignore[arg-type]


def test_owner_approval_and_explicit_repository_allowlist_are_required() -> None:
    supply_chain.validate_supply_chain_scope(scope())

    with pytest.raises(ValueError, match="missing_approved_by_user_id"):
        supply_chain.validate_supply_chain_scope(scope(approved_by_user_id=""))

    with pytest.raises(ValueError, match="repository_allowlist_required"):
        supply_chain.validate_supply_chain_scope(scope(repositories=()))

    denied = supply_chain.evaluate_supply_chain_assessment(scope=scope(), request=request(repository_id="missing"))

    assert not denied.allowed
    assert denied.reason == "repository_not_allowlisted"


def test_local_checks_run_against_trusted_target_repositories_only() -> None:
    decision = supply_chain.evaluate_supply_chain_assessment(scope=scope(), request=request())

    assert decision.allowed
    assert decision.reason == "supply_chain_local_checks_allowed"

    plan = supply_chain.build_supply_chain_check_plan(scope=scope(), request=request())

    assert plan.local_only
    assert set(plan.check_kinds) == set(request().check_kinds)

    untrusted = supply_chain.evaluate_supply_chain_assessment(
        scope=scope(repositories=(repository(trusted=False),)),
        request=request(),
    )

    assert not untrusted.allowed
    assert untrusted.reason == "trusted_repository_required"


def test_redacted_sensitive_evidence_rejects_raw_values_and_canary_leaks() -> None:
    supply_chain.validate_redacted_sensitive_evidence(
        supply_chain.RedactedSensitiveEvidence(
            evidence_id="supply-evidence-1",
            redaction_status=evidence_chain.RedactionStatus.REDACTED,
            redacted_locations=("src/config.py:12 [redacted]",),
            raw_value_recorded=False,
            canary_markers=("CANARY_MARKER",),
        )
    )

    with pytest.raises(ValueError, match="raw_sensitive_value_forbidden"):
        supply_chain.validate_redacted_sensitive_evidence(
            supply_chain.RedactedSensitiveEvidence(
                evidence_id="supply-evidence-2",
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                redacted_locations=("src/config.py:12 [redacted]",),
                raw_value_recorded=True,
            )
        )

    with pytest.raises(ValueError, match="canary_marker_leaked"):
        supply_chain.validate_redacted_sensitive_evidence(
            supply_chain.RedactedSensitiveEvidence(
                evidence_id="supply-evidence-3",
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                redacted_locations=("src/config.py:12 CANARY_MARKER",),
                raw_value_recorded=False,
                canary_markers=("CANARY_MARKER",),
            )
        )


def test_external_verification_is_disabled_unless_separately_approved() -> None:
    denied = supply_chain.evaluate_supply_chain_assessment(
        scope=scope(),
        request=request(external_verification_requested=True),
    )

    assert not denied.allowed
    assert denied.reason == "external_verification_not_approved"

    allowed = supply_chain.evaluate_supply_chain_assessment(
        scope=scope(external_verification_approved=True),
        request=request(external_verification_requested=True),
    )

    assert allowed.allowed


def test_results_map_to_location_control_severity_remediation_and_false_positive_workflow() -> None:
    mapping = supply_chain.build_supply_chain_finding_mapping(
        finding_id="supply-finding-1",
        location_type=supply_chain.SupplyChainLocationType.SOURCE_FILE,
        location="src/package-lock.json",
        control_category=supply_chain.SupplyChainControlCategory.DEPENDENCY_RISK,
        severity=Severity.MEDIUM,
        remediation_guidance="Upgrade the affected dependency after compatibility review.",
        false_positive_workflow="Reviewer may mark false positive with package evidence and expiry date.",
    )

    assert mapping.location_type is supply_chain.SupplyChainLocationType.SOURCE_FILE
    assert mapping.location == "src/package-lock.json"
    assert mapping.control_category is supply_chain.SupplyChainControlCategory.DEPENDENCY_RISK
    assert mapping.severity is Severity.MEDIUM
    assert "Upgrade" in mapping.remediation_guidance
    assert "false positive" in mapping.false_positive_workflow
