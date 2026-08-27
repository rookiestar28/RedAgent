from datetime import datetime, timezone

from redagent_platform.findings import Severity
from redagent_platform.platform_security_assessment import (
    ASVSAssessment,
    ASVSDomain,
    AssessmentStatus,
    FindingDisposition,
    FindingDispositionStatus,
    PlatformControlCategory,
    PlatformControlCheck,
    build_platform_security_baseline_assessment,
    release_blocking_findings,
    validate_platform_security_assessment,
)


def test_r031_baseline_assessment_is_accepted():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))

    validation = validate_platform_security_assessment(assessment)

    assert validation.accepted is True
    assert validation.reason == "platform_security_assessment_accepted"


def test_asvs_informed_assessment_covers_required_domains():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))

    domains = {entry.domain for entry in assessment.asvs_assessments}

    assert domains == set(ASVSDomain)
    assert all(entry.evidence_refs for entry in assessment.asvs_assessments)


def test_required_security_control_categories_are_represented():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))

    categories = {check.category for check in assessment.control_checks}

    assert categories == set(PlatformControlCategory)


def test_missing_runner_boundary_control_fails_closed():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))
    without_runner = tuple(
        check for check in assessment.control_checks if check.category is not PlatformControlCategory.RUNNER_BOUNDARY
    )
    changed = _replace_assessment(assessment, control_checks=without_runner)

    validation = validate_platform_security_assessment(changed)

    assert validation.accepted is False
    assert "missing_control_category:runner_boundary" in validation.gaps


def test_failed_dependency_control_blocks_assessment():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))
    failed_dependency = PlatformControlCheck(
        category=PlatformControlCategory.DEPENDENCY,
        name="dependency_gate",
        status=AssessmentStatus.FAIL,
        evidence_refs=("scripts/run_full_tests_windows.ps1",),
        notes="simulated failure",
    )
    changed = _replace_assessment(assessment, control_checks=(failed_dependency,) + assessment.control_checks[1:])

    validation = validate_platform_security_assessment(changed)

    assert validation.accepted is False
    assert "failed_control:dependency:dependency_gate" in validation.gaps


def test_missing_asvs_domain_blocks_assessment():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))
    missing_api = tuple(entry for entry in assessment.asvs_assessments if entry.domain is not ASVSDomain.API)
    changed = _replace_assessment(assessment, asvs_assessments=missing_api)

    validation = validate_platform_security_assessment(changed)

    assert validation.accepted is False
    assert "missing_asvs_domain:api" in validation.gaps


def test_failed_asvs_control_blocks_assessment():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))
    failed_control = ASVSAssessment(
        control_id="ASVS-test",
        domain=ASVSDomain.API,
        objective="simulated failed control",
        status=AssessmentStatus.FAIL,
        evidence_refs=("tests/unit/test_platform_security_assessment.py",),
    )
    changed = _replace_assessment(assessment, asvs_assessments=assessment.asvs_assessments[:-1] + (failed_control,))

    validation = validate_platform_security_assessment(changed)

    assert validation.accepted is False
    assert "failed_asvs_control:ASVS-test" in validation.gaps


def test_critical_and_high_findings_must_be_fixed_or_risk_accepted():
    unresolved = FindingDisposition(
        finding_id="R031-HIGH-open",
        severity=Severity.HIGH,
        status=FindingDispositionStatus.OPEN,
        owner_user_id="security-lead",
        rationale="not yet reviewed",
        evidence_refs=("PUBLIC_RELEASE.md",),
    )

    blockers = release_blocking_findings((unresolved,))

    assert blockers == (unresolved,)


def test_release_blocker_requires_owner_rationale_and_evidence():
    assessment = build_platform_security_baseline_assessment(assessed_at=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc))
    incomplete = FindingDisposition(
        finding_id="R031-CRIT-incomplete",
        severity=Severity.CRITICAL,
        status=FindingDispositionStatus.RISK_ACCEPTED,
        owner_user_id=" ",
        rationale=" ",
        evidence_refs=(),
    )
    changed = _replace_assessment(assessment, finding_dispositions=(incomplete,))

    validation = validate_platform_security_assessment(changed)

    assert validation.accepted is False
    assert "missing_release_blocker_owner:R031-CRIT-incomplete" in validation.gaps
    assert "missing_release_blocker_rationale:R031-CRIT-incomplete" in validation.gaps
    assert "missing_release_blocker_evidence:R031-CRIT-incomplete" in validation.gaps


def _replace_assessment(assessment, **changes):
    values = {
        "assessment_id": assessment.assessment_id,
        "assessed_at": assessment.assessed_at,
        "threat_model_path": assessment.threat_model_path,
        "asvs_assessments": assessment.asvs_assessments,
        "control_checks": assessment.control_checks,
        "finding_dispositions": assessment.finding_dispositions,
    }
    values.update(changes)
    return type(assessment)(**values)
