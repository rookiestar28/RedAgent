"""Platform security assessment and release-blocker validation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.findings import Severity


class ASVSDomain(str, Enum):
    ARCHITECTURE = "architecture"
    AUTHENTICATION = "authentication"
    SESSION = "session"
    ACCESS_CONTROL = "access_control"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    CONFIGURATION = "configuration"
    DATA_PROTECTION = "data_protection"
    ERROR_LOGGING = "error_logging"
    API = "api"


class PlatformControlCategory(str, Enum):
    DEPENDENCY = "dependency"
    SENSITIVE_VALUE = "sensitive_value"
    AUTHORIZATION = "authorization"
    AUDIT = "audit"
    EVIDENCE_INTEGRITY = "evidence_integrity"
    RUNNER_BOUNDARY = "runner_boundary"


class AssessmentStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class FindingDispositionStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    RISK_ACCEPTED = "risk_accepted"
    DEFERRED = "deferred"


@dataclass(frozen=True, kw_only=True)
class ASVSAssessment:
    control_id: str
    domain: ASVSDomain
    objective: str
    status: AssessmentStatus
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class PlatformControlCheck:
    category: PlatformControlCategory
    name: str
    status: AssessmentStatus
    evidence_refs: tuple[str, ...]
    notes: str


@dataclass(frozen=True, kw_only=True)
class FindingDisposition:
    finding_id: str
    severity: Severity
    status: FindingDispositionStatus
    owner_user_id: str | None
    rationale: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class PlatformSecurityAssessment:
    assessment_id: str
    assessed_at: datetime
    threat_model_path: str
    asvs_assessments: tuple[ASVSAssessment, ...]
    control_checks: tuple[PlatformControlCheck, ...]
    finding_dispositions: tuple[FindingDisposition, ...]


@dataclass(frozen=True, kw_only=True)
class PlatformAssessmentValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()


MANDATORY_ASVS_DOMAINS: frozenset[ASVSDomain] = frozenset(ASVSDomain)
MANDATORY_CONTROL_CATEGORIES: frozenset[PlatformControlCategory] = frozenset(PlatformControlCategory)
RELEASE_BLOCKING_SEVERITIES: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})
RELEASE_ACCEPTED_DISPOSITIONS: frozenset[FindingDispositionStatus] = frozenset(
    {FindingDispositionStatus.FIXED, FindingDispositionStatus.RISK_ACCEPTED}
)


def build_r031_baseline_assessment(*, assessed_at: datetime) -> PlatformSecurityAssessment:
    """Return the compat_031 baseline assessment for the current implementation surface."""
    return PlatformSecurityAssessment(
        assessment_id="R031-platform-security-assessment",
        assessed_at=assessed_at,
        threat_model_path="docs/governance/RedAgent-threat-model.md",
        asvs_assessments=(
            ASVSAssessment(
                control_id="ASVS-1.2.1",
                domain=ASVSDomain.ARCHITECTURE,
                objective="Document trust boundaries for control plane, runner boundary, evidence, credentials, and reference material.",
                status=AssessmentStatus.PASS,
                evidence_refs=("docs/governance/RedAgent-threat-model.md", "docs/security/PLATFORM_SECURITY_ASSESSMENT_POLICY.md"),
            ),
            ASVSAssessment(
                control_id="ASVS-2.1.1",
                domain=ASVSDomain.AUTHENTICATION,
                objective="Require authenticated subjects for protected platform actions.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/rbac.py", "tests/unit/test_rbac.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-3.2.1",
                domain=ASVSDomain.SESSION,
                objective="Track required session security controls before browser session implementation.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/rbac.py", "docs/security/AUTH_SESSION_HARNESS_POLICY.md"),
            ),
            ASVSAssessment(
                control_id="ASVS-4.1.1",
                domain=ASVSDomain.ACCESS_CONTROL,
                objective="Deny unauthenticated, cross-tenant, and missing-permission requests by default.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/rbac.py", "redagent_platform/scope_authorization.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-5.1.1",
                domain=ASVSDomain.INPUT_VALIDATION,
                objective="Validate scope, target, timing, runner, and evidence inputs before policy decisions.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/scope_authorization.py", "redagent_platform/active_policy.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-5.3.1",
                domain=ASVSDomain.OUTPUT_ENCODING,
                objective="Reject secret-like text and unredacted sensitive evidence in exported findings.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/findings.py", "redagent_platform/reporting.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-14.1.1",
                domain=ASVSDomain.CONFIGURATION,
                objective="Keep active execution disabled until policy gates and runner controls approve the request.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/active_policy.py", "docs/security/ACTIVE_TESTING_POLICY_GATE.md"),
            ),
            ASVSAssessment(
                control_id="ASVS-8.3.1",
                domain=ASVSDomain.DATA_PROTECTION,
                objective="Protect credential leases and evidence records with redaction and integrity requirements.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/credentials.py", "redagent_platform/evidence_chain.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-7.1.1",
                domain=ASVSDomain.ERROR_LOGGING,
                objective="Require audit events for policy, job, evidence, finding, report, export, and credential actions.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/evidence_chain.py", "tests/unit/test_evidence_chain.py"),
            ),
            ASVSAssessment(
                control_id="ASVS-13.1.1",
                domain=ASVSDomain.API,
                objective="Model API and runner callbacks as service-authorized resources before route implementation.",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/rbac.py", "redagent_platform/job_queue.py"),
            ),
        ),
        control_checks=(
            PlatformControlCheck(
                category=PlatformControlCategory.DEPENDENCY,
                name="pre_commit_and_dependency_gate",
                status=AssessmentStatus.PASS,
                evidence_refs=("scripts/run_full_tests_windows.ps1", ".pre-commit-config.yaml"),
                notes="Full gate runs secret detection, pre-commit hooks, backend unit tests, and E2E smoke validation.",
            ),
            PlatformControlCheck(
                category=PlatformControlCategory.SENSITIVE_VALUE,
                name="secret_and_canary_redaction",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/credentials.py", "redagent_platform/supply_chain.py", "redagent_platform/dlp_validation.py"),
                notes="Sensitive markers are rejected or redacted before evidence/export boundaries.",
            ),
            PlatformControlCheck(
                category=PlatformControlCategory.AUTHORIZATION,
                name="rbac_and_scope_fail_closed",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/rbac.py", "redagent_platform/scope_authorization.py"),
                notes="Unauthenticated, cross-tenant, missing-role, and out-of-scope requests deny by default.",
            ),
            PlatformControlCheck(
                category=PlatformControlCategory.AUDIT,
                name="required_audit_action_coverage",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/evidence_chain.py", "tests/unit/test_evidence_chain.py"),
                notes="Audit chain supports required platform security events.",
            ),
            PlatformControlCheck(
                category=PlatformControlCategory.EVIDENCE_INTEGRITY,
                name="immutable_evidence_hash_chain",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/evidence_chain.py", "tests/unit/test_evidence_chain.py"),
                notes="Evidence overwrite is blocked and integrity hashes are recomputable.",
            ),
            PlatformControlCheck(
                category=PlatformControlCategory.RUNNER_BOUNDARY,
                name="runner_isolation_and_persistent_agent_gate",
                status=AssessmentStatus.PASS,
                evidence_refs=("redagent_platform/runner_isolation.py", "tests/unit/test_runner_isolation.py"),
                notes="Persistent agents remain blocked pending threat-model review; Kali lab node is not a primary development root.",
            ),
        ),
        finding_dispositions=(
            FindingDisposition(
                finding_id="R031-CRIT-001",
                severity=Severity.CRITICAL,
                status=FindingDispositionStatus.RISK_ACCEPTED,
                owner_user_id="security-lead",
                rationale="No production control plane or runner exists yet; release is blocked from production use until R032-R034 complete.",
                evidence_refs=("SECURITY.md", "PUBLIC_RELEASE.md"),
            ),
            FindingDisposition(
                finding_id="R031-HIGH-001",
                severity=Severity.HIGH,
                status=FindingDispositionStatus.FIXED,
                owner_user_id="security-lead",
                rationale="Current implementation has fail-closed scope, RBAC, evidence, credential, and runner-boundary validators with tests.",
                evidence_refs=("tests/unit/test_platform_security_assessment.py", "scripts/run_full_tests_windows.ps1"),
            ),
        ),
    )


def validate_platform_security_assessment(assessment: PlatformSecurityAssessment) -> PlatformAssessmentValidation:
    gaps = list(_shape_gaps(assessment))
    gaps.extend(_asvs_gaps(assessment.asvs_assessments))
    gaps.extend(_control_gaps(assessment.control_checks))
    gaps.extend(_finding_disposition_gaps(assessment.finding_dispositions))
    if gaps:
        return PlatformAssessmentValidation(accepted=False, reason="platform_security_assessment_incomplete", gaps=tuple(gaps))
    return PlatformAssessmentValidation(accepted=True, reason="platform_security_assessment_accepted")


def release_blocking_findings(dispositions: tuple[FindingDisposition, ...]) -> tuple[FindingDisposition, ...]:
    return tuple(
        disposition
        for disposition in dispositions
        if disposition.severity in RELEASE_BLOCKING_SEVERITIES and disposition.status not in RELEASE_ACCEPTED_DISPOSITIONS
    )


def _shape_gaps(assessment: PlatformSecurityAssessment) -> tuple[str, ...]:
    gaps: list[str] = []
    _append_missing(gaps, "assessment_id", assessment.assessment_id)
    _append_missing(gaps, "threat_model_path", assessment.threat_model_path)
    if assessment.assessed_at.tzinfo is None or assessment.assessed_at.utcoffset() is None:
        gaps.append("timezone_required")
    if "RedAgent-threat-model.md" not in assessment.threat_model_path:
        gaps.append("implementation_threat_model_required")
    return tuple(gaps)


def _asvs_gaps(assessments: tuple[ASVSAssessment, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    if not assessments:
        return ("asvs_assessment_required",)
    present_domains = {assessment.domain for assessment in assessments}
    missing_domains = MANDATORY_ASVS_DOMAINS - present_domains
    gaps.extend(f"missing_asvs_domain:{domain.value}" for domain in sorted(missing_domains, key=lambda item: item.value))
    for assessment in assessments:
        _append_missing(gaps, "asvs_control_id", assessment.control_id)
        _append_missing(gaps, "asvs_objective", assessment.objective)
        if assessment.status is AssessmentStatus.FAIL:
            gaps.append(f"failed_asvs_control:{assessment.control_id}")
        if assessment.status is not AssessmentStatus.NOT_APPLICABLE and not assessment.evidence_refs:
            gaps.append(f"missing_asvs_evidence:{assessment.control_id}")
    return tuple(gaps)


def _control_gaps(checks: tuple[PlatformControlCheck, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    if not checks:
        return ("platform_control_checks_required",)
    present_categories = {check.category for check in checks}
    missing_categories = MANDATORY_CONTROL_CATEGORIES - present_categories
    gaps.extend(f"missing_control_category:{category.value}" for category in sorted(missing_categories, key=lambda item: item.value))
    for check in checks:
        _append_missing(gaps, "control_name", check.name)
        _append_missing(gaps, "control_notes", check.notes)
        if check.status is AssessmentStatus.FAIL:
            gaps.append(f"failed_control:{check.category.value}:{check.name}")
        if check.status is not AssessmentStatus.NOT_APPLICABLE and not check.evidence_refs:
            gaps.append(f"missing_control_evidence:{check.category.value}:{check.name}")
    return tuple(gaps)


def _finding_disposition_gaps(dispositions: tuple[FindingDisposition, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    for disposition in dispositions:
        _append_missing(gaps, "finding_id", disposition.finding_id)
        if disposition.severity in RELEASE_BLOCKING_SEVERITIES:
            if disposition.status not in RELEASE_ACCEPTED_DISPOSITIONS:
                gaps.append(f"release_blocker_unresolved:{disposition.finding_id}")
            if not disposition.owner_user_id or not disposition.owner_user_id.strip():
                gaps.append(f"missing_release_blocker_owner:{disposition.finding_id}")
            if not disposition.rationale.strip():
                gaps.append(f"missing_release_blocker_rationale:{disposition.finding_id}")
            if not disposition.evidence_refs:
                gaps.append(f"missing_release_blocker_evidence:{disposition.finding_id}")
    return tuple(gaps)


def _append_missing(gaps: list[str], field_name: str, value: str) -> None:
    if not value or not value.strip():
        gaps.append(f"missing_{field_name}")
