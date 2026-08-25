"""Core domain contracts for the RedAgent platform.

These contracts are intentionally non-executing. They define stable names,
boundaries, and lifecycle vocabulary for later roadmap items.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class RoleName(str, Enum):
    ADMINISTRATOR = "administrator"
    SECURITY_LEAD = "security_lead"
    OPERATOR = "operator"
    REVIEWER = "reviewer"
    READ_ONLY_AUDITOR = "read_only_auditor"
    SERVICE_RUNNER = "service_runner"


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    PASSIVE_APPROVED = "passive_approved"
    ACTIVE_APPROVED = "active_approved"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class TargetType(str, Enum):
    WEB_ORIGIN = "web_origin"
    API_SPEC = "api_spec"
    DOMAIN = "domain"
    CIDR = "cidr"
    REPOSITORY = "repository"
    MOBILE_PACKAGE = "mobile_package"
    AI_APPLICATION = "ai_application"
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_PROJECT = "cloud_project"
    CLOUD_SUBSCRIPTION = "cloud_subscription"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    SAAS_TENANT = "saas_tenant"
    LAB_TARGET = "lab_target"


class AuthorizationStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class TestMode(str, Enum):
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"
    ADVERSARY_EMULATION = "adversary_emulation"
    CLOUD_TECHNIQUE = "cloud_technique"
    IDENTITY_POSTURE = "identity_posture"
    SUPPLY_CHAIN_POSTURE = "supply_chain_posture"
    MOBILE_ASSESSMENT = "mobile_assessment"
    AI_AGENTIC_ASSESSMENT = "ai_agentic_assessment"
    DLP_CANARY_VALIDATION = "dlp_canary_validation"
    EMAIL_RESILIENCE = "email_resilience"
    LAB_ONLY_RUN = "lab_only_run"


class TestRiskClass(str, Enum):
    METADATA_ONLY = "metadata_only"
    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    ACTIVE_INTRUSIVE = "active_intrusive"
    DESTRUCTIVE = "destructive"
    LAB_ONLY = "lab_only"


class RunnerKind(str, Enum):
    LOCAL_MANUAL = "local_manual"
    EPHEMERAL_WORKER = "ephemeral_worker"
    CONTROLLED_LAB = "controlled_lab"
    CLOUD_SANDBOX = "cloud_sandbox"


class JobStatus(str, Enum):
    PLANNED = "planned"
    AUTHORIZED = "authorized"
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EVIDENCE_LOCKED = "evidence_locked"


class EvidenceKind(str, Enum):
    COMMAND_LOG = "command_log"
    HTTP_METADATA = "http_metadata"
    TLS_METADATA = "tls_metadata"
    DNS_METADATA = "dns_metadata"
    OPENAPI_METADATA = "openapi_metadata"
    TECH_FINGERPRINT = "tech_fingerprint"
    SCANNER_OUTPUT = "scanner_output"
    TELEMETRY = "telemetry"
    SCREENSHOT = "screenshot"
    REPORT_SOURCE = "report_source"


class FindingStatus(str, Enum):
    NEW = "new"
    RAW_ALERT = "raw_alert"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    FIXED = "fixed"
    REMEDIATED = "remediated"
    RETEST_REQUIRED = "retest_required"
    RETEST_REQUESTED = "retest_requested"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"


class PolicyDecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"


@dataclass(frozen=True, kw_only=True)
class Organization:
    id: str
    name: str


@dataclass(frozen=True, kw_only=True)
class User:
    id: str
    organization_id: str
    email: str
    display_name: str


@dataclass(frozen=True, kw_only=True)
class Role:
    id: str
    organization_id: str
    name: RoleName


@dataclass(frozen=True, kw_only=True)
class Engagement:
    id: str
    organization_id: str
    name: str
    status: EngagementStatus
    owner_user_id: str


@dataclass(frozen=True, kw_only=True)
class Target:
    id: str
    engagement_id: str
    target_type: TargetType
    value: str
    environment: str
    data_sensitivity: str


@dataclass(frozen=True, kw_only=True)
class Authorization:
    id: str
    engagement_id: str
    status: AuthorizationStatus
    approved_by_user_id: str | None
    allowed_modes: tuple[TestMode, ...]


@dataclass(frozen=True, kw_only=True)
class TestDefinition:
    id: str
    name: str
    version: str
    mode: TestMode
    risk_class: TestRiskClass
    target_types: tuple[TargetType, ...]


@dataclass(frozen=True, kw_only=True)
class Runner:
    id: str
    organization_id: str
    kind: RunnerKind
    capabilities: tuple[TestMode, ...]


@dataclass(frozen=True, kw_only=True)
class Job:
    id: str
    engagement_id: str
    test_definition_id: str
    target_id: str
    runner_id: str | None
    status: JobStatus


@dataclass(frozen=True, kw_only=True)
class Evidence:
    id: str
    job_id: str
    kind: EvidenceKind
    redaction_status: str
    integrity_hash: str


@dataclass(frozen=True, kw_only=True)
class Finding:
    id: str
    engagement_id: str
    status: FindingStatus
    title: str
    severity: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class Report:
    id: str
    engagement_id: str
    title: str
    finding_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class AuditEvent:
    id: str
    organization_id: str
    actor_user_id: str | None
    action: str
    subject_type: str
    subject_id: str


@dataclass(frozen=True, kw_only=True)
class PolicyDecision:
    id: str
    organization_id: str
    outcome: PolicyDecisionOutcome
    reason: str
    subject_type: str
    subject_id: str


CORE_ENTITY_TYPES: Final[tuple[type[object], ...]] = (
    Organization,
    User,
    Role,
    Engagement,
    Target,
    Authorization,
    TestDefinition,
    Runner,
    Job,
    Evidence,
    Finding,
    Report,
    AuditEvent,
    PolicyDecision,
)

REQUIRED_TEST_MODE_SEPARATION: Final[frozenset[TestMode]] = frozenset(
    {
        TestMode.PASSIVE_SCAN,
        TestMode.ACTIVE_SCAN,
        TestMode.ADVERSARY_EMULATION,
        TestMode.CLOUD_TECHNIQUE,
        TestMode.LAB_ONLY_RUN,
    }
)


def core_entity_names() -> tuple[str, ...]:
    """Return the canonical core entity class names."""
    return tuple(entity.__name__ for entity in CORE_ENTITY_TYPES)


def missing_core_entities(required_names: set[str]) -> tuple[str, ...]:
    """Return required core entity names that are not present."""
    present = set(core_entity_names())
    return tuple(sorted(required_names - present))


def execution_modes_are_separated() -> bool:
    """Return True when the required execution modes have distinct values."""
    values = {mode.value for mode in REQUIRED_TEST_MODE_SEPARATION}
    return len(values) == len(REQUIRED_TEST_MODE_SEPARATION)
