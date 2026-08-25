"""Local lab validation suite and golden evidence corpus contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import TargetType, TestMode
from redagent_platform.lab_harness import LabTargetRegistration
from redagent_platform.target_inventory import EnvironmentType, InventoryTarget


class LabEnvironmentClass(str, Enum):
    LOCAL_LAB = "local_lab"
    ENTERPRISE_STAGING = "enterprise_staging"
    PRODUCTION = "production"


class LabValidationFixtureKind(str, Enum):
    PASSIVE_WEB = "passive_web"
    API_LAB = "api_lab"
    ZAP = "zap"
    NUCLEI = "nuclei"
    AUTH_ROLE_CASES = "auth_role_cases"
    EVIDENCE_REPORT = "evidence_report"


@dataclass(frozen=True, kw_only=True)
class ScannerPolicyProfile:
    profile_id: str
    module_id: str
    allowed_modes: tuple[TestMode, ...]
    required_fixture_kinds: tuple[LabValidationFixtureKind, ...]
    max_age_seconds: int


@dataclass(frozen=True, kw_only=True)
class GoldenEvidenceFixture:
    fixture_id: str
    kind: LabValidationFixtureKind
    policy_profile_id: str
    sanitized_artifact_id: str
    evidence_hash: str
    generated_at: datetime


@dataclass(frozen=True, kw_only=True)
class LabValidationRecord:
    validation_id: str
    policy_profile_id: str
    module_id: str
    lab_target_id: str
    fixture_ids: tuple[str, ...]
    sanitized_artifact_ids: tuple[str, ...]
    validated_at: datetime
    expires_at: datetime
    passed: bool


@dataclass(frozen=True, kw_only=True)
class EnterpriseJobLabGate:
    allowed: bool
    reason: str
    validation_id: str | None = None


REQUIRED_GOLDEN_FIXTURE_KINDS: tuple[LabValidationFixtureKind, ...] = (
    LabValidationFixtureKind.PASSIVE_WEB,
    LabValidationFixtureKind.API_LAB,
    LabValidationFixtureKind.ZAP,
    LabValidationFixtureKind.NUCLEI,
    LabValidationFixtureKind.AUTH_ROLE_CASES,
    LabValidationFixtureKind.EVIDENCE_REPORT,
)


def classify_target_environment(target: InventoryTarget) -> LabEnvironmentClass:
    if target.target_type is TargetType.LAB_TARGET or target.environment is EnvironmentType.LAB:
        return LabEnvironmentClass.LOCAL_LAB
    if target.environment is EnvironmentType.PRODUCTION:
        return LabEnvironmentClass.PRODUCTION
    return LabEnvironmentClass.ENTERPRISE_STAGING


def build_golden_evidence_corpus(
    *,
    policy_profile_id: str,
    generated_at: datetime,
) -> tuple[GoldenEvidenceFixture, ...]:
    _require_non_empty("policy_profile_id", policy_profile_id)
    _require_timezone(generated_at)
    return tuple(
        GoldenEvidenceFixture(
            fixture_id=f"{policy_profile_id}:{kind.value}",
            kind=kind,
            policy_profile_id=policy_profile_id,
            sanitized_artifact_id=f"sanitized:{policy_profile_id}:{kind.value}",
            evidence_hash=f"fixture-hash:{policy_profile_id}:{kind.value}",
            generated_at=generated_at,
        )
        for kind in REQUIRED_GOLDEN_FIXTURE_KINDS
    )


def record_lab_validation(
    *,
    validation_id: str,
    profile: ScannerPolicyProfile,
    lab_target: LabTargetRegistration,
    fixtures: tuple[GoldenEvidenceFixture, ...],
    validated_at: datetime,
    expires_at: datetime,
    passed: bool,
) -> LabValidationRecord:
    _validate_profile(profile)
    _require_non_empty("validation_id", validation_id)
    _require_timezone(validated_at)
    _require_timezone(expires_at)
    if validated_at >= expires_at:
        raise ValueError("invalid_validation_window")
    if not passed:
        raise ValueError("lab_validation_must_pass")
    fixture_by_kind = {fixture.kind: fixture for fixture in fixtures}
    missing = tuple(kind for kind in profile.required_fixture_kinds if kind not in fixture_by_kind)
    if missing:
        raise ValueError("missing_required_golden_fixture")
    for fixture in fixtures:
        if fixture.policy_profile_id != profile.profile_id:
            raise ValueError("fixture_profile_mismatch")
        if not fixture.sanitized_artifact_id.startswith("sanitized:"):
            raise ValueError("lab_artifact_not_sanitized")
    return LabValidationRecord(
        validation_id=validation_id.strip(),
        policy_profile_id=profile.profile_id,
        module_id=profile.module_id,
        lab_target_id=lab_target.target_id,
        fixture_ids=tuple(sorted(fixture.fixture_id for fixture in fixtures)),
        sanitized_artifact_ids=tuple(sorted(fixture.sanitized_artifact_id for fixture in fixtures)),
        validated_at=validated_at,
        expires_at=expires_at,
        passed=True,
    )


def validate_enterprise_job_lab_gate(
    *,
    target: InventoryTarget,
    profile: ScannerPolicyProfile,
    validation_records: tuple[LabValidationRecord, ...],
    requested_at: datetime,
) -> EnterpriseJobLabGate:
    _validate_profile(profile)
    _require_timezone(requested_at)
    environment_class = classify_target_environment(target)
    if environment_class is LabEnvironmentClass.LOCAL_LAB:
        return EnterpriseJobLabGate(allowed=True, reason="local_lab_target")
    for record in validation_records:
        if record.policy_profile_id != profile.profile_id:
            continue
        if record.module_id != profile.module_id:
            continue
        if not record.passed:
            continue
        if not (record.validated_at <= requested_at < record.expires_at):
            continue
        return EnterpriseJobLabGate(allowed=True, reason="matching_lab_validation", validation_id=record.validation_id)
    return EnterpriseJobLabGate(allowed=False, reason="matching_lab_validation_required")


def _validate_profile(profile: ScannerPolicyProfile) -> None:
    _require_non_empty("profile_id", profile.profile_id)
    _require_non_empty("module_id", profile.module_id)
    if not profile.allowed_modes:
        raise ValueError("profile_modes_required")
    if not profile.required_fixture_kinds:
        raise ValueError("profile_fixtures_required")
    if profile.max_age_seconds <= 0:
        raise ValueError("invalid_profile_max_age")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
