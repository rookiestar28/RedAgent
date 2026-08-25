"""Governed coverage-pack registry and control-mapping contracts.

Coverage packs are metadata-only governance objects. This module never loads
external scanner templates, executes scanners, dispatches runners, or contacts
targets.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from redagent_platform.domain import PolicyDecisionOutcome, TestMode, TestRiskClass
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.test_registry import TaxonomyMapping


class CoveragePackStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class CoverageImplementationStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PLANNED = "planned"
    DISABLED = "disabled"
    LAB_ONLY = "lab_only"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, kw_only=True)
class CoveragePackProfile:
    profile_id: str
    name: str
    safe_by_default: bool
    live_job_selectable: bool
    allowed_modes: tuple[TestMode, ...]


@dataclass(frozen=True, kw_only=True)
class CoveragePackTest:
    test_definition_id: str
    test_definition_version: str
    implementation_status: CoverageImplementationStatus
    taxonomy_mappings: tuple[TaxonomyMapping, ...]


@dataclass(frozen=True, kw_only=True)
class CoveragePackImport:
    pack_id: str
    name: str
    version: str
    owner_user_id: str
    source_references: tuple[str, ...]
    risk_class: TestRiskClass
    supported_adapters: tuple[str, ...]
    default_profile: CoveragePackProfile
    profiles: tuple[CoveragePackProfile, ...]
    deprecation_policy: str
    taxonomy_mappings: tuple[TaxonomyMapping, ...]
    tests: tuple[CoveragePackTest, ...]
    executable_content_present: bool = False


@dataclass(frozen=True, kw_only=True)
class CoveragePack:
    pack_id: str
    name: str
    version: str
    owner_user_id: str
    reviewer_user_id: str | None
    source_references: tuple[str, ...]
    risk_class: TestRiskClass
    supported_adapters: tuple[str, ...]
    default_profile_id: str
    profiles: tuple[CoveragePackProfile, ...]
    deprecation_policy: str
    taxonomy_mappings: tuple[TaxonomyMapping, ...]
    tests: tuple[CoveragePackTest, ...]
    status: CoveragePackStatus
    approved_at: datetime | None = None
    deprecated_at: datetime | None = None
    deprecation_reason: str | None = None
    metadata_only: bool = True

    @property
    def default_profile(self) -> CoveragePackProfile:
        for profile in self.profiles:
            if profile.profile_id == self.default_profile_id:
                return profile
        raise ValueError("default_profile_missing")


@dataclass(frozen=True, kw_only=True)
class CoverageSelectionDecision:
    outcome: PolicyDecisionOutcome
    reason: str
    pack_id: str
    version: str
    adapter_id: str
    profile_id: str

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


@dataclass(frozen=True, kw_only=True)
class CoverageReportRow:
    pack_id: str
    version: str
    test_definition_id: str
    test_definition_version: str
    implementation_status: CoverageImplementationStatus
    taxonomy_mappings: tuple[TaxonomyMapping, ...]


@dataclass(frozen=True, kw_only=True)
class CoverageReport:
    total_packs: int
    rows: tuple[CoverageReportRow, ...]
    implemented_count: int
    planned_count: int
    disabled_count: int
    lab_only_count: int
    unsupported_count: int


@dataclass(frozen=True)
class CoveragePackRegistry:
    packs: tuple[CoveragePack, ...] = ()
    audit_chain: EvidenceChain = EvidenceChain()

    def register(
        self,
        pack: CoveragePack,
        *,
        event_id: str,
        actor_user_id: str,
        occurred_at: datetime,
    ) -> "CoveragePackRegistry":
        _require_approved_pack(pack)
        _require_non_empty("event_id", event_id)
        _require_non_empty("actor_user_id", actor_user_id)
        _require_timezone(occurred_at)
        if any(existing.pack_id == pack.pack_id and existing.version == pack.version for existing in self.packs):
            raise ValueError("coverage_pack_version_already_registered")
        next_chain = self.audit_chain.append_audit_event(
            event_id=event_id,
            organization_id="coverage-registry",
            actor_user_id=actor_user_id,
            action=AuditAction.TEST_DEFINITION_CHANGE,
            subject_type="coverage_pack",
            subject_id=f"{pack.pack_id}:{pack.version}",
            occurred_at=occurred_at,
            details={
                "owner_user_id": pack.owner_user_id,
                "reviewer_user_id": pack.reviewer_user_id,
                "risk_class": pack.risk_class.value,
                "supported_adapters": pack.supported_adapters,
                "default_profile_id": pack.default_profile_id,
                "test_count": len(pack.tests),
            },
        )
        return CoveragePackRegistry(packs=self.packs + (pack,), audit_chain=next_chain)

    def deprecate(
        self,
        *,
        pack_id: str,
        version: str,
        reviewer_user_id: str,
        reason: str,
        deprecated_at: datetime,
        event_id: str,
    ) -> "CoveragePackRegistry":
        _require_non_empty("pack_id", pack_id)
        _require_non_empty("version", version)
        _require_non_empty("reviewer_user_id", reviewer_user_id)
        _require_non_empty("reason", reason)
        _require_non_empty("event_id", event_id)
        _require_timezone(deprecated_at)
        index = _pack_index(self.packs, pack_id, version)
        pack = self.packs[index]
        if reviewer_user_id == pack.owner_user_id:
            raise PermissionError("coverage_pack_deprecation_requires_independent_reviewer")
        deprecated = replace(
            pack,
            status=CoveragePackStatus.DEPRECATED,
            reviewer_user_id=reviewer_user_id.strip(),
            deprecated_at=deprecated_at,
            deprecation_reason=reason.strip(),
        )
        updated = self.packs[:index] + (deprecated,) + self.packs[index + 1 :]
        next_chain = self.audit_chain.append_audit_event(
            event_id=event_id,
            organization_id="coverage-registry",
            actor_user_id=reviewer_user_id,
            action=AuditAction.TEST_DEFINITION_CHANGE,
            subject_type="coverage_pack",
            subject_id=f"{pack.pack_id}:{pack.version}",
            occurred_at=deprecated_at,
            details={
                "status": CoveragePackStatus.DEPRECATED.value,
                "reason_hash": _stable_text_hash(reason),
            },
        )
        return CoveragePackRegistry(packs=updated, audit_chain=next_chain)

    def select_for_live_job(
        self,
        *,
        pack_id: str,
        version: str,
        adapter_id: str,
        profile_id: str,
    ) -> CoverageSelectionDecision:
        _require_non_empty("adapter_id", adapter_id)
        _require_non_empty("profile_id", profile_id)
        try:
            pack = self.packs[_pack_index(self.packs, pack_id, version)]
        except ValueError:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_pack_not_registered")
        if pack.status is CoveragePackStatus.DEPRECATED:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_pack_deprecated")
        if pack.status is CoveragePackStatus.DISABLED:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_pack_disabled")
        if pack.status is not CoveragePackStatus.APPROVED:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_pack_not_approved")
        if adapter_id not in pack.supported_adapters:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "adapter_not_supported_by_pack")
        profile = _profile_by_id(pack, profile_id)
        if profile is None:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_profile_not_found")
        if not profile.safe_by_default or not profile.live_job_selectable:
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_profile_not_safe_for_live_jobs")
        if not any(test.implementation_status is CoverageImplementationStatus.IMPLEMENTED for test in pack.tests):
            return _selection_denied(pack_id, version, adapter_id, profile_id, "coverage_pack_unsupported")
        return CoverageSelectionDecision(
            outcome=PolicyDecisionOutcome.ALLOW,
            reason="coverage_pack_selectable",
            pack_id=pack_id,
            version=version,
            adapter_id=adapter_id,
            profile_id=profile_id,
        )

    def coverage_report(self) -> CoverageReport:
        rows = tuple(
            CoverageReportRow(
                pack_id=pack.pack_id,
                version=pack.version,
                test_definition_id=test.test_definition_id,
                test_definition_version=test.test_definition_version,
                implementation_status=test.implementation_status,
                taxonomy_mappings=test.taxonomy_mappings,
            )
            for pack in self.packs
            for test in pack.tests
        )
        return CoverageReport(
            total_packs=len(self.packs),
            rows=rows,
            implemented_count=_count(rows, CoverageImplementationStatus.IMPLEMENTED),
            planned_count=_count(rows, CoverageImplementationStatus.PLANNED),
            disabled_count=_count(rows, CoverageImplementationStatus.DISABLED),
            lab_only_count=_count(rows, CoverageImplementationStatus.LAB_ONLY),
            unsupported_count=_count(rows, CoverageImplementationStatus.UNSUPPORTED),
        )


def import_coverage_pack(metadata: CoveragePackImport) -> CoveragePack:
    _validate_import(metadata)
    if metadata.executable_content_present:
        raise ValueError("coverage_pack_executable_content_forbidden")
    return CoveragePack(
        pack_id=metadata.pack_id.strip(),
        name=metadata.name.strip(),
        version=metadata.version.strip(),
        owner_user_id=metadata.owner_user_id.strip(),
        reviewer_user_id=None,
        source_references=tuple(reference.strip() for reference in metadata.source_references),
        risk_class=metadata.risk_class,
        supported_adapters=tuple(adapter.strip() for adapter in metadata.supported_adapters),
        default_profile_id=metadata.default_profile.profile_id.strip(),
        profiles=metadata.profiles,
        deprecation_policy=metadata.deprecation_policy.strip(),
        taxonomy_mappings=metadata.taxonomy_mappings,
        tests=metadata.tests,
        status=CoveragePackStatus.DRAFT,
    )


def approve_coverage_pack(
    pack: CoveragePack,
    *,
    reviewer_user_id: str,
    approved_at: datetime,
) -> CoveragePack:
    _require_non_empty("reviewer_user_id", reviewer_user_id)
    _require_timezone(approved_at)
    _validate_pack(pack)
    _validate_mapping_consistency(pack)
    if reviewer_user_id == pack.owner_user_id:
        raise PermissionError("coverage_pack_approval_requires_independent_reviewer")
    if not pack.default_profile.safe_by_default:
        raise ValueError("default_profile_must_be_safe")
    return replace(
        pack,
        reviewer_user_id=reviewer_user_id.strip(),
        status=CoveragePackStatus.APPROVED,
        approved_at=approved_at,
    )


def _validate_import(metadata: CoveragePackImport) -> None:
    for field_name, value in (
        ("pack_id", metadata.pack_id),
        ("name", metadata.name),
        ("version", metadata.version),
        ("owner_user_id", metadata.owner_user_id),
        ("deprecation_policy", metadata.deprecation_policy),
    ):
        _require_non_empty(field_name, value)
    if not metadata.source_references:
        raise ValueError("coverage_pack_source_references_required")
    if not metadata.supported_adapters:
        raise ValueError("coverage_pack_supported_adapters_required")
    if not metadata.profiles:
        raise ValueError("coverage_pack_profiles_required")
    if not metadata.taxonomy_mappings:
        raise ValueError("coverage_pack_mappings_required")
    if not metadata.tests:
        raise ValueError("coverage_pack_tests_required")
    _validate_profile(metadata.default_profile)
    for profile in metadata.profiles:
        _validate_profile(profile)
    if metadata.default_profile.profile_id not in {profile.profile_id for profile in metadata.profiles}:
        raise ValueError("default_profile_missing")
    for reference in metadata.source_references:
        _require_non_empty("source_reference", reference)
    for adapter in metadata.supported_adapters:
        _require_non_empty("supported_adapter", adapter)
    for mapping in metadata.taxonomy_mappings:
        _validate_mapping(mapping)
    for test in metadata.tests:
        _validate_test(test)


def _validate_pack(pack: CoveragePack) -> None:
    for field_name, value in (
        ("pack_id", pack.pack_id),
        ("name", pack.name),
        ("version", pack.version),
        ("owner_user_id", pack.owner_user_id),
        ("deprecation_policy", pack.deprecation_policy),
    ):
        _require_non_empty(field_name, value)
    if not pack.source_references:
        raise ValueError("coverage_pack_source_references_required")
    if not pack.supported_adapters:
        raise ValueError("coverage_pack_supported_adapters_required")
    if not pack.taxonomy_mappings:
        raise ValueError("coverage_pack_mappings_required")
    if not pack.tests:
        raise ValueError("coverage_pack_tests_required")
    for profile in pack.profiles:
        _validate_profile(profile)
    for mapping in pack.taxonomy_mappings:
        _validate_mapping(mapping)
    for test in pack.tests:
        _validate_test(test)


def _validate_mapping_consistency(pack: CoveragePack) -> None:
    pack_keys = {_mapping_key(mapping) for mapping in pack.taxonomy_mappings}
    test_keys = {_mapping_key(mapping) for test in pack.tests for mapping in test.taxonomy_mappings}
    if not test_keys.issubset(pack_keys):
        raise ValueError("test_mapping_not_declared_by_pack")
    if not pack_keys.issubset(test_keys):
        raise ValueError("pack_mapping_without_test")
    seen_tests: set[tuple[str, str]] = set()
    for test in pack.tests:
        key = (test.test_definition_id, test.test_definition_version)
        if key in seen_tests:
            raise ValueError("duplicate_coverage_pack_test")
        seen_tests.add(key)


def _require_approved_pack(pack: CoveragePack) -> None:
    _validate_pack(pack)
    _validate_mapping_consistency(pack)
    if pack.status is not CoveragePackStatus.APPROVED:
        raise ValueError("coverage_pack_requires_approval")
    _require_non_empty("reviewer_user_id", pack.reviewer_user_id or "")
    if pack.approved_at is None:
        raise ValueError("coverage_pack_approval_timestamp_required")
    _require_timezone(pack.approved_at)


def _profile_by_id(pack: CoveragePack, profile_id: str) -> CoveragePackProfile | None:
    for profile in pack.profiles:
        if profile.profile_id == profile_id:
            return profile
    return None


def _pack_index(packs: tuple[CoveragePack, ...], pack_id: str, version: str) -> int:
    _require_non_empty("pack_id", pack_id)
    _require_non_empty("version", version)
    for index, pack in enumerate(packs):
        if pack.pack_id == pack_id and pack.version == version:
            return index
    raise ValueError("coverage_pack_not_registered")


def _selection_denied(
    pack_id: str,
    version: str,
    adapter_id: str,
    profile_id: str,
    reason: str,
) -> CoverageSelectionDecision:
    return CoverageSelectionDecision(
        outcome=PolicyDecisionOutcome.DENY,
        reason=reason,
        pack_id=pack_id,
        version=version,
        adapter_id=adapter_id,
        profile_id=profile_id,
    )


def _count(rows: tuple[CoverageReportRow, ...], status: CoverageImplementationStatus) -> int:
    return sum(1 for row in rows if row.implementation_status is status)


def _validate_profile(profile: CoveragePackProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("profile_name", profile.name)):
        _require_non_empty(field_name, value)
    if not profile.allowed_modes:
        raise ValueError("coverage_profile_modes_required")


def _validate_test(test: CoveragePackTest) -> None:
    _require_non_empty("test_definition_id", test.test_definition_id)
    _require_non_empty("test_definition_version", test.test_definition_version)
    if not test.taxonomy_mappings:
        raise ValueError("coverage_test_mappings_required")
    for mapping in test.taxonomy_mappings:
        _validate_mapping(mapping)


def _validate_mapping(mapping: TaxonomyMapping) -> None:
    _require_non_empty("taxonomy_identifier", mapping.identifier)


def _mapping_key(mapping: TaxonomyMapping) -> tuple[str, str]:
    return (mapping.kind.value, mapping.identifier.strip().lower())


def _stable_text_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
