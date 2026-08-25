"""Reviewed test definition registry and metadata-only import contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import EvidenceKind, TargetType, TestMode, TestRiskClass
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


class TestDefinitionSource(str, Enum):
    ATOMIC = "atomic"
    NUCLEI = "nuclei"
    ZAP = "zap"
    INTERNAL = "internal"


class TaxonomyKind(str, Enum):
    MITRE_ATTACK = "mitre_attack"
    OWASP_WSTG = "owasp_wstg"
    OWASP_ASVS = "owasp_asvs"
    OWASP_API_TOP10 = "owasp_api_top10"
    CWE = "cwe"
    INTERNAL_CONTROL = "internal_control"


class CleanupBehavior(str, Enum):
    NONE = "none"
    MANUAL_REQUIRED = "manual_required"
    AUTOMATED = "automated"
    UNKNOWN = "unknown"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, kw_only=True)
class TaxonomyMapping:
    kind: TaxonomyKind
    identifier: str
    name: str | None = None


@dataclass(frozen=True, kw_only=True)
class MetadataImport:
    id: str
    name: str
    version: str
    source: TestDefinitionSource
    source_reference: str
    author: str
    target_types: tuple[TargetType, ...]
    mode: TestMode
    risk_class: TestRiskClass
    required_permissions: tuple[str, ...]
    expected_evidence: tuple[EvidenceKind, ...]
    cleanup_behavior: CleanupBehavior
    taxonomy_mappings: tuple[TaxonomyMapping, ...]
    executable_content_present: bool = False


@dataclass(frozen=True, kw_only=True)
class RegistryTestDefinition:
    id: str
    name: str
    version: str
    source: TestDefinitionSource
    source_reference: str
    author: str
    reviewer_user_id: str | None
    target_types: tuple[TargetType, ...]
    mode: TestMode
    risk_class: TestRiskClass
    required_permissions: tuple[str, ...]
    expected_evidence: tuple[EvidenceKind, ...]
    cleanup_behavior: CleanupBehavior
    taxonomy_mappings: tuple[TaxonomyMapping, ...]
    review_status: ReviewStatus
    execution_enabled: bool
    execution_block_reason: str
    metadata_only: bool = True

    @property
    def high_risk_or_destructive(self) -> bool:
        return is_high_risk_or_destructive(self.mode, self.risk_class)


@dataclass(frozen=True)
class TestDefinitionRegistry:
    definitions: tuple[RegistryTestDefinition, ...] = ()
    audit_chain: EvidenceChain = EvidenceChain()

    def register(
        self,
        definition: RegistryTestDefinition,
        *,
        event_id: str,
        actor_user_id: str,
        occurred_at: datetime,
    ) -> "TestDefinitionRegistry":
        if definition.review_status is not ReviewStatus.APPROVED or not definition.reviewer_user_id:
            raise ValueError("registry_change_requires_review")
        if any(existing.id == definition.id and existing.version == definition.version for existing in self.definitions):
            raise ValueError("test_definition_version_already_registered")
        next_chain = self.audit_chain.append_audit_event(
            event_id=event_id,
            organization_id="registry",
            actor_user_id=actor_user_id,
            action=AuditAction.TEST_DEFINITION_CHANGE,
            subject_type="test_definition",
            subject_id=f"{definition.id}:{definition.version}",
            occurred_at=occurred_at,
            details={
                "source": definition.source.value,
                "reviewer_user_id": definition.reviewer_user_id,
                "execution_enabled": definition.execution_enabled,
                "risk_class": definition.risk_class.value,
            },
        )
        return TestDefinitionRegistry(definitions=self.definitions + (definition,), audit_chain=next_chain)


_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,127}$")


def import_metadata_only(metadata: MetadataImport) -> RegistryTestDefinition:
    """Convert source metadata into a disabled, pending registry definition."""
    _validate_metadata(metadata)
    if metadata.executable_content_present:
        raise ValueError("executable_content_forbidden_in_metadata_import")
    return RegistryTestDefinition(
        id=metadata.id.strip(),
        name=metadata.name.strip(),
        version=metadata.version.strip(),
        source=metadata.source,
        source_reference=metadata.source_reference.strip(),
        author=metadata.author.strip(),
        reviewer_user_id=None,
        target_types=tuple(metadata.target_types),
        mode=metadata.mode,
        risk_class=metadata.risk_class,
        required_permissions=tuple(metadata.required_permissions),
        expected_evidence=tuple(metadata.expected_evidence),
        cleanup_behavior=metadata.cleanup_behavior,
        taxonomy_mappings=tuple(metadata.taxonomy_mappings),
        review_status=ReviewStatus.PENDING,
        execution_enabled=False,
        execution_block_reason="metadata_import_requires_review",
    )


def review_definition(
    definition: RegistryTestDefinition,
    *,
    reviewer_user_id: str,
    enable_execution: bool = False,
    allow_high_risk: bool = False,
) -> RegistryTestDefinition:
    _require_non_empty("reviewer_user_id", reviewer_user_id)
    if enable_execution and definition.high_risk_or_destructive and not allow_high_risk:
        execution_enabled = False
        block_reason = "high_risk_or_destructive_blocked_by_default"
    elif enable_execution:
        execution_enabled = True
        block_reason = "execution_review_enabled"
    else:
        execution_enabled = False
        block_reason = "execution_disabled_until_policy_gate"
    return RegistryTestDefinition(
        id=definition.id,
        name=definition.name,
        version=definition.version,
        source=definition.source,
        source_reference=definition.source_reference,
        author=definition.author,
        reviewer_user_id=reviewer_user_id,
        target_types=definition.target_types,
        mode=definition.mode,
        risk_class=definition.risk_class,
        required_permissions=definition.required_permissions,
        expected_evidence=definition.expected_evidence,
        cleanup_behavior=definition.cleanup_behavior,
        taxonomy_mappings=definition.taxonomy_mappings,
        review_status=ReviewStatus.APPROVED,
        execution_enabled=execution_enabled,
        execution_block_reason=block_reason,
        metadata_only=True,
    )


def is_high_risk_or_destructive(mode: TestMode, risk_class: TestRiskClass) -> bool:
    return risk_class in {TestRiskClass.ACTIVE_INTRUSIVE, TestRiskClass.DESTRUCTIVE} or mode in {
        TestMode.ADVERSARY_EMULATION,
        TestMode.CLOUD_TECHNIQUE,
    }


def _validate_metadata(metadata: MetadataImport) -> None:
    for field_name, value in (
        ("id", metadata.id),
        ("name", metadata.name),
        ("version", metadata.version),
        ("source_reference", metadata.source_reference),
        ("author", metadata.author),
    ):
        _require_non_empty(field_name, value)
    if not _SAFE_ID.fullmatch(metadata.id.strip()):
        raise ValueError("invalid_test_definition_id")
    if not metadata.target_types:
        raise ValueError("missing_target_types")
    if not metadata.expected_evidence:
        raise ValueError("missing_expected_evidence")
    if not metadata.taxonomy_mappings:
        raise ValueError("missing_taxonomy_mappings")
    for mapping in metadata.taxonomy_mappings:
        _require_non_empty("taxonomy_identifier", mapping.identifier)
    for permission in metadata.required_permissions:
        _require_non_empty("required_permission", permission)


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
