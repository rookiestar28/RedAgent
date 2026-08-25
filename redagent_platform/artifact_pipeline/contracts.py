"""Immutable compat_110 artifact, profile, stage, and authorization contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class ArtifactKind(str, Enum):
    REPOSITORY_SNAPSHOT = "repository_snapshot"
    PACKAGED_ARTIFACT = "packaged_artifact"
    MOBILE_STATIC = "mobile_static"


class StageKind(str, Enum):
    MANIFEST_VALIDATE = "manifest_validate"
    SBOM = "sbom"
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    CREDENTIAL_PATTERN = "credential_pattern"
    STRUCTURAL = "structural"
    CI_WORKFLOW = "ci_workflow"
    MOBILE_STATIC = "mobile_static"


@dataclass(frozen=True, kw_only=True)
class ArtifactProfile:
    profile_id: str; artifact_kind: ArtifactKind; stages: tuple[StageKind, ...]
    max_files: int; max_bytes: int; max_depth: int; max_expansion_ratio: int; timeout_seconds: int
    network_allowed: bool = False; subprocess_allowed: bool = False
    package_lifecycle_allowed: bool = False; project_config_allowed: bool = False
    mobile_dynamic_allowed: bool = False; emulator_only: bool = True

    def __post_init__(self) -> None:
        _identifier(self.profile_id)
        if not self.stages or len(set(self.stages)) != len(self.stages): raise ValueError("artifact_profile_stages_invalid")
        if any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in (self.max_files, self.max_bytes, self.max_depth, self.max_expansion_ratio, self.timeout_seconds)): raise ValueError("artifact_profile_budget_invalid")
        if self.network_allowed or self.subprocess_allowed or self.package_lifecycle_allowed or self.project_config_allowed or self.mobile_dynamic_allowed or not self.emulator_only: raise ValueError("artifact_execution_boundary_invalid")


@dataclass(frozen=True, kw_only=True)
class ArtifactAuthorization:
    authorization_id: str; policy_decision_id: str; policy_revision: str; reservation_id: str
    artifact_lease_id: str; artifact_binding_id: str; artifact_sha256: str; artifact_kind: ArtifactKind
    manifest_sha256: str; profile_id: str; stage_ids: tuple[str, ...]; approved_at: datetime; expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.authorization_id, self.policy_decision_id, self.policy_revision, self.reservation_id, self.artifact_lease_id, self.artifact_binding_id, self.profile_id): _identifier(value)
        for value in (self.artifact_sha256, self.manifest_sha256):
            if not _SHA.fullmatch(value): raise ValueError("artifact_sha256_invalid")
        _aware(self.approved_at); _aware(self.expires_at)
        if not self.approved_at < self.expires_at: raise ValueError("artifact_authorization_invalid")


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value): raise ValueError("artifact_identifier_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError("artifact_time_invalid")
