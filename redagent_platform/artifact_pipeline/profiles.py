"""First compat_110 certified canonical-data-only profiles."""

from types import MappingProxyType
from typing import Mapping

from redagent_platform.artifact_pipeline.contracts import ArtifactKind, ArtifactProfile, StageKind


def certified_profiles() -> Mapping[str, ArtifactProfile]:
    profiles = (
        ArtifactProfile(profile_id="r110-repository-snapshot-v1", artifact_kind=ArtifactKind.REPOSITORY_SNAPSHOT,
            stages=(StageKind.MANIFEST_VALIDATE, StageKind.SBOM, StageKind.LICENSE, StageKind.CREDENTIAL_PATTERN, StageKind.STRUCTURAL, StageKind.CI_WORKFLOW),
            max_files=64, max_bytes=262_144, max_depth=8, max_expansion_ratio=20, timeout_seconds=30),
        ArtifactProfile(profile_id="r110-packaged-artifact-v1", artifact_kind=ArtifactKind.PACKAGED_ARTIFACT,
            stages=(StageKind.MANIFEST_VALIDATE, StageKind.SBOM, StageKind.VULNERABILITY, StageKind.LICENSE),
            max_files=64, max_bytes=262_144, max_depth=4, max_expansion_ratio=20, timeout_seconds=30),
        ArtifactProfile(profile_id="r110-mobile-static-v1", artifact_kind=ArtifactKind.MOBILE_STATIC,
            stages=(StageKind.MANIFEST_VALIDATE, StageKind.MOBILE_STATIC), max_files=16, max_bytes=65_536,
            max_depth=4, max_expansion_ratio=10, timeout_seconds=20),
    )
    return MappingProxyType({item.profile_id: item for item in profiles})
