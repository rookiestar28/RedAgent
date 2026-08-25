"""Closed compat_110 compiler binding exact artifact, manifest, stages, and zero-execution limits."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization, ArtifactKind, ArtifactProfile


@dataclass(frozen=True, kw_only=True)
class CompiledArtifactPlan:
    profile_id: str; artifact_binding_id: str; artifact_sha256: str; artifact_kind: ArtifactKind
    manifest_sha256: str; stage_ids: tuple[str, ...]; max_files: int; max_bytes: int; max_depth: int
    max_expansion_ratio: int; timeout_seconds: int; network_allowed: bool; subprocess_allowed: bool
    package_lifecycle_allowed: bool; project_config_allowed: bool; mobile_dynamic_allowed: bool; plan_sha256: str


def compile_artifact_plan(*, profile: ArtifactProfile, authorization: ArtifactAuthorization, now: datetime) -> CompiledArtifactPlan:
    if now.tzinfo is None or now.utcoffset() is None: raise ValueError("artifact_time_invalid")
    if now < authorization.approved_at or now >= authorization.expires_at: raise ValueError("artifact_authorization_inactive")
    if authorization.profile_id != profile.profile_id: raise ValueError("artifact_profile_mismatch")
    if authorization.artifact_kind is not profile.artifact_kind: raise ValueError("artifact_kind_mismatch")
    required = tuple(item.value for item in profile.stages)
    if not set(required) <= set(authorization.stage_ids): raise ValueError("artifact_stage_undergrant")
    if tuple(authorization.stage_ids) != required: raise ValueError("artifact_stage_overgrant")
    material = {"schema": "redagent.r110-artifact-plan/v1", "profile": profile.profile_id, "binding": authorization.artifact_binding_id,
        "artifact": [authorization.artifact_kind.value, authorization.artifact_sha256, authorization.manifest_sha256], "stages": list(required),
        "limits": [profile.max_files, profile.max_bytes, profile.max_depth, profile.max_expansion_ratio, profile.timeout_seconds],
        "execution": [False, False, False, False, False]}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledArtifactPlan(profile_id=profile.profile_id, artifact_binding_id=authorization.artifact_binding_id,
        artifact_sha256=authorization.artifact_sha256, artifact_kind=profile.artifact_kind, manifest_sha256=authorization.manifest_sha256,
        stage_ids=required, max_files=profile.max_files, max_bytes=profile.max_bytes, max_depth=profile.max_depth,
        max_expansion_ratio=profile.max_expansion_ratio, timeout_seconds=profile.timeout_seconds, network_allowed=False,
        subprocess_allowed=False, package_lifecycle_allowed=False, project_config_allowed=False, mobile_dynamic_allowed=False, plan_sha256=digest)
