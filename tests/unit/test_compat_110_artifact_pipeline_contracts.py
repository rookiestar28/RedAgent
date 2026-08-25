from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.artifact_pipeline.contracts import ArtifactAuthorization, ArtifactKind, ArtifactProfile, StageKind
from redagent_platform.artifact_pipeline.compiler import compile_artifact_plan
from redagent_platform.artifact_pipeline.profiles import certified_profiles


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def _authorization(profile: ArtifactProfile, **overrides):
    values = dict(authorization_id="auth-r110", policy_decision_id="policy-r110", policy_revision="r110-v1",
        reservation_id="reservation-r110", artifact_lease_id="lease-r110", artifact_binding_id="binding-r110",
        artifact_sha256="a" * 64, artifact_kind=profile.artifact_kind, manifest_sha256="b" * 64,
        profile_id=profile.profile_id, stage_ids=tuple(item.value for item in profile.stages),
        approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10))
    values.update(overrides); return ArtifactAuthorization(**values)


@pytest.mark.parametrize("profile", certified_profiles().values(), ids=lambda item: item.profile_id)
def test_profiles_compile_to_deterministic_zero_execution_plans(profile):
    first = compile_artifact_plan(profile=profile, authorization=_authorization(profile), now=NOW)
    second = compile_artifact_plan(profile=profile, authorization=_authorization(profile), now=NOW)
    assert first == second
    assert first.network_allowed is False and first.subprocess_allowed is False
    assert first.package_lifecycle_allowed is False and first.mobile_dynamic_allowed is False
    assert first.stage_ids == tuple(item.value for item in profile.stages)


def test_compiler_rejects_kind_digest_stage_overgrant_and_inactive_authorization():
    profile = certified_profiles()["r110-repository-snapshot-v1"]
    with pytest.raises(ValueError, match="artifact_kind_mismatch"):
        compile_artifact_plan(profile=profile, authorization=_authorization(profile, artifact_kind=ArtifactKind.MOBILE_STATIC), now=NOW)
    with pytest.raises(ValueError, match="artifact_stage_overgrant"):
        compile_artifact_plan(profile=profile, authorization=_authorization(profile, stage_ids=tuple(item.value for item in profile.stages) + (StageKind.MOBILE_STATIC.value,)), now=NOW)
    with pytest.raises(ValueError, match="artifact_authorization_inactive"):
        compile_artifact_plan(profile=profile, authorization=_authorization(profile, expires_at=NOW), now=NOW)
    with pytest.raises(ValueError, match="artifact_sha256_invalid"):
        compile_artifact_plan(profile=profile, authorization=_authorization(profile, artifact_sha256="not-a-digest"), now=NOW)
