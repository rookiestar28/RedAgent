"""compat_100 capability projection for the certified compat_104 ZAP adapter."""

from __future__ import annotations

from redagent_platform.runner_service.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)
from redagent_platform.zap_service.contracts import (
    CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM,
    certified_profiles,
)


def build_zap_capability_manifest(*, platform: str, artifact_receipt_id: str) -> ExecutionCapabilityManifest:
    digest = CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM.get(platform)
    if digest is None:
        raise ValueError("zap_platform_unsupported")
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id="zap-controlled-runtime", revision=3,
        adapter_id="zap-service", adapter_version="2.17.0-r104.3",
        image_digest=digest, input_schema_id="zap-certified-profile-v1",
        supported_modes=tuple(profile.value for profile in certified_profiles()),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="zap-r104-isolated", network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.HTTP_HEADER,
        evidence_schema=("zap-alert-v1", "zap-progress-v1", "zap-cleanup-v1"),
        unsupported_features=(
            "arbitrary_command", "native_template", "plugin_loading", "arbitrary_url",
            "native_api", "script_loading", "file_transfer", "oast", "external_origin",
        ),
        limits=ResourceLimits(
            cpu_millis=2_000, memory_mib=2_048, pids=128,
            timeout_seconds=60, evidence_bytes=10 * 1024 * 1024,
        ),
        artifact_receipt_id=artifact_receipt_id,
        reviewed_by="redagent-r104-review", status="certified",
    )
