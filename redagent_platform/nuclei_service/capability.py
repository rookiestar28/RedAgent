"""compat_100 capability projection for the certified compat_105 Nuclei adapter."""

from __future__ import annotations

from redagent_platform.nuclei_service.contracts import (
    CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    certified_profiles,
)
from redagent_platform.runner_service.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)


def build_nuclei_capability_manifest(*, platform: str, artifact_receipt_id: str) -> ExecutionCapabilityManifest:
    digest = CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM.get(platform)
    if digest is None:
        raise ValueError("nuclei_platform_unsupported")
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id="nuclei-trusted-runtime", revision=2,
        adapter_id="nuclei-service", adapter_version="3.11.1-r105.2",
        image_digest=digest, input_schema_id="nuclei-certified-profile-v1",
        supported_modes=tuple(profile.value for profile in certified_profiles()),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="nuclei-r105-isolated", network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.NONE,
        evidence_schema=("nuclei-result-v1", "nuclei-gateway-v1", "nuclei-cleanup-v1"),
        unsupported_features=(
            "arbitrary_command", "native_template", "plugin_loading", "arbitrary_template",
            "community_templates", "workflow",
            "code", "javascript", "headless", "file", "network", "dns", "ssl",
            "websocket", "whois", "fuzz", "dast", "oast", "payloads",
            "local_file_access", "runtime_update", "cloud_upload", "external_origin",
        ),
        limits=ResourceLimits(
            cpu_millis=1_000, memory_mib=512, pids=64,
            timeout_seconds=60, evidence_bytes=2 * 1024 * 1024,
        ),
        artifact_receipt_id=artifact_receipt_id,
        reviewed_by="redagent-r105-review", status="certified",
    )
