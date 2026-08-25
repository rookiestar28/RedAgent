"""compat_100 capability projection for the certified compat_106 API differential adapter."""

from __future__ import annotations

from redagent_platform.api_differential_service.artifact import EXPECTED_WHEEL_SHA256
from redagent_platform.api_differential_service.contracts import certified_profiles
from redagent_platform.runner_service.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)


def build_api_differential_capability_manifest(*, artifact_receipt_id: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id="api-authorization-differential", revision=1,
        adapter_id="schemathesis", adapter_version="4.22.4-r106.1",
        image_digest=f"sha256:{EXPECTED_WHEEL_SHA256}",
        input_schema_id="api-differential-certified-profile-v1",
        supported_modes=tuple(profile.value for profile in certified_profiles()),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="api-r106-isolated", network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.HTTP_HEADER,
        evidence_schema=("api-differential-v1", "api-gateway-v1", "api-replay-v1", "api-cleanup-v1"),
        unsupported_features=(
            "arbitrary_command", "native_template", "plugin_loading", "arbitrary_target",
            "arbitrary_spec", "arbitrary_request", "arbitrary_header", "arbitrary_credential",
            "external_reference", "callback", "webhook", "redirect", "unexpected_method",
            "file_upload", "download", "streaming", "websocket", "graphql", "grpc",
            "xml", "binary_body", "restler", "aggressive_fuzz", "model_authored_request",
            "shared_identity", "production_target", "public_demo",
        ),
        limits=ResourceLimits(
            cpu_millis=1_000, memory_mib=1_024, pids=64,
            timeout_seconds=60, evidence_bytes=2 * 1024 * 1024,
        ),
        artifact_receipt_id=artifact_receipt_id,
        reviewed_by="redagent-r106-review", status="certified",
    )
