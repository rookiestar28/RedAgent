"""compat_100 capability projection for the compat_108 emulator and offline execution boundary."""

from redagent_platform.cloud_connectors.profiles import emulator_profiles
from redagent_platform.runner_service.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)


def build_cloud_connector_capability(
    *, artifact_receipt_id: str, source_digest: str
) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id="cloud-posture",
        revision=1,
        adapter_id="redagent-cloud-emulator-offline",
        adapter_version="1.0.0-r108.1",
        image_digest=source_digest,
        input_schema_id="cloud-certified-plan-v1",
        supported_modes=tuple(sorted(provider.value for provider in emulator_profiles())),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="cloud-r108-emulator-offline",
        network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.CLOUD_READ_ONLY,
        evidence_schema=("cloud-snapshot-v1", "cloud-check-result-v1", "cloud-cleanup-v1"),
        unsupported_features=(
            "arbitrary_command", "native_template", "plugin_loading",
            "arbitrary_endpoint", "ambient_credentials", "wildcard_permission", "mutation",
            "remediation", "credential_attack", "sensitive_value_read", "data_plane_read",
            "production_tenant", "external_scanner", "runtime_download", "module_download",
            "repository_config", "executable_policy", "host_access", "cluster_admin",
            "kubernetes_exec", "kubernetes_attach", "docker_socket", "registry_pull",
            "model_authored_transport",
        ),
        limits=ResourceLimits(
            cpu_millis=500, memory_mib=256, pids=32, timeout_seconds=60,
            evidence_bytes=64 * 1024,
        ),
        artifact_receipt_id=artifact_receipt_id,
        reviewed_by="redagent-r108-review",
        status="certified",
    )
