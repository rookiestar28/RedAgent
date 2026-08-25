"""compat_100 capability projection for the certified compat_107 connector worker."""

from redagent_platform.network_service.contracts import certified_profiles
from redagent_platform.runner_service.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)


WORKER_IMAGE_DIGEST = "sha256:bae98a1c31a0c550038eb617f34f8445e06415e9c120b42665aed46365fadd0d"


def build_network_capability_manifest(*, artifact_receipt_id: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id="network-assessment",
        revision=1,
        adapter_id="redagent-tcp-connect",
        adapter_version="1.0.0-r107.1",
        image_digest=WORKER_IMAGE_DIGEST,
        input_schema_id="network-certified-plan-v1",
        supported_modes=tuple(profile.value for profile in certified_profiles()),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="network-r107-isolated",
        network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.NONE,
        evidence_schema=("network-observation-v1", "network-gateway-v1", "network-cleanup-v1"),
        unsupported_features=(
            "arbitrary_command", "native_template", "plugin_loading", "arbitrary_target",
            "hostname", "dns", "cidr_execution", "port_range", "udp", "raw_socket",
            "syn_scan", "icmp", "os_detection", "script", "nse", "active_probe",
            "credential_attack", "exploit", "evasion", "spoofing", "proxy",
            "custom_resolver", "cloud_upload", "runtime_update", "external_scanner",
            "production_target", "public_target", "model_authored_transport",
        ),
        limits=ResourceLimits(
            cpu_millis=500, memory_mib=128, pids=64,
            timeout_seconds=30, evidence_bytes=64 * 1024,
        ),
        artifact_receipt_id=artifact_receipt_id,
        reviewed_by="redagent-r107-review",
        status="certified",
    )
