"""compat_100 capability projection for the compat_111 lab-only owned ability runtime."""

from redagent_platform.purple_runtime.catalog import certified_abilities
from redagent_platform.runner_service.contracts import CONTRACT_SCHEMA_VERSION, CredentialClass, ExecutionCapabilityManifest, NetworkMode, ResourceLimits


def build_purple_capability(*, artifact_receipt_id: str, source_digest: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version=CONTRACT_SCHEMA_VERSION, capability_id="purple-lab", revision=1,
        adapter_id="redagent-owned-marker-adapter", adapter_version="1.0.0-r111.1", image_digest=source_digest,
        input_schema_id="purple-certified-ability-plan-v1", supported_modes=tuple(sorted(certified_abilities())),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="purple-r111-disposable-filesystem-lab", network_mode=NetworkMode.NONE,
        credential_class=CredentialClass.NONE,
        evidence_schema=("purple-before-snapshot-v1", "purple-action-receipt-v1", "purple-detection-event-v1",
                         "purple-cleanup-v1", "purple-teardown-v1"),
        unsupported_features=("arbitrary_command", "native_template", "native_ability", "plugin_loading", "payload", "agent", "c2",
            "prerequisite_download", "external_adapter", "external_content", "network", "credential", "privilege",
            "persistence", "evasion", "lateral_movement", "exfiltration", "cloud_detonation", "production_target",
            "third_party_target", "model_authored_ability"),
        limits=ResourceLimits(cpu_millis=250, memory_mib=128, pids=4, timeout_seconds=10, evidence_bytes=16 * 1024),
        artifact_receipt_id=artifact_receipt_id, reviewed_by="redagent-r111-review", status="certified",
    )
