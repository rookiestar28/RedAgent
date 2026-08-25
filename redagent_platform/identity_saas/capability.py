"""compat_100 capability projection for the compat_109 contained identity runtime."""

from redagent_platform.identity_saas.profiles import emulator_profiles
from redagent_platform.runner_service.contracts import CONTRACT_SCHEMA_VERSION, CredentialClass, ExecutionCapabilityManifest, NetworkMode, ResourceLimits


def build_identity_capability(*, artifact_receipt_id: str, source_digest: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(schema_version=CONTRACT_SCHEMA_VERSION, capability_id="identity-posture", revision=1,
        adapter_id="redagent-identity-emulator", adapter_version="1.0.0-r109.1", image_digest=source_digest,
        input_schema_id="identity-certified-plan-v1", supported_modes=tuple(sorted(item.value for item in emulator_profiles())),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="identity-r109-loopback", network_mode=NetworkMode.TARGET_ALLOWLIST,
        credential_class=CredentialClass.CLOUD_READ_ONLY,
        evidence_schema=("identity-protected-snapshot-v1", "identity-baseline-result-v1", "identity-cleanup-v1"),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading", "arbitrary_endpoint", "credential_material", "ambient_credentials", "wildcard_permission", "overgrant",
            "write", "remediation", "authentication_test", "password_spraying", "mfa_trigger", "user_content", "cross_tenant",
            "graph_export", "model_graph_access", "external_adapter", "runtime_download", "model_authored_query"),
        limits=ResourceLimits(cpu_millis=500, memory_mib=256, pids=32, timeout_seconds=60, evidence_bytes=64 * 1024),
        artifact_receipt_id=artifact_receipt_id, reviewed_by="redagent-r109-review", status="certified")
