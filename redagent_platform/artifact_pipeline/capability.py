"""compat_100 capability projection for the compat_110 zero-execution artifact pipeline."""

from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.runner_service.contracts import CONTRACT_SCHEMA_VERSION, CredentialClass, ExecutionCapabilityManifest, NetworkMode, ResourceLimits


def build_artifact_capability(*, artifact_receipt_id: str, source_digest: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(schema_version=CONTRACT_SCHEMA_VERSION, capability_id="artifact-posture", revision=1,
        adapter_id="redagent-canonical-artifact", adapter_version="1.0.0-r110.1", image_digest=source_digest,
        input_schema_id="artifact-certified-plan-v1", supported_modes=tuple(sorted(certified_profiles())),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="artifact-r110-data-only", network_mode=NetworkMode.NONE, credential_class=CredentialClass.NONE,
        evidence_schema=("artifact-manifest-v1", "artifact-component-v1", "artifact-static-result-v1", "artifact-cleanup-v1"),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading", "repository_url", "forge_token", "package_install",
            "build", "test_execution", "lifecycle_hook", "workflow_execution", "container_execution", "native_parser", "archive_extraction",
            "project_config", "external_rule", "external_database", "mobile_install", "mobile_dynamic", "device_access", "emulator_access",
            "raw_match_persistence", "model_authored_rule"), limits=ResourceLimits(cpu_millis=500, memory_mib=256, pids=16, timeout_seconds=60, evidence_bytes=64 * 1024),
        artifact_receipt_id=artifact_receipt_id, reviewed_by="redagent-r110-review", status="certified")
