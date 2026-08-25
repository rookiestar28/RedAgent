"""compat_100 capability projection for the compat_112 sink-only simulation runtime."""

from redagent_platform.runner_service.contracts import CONTRACT_SCHEMA_VERSION, CredentialClass, ExecutionCapabilityManifest, NetworkMode, ResourceLimits


def build_human_simulation_capability(*, artifact_receipt_id: str, source_digest: str) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(schema_version=CONTRACT_SCHEMA_VERSION, capability_id="human-simulation-sink", revision=1,
        adapter_id="redagent-owned-message-sink", adapter_version="1.0.0-r112.1", image_digest=source_digest,
        input_schema_id="human-simulation-certified-plan-v1", supported_modes=("r112-sink-email-canary-v1",),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="human-r112-in-process-sink", network_mode=NetworkMode.NONE, credential_class=CredentialClass.NONE,
        evidence_schema=("human-render-receipt-v1", "human-sink-delivery-v1", "human-minimized-event-v1",
                         "human-canary-correlation-v1", "human-stop-v1", "human-deletion-v1"),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading", "real_recipient", "human_delivery",
            "external_delivery", "smtp", "provider_api", "provider_credential", "relay", "forward", "release",
            "tracking_pixel", "external_link", "attachment", "raw_submission", "credential_capture", "ip_collection",
            "user_agent_collection", "dns_callback", "http_callback", "third_party_brand", "stealth", "model_authored_template"),
        limits=ResourceLimits(cpu_millis=250, memory_mib=128, pids=4, timeout_seconds=10, evidence_bytes=16 * 1024),
        artifact_receipt_id=artifact_receipt_id, reviewed_by="redagent-r112-review", status="certified")
