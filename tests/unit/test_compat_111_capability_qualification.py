from datetime import datetime, timezone
from pathlib import Path

from redagent_platform.purple_runtime.capability import build_purple_capability
from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from scripts.compat_111_purple_lab import qualify


NOW = datetime(2026, 7, 11, 16, 30, tzinfo=timezone.utc)


def test_capability_is_single_ability_no_network_no_credentials():
    capability = build_purple_capability(artifact_receipt_id="receipt-r111", source_digest="sha256:" + "a" * 64)
    assert capability.supported_modes == ("r111-file-stage-marker-v1",)
    assert capability.network_mode is NetworkMode.NONE and capability.credential_class is CredentialClass.NONE
    assert {"external_content", "production_target", "model_authored_ability"} <= set(capability.unsupported_features)


def test_owned_qualification_proves_telemetry_cleanup_and_zero_external_contact(tmp_path: Path):
    receipt = qualify(workspace=tmp_path, now=NOW)
    assert receipt["status"] == "passed" and receipt["detection"]["observed"] is True
    assert receipt["lifecycle"]["final_state"] == "succeeded" and receipt["lifecycle"]["residual_resource_count"] == 0
    assert not any(receipt["safety"].values())
    assert not (tmp_path / ".local/r111-labs/lab-r111/r111-file-stage-marker-v1.marker").exists()
