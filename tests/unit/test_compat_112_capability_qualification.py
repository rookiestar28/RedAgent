from datetime import datetime, timezone
import json

from redagent_platform.human_simulation.capability import build_human_simulation_capability
from redagent_platform.runner_service.contracts import CredentialClass, NetworkMode
from scripts.compat_112_human_sink import SYNTHETIC_SENTINEL, qualify


NOW = datetime(2026, 7, 11, 17, 30, tzinfo=timezone.utc)


def test_capability_has_no_network_credentials_or_real_delivery_features():
    capability = build_human_simulation_capability(artifact_receipt_id="receipt-r112", source_digest="sha256:" + "a" * 64)
    assert capability.network_mode is NetworkMode.NONE and capability.credential_class is CredentialClass.NONE
    assert capability.supported_modes == ("r112-sink-email-canary-v1",)
    assert {"real_recipient", "human_delivery", "external_delivery", "raw_submission", "provider_credential"} <= set(capability.unsupported_features)


def test_qualification_proves_minimized_event_canary_and_deletion_without_raw_value():
    receipt = qualify(now=NOW); encoded = json.dumps(receipt, sort_keys=True)
    assert receipt["status"] == "passed" and receipt["delivery"]["captured"] is True
    assert receipt["event"]["raw_value_retained"] is False and receipt["canary"]["triggered_in_owned_sink"] is True
    assert receipt["deletion"]["final_state"] == "deleted" and receipt["deletion"]["zero_residual"] is True
    assert not any(receipt["safety"].values()) and SYNTHETIC_SENTINEL not in encoded
