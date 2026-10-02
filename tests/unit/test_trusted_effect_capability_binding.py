from dataclasses import asdict

import pytest

from redagent_platform.campaign_service.repository import CampaignRecordConflict, _trusted_effect_closed_binding
from tests.integration.test_compat_123_campaign_repository import _activity_binding


@pytest.mark.parametrize("capability_id", ["zap-controlled-runtime", "nuclei-trusted-runtime"])
def test_trusted_result_accepts_explicit_current_dag_binding_and_legacy_key(capability_id):
    binding = _activity_binding(capability_id)
    payload = {"schema_version": "redagent.campaign-dag-effect-intent/v1",
               "capability_id": capability_id, "binding": asdict(binding)}
    assert _trusted_effect_closed_binding(payload).capability_key == f"{capability_id}@3"
    assert _trusted_effect_closed_binding({"capability_id": f"{capability_id}@3"}).capability_key == f"{capability_id}@3"


@pytest.mark.parametrize("field,value", [
    ("capability_id", "nuclei-trusted-runtime"), ("capability_revision", 2),
    ("adapter_version", "2.17.0-r104.2"), ("profile_sha256", "0" * 64),
    ("bundle_id", "unexpected"), ("schema_version", "unknown"),
])
def test_trusted_result_rejects_drifted_dag_binding(field, value):
    binding = asdict(_activity_binding("zap-controlled-runtime"))
    binding[field] = value
    with pytest.raises(CampaignRecordConflict, match="effect_trusted_capability_invalid"):
        _trusted_effect_closed_binding({"schema_version": "redagent.campaign-dag-effect-intent/v1",
            "capability_id": "zap-controlled-runtime", "binding": binding})


@pytest.mark.parametrize("payload", [
    {"capability_id": "zap-controlled-runtime"},
    {"schema_version": "unknown", "capability_id": "zap-controlled-runtime"},
    {"schema_version": "redagent.campaign-dag-effect-intent/v1", "capability_id": "zap-controlled-runtime"},
    {"schema_version": "redagent.campaign-dag-effect-intent/v1", "capability_id": "nuclei-trusted-runtime",
     "binding": asdict(_activity_binding("zap-controlled-runtime"))},
])
def test_trusted_result_rejects_missing_or_mixed_capability_identity(payload):
    with pytest.raises(CampaignRecordConflict, match="effect_trusted_capability_invalid"):
        _trusted_effect_closed_binding(payload)
