"""Client material cannot widen the server-selected owned execution boundary."""

import pytest
from fastapi.testclient import TestClient

from tests.unit.test_autonomous_campaign_admission_start_api import ADMIT_AUTH, _configured_app


@pytest.mark.parametrize("injected", (
    {"execution_mode": "owned_loopback_auto"},
    {"mode": "owned_loopback_auto"},
    {"target_url": "https://external.example.invalid/"},
    {"capability_bindings": [{"capability_id": "zap-active-xss-lab-v1"}]},
    {"arguments": ["arbitrary-command"]},
))
def test_admission_api_rejects_client_execution_expansion_before_any_owner_call(monkeypatch, injected):
    app, bundle, captured = _configured_app(monkeypatch)
    response = TestClient(app).post(
        "/api/v1/autonomous-campaigns/campaign-a/admission-start",
        headers={
            **ADMIT_AUTH,
            "If-Match": f'"r173-{bundle.application.aggregate_revision}-{bundle.approval_receipt.receipt_sha256}"',
        },
        json={
            "approval_receipt_id": bundle.approval_receipt.receipt_id,
            "approval_receipt_sha256": bundle.approval_receipt.receipt_sha256,
            **injected,
        },
    )
    assert response.status_code == 422
    assert captured == []
