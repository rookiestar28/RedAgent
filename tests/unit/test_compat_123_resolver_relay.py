from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from redagent_platform.campaign_service.relay import (
    OutboxDeliveryState,
    RelayFailure,
    apply_relay_failure,
)
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
    ResolutionRequest,
)


NOW = datetime(2026, 8, 24, 0, 30, tzinfo=timezone.utc)


class ReadOnlyAuthorityProvider:
    def __init__(self, snapshot: CanonicalAuthoritySnapshot | None) -> None:
        self.snapshot = snapshot
        self.calls: list[ResolutionRequest] = []

    async def read_current_authority(
        self, request: ResolutionRequest
    ) -> CanonicalAuthoritySnapshot | None:
        self.calls.append(request)
        return self.snapshot


def _snapshot() -> CanonicalAuthoritySnapshot:
    target_value = "http://127.0.0.1:41731"
    target_sha256 = _target_digest(target_value)
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="eng-r123",
        engagement_version=7,
        roe_version_id="roe-r123-v3",
        roe_revision=3,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=4,
        policy_decision_id="policy-decision-r123",
        policy_revision="policy-r123-v8",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=5,
        target_id="target-r123",
        target_revision=9,
        target_sha256=target_sha256,
        target_value=target_value,
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-r123",
        quota_available=True,
        runner_id="runner-r123",
        runner_workload_identity="spiffe://redagent.test/runner/compat_123",
        runner_ready=True,
        reservation_id="reservation-r123",
        lease_id="lease-r123",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )


def _request() -> ResolutionRequest:
    return ResolutionRequest(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="eng-r123",
        target_id="target-r123",
    )


def _target_digest(target_value: str) -> str:
    document = {
        "target_id": "target-r123",
        "revision": 9,
        "target_type": "url",
        "normalized_value": target_value,
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _target_snapshot(target_value: str) -> CanonicalAuthoritySnapshot:
    return replace(
        _snapshot(),
        target_value=target_value,
        target_sha256=_target_digest(target_value),
    )


def test_resolver_returns_exact_current_canonical_bindings_without_minting() -> None:
    provider = ReadOnlyAuthorityProvider(_snapshot())

    result = asyncio.run(CampaignContextResolver(provider).resolve(_request(), now=NOW))

    assert result.allowed is True
    assert result.reason == "resolved"
    assert result.bindings == _snapshot()
    assert provider.calls == [_request()]


@pytest.mark.parametrize(
    ("snapshot", "reason"),
    [
        (None, "canonical_authority_not_found"),
        (replace(_snapshot(), tenant_id="other"), "tenant_binding_mismatch"),
        (replace(_snapshot(), principal_id="other"), "principal_binding_mismatch"),
        (replace(_snapshot(), engagement_id="other"), "engagement_binding_mismatch"),
        (replace(_snapshot(), target_id="other"), "target_binding_mismatch"),
        (replace(_snapshot(), roe_status="draft"), "roe_not_approved"),
        (replace(_snapshot(), policy_status="denied"), "policy_not_allowed"),
        (replace(_snapshot(), quota_available=False), "quota_unavailable"),
        (replace(_snapshot(), runner_ready=False), "runner_not_ready"),
        (replace(_snapshot(), stop_requested=True), "stop_requested"),
        (replace(_snapshot(), observed_at=NOW - timedelta(minutes=6)), "authority_observation_stale"),
        (replace(_snapshot(), expires_at=NOW), "authority_expired"),
        (replace(_snapshot(), lease_expires_at=NOW), "authority_lease_expired"),
        (replace(_snapshot(), target_resolution_mode="public-dns"), "target_resolution_mode_denied"),
        (replace(_snapshot(), target_sha256="3" * 64), "target_digest_mismatch"),
        (_target_snapshot("https://example.com"), "owned_loopback_target_denied"),
        (_target_snapshot("http://localhost:41731"), "owned_loopback_target_denied"),
        (_target_snapshot("http://127.0.0.1:41731/redirect"), "owned_loopback_target_denied"),
        (_target_snapshot("http://127.0.0.1:41731?next=public"), "owned_loopback_target_denied"),
        (replace(_snapshot(), credential_class="password"), "credential_class_denied"),
    ],
)
def test_resolver_denies_every_missing_stale_or_drifted_binding(
    snapshot: CanonicalAuthoritySnapshot | None, reason: str
) -> None:
    provider = ReadOnlyAuthorityProvider(snapshot)

    result = asyncio.run(CampaignContextResolver(provider).resolve(_request(), now=NOW))

    assert result.allowed is False
    assert result.reason == reason
    assert result.bindings is None
    assert provider.calls == [_request()]


def test_relay_failure_applies_bounded_backoff_without_losing_claim_history() -> None:
    first = apply_relay_failure(
        attempt_count=1,
        failure=RelayFailure.TRANSIENT,
        now=NOW,
        max_attempts=5,
    )
    second = apply_relay_failure(
        attempt_count=2,
        failure=RelayFailure.TRANSIENT,
        now=NOW,
        max_attempts=5,
    )

    assert first.delivery_state is OutboxDeliveryState.PENDING
    assert first.reconciliation_state == "none"
    assert first.available_at == NOW + timedelta(seconds=2)
    assert second.available_at == NOW + timedelta(seconds=4)
    assert first.attempt_count == 1
    assert second.attempt_count == 2


def test_relay_ambiguity_and_exhaustion_never_auto_redeliver() -> None:
    ambiguous = apply_relay_failure(
        attempt_count=1,
        failure=RelayFailure.AMBIGUOUS_START,
        now=NOW,
        max_attempts=5,
    )
    exhausted = apply_relay_failure(
        attempt_count=5,
        failure=RelayFailure.TRANSIENT,
        now=NOW,
        max_attempts=5,
    )

    assert ambiguous.delivery_state is OutboxDeliveryState.RECONCILIATION_REQUIRED
    assert ambiguous.reconciliation_state == "manual_review_required"
    assert ambiguous.available_at is None
    assert exhausted.delivery_state is OutboxDeliveryState.DEAD_LETTER
    assert exhausted.reconciliation_state == "manual_review_required"
    assert exhausted.dead_lettered_at == NOW


def test_relay_failure_rejects_unbounded_or_invalid_attempt_state() -> None:
    with pytest.raises(ValueError, match="relay_attempt_count_invalid"):
        apply_relay_failure(
            attempt_count=0,
            failure=RelayFailure.TRANSIENT,
            now=NOW,
            max_attempts=5,
        )
    with pytest.raises(ValueError, match="relay_max_attempts_invalid"):
        apply_relay_failure(
            attempt_count=1,
            failure=RelayFailure.TRANSIENT,
            now=NOW,
            max_attempts=11,
        )
