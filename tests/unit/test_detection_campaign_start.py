from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from redagent_platform.campaign_service.context import (
    build_decision_context_snapshot,
    build_first_slice_target_mapping,
)
from redagent_platform.campaign_service.contracts import (
    CollectionState,
    Confidence,
    DetectionSeverity,
    TelemetrySource,
    TypedReferenceV1,
)
from redagent_platform.campaign_service.detection_feedback import (
    DetectionAdaptationRequestV1,
    ingest_detection_observation,
    load_detection_coverage_matrix,
    promote_detection_observation_by_human,
)
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.campaign_service.service import (
    CampaignPlanningFacts,
    CampaignStartService,
    DeterministicCampaignStartPlanner,
)
from tests.unit.test_compat_121_autonomous_strategy import NOW, empty_snapshot
from tests.unit.test_compat_123_campaign_start_service import (
    AuthorizationOwner,
    AuthorityProvider,
    Identities,
    Store,
    _request,
    _snapshot,
    _target_digest,
)


ROOT = Path(__file__).resolve().parents[2]


def _adaptation() -> DetectionAdaptationRequestV1:
    return DetectionAdaptationRequestV1(
        schema_version="redagent.detection-adaptation-request/v1",
        correlation_key="campaign-start:zap",
        attack_technique_id="T1595.002",
        max_age_seconds=300,
        coverage_matrix=load_detection_coverage_matrix(
            ROOT / "config" / "detection-coverage-matrix.json"
        ),
    )


class DetectionFactsOwner:
    def __init__(self, *, with_signal: bool) -> None:
        self._with_signal = with_signal

    async def read(self, request, authority, *, now):
        del request, now
        snapshot, r119_authority, projections = empty_snapshot()
        r119_authority = replace(
            r119_authority,
            target=replace(r119_authority.target, sha256=authority.target_sha256),
        )
        if not self._with_signal:
            return CampaignPlanningFacts(
                snapshot,
                r119_authority,
                projections,
                _adaptation(),
            )
        observed = ingest_detection_observation(
            observation_id="campaign-start-detection",
            tenant_id=r119_authority.tenant_id,
            engagement_id=r119_authority.engagement_id,
            correlation_key="campaign-start:zap",
            capability_id="zap-controlled-runtime",
            source=TelemetrySource.SIEM,
            source_system="owned-purple-fixture",
            attack_technique_id="T1595.002",
            attack_version="18.0",
            confidence=Confidence.MEDIUM,
            severity=DetectionSeverity.MEDIUM,
            evidence_ref=TypedReferenceV1(
                kind="evidence", reference_id="campaign-start-alert", sha256="c" * 64
            ),
            observed_at=NOW - timedelta(seconds=30),
            ingested_at=NOW - timedelta(seconds=20),
            expires_at=NOW + timedelta(minutes=5),
        )
        confirmed = promote_detection_observation_by_human(
            observation=observed,
            review_ref=TypedReferenceV1(
                kind="human-review", reference_id="campaign-start-review", sha256="d" * 64
            ),
            reviewed_at=NOW - timedelta(seconds=10),
        )
        detection_snapshot = build_decision_context_snapshot(
            semantics=snapshot.semantics,
            target_mapping=build_first_slice_target_mapping(snapshot.semantics),
            authority=r119_authority,
            collection_state=CollectionState.COMPLETE,
            current_observations=(),
            current_evidence_facts=(),
            current_finding_facts=(),
            current_detection_observations=(confirmed,),
            prior_complete_snapshot=None,
            snapshot_at=NOW,
        )
        return CampaignPlanningFacts(
            detection_snapshot,
            r119_authority,
            projections,
            _adaptation(),
        )


def _resolver_authority(*, digest: str):
    return replace(
        _snapshot(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        roe_version_id="roe-v1",
        roe_sha256="a" * 64,
        policy_decision_id="policy-decision-1",
        policy_revision="policy-v1",
        policy_sha256="b" * 64,
        target_id="target-a",
        target_sha256=digest,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
        lease_expires_at=NOW + timedelta(minutes=20),
    )


def _request_for_owned_target():
    return replace(
        _request(),
        tenant_id="tenant-a",
        principal_id="principal-a",
        engagement_id="engagement-a",
        target_id="target-a",
    )


def test_campaign_start_durably_carries_detection_adaptation_v2() -> None:
    digest = _target_digest("target-a")
    authority = _resolver_authority(digest=digest)
    store = Store()
    service = CampaignStartService(
        CampaignContextResolver(AuthorityProvider(authority)),
        DeterministicCampaignStartPlanner(
            DetectionFactsOwner(with_signal=True), AuthorizationOwner()
        ),
        store,
        Identities(),
    )

    asyncio.run(service.start(_request_for_owned_target(), now=NOW + timedelta(minutes=1)))

    assert len(store.commands) == 1
    command = store.commands[0][0]
    assert command.context_schema == "redagent.detection-decision-context/v2"
    assert command.decision_schema == "redagent.detection-strategy-receipt/v2"
    assert command.plan_payload["primary"]["capability_id"] == "nuclei-trusted-runtime"
    assert command.plan_payload["successor"] is None
    assert command.decision_payload["reason"] == "primary_switched_after_confirmed_detection"
    assert command.decision_payload["detection_disposition"]["tenant_id"] == "tenant-a"


def test_campaign_start_with_enabled_adaptation_and_no_signal_remains_legacy_v1() -> None:
    authority = _resolver_authority(digest="a" * 64)
    material = asyncio.run(
        DeterministicCampaignStartPlanner(
            DetectionFactsOwner(with_signal=False), AuthorizationOwner()
        ).prepare(
            _request_for_owned_target(),
            authority,
            campaign_id="campaign-no-detection-signal",
            now=NOW + timedelta(minutes=1),
        )
    )
    assert material.context_schema == "redagent.r119-decision-context/v1"
    assert material.decision_schema == "redagent.r121-strategy-receipt/v1"
    assert material.plan_payload["primary"]["capability_id"] == "zap-controlled-runtime"
    assert material.decision_payload["detection_disposition"] is None
