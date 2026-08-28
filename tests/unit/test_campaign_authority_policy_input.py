from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest

from redagent_platform.campaign_service.authority_envelope import (
    CampaignApproverRequirementV2,
    CampaignAuthorityBoundsV2,
    CampaignAuthorityEnvelopeV2,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
    CampaignCredentialClass,
    CampaignDataAccessClass,
    CampaignEffectClass,
    CampaignEnvironmentClass,
    CampaignSafetyRequirementsV2,
    campaign_authority_policy_attributes,
)
from redagent_platform.policy_service.contracts import (
    POLICY_DECISION_CONTRACT_VERSION,
    PolicyBoundary,
    PolicyDecisionInput,
    canonical_policy_input,
)


NOW = datetime(2026, 8, 29, 5, 0, tzinfo=timezone.utc)
SHA_A = "a" * 64
SHA_B = "b" * 64


def authority() -> CampaignAuthorityEnvelopeV2:
    return CampaignAuthorityEnvelopeV2(
        schema_version="redagent.campaign-authority-envelope/v2",
        canonicalization_version="redagent.canonical-json/v1",
        envelope_id="authority-policy-a",
        tenant_id="tenant-a",
        engagement_id="engagement-a",
        target_ids=("target-a",),
        capability_ids=("artifact-posture",),
        objective_ids=("objective-a",),
        success_condition_ids=("success-a",),
        allowed_effect_classes=(CampaignEffectClass.READ_ONLY_OBSERVATION,),
        forbidden_effect_classes=(CampaignEffectClass.CONTROLLED_STATE_CHANGE, CampaignEffectClass.DISRUPTIVE),
        allowed_data_access_classes=(CampaignDataAccessClass.METADATA_ONLY,),
        allowed_credential_classes=(CampaignCredentialClass.NONE,),
        allowed_environment_classes=(CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,),
        valid_from=NOW,
        expires_at=NOW + timedelta(minutes=10),
        bounds=CampaignAuthorityBoundsV2(
            max_duration_seconds=600,
            max_search_seconds=10,
            max_depth=2,
            max_width=2,
            max_nodes=4,
            max_frontier=2,
            max_replans=0,
            max_retries_per_node=0,
            max_requests=4,
            max_rate_per_minute=2,
            max_concurrency=1,
            max_risk_micropoints=0,
            max_cost_microunits=0,
            max_evidence_bytes=1024,
            max_data_bytes=1024,
        ),
        required_approvers=(CampaignApproverRequirementV2("approver-a", "campaign-owner"),),
        safety_requirements=CampaignSafetyRequirementsV2(True, True, True, True, True, True),
        policy_bundle_sha256=SHA_A,
        policy_revision="policy-revision-a",
        policy_revocation_epoch=3,
        roe_sha256=SHA_B,
        roe_revocation_epoch=5,
        lifecycle_epoch=7,
        kill_switch_epoch=11,
        nonce="nonce-policy-a",
        parent_authority_sha256=None,
        expansion_requires_new_approval=True,
    )


def lifecycle(item: CampaignAuthorityEnvelopeV2, **overrides: object) -> CampaignAuthorityLifecycleV2:
    values: dict[str, object] = {
        "schema_version": "redagent.campaign-authority-lifecycle/v2",
        "authority_sha256": item.authority_sha256,
        "tenant_id": item.tenant_id,
        "engagement_id": item.engagement_id,
        "state": CampaignAuthorityLifecycleState.ACTIVE,
        "lifecycle_epoch": item.lifecycle_epoch,
        "policy_revocation_epoch": item.policy_revocation_epoch,
        "roe_revocation_epoch": item.roe_revocation_epoch,
        "kill_switch_epoch": item.kill_switch_epoch,
        "observed_at": NOW + timedelta(seconds=1),
        "valid_until": NOW + timedelta(minutes=5),
        "revoked_at": None,
        "reason_code": None,
    }
    values.update(overrides)
    return CampaignAuthorityLifecycleV2(**values)  # type: ignore[arg-type]


def test_policy_projection_is_closed_metadata_only_and_v1_compatible() -> None:
    item = authority()
    attributes = campaign_authority_policy_attributes(
        item,
        lifecycle(item),
        target_id="target-a",
        capability_id="artifact-posture",
        effect_class=CampaignEffectClass.READ_ONLY_OBSERVATION,
        data_access_class=CampaignDataAccessClass.METADATA_ONLY,
        credential_class=CampaignCredentialClass.NONE,
        environment_class=CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
        residual_budget_sha256=SHA_B,
        now=NOW + timedelta(minutes=1),
    )
    request = PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign_effect_admit",
        tenant_id="tenant-a",
        subject_id="operator-a",
        roles=("operator",),
        permissions=("campaign.execute",),
        resource_type="campaign-authority",
        resource_id="authority-policy-a",
        policy_reference="bundle/policy-revision-a",
        roe_version_id="roe-version-a",
        correlation_id="correlation-a",
        requested_at=NOW + timedelta(minutes=1),
        attributes=attributes,
    )
    payload = json.loads(canonical_policy_input(request))
    assert POLICY_DECISION_CONTRACT_VERSION == "1.0"
    assert payload["attributes"] == {
        "campaign_authority_sha256": item.authority_sha256,
        "campaign_authority_version": "v2",
        "campaign_capability_id": "artifact-posture",
        "campaign_credential_class": "none",
        "campaign_data_access_class": "metadata_only",
        "campaign_effect_class": "read_only_observation",
        "campaign_environment_class": "synthetic_loopback",
        "campaign_kill_switch_epoch": 11,
        "campaign_lifecycle_epoch": 7,
        "campaign_lifecycle_state": "active",
        "campaign_residual_budget_sha256": SHA_B,
        "campaign_target_id": "target-a",
    }
    assert "nonce" not in payload["attributes"]
    assert "signature" not in payload["attributes"]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    (
        ({"target_id": "target-b"}, "campaign_policy_target_not_authorized"),
        ({"capability_id": "unknown-capability"}, "campaign_policy_capability_not_authorized"),
        ({"effect_class": CampaignEffectClass.DISRUPTIVE}, "campaign_policy_effect_not_authorized"),
        ({"data_access_class": CampaignDataAccessClass.SENSITIVE}, "campaign_policy_data_access_not_authorized"),
        ({"credential_class": CampaignCredentialClass.SCOPED_READ}, "campaign_policy_credential_not_authorized"),
        ({"environment_class": CampaignEnvironmentClass.OWNED_STAGING}, "campaign_policy_environment_not_authorized"),
    ),
)
def test_policy_projection_denies_out_of_envelope_values(overrides: dict[str, object], reason: str) -> None:
    item = authority()
    values: dict[str, object] = {
        "target_id": "target-a",
        "capability_id": "artifact-posture",
        "effect_class": CampaignEffectClass.READ_ONLY_OBSERVATION,
        "data_access_class": CampaignDataAccessClass.METADATA_ONLY,
        "credential_class": CampaignCredentialClass.NONE,
        "environment_class": CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
        "residual_budget_sha256": SHA_B,
        "now": NOW + timedelta(minutes=1),
    }
    values.update(overrides)
    with pytest.raises(ValueError, match=reason):
        campaign_authority_policy_attributes(item, lifecycle(item), **values)  # type: ignore[arg-type]


def test_policy_projection_denies_revocation_or_epoch_drift() -> None:
    item = authority()
    with pytest.raises(ValueError, match="campaign_authority_not_active"):
        campaign_authority_policy_attributes(
            item,
            lifecycle(
                item,
                state=CampaignAuthorityLifecycleState.REVOKED,
                revoked_at=NOW,
                reason_code="operator_revoked",
            ),
            target_id="target-a",
            capability_id="artifact-posture",
            effect_class=CampaignEffectClass.READ_ONLY_OBSERVATION,
            data_access_class=CampaignDataAccessClass.METADATA_ONLY,
            credential_class=CampaignCredentialClass.NONE,
            environment_class=CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
            residual_budget_sha256=SHA_B,
            now=NOW + timedelta(minutes=1),
        )

    with pytest.raises(ValueError, match="campaign_kill_switch_epoch_mismatch"):
        campaign_authority_policy_attributes(
            item,
            lifecycle(item, kill_switch_epoch=12),
            target_id="target-a",
            capability_id="artifact-posture",
            effect_class=CampaignEffectClass.READ_ONLY_OBSERVATION,
            data_access_class=CampaignDataAccessClass.METADATA_ONLY,
            credential_class=CampaignCredentialClass.NONE,
            environment_class=CampaignEnvironmentClass.SYNTHETIC_LOOPBACK,
            residual_budget_sha256=SHA_B,
            now=NOW + timedelta(minutes=1),
        )
