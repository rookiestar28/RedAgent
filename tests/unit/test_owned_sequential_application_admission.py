from __future__ import annotations

import asyncio
from dataclasses import asdict, replace

import pytest

from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter, CampaignPlanAdmissionService
from redagent_platform.campaign_service.application_contracts import ApplicationPlanInvalid, AutonomousCampaignLifecycle, AutonomousCampaignMode
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
from tests.unit.test_autonomous_campaign_plan_approval import ApprovalContextProvider, Repository, _stage_command
from tests.unit.test_campaign_plan_admission import _CountingProvider, _Store, _signed_authority
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_owned_bounded_replanning import _inputs


def _stage_material():
    values = _inputs()
    signed, lifecycle, trusted = _signed_authority(values["authority"])
    command, _ = _stage_command()
    from redagent_platform.campaign_service.planning.owned_sequential import validate_owned_sequential_candidate_plan
    certificate = validate_owned_sequential_candidate_plan(values["parent_revision"].candidate_plan, values["domain"],
        values["authority"], limits=ValidationLimitsV1(2, 1, 32), validated_at=NOW)
    command = replace(command, domain=values["domain"], revision=values["parent_revision"], certificate=certificate,
                      signed_authority=signed, authority_lifecycle=lifecycle)
    return command, trusted


def test_bounded_application_recomputes_distinct_closed_certificate_without_relaxing_ordinary_staging():
    command, trusted = _stage_material()
    repository = Repository()
    repository.state = replace(repository.state, mode=AutonomousCampaignMode.BOUNDED_REPLAN)
    provider = ApprovalContextProvider(command)
    bindings = tuple(CapabilityBindingKeyV1(**asdict(op.capability), schema_version="redagent.r119-capability-binding/v1",
        semantics_revision=1, semantics_sha256="a" * 64, normalized_output_sha256="a" * 64,
        projection_revision=1, projection_sha256="a" * 64) for op in command.domain.operators)
    provider.context = replace(provider.context, execution_bindings=bindings)
    service = AutonomousCampaignApplicationService(repository, mode=AutonomousCampaignMode.BOUNDED_REPLAN,
        approval_context_provider=provider, trusted_approval_keys=trusted, validation_limits=ValidationLimitsV1(2, 1, 32),
        trusted_validator_version=command.certificate.validator_version,
        trusted_validator_sha256=command.certificate.validator_sha256)
    result = asyncio.run(service.stage_plan(command))
    assert result.preview.execution_mode is AutonomousCampaignMode.BOUNDED_REPLAN
    assert len(result.preview.actions) == 2 and result.preview.child_lineage_sha256 is None
    assert repository.stage_calls == 1
    repository.state = replace(repository.state, lifecycle_state=AutonomousCampaignLifecycle.RUNNING)
    with pytest.raises(ApplicationPlanInvalid, match="plan_staging_state_invalid"):
        asyncio.run(service.stage_plan(replace(command, expected_revision=repository.state.aggregate_revision)))
    assert repository.stage_calls == 1


@pytest.mark.parametrize("owned", [True, False])
def test_admission_uses_closed_recomputation_only_when_explicitly_server_selected(owned):
    command, trusted = _stage_material()
    provider, store = _CountingProvider(), _Store()
    authority = command.signed_authority.authority
    service = CampaignPlanAdmissionService(policy=AdmissionPolicyAdapter(provider,
        required_revision=authority.policy_revision, trusted_bundle_sha256=authority.policy_bundle_sha256),
        store=store, trusted_keys=trusted, validation_limits=ValidationLimitsV1(2, 1, 32),
        trusted_validator_version=command.certificate.validator_version,
        trusted_validator_sha256=command.certificate.validator_sha256, owned_sequential=owned)
    result = asyncio.run(service.admit_plan(signed_authority=command.signed_authority, lifecycle=command.authority_lifecycle,
        revision=command.revision, domain=command.domain, certificate=command.certificate, campaign_id=command.campaign_id,
        subject_id="operator-a", roles=("campaign-operator",), permissions=("campaign:admit",),
        correlation_id="correlation-a", idempotency_key="admission-a", now=command.occurred_at))
    assert result == ("admitted-result" if owned else "denied-result")
    assert provider.decisions == int(owned)
    assert (store.command is not None) is owned
