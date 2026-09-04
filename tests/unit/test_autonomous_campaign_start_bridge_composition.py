from __future__ import annotations

from redagent_platform.campaign_service.admission_start_composition import (
    build_autonomous_campaign_admission_start_factory,
    build_stock_autonomous_campaign_start_bridge_relay_factory,
)
from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
)
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from tests.unit.test_autonomous_campaign_admission_start_service import (
    _approved_material,
)
from tests.unit.test_campaign_planning_contracts import limits
from redagent_platform.campaign_service.admission_start_relay_runtime import (
    AutonomousCampaignStartBridgeRelayPump,
)


class Dependency:
    pass


def test_stock_start_bridge_relay_is_closed_when_disabled_and_owned_in_plan_only() -> None:
    assert build_stock_autonomous_campaign_start_bridge_relay_factory(
        {"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled"}
    ) is None

    factory = build_stock_autonomous_campaign_start_bridge_relay_factory({})
    assert callable(factory)
    relay = factory(
        Dependency(),
        Dependency(),
        type("Settings", (), {"task_queue": "redagent-workflows-v1"})(),
    )
    assert isinstance(relay, AutonomousCampaignStartBridgeRelayPump)
    assert callable(relay.run)


def test_admission_start_service_factory_requires_the_complete_server_owned_graph() -> None:
    assert build_autonomous_campaign_admission_start_factory({}) is None
    _stage, key, _bundle, context = _approved_material()
    policy = AdmissionPolicyAdapter(
        DeterministicFakePolicyProvider(
            revision=context.signed_authority.authority.policy_revision
        ),
        required_revision=context.signed_authority.authority.policy_revision,
        trusted_bundle_sha256=context.signed_authority.authority.policy_bundle_sha256,
    )
    factory = build_autonomous_campaign_admission_start_factory(
        {},
        admission_context_provider=type(
            "Provider",
            (),
            {"read_current_admission_context": lambda *args, **kwargs: None},
        )(),
        policy=policy,
        trusted_approval_keys={"key-a": key},
        validation_limits=limits(),
        trusted_validator_version=VALIDATOR_VERSION,
        trusted_validator_sha256=VALIDATOR_SHA256,
    )
    assert callable(factory)
    assert isinstance(factory(Dependency()), AutonomousCampaignAdmissionStartService)
