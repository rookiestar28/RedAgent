from dataclasses import FrozenInstanceError

import pytest

from redagent_platform import domain


REQUIRED_R003_ENTITIES = {
    "Organization",
    "User",
    "Role",
    "Engagement",
    "Target",
    "Authorization",
    "TestDefinition",
    "Runner",
    "Job",
    "Evidence",
    "Finding",
    "Report",
    "AuditEvent",
    "PolicyDecision",
}


def test_core_domain_model_contains_all_r003_entities() -> None:
    assert domain.missing_core_entities(REQUIRED_R003_ENTITIES) == ()
    assert REQUIRED_R003_ENTITIES.issubset(set(domain.core_entity_names()))


def test_core_entity_type_names_are_unique() -> None:
    names = [entity.__name__ for entity in domain.CORE_ENTITY_TYPES]
    assert len(names) == len(set(names))


def test_execution_modes_are_explicitly_separated() -> None:
    assert domain.REQUIRED_TEST_MODE_SEPARATION == {
        domain.TestMode.PASSIVE_SCAN,
        domain.TestMode.ACTIVE_SCAN,
        domain.TestMode.ADVERSARY_EMULATION,
        domain.TestMode.CLOUD_TECHNIQUE,
        domain.TestMode.LAB_ONLY_RUN,
    }
    assert domain.execution_modes_are_separated()


def test_target_types_cover_required_r003_surfaces() -> None:
    assert {
        domain.TargetType.WEB_ORIGIN,
        domain.TargetType.API_SPEC,
        domain.TargetType.DOMAIN,
        domain.TargetType.CIDR,
        domain.TargetType.CLOUD_ACCOUNT,
        domain.TargetType.KUBERNETES_CLUSTER,
        domain.TargetType.LAB_TARGET,
    }.issubset(set(domain.TargetType))


def test_job_lifecycle_contains_policy_and_evidence_lock_states() -> None:
    assert domain.JobStatus.PLANNED.value == "planned"
    assert domain.JobStatus.AUTHORIZED.value == "authorized"
    assert domain.JobStatus.CLEANUP.value == "cleanup"
    assert domain.JobStatus.EVIDENCE_LOCKED.value == "evidence_locked"


def test_contract_objects_are_immutable() -> None:
    engagement = domain.Engagement(
        id="eng-1",
        organization_id="org-1",
        name="Example",
        status=domain.EngagementStatus.DRAFT,
        owner_user_id="user-1",
    )

    with pytest.raises(FrozenInstanceError):
        engagement.name = "Changed"  # type: ignore[misc]


def test_authorization_keeps_allowed_modes_explicit() -> None:
    authorization = domain.Authorization(
        id="auth-1",
        engagement_id="eng-1",
        status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="user-1",
        allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
    )

    assert authorization.allowed_modes == (domain.TestMode.PASSIVE_SCAN,)


def test_test_definition_binds_mode_risk_and_target_types() -> None:
    definition = domain.TestDefinition(
        id="test-1",
        name="Passive metadata",
        version="1.0.0",
        mode=domain.TestMode.PASSIVE_SCAN,
        risk_class=domain.TestRiskClass.PASSIVE,
        target_types=(domain.TargetType.WEB_ORIGIN, domain.TargetType.DOMAIN),
    )

    assert definition.mode is domain.TestMode.PASSIVE_SCAN
    assert definition.risk_class is domain.TestRiskClass.PASSIVE
    assert domain.TargetType.WEB_ORIGIN in definition.target_types
