import pytest

from redagent_platform import domain, target_inventory


def candidate(**overrides: object) -> target_inventory.TargetImportCandidate:
    values = {
        "id": "target-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "owner_label": "Security",
        "target_type": domain.TargetType.DOMAIN,
        "value": "Example.COM.",
        "environment": target_inventory.EnvironmentType.PRODUCTION,
        "data_sensitivity": target_inventory.DataSensitivity.INTERNAL,
        "authorization_status": domain.AuthorizationStatus.APPROVED,
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
    }
    values.update(overrides)
    return target_inventory.TargetImportCandidate(**values)  # type: ignore[arg-type]


def test_inventory_supports_r007_target_types() -> None:
    assert {
        domain.TargetType.WEB_ORIGIN,
        domain.TargetType.API_SPEC,
        domain.TargetType.DOMAIN,
        domain.TargetType.CIDR,
        domain.TargetType.CLOUD_ACCOUNT,
        domain.TargetType.CLOUD_PROJECT,
        domain.TargetType.CLOUD_SUBSCRIPTION,
        domain.TargetType.KUBERNETES_CLUSTER,
        domain.TargetType.LAB_TARGET,
    }.issubset(set(domain.TargetType))


def test_inventory_target_records_required_classification_metadata() -> None:
    target = target_inventory.build_inventory_target(candidate())

    assert target.owner_label == "Security"
    assert target.environment is target_inventory.EnvironmentType.PRODUCTION
    assert target.data_sensitivity is target_inventory.DataSensitivity.INTERNAL
    assert target.authorization_status is domain.AuthorizationStatus.APPROVED
    assert target.allowed_modes == (domain.TestMode.PASSIVE_SCAN,)
    assert target.value == "example.com"


def test_web_origin_must_be_origin_only() -> None:
    result = target_inventory.validate_import_candidate(
        candidate(target_type=domain.TargetType.WEB_ORIGIN, value="https://Example.com/login")
    )

    assert "web_origin_must_be_origin_only" in result.errors


def test_api_spec_accepts_spec_references_only() -> None:
    target = target_inventory.build_inventory_target(
        candidate(target_type=domain.TargetType.API_SPEC, value="https://api.example.com/openapi.yaml")
    )
    result = target_inventory.validate_import_candidate(
        candidate(target_type=domain.TargetType.API_SPEC, value="https://api.example.com/docs")
    )

    assert target.value == "https://api.example.com/openapi.yaml"
    assert "api_spec_extension_required" in result.errors


def test_cloud_target_types_validate_expected_identifiers() -> None:
    account = target_inventory.build_inventory_target(
        candidate(target_type=domain.TargetType.CLOUD_ACCOUNT, value="aws:123456789012")
    )
    project = target_inventory.build_inventory_target(
        candidate(target_type=domain.TargetType.CLOUD_PROJECT, value="gcp:agentique-prod1")
    )
    subscription = target_inventory.build_inventory_target(
        candidate(
            target_type=domain.TargetType.CLOUD_SUBSCRIPTION,
            value="azure:12345678-1234-1234-1234-1234567890ab",
        )
    )

    assert account.value == "aws:123456789012"
    assert project.value == "gcp:agentique-prod1"
    assert subscription.value == "azure:12345678-1234-1234-1234-1234567890ab"


def test_malformed_domain_is_rejected() -> None:
    result = target_inventory.validate_import_candidate(candidate(value="-bad..example"))

    assert result.errors == ("invalid_domain",)
    assert not result.accepted


def test_wildcard_domain_requires_explicit_review() -> None:
    result = target_inventory.validate_import_candidate(candidate(value="*.example.com"))
    reviewed = target_inventory.build_inventory_target(
        candidate(value="*.example.com", explicit_review=True, review_reason="Owner approved wildcard.")
    )

    assert result.review_required == ("wildcard_domain",)
    assert reviewed.value == "*.example.com"
    assert reviewed.explicit_review


def test_broad_or_private_cidr_requires_explicit_review() -> None:
    result = target_inventory.validate_import_candidate(
        candidate(target_type=domain.TargetType.CIDR, value="10.0.0.0/8")
    )
    reviewed = target_inventory.build_inventory_target(
        candidate(
            target_type=domain.TargetType.CIDR,
            value="10.0.0.0/8",
            explicit_review=True,
            review_reason="Private enterprise range explicitly approved.",
        )
    )

    assert "over_broad_ipv4_cidr" in result.review_required
    assert "private_public_ambiguous_cidr" in result.review_required
    assert reviewed.value == "10.0.0.0/8"


def test_unknown_classification_requires_explicit_review() -> None:
    result = target_inventory.validate_import_candidate(
        candidate(
            environment=target_inventory.EnvironmentType.UNKNOWN,
            data_sensitivity=target_inventory.DataSensitivity.UNKNOWN,
        )
    )

    assert result.review_required == ("unknown_data_sensitivity", "unknown_environment")


def test_missing_review_reason_blocks_explicit_review() -> None:
    result = target_inventory.validate_import_candidate(candidate(value="*.example.com", explicit_review=True))

    assert result.errors == ("missing_review_reason",)


def test_inventory_target_converts_to_scope_target_without_widening_scope() -> None:
    target = target_inventory.build_inventory_target(
        candidate(target_type=domain.TargetType.WEB_ORIGIN, value="https://WWW.Example.com/")
    )

    scope_target = target.to_scope_target()
    assert scope_target.target_type is domain.TargetType.WEB_ORIGIN
    assert scope_target.value == "https://www.example.com"


def test_inventory_changes_emit_audit_event_candidates() -> None:
    target = target_inventory.build_inventory_target(candidate())
    event = target_inventory.audit_inventory_change(
        event_id="audit-1",
        action=target_inventory.InventoryAuditAction.CREATE,
        target=target,
        actor_user_id="user-1",
    )

    assert event.organization_id == "org-1"
    assert event.actor_user_id == "user-1"
    assert event.action == "target_inventory.create"
    assert event.subject_type == "target_inventory"
    assert event.subject_id == "target-1"


def test_import_policy_decision_requires_review_for_ambiguous_target() -> None:
    decision = target_inventory.policy_decision_for_import(
        decision_id="decision-1",
        organization_id="org-1",
        candidate=candidate(target_type=domain.TargetType.CIDR, value="192.168.0.0/16"),
    )

    assert decision.outcome is domain.PolicyDecisionOutcome.REQUIRE_REVIEW
    assert decision.reason.startswith("target_import_requires_review:")


def test_import_builder_raises_on_unreviewed_risky_target() -> None:
    with pytest.raises(ValueError, match="target_import_rejected"):
        target_inventory.build_inventory_target(candidate(target_type=domain.TargetType.CIDR, value="192.168.0.0/16"))
