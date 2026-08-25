from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import cloud_posture, evidence_chain
from redagent_platform.target_inventory import EnvironmentType


NOW = datetime(2026, 7, 8, 21, 0, tzinfo=timezone.utc)


def scope(**overrides: object) -> cloud_posture.CloudScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.AWS,
        "environment": EnvironmentType.TEST,
        "account_ids": ("aws:123456789012",),
        "project_ids": (),
        "cluster_ids": ("cluster-1",),
        "regions": ("ap-northeast-1",),
        "owner_approved_by_user_id": "lead-1",
        "credential_reference_id": "cred-ref-1",
        "allowed_read_permissions": ("ReadOnlyAccess",),
        "monthly_cost_estimate_usd": 25.0,
        "blast_radius_reviewed": True,
    }
    values.update(overrides)
    return cloud_posture.CloudScope(**values)  # type: ignore[arg-type]


def boundary(**overrides: object) -> cloud_posture.CloudCredentialBoundary:
    values = {
        "credential_reference_id": "cred-ref-1",
        "lease_id": "lease-1",
        "permissions": ("ReadOnlyAccess",),
        "read_only": True,
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "cloud-readonly-lease",
    }
    values.update(overrides)
    return cloud_posture.CloudCredentialBoundary(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> cloud_posture.CloudPostureRequest:
    values = {
        "job_id": "cloud-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.AWS,
        "mode": cloud_posture.CloudPostureMode.READ_ONLY_POSTURE,
        "requested_at": NOW,
        "target_id": "aws:123456789012",
        "requested_permissions": ("ReadOnlyAccess",),
        "credential_boundary": boundary(),
    }
    values.update(overrides)
    return cloud_posture.CloudPostureRequest(**values)  # type: ignore[arg-type]


def test_scope_requires_allowlists_environment_credential_cost_and_blast_radius() -> None:
    cloud_posture.validate_cloud_scope(scope())

    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"account_ids": (), "project_ids": (), "cluster_ids": ()}, "cloud_target_allowlist_required"),
        ({"environment": EnvironmentType.UNKNOWN}, "cloud_environment_classification_required"),
        ({"credential_reference_id": ""}, "missing_credential_reference_id"),
        ({"monthly_cost_estimate_usd": -1}, "cloud_cost_estimate_invalid"),
        ({"blast_radius_reviewed": False}, "cloud_blast_radius_review_required"),
    )
    for overrides, expected in cases:
        with pytest.raises(ValueError, match=expected):
            cloud_posture.validate_cloud_scope(scope(**overrides))


def test_read_only_posture_collection_is_allowed_and_mutating_modes_are_blocked() -> None:
    decision = cloud_posture.evaluate_cloud_posture(scope(), request())

    assert decision.allowed
    assert decision.reason == "cloud_read_only_posture_allowed"

    plan = cloud_posture.build_cloud_collection_plan(scope(), request())

    assert plan.mode is cloud_posture.CloudPostureMode.READ_ONLY_POSTURE
    assert all(step.read_only for step in plan.steps)
    assert {step.control_domain for step in plan.steps} >= {
        cloud_posture.CloudControlDomain.IDENTITY_ACCESS,
        cloud_posture.CloudControlDomain.LOGGING_MONITORING,
        cloud_posture.CloudControlDomain.NETWORK_SECURITY,
        cloud_posture.CloudControlDomain.ENCRYPTION,
        cloud_posture.CloudControlDomain.IAC_CONFIGURATION,
    }

    for mode in (
        cloud_posture.CloudPostureMode.CLOUD_DETONATION,
        cloud_posture.CloudPostureMode.RESOURCE_MUTATION,
        cloud_posture.CloudPostureMode.PERSISTENCE_TEST,
        cloud_posture.CloudPostureMode.PRIVILEGE_ESCALATION,
        cloud_posture.CloudPostureMode.CLEANUP_DEPENDENT_TEST,
    ):
        blocked = cloud_posture.evaluate_cloud_posture(scope(), request(mode=mode))
        assert not blocked.allowed
        assert blocked.reason == "cloud_mutating_mode_blocked"


def test_read_only_credential_boundary_is_required() -> None:
    missing = cloud_posture.evaluate_cloud_posture(scope(), request(credential_boundary=None))
    assert not missing.allowed
    assert missing.reason == "cloud_credential_boundary_required"

    write_capable = cloud_posture.evaluate_cloud_posture(scope(), request(credential_boundary=boundary(read_only=False)))
    assert not write_capable.allowed
    assert write_capable.reason == "cloud_read_only_credential_required"

    disallowed_permission = cloud_posture.evaluate_cloud_posture(
        scope(),
        request(requested_permissions=("AdministratorAccess",)),
    )
    assert not disallowed_permission.allowed
    assert disallowed_permission.reason == "cloud_permission_not_allowed"


def test_kubernetes_check_mappings_distinguish_required_areas() -> None:
    mappings = cloud_posture.kubernetes_check_mappings()

    assert {mapping.area for mapping in mappings} == {
        cloud_posture.KubernetesFindingArea.CONTROL_PLANE,
        cloud_posture.KubernetesFindingArea.WORKER_NODE,
        cloud_posture.KubernetesFindingArea.NAMESPACE,
        cloud_posture.KubernetesFindingArea.WORKLOAD,
        cloud_posture.KubernetesFindingArea.RBAC,
        cloud_posture.KubernetesFindingArea.NETWORK_POLICY,
        cloud_posture.KubernetesFindingArea.SENSITIVE_CONFIGURATION,
    }


def test_iac_and_container_evidence_blocks_private_external_uploads_and_requires_redaction() -> None:
    cloud_posture.validate_artifact_evidence_policy(
        cloud_posture.ArtifactEvidencePolicy(
            artifact_id="iac-1",
            artifact_kind="iac",
            private_artifact=True,
            upload_to_external_service=False,
            redaction_status=evidence_chain.RedactionStatus.REDACTED,
            contains_sensitive_material=True,
        )
    )

    with pytest.raises(ValueError, match="private_artifact_external_upload_forbidden"):
        cloud_posture.validate_artifact_evidence_policy(
            cloud_posture.ArtifactEvidencePolicy(
                artifact_id="image-1",
                artifact_kind="container_image",
                private_artifact=True,
                upload_to_external_service=True,
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                contains_sensitive_material=True,
            )
        )

    with pytest.raises(ValueError, match="sensitive_artifact_requires_redaction"):
        cloud_posture.validate_artifact_evidence_policy(
            cloud_posture.ArtifactEvidencePolicy(
                artifact_id="iac-2",
                artifact_kind="iac",
                private_artifact=False,
                upload_to_external_service=False,
                redaction_status=evidence_chain.RedactionStatus.NOT_APPLICABLE,
                contains_sensitive_material=True,
            )
        )


def test_cloud_findings_map_control_domain_resource_region_cluster_severity_and_remediation() -> None:
    mapping = cloud_posture.build_cloud_finding_mapping(
        finding_id="cloud-finding-1",
        control_domain=cloud_posture.CloudControlDomain.KUBERNETES_RBAC,
        affected_resource_id="cluster-1:rolebinding/admin",
        region="ap-northeast-1",
        cluster_id="cluster-1",
        severity="medium",
        remediation_guidance="Restrict cluster-admin role binding to approved groups.",
        evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
    )

    assert mapping.control_domain is cloud_posture.CloudControlDomain.KUBERNETES_RBAC
    assert mapping.affected_resource_id == "cluster-1:rolebinding/admin"
    assert mapping.region == "ap-northeast-1"
    assert mapping.cluster_id == "cluster-1"
    assert mapping.severity == "medium"
    assert "cluster-admin" in mapping.remediation_guidance
    assert mapping.evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
