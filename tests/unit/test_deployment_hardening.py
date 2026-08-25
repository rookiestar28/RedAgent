from redagent_platform.deployment_hardening import (
    AdminAccessPlan,
    BackupRestorePlan,
    DeploymentExposure,
    EmergencyShutdownPlan,
    HardenedDeploymentTopology,
    LeastPrivilegeBoundary,
    NetworkIsolationPlan,
    RetentionPlan,
    RollbackDisasterRecoveryPlan,
    RunnerNetworkPolicy,
    StorageComponent,
    TLSPlan,
    build_r032_private_topology,
    validate_hardened_deployment,
)


def test_r032_private_topology_is_accepted():
    topology = build_r032_private_topology()

    validation = validate_hardened_deployment(topology)

    assert validation.accepted is True
    assert validation.reason == "deployment_hardening_accepted"


def test_public_internet_exposure_is_blocked_by_default():
    topology = build_r032_private_topology()
    changed = _replace_topology(
        topology,
        exposure=DeploymentExposure.PUBLIC_INTERNET,
        network=NetworkIsolationPlan(
            private_subnets=topology.network.private_subnets,
            public_ingress_allowed=True,
            allowed_ingress_sources=topology.network.allowed_ingress_sources,
            egress_default_deny=True,
            runner_to_target_egress_requires_policy=True,
        ),
    )

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "public_internet_exposure_forbidden" in validation.gaps
    assert "public_ingress_must_be_blocked_by_default" in validation.gaps


def test_tls_and_admin_access_are_required():
    topology = build_r032_private_topology()
    changed = _replace_topology(
        topology,
        tls=TLSPlan(
            internal_tls_required=False,
            external_tls_required=False,
            min_tls_version="1.2",
            certificate_rotation_days=500,
        ),
        admin_access=AdminAccessPlan(
            sso_required=False,
            mfa_required=False,
            vpn_or_zero_trust_required=False,
            break_glass_users=(),
            admin_actions_audited=False,
        ),
    )

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "internal_tls_required" in validation.gaps
    assert "external_tls_required" in validation.gaps
    assert "tls_1_3_minimum_required" in validation.gaps
    assert "admin_sso_required" in validation.gaps
    assert "admin_mfa_required" in validation.gaps
    assert "admin_private_access_required" in validation.gaps


def test_backup_restore_and_retention_require_evidence():
    topology = build_r032_private_topology()
    changed = _replace_topology(
        topology,
        backup_restore=BackupRestorePlan(
            backups_enabled=True,
            restore_tested=False,
            rpo_minutes=0,
            rto_minutes=0,
            evidence_refs=(),
        ),
        retention=RetentionPlan(
            data_retention_days=90,
            log_retention_days=30,
            legal_hold_supported=False,
            retention_policy_refs=(),
        ),
    )

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "restore_test_required" in validation.gaps
    assert "backup_restore_evidence_required" in validation.gaps
    assert "log_retention_must_cover_data_retention" in validation.gaps
    assert "legal_hold_required" in validation.gaps


def test_runner_network_policy_and_emergency_shutdown_are_required():
    topology = build_r032_private_topology()
    changed = _replace_topology(
        topology,
        runner_network=RunnerNetworkPolicy(
            egress_default_deny=False,
            target_allowlist_required=False,
            dns_logging_required=False,
            emergency_shutdown_cuts_egress=False,
        ),
        emergency_shutdown=EmergencyShutdownPlan(
            kill_switch_documented=False,
            disables_queue_dispatch=False,
            revokes_runner_tokens=False,
            cuts_runner_egress=False,
            emergency_contact_method=" ",
        ),
    )

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "runner_egress_default_deny_required" in validation.gaps
    assert "runner_target_allowlist_required" in validation.gaps
    assert "runner_dns_logging_required" in validation.gaps
    assert "kill_switch_documentation_required" in validation.gaps
    assert "runner_token_revocation_required" in validation.gaps
    assert "missing_emergency_contact_method" in validation.gaps


def test_all_required_least_privilege_components_are_required():
    topology = build_r032_private_topology()
    without_queue = tuple(boundary for boundary in topology.least_privilege_boundaries if boundary.component is not StorageComponent.QUEUE)
    changed = _replace_topology(topology, least_privilege_boundaries=without_queue)

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "missing_least_privilege_component:queue" in validation.gaps


def test_least_privilege_boundary_requires_identity_scope_encryption_and_evidence():
    topology = build_r032_private_topology()
    weak_boundary = LeastPrivilegeBoundary(
        component=StorageComponent.SENSITIVE_VALUE_STORE,
        dedicated_identity=False,
        read_write_scoped=False,
        encryption_required=False,
        rotation_or_lifecycle_policy=False,
        evidence_refs=(),
    )
    changed = _replace_topology(topology, least_privilege_boundaries=(weak_boundary,) + topology.least_privilege_boundaries[1:])

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "dedicated_identity_required:sensitive_value_store" in validation.gaps
    assert "read_write_scope_required:sensitive_value_store" in validation.gaps
    assert "encryption_required:sensitive_value_store" in validation.gaps
    assert "least_privilege_evidence_required:sensitive_value_store" in validation.gaps


def test_rollback_and_disaster_recovery_must_be_tested():
    topology = build_r032_private_topology()
    changed = _replace_topology(
        topology,
        rollback_dr=RollbackDisasterRecoveryPlan(
            rollback_documented=True,
            disaster_recovery_documented=True,
            rollback_tested=False,
            disaster_recovery_tested=False,
            evidence_refs=(),
        ),
    )

    validation = validate_hardened_deployment(changed)

    assert validation.accepted is False
    assert "rollback_test_required" in validation.gaps
    assert "disaster_recovery_test_required" in validation.gaps
    assert "rollback_dr_evidence_required" in validation.gaps


def _replace_topology(topology: HardenedDeploymentTopology, **changes):
    values = {
        "topology_id": topology.topology_id,
        "exposure": topology.exposure,
        "network": topology.network,
        "tls": topology.tls,
        "admin_access": topology.admin_access,
        "backup_restore": topology.backup_restore,
        "retention": topology.retention,
        "runner_network": topology.runner_network,
        "emergency_shutdown": topology.emergency_shutdown,
        "least_privilege_boundaries": topology.least_privilege_boundaries,
        "rollback_dr": topology.rollback_dr,
    }
    values.update(changes)
    return HardenedDeploymentTopology(**values)
