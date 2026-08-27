"""Production deployment hardening topology contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DeploymentExposure(str, Enum):
    PRIVATE_ONLY = "private_only"
    INTERNAL_CONTROLLED = "internal_controlled"
    PUBLIC_INTERNET = "public_internet"


class StorageComponent(str, Enum):
    SENSITIVE_VALUE_STORE = "sensitive_value_store"
    EVIDENCE_STORAGE = "evidence_storage"
    DATABASE = "database"
    QUEUE = "queue"
    OBJECT_STORAGE = "object_storage"


@dataclass(frozen=True, kw_only=True)
class NetworkIsolationPlan:
    private_subnets: tuple[str, ...]
    public_ingress_allowed: bool
    allowed_ingress_sources: tuple[str, ...]
    egress_default_deny: bool
    runner_to_target_egress_requires_policy: bool


@dataclass(frozen=True, kw_only=True)
class TLSPlan:
    internal_tls_required: bool
    external_tls_required: bool
    min_tls_version: str
    certificate_rotation_days: int


@dataclass(frozen=True, kw_only=True)
class AdminAccessPlan:
    sso_required: bool
    mfa_required: bool
    vpn_or_zero_trust_required: bool
    break_glass_users: tuple[str, ...]
    admin_actions_audited: bool


@dataclass(frozen=True, kw_only=True)
class BackupRestorePlan:
    backups_enabled: bool
    restore_tested: bool
    rpo_minutes: int
    rto_minutes: int
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RetentionPlan:
    data_retention_days: int
    log_retention_days: int
    legal_hold_supported: bool
    retention_policy_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RunnerNetworkPolicy:
    egress_default_deny: bool
    target_allowlist_required: bool
    dns_logging_required: bool
    emergency_shutdown_cuts_egress: bool


@dataclass(frozen=True, kw_only=True)
class EmergencyShutdownPlan:
    kill_switch_documented: bool
    disables_queue_dispatch: bool
    revokes_runner_tokens: bool
    cuts_runner_egress: bool
    emergency_contact_method: str


@dataclass(frozen=True, kw_only=True)
class LeastPrivilegeBoundary:
    component: StorageComponent
    dedicated_identity: bool
    read_write_scoped: bool
    encryption_required: bool
    rotation_or_lifecycle_policy: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RollbackDisasterRecoveryPlan:
    rollback_documented: bool
    disaster_recovery_documented: bool
    rollback_tested: bool
    disaster_recovery_tested: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class HardenedDeploymentTopology:
    topology_id: str
    exposure: DeploymentExposure
    network: NetworkIsolationPlan
    tls: TLSPlan
    admin_access: AdminAccessPlan
    backup_restore: BackupRestorePlan
    retention: RetentionPlan
    runner_network: RunnerNetworkPolicy
    emergency_shutdown: EmergencyShutdownPlan
    least_privilege_boundaries: tuple[LeastPrivilegeBoundary, ...]
    rollback_dr: RollbackDisasterRecoveryPlan


@dataclass(frozen=True, kw_only=True)
class DeploymentHardeningValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()


REQUIRED_STORAGE_COMPONENTS: frozenset[StorageComponent] = frozenset(StorageComponent)


def build_private_topology() -> HardenedDeploymentTopology:
    return HardenedDeploymentTopology(
        topology_id="R032-private-production-topology",
        exposure=DeploymentExposure.PRIVATE_ONLY,
        network=NetworkIsolationPlan(
            private_subnets=("control-plane-private", "runner-private", "data-private"),
            public_ingress_allowed=False,
            allowed_ingress_sources=("enterprise-vpn-or-zero-trust",),
            egress_default_deny=True,
            runner_to_target_egress_requires_policy=True,
        ),
        tls=TLSPlan(
            internal_tls_required=True,
            external_tls_required=True,
            min_tls_version="1.3",
            certificate_rotation_days=90,
        ),
        admin_access=AdminAccessPlan(
            sso_required=True,
            mfa_required=True,
            vpn_or_zero_trust_required=True,
            break_glass_users=("security-lead-break-glass",),
            admin_actions_audited=True,
        ),
        backup_restore=BackupRestorePlan(
            backups_enabled=True,
            restore_tested=True,
            rpo_minutes=60,
            rto_minutes=240,
            evidence_refs=("docs/security/PRODUCTION_DEPLOYMENT_HARDENING_POLICY.md",),
        ),
        retention=RetentionPlan(
            data_retention_days=90,
            log_retention_days=365,
            legal_hold_supported=True,
            retention_policy_refs=("docs/security/PRODUCTION_DEPLOYMENT_HARDENING_POLICY.md",),
        ),
        runner_network=RunnerNetworkPolicy(
            egress_default_deny=True,
            target_allowlist_required=True,
            dns_logging_required=True,
            emergency_shutdown_cuts_egress=True,
        ),
        emergency_shutdown=EmergencyShutdownPlan(
            kill_switch_documented=True,
            disables_queue_dispatch=True,
            revokes_runner_tokens=True,
            cuts_runner_egress=True,
            emergency_contact_method="security-on-call-email",
        ),
        least_privilege_boundaries=tuple(
            LeastPrivilegeBoundary(
                component=component,
                dedicated_identity=True,
                read_write_scoped=True,
                encryption_required=True,
                rotation_or_lifecycle_policy=True,
                evidence_refs=("docs/security/PRODUCTION_DEPLOYMENT_HARDENING_POLICY.md",),
            )
            for component in StorageComponent
        ),
        rollback_dr=RollbackDisasterRecoveryPlan(
            rollback_documented=True,
            disaster_recovery_documented=True,
            rollback_tested=True,
            disaster_recovery_tested=True,
            evidence_refs=("docs/security/PRODUCTION_DEPLOYMENT_HARDENING_POLICY.md",),
        ),
    )


def validate_hardened_deployment(topology: HardenedDeploymentTopology) -> DeploymentHardeningValidation:
    gaps: list[str] = []
    _append_missing(gaps, "topology_id", topology.topology_id)
    gaps.extend(_network_gaps(topology.exposure, topology.network))
    gaps.extend(_tls_gaps(topology.tls))
    gaps.extend(_admin_gaps(topology.admin_access))
    gaps.extend(_backup_restore_gaps(topology.backup_restore))
    gaps.extend(_retention_gaps(topology.retention))
    gaps.extend(_runner_network_gaps(topology.runner_network))
    gaps.extend(_emergency_shutdown_gaps(topology.emergency_shutdown))
    gaps.extend(_least_privilege_gaps(topology.least_privilege_boundaries))
    gaps.extend(_rollback_dr_gaps(topology.rollback_dr))
    if gaps:
        return DeploymentHardeningValidation(accepted=False, reason="deployment_hardening_incomplete", gaps=tuple(gaps))
    return DeploymentHardeningValidation(accepted=True, reason="deployment_hardening_accepted")


def _network_gaps(exposure: DeploymentExposure, network: NetworkIsolationPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if exposure is DeploymentExposure.PUBLIC_INTERNET:
        gaps.append("public_internet_exposure_forbidden")
    if network.public_ingress_allowed:
        gaps.append("public_ingress_must_be_blocked_by_default")
    if not network.private_subnets:
        gaps.append("private_subnets_required")
    if not network.allowed_ingress_sources:
        gaps.append("controlled_ingress_source_required")
    if not network.egress_default_deny:
        gaps.append("egress_default_deny_required")
    if not network.runner_to_target_egress_requires_policy:
        gaps.append("runner_egress_policy_gate_required")
    return tuple(gaps)


def _tls_gaps(tls: TLSPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if not tls.internal_tls_required:
        gaps.append("internal_tls_required")
    if not tls.external_tls_required:
        gaps.append("external_tls_required")
    if tls.min_tls_version not in {"1.3", "TLS1.3"}:
        gaps.append("tls_1_3_minimum_required")
    if tls.certificate_rotation_days <= 0 or tls.certificate_rotation_days > 397:
        gaps.append("certificate_rotation_policy_required")
    return tuple(gaps)


def _admin_gaps(admin: AdminAccessPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if not admin.sso_required:
        gaps.append("admin_sso_required")
    if not admin.mfa_required:
        gaps.append("admin_mfa_required")
    if not admin.vpn_or_zero_trust_required:
        gaps.append("admin_private_access_required")
    if not admin.break_glass_users:
        gaps.append("break_glass_admin_required")
    if not admin.admin_actions_audited:
        gaps.append("admin_action_audit_required")
    return tuple(gaps)


def _backup_restore_gaps(backup: BackupRestorePlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if not backup.backups_enabled:
        gaps.append("backups_required")
    if not backup.restore_tested:
        gaps.append("restore_test_required")
    if backup.rpo_minutes <= 0:
        gaps.append("rpo_required")
    if backup.rto_minutes <= 0:
        gaps.append("rto_required")
    if not backup.evidence_refs:
        gaps.append("backup_restore_evidence_required")
    return tuple(gaps)


def _retention_gaps(retention: RetentionPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if retention.data_retention_days <= 0:
        gaps.append("data_retention_required")
    if retention.log_retention_days <= 0:
        gaps.append("log_retention_required")
    if retention.log_retention_days < retention.data_retention_days:
        gaps.append("log_retention_must_cover_data_retention")
    if not retention.legal_hold_supported:
        gaps.append("legal_hold_required")
    if not retention.retention_policy_refs:
        gaps.append("retention_policy_reference_required")
    return tuple(gaps)


def _runner_network_gaps(policy: RunnerNetworkPolicy) -> tuple[str, ...]:
    gaps: list[str] = []
    if not policy.egress_default_deny:
        gaps.append("runner_egress_default_deny_required")
    if not policy.target_allowlist_required:
        gaps.append("runner_target_allowlist_required")
    if not policy.dns_logging_required:
        gaps.append("runner_dns_logging_required")
    if not policy.emergency_shutdown_cuts_egress:
        gaps.append("runner_emergency_egress_cutoff_required")
    return tuple(gaps)


def _emergency_shutdown_gaps(plan: EmergencyShutdownPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if not plan.kill_switch_documented:
        gaps.append("kill_switch_documentation_required")
    if not plan.disables_queue_dispatch:
        gaps.append("queue_dispatch_shutdown_required")
    if not plan.revokes_runner_tokens:
        gaps.append("runner_token_revocation_required")
    if not plan.cuts_runner_egress:
        gaps.append("runner_egress_shutdown_required")
    _append_missing(gaps, "emergency_contact_method", plan.emergency_contact_method)
    return tuple(gaps)


def _least_privilege_gaps(boundaries: tuple[LeastPrivilegeBoundary, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {boundary.component for boundary in boundaries}
    missing = REQUIRED_STORAGE_COMPONENTS - present
    gaps.extend(f"missing_least_privilege_component:{component.value}" for component in sorted(missing, key=lambda item: item.value))
    for boundary in boundaries:
        if not boundary.dedicated_identity:
            gaps.append(f"dedicated_identity_required:{boundary.component.value}")
        if not boundary.read_write_scoped:
            gaps.append(f"read_write_scope_required:{boundary.component.value}")
        if not boundary.encryption_required:
            gaps.append(f"encryption_required:{boundary.component.value}")
        if not boundary.rotation_or_lifecycle_policy:
            gaps.append(f"rotation_or_lifecycle_required:{boundary.component.value}")
        if not boundary.evidence_refs:
            gaps.append(f"least_privilege_evidence_required:{boundary.component.value}")
    return tuple(gaps)


def _rollback_dr_gaps(plan: RollbackDisasterRecoveryPlan) -> tuple[str, ...]:
    gaps: list[str] = []
    if not plan.rollback_documented:
        gaps.append("rollback_documentation_required")
    if not plan.disaster_recovery_documented:
        gaps.append("disaster_recovery_documentation_required")
    if not plan.rollback_tested:
        gaps.append("rollback_test_required")
    if not plan.disaster_recovery_tested:
        gaps.append("disaster_recovery_test_required")
    if not plan.evidence_refs:
        gaps.append("rollback_dr_evidence_required")
    return tuple(gaps)


def _append_missing(gaps: list[str], field_name: str, value: str) -> None:
    if not value or not value.strip():
        gaps.append(f"missing_{field_name}")
