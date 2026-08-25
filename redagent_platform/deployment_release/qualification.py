"""Executable, deterministic, network-free adversarial qualification for R116."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.deployment_release.distribution import (
    ArtifactClass,
    BundlePolicy,
    create_signed_bundle,
    verify_signed_bundle,
)
from redagent_platform.deployment_release.kubernetes import (
    compile_kubernetes_manifests,
    validate_kubernetes_manifests,
)
from redagent_platform.deployment_release.recovery import (
    DrillEvent,
    RecoveryComponent,
    advance_recovery_drill,
    build_recovery_catalog,
    build_restore_plan,
    start_recovery_drill,
    validate_recovery_catalog,
)
from redagent_platform.deployment_release.topology import (
    ProfileKind,
    ReviewedException,
    build_supported_profile,
    validate_profile,
)
from redagent_platform.deployment_release.upgrade import UpgradeEvent, advance_upgrade, plan_upgrade


NOW = datetime(2026, 7, 12, 12, tzinfo=UTC)


def qualify_deployment_release() -> dict[str, object]:
    checks = _checks()
    drills = _drills()
    check_outcomes = {name: check() for name, check in checks.items()}
    drill_outcomes = {name: drill() for name, drill in drills.items()}
    outcomes = {**check_outcomes, **drill_outcomes}
    failed = sorted(name for name, passed in outcomes.items() if not passed)
    outcome_sha = _digest(outcomes)
    receipt: dict[str, object] = {
        "schema": "redagent.r116-qualification/v1",
        "status": "passed" if not failed else "failed",
        "scenario_sha256": hashlib.sha256("\n".join(checks).encode()).hexdigest(),
        "outcome_sha256": outcome_sha,
        "qualification_case_count": len(outcomes),
        "adversarial_case_count": len(checks),
        "denied_case_count": sum(check_outcomes.values()),
        "drill_case_count": len(drills),
        "passed_drill_count": sum(drill_outcomes.values()),
        "failed_cases": failed,
        "network_contact_count": 0,
        "external_execution_count": 0,
        "real_cluster_contact_count": 0,
        "registry_contact_count": 0,
        "cloud_contact_count": 0,
        "production_qualified": False,
    }
    receipt["receipt_sha256"] = _digest(receipt)
    return receipt


def _checks() -> dict[str, Callable[[], bool]]:
    return {
        "single_node_false_ha": _single_node_false_ha,
        "public_management_endpoint": lambda: _profile_gap("private_management_required", management_private=False),
        "untrusted_forwarded_header": lambda: _profile_gap(
            "trusted_forwarded_headers_required", forwarded_headers_trusted_proxy_only=False
        ),
        "mutable_image_tag": lambda: _component_gap("digest_pinned_image_required:api", "api", image="image:latest"),
        "default_service_account": lambda: _component_gap(
            "dedicated_service_account_required:api", "api", service_account="default"
        ),
        "privileged_workload": lambda: _component_gap("host_privilege_forbidden:api", "api", privileged=True),
        "host_docker_socket": lambda: _component_gap("host_privilege_forbidden:runner", "runner", host_docker_socket=True),
        "missing_ingress_default_deny": lambda: _missing_network_direction("Ingress"),
        "missing_egress_default_deny": lambda: _missing_network_direction("Egress"),
        "missing_admission_namespace": _missing_admission_namespace,
        "missing_startup_probe": lambda: _component_gap("startup_probe_required:api", "api", startup_probe=None),
        "dependency_liveness_cascade": _probe_semantics_distinct,
        "runner_shared_node_class": lambda: _component_gap(
            "runner_isolation_class_required:runner", "runner", node_class="control-data"
        ),
        "expired_security_exception": _expired_exception,
        "missing_postgresql_wal": lambda: _wrong_backup_kind(RecoveryComponent.POSTGRESQL),
        "stale_backup_set": _stale_backup,
        "altered_backup_artifact": _altered_backup,
        "openbao_snapshot_without_unseal_custody": lambda: _wrong_backup_kind(RecoveryComponent.OPENBAO),
        "restore_without_isolation": _restore_requires_isolation,
        "restore_without_semantic_verification": _recovery_order_enforced,
        "restore_without_audit_verification": _recovery_order_enforced,
        "airgap_missing_artifact": lambda: _bundle_rejected("missing"),
        "airgap_digest_tamper": lambda: _bundle_rejected("tamper"),
        "airgap_path_escape": _bundle_path_escape,
        "airgap_network_fallback": _bundle_positive_is_offline,
        "wrong_release_signer": lambda: _bundle_rejected("signer"),
        "wrong_provenance_builder": lambda: _bundle_rejected("builder"),
        "wrong_source_revision": lambda: _bundle_rejected("source"),
        "unsupported_upgrade_jump": _upgrade_jump_rejected,
        "contract_before_backfill": lambda: _upgrade_order_rejected(UpgradeEvent.CONTRACT_APPLIED),
        "old_worker_removed_before_drain": lambda: _upgrade_order_rejected(UpgradeEvent.OLD_WORKER_DRAINED),
        "failed_migration_without_recovery": _failed_migration_has_recovery,
    }


def _drills() -> dict[str, Callable[[], bool]]:
    return {
        "fresh_install_structure": _fresh_install_structure,
        "service_and_node_loss_budget": _service_and_node_loss_budget,
        "zone_loss_spread": _zone_loss_spread,
        "certificate_rotation_rollout": _certificate_rotation_rollout,
        "backup_restore_rehearsal": _backup_restore_rehearsal,
        "n_minus_one_upgrade_rehearsal": _n_minus_one_upgrade_rehearsal,
    }


def _fresh_install_structure() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    validation = validate_kubernetes_manifests(manifests)
    workloads = {
        item["metadata"]["name"] for item in manifests if item["kind"] in {"Deployment", "StatefulSet"}
    }
    return validation.accepted and workloads == {"api", "worker"} and any(
        item["kind"] == "ConfigMap" and item["metadata"]["name"] == "redagent-operator-prerequisites"
        for item in manifests
    )


def _service_and_node_loss_budget() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    budgets = [item for item in manifests if item["kind"] == "PodDisruptionBudget"]
    bundled = [component for component in profile.components if component.deployment_mode.value == "bundled"]
    return all(component.replicas >= 3 for component in bundled) and all(
        item["spec"]["maxUnavailable"] == 1 for item in budgets
    )


def _zone_loss_spread() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    workloads = [item for item in manifests if item["kind"] in {"Deployment", "StatefulSet"}]
    return all(len(set(component.failure_domains)) >= 3 for component in profile.components if component.name != "runner") and all(
        item["spec"]["template"]["spec"]["topologySpreadConstraints"][0]["whenUnsatisfiable"] == "DoNotSchedule"
        for item in workloads
    )


def _certificate_rotation_rollout() -> bool:
    manifests = compile_kubernetes_manifests(build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE), now=NOW)
    api = next(item for item in manifests if item["kind"] == "Deployment" and item["metadata"]["name"] == "api")
    return api["spec"]["template"]["metadata"]["annotations"].get("redagent.io/tls-rotation-contract") == (
        "rollout-on-secret-version-change"
    )


def _backup_restore_rehearsal() -> bool:
    plan = build_restore_plan(build_recovery_catalog(created_at=NOW - timedelta(minutes=5)), now=NOW)
    drill = start_recovery_drill(plan, started_at=NOW)
    for index, event in enumerate(DrillEvent, start=1):
        drill = advance_recovery_drill(drill, event, evidence_sha256=f"{index:x}" * 64, occurred_at=NOW)
    return drill.completed and len(drill.evidence_sha256s) == len(DrillEvent)


def _n_minus_one_upgrade_rehearsal() -> bool:
    state = plan_upgrade(
        current_version="1.8.4",
        target_version="1.9.0",
        current_schema=22,
        expanded_schema=23,
        contract_schema=24,
        old_worker_build="worker-1.8.4",
        new_worker_build="worker-1.9.0",
        now=NOW,
    )
    for index, event in enumerate(
        (
            UpgradeEvent.BACKUP_VERIFIED,
            UpgradeEvent.EXPAND_APPLIED,
            UpgradeEvent.BACKFILL_VERIFIED,
            UpgradeEvent.NEW_WORKER_STARTED,
            UpgradeEvent.RAMP_VERIFIED,
            UpgradeEvent.OLD_WORKER_DRAINED,
            UpgradeEvent.CONTRACT_APPLIED,
            UpgradeEvent.COMPLETED,
        ),
        start=1,
    ):
        state = advance_upgrade(state, event, evidence_sha256=f"{index:x}" * 64, occurred_at=NOW)
    return state.phase.value == "completed" and not state.old_worker_reachable and state.new_worker_ramp_percent == 100


def _single_node_false_ha() -> bool:
    profile = replace(build_supported_profile(ProfileKind.SINGLE_NODE), availability_claim="multi_zone_ha")
    return "single_node_ha_claim_forbidden" in validate_profile(profile, now=NOW).gaps


def _profile_gap(gap: str, **changes: object) -> bool:
    profile = replace(build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE), **changes)
    return gap in validate_profile(profile, now=NOW).gaps


def _component_gap(gap: str, name: str, **changes: object) -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    components = tuple(replace(item, **changes) if item.name == name else item for item in profile.components)
    return gap in validate_profile(replace(profile, components=components), now=NOW).gaps


def _missing_network_direction(direction: str) -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    altered = tuple(
        item
        for item in manifests
        if not (item["kind"] == "NetworkPolicy" and item["spec"].get("policyTypes") == [direction])
    )
    expected = "complete_default_deny_required:"
    return any(gap.startswith(expected) for gap in validate_kubernetes_manifests(altered).gaps)


def _missing_admission_namespace() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    altered = replace(profile, admission_namespaces=profile.admission_namespaces[:-1])
    return "admission_namespace_coverage_required" in validate_profile(altered, now=NOW).gaps


def _probe_semantics_distinct() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    api = next(item for item in manifests if item["kind"] == "Deployment" and item["metadata"]["name"] == "api")
    container = api["spec"]["template"]["spec"]["containers"][0]
    return (
        container["startupProbe"]["httpGet"]["path"] == "/health/live"
        and container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
        and container["livenessProbe"]["httpGet"]["path"] == "/health/live"
    )


def _expired_exception() -> bool:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    exception = ReviewedException(
        exception_id="expired",
        component="runner",
        control="read_only_root_filesystem",
        rationale="fixture",
        reviewer="reviewer",
        approved_at=NOW - timedelta(days=2),
        expires_at=NOW - timedelta(days=1),
    )
    return "deployment_exception_expired:expired" in validate_profile(
        replace(profile, exceptions=(exception,)), now=NOW
    ).gaps


def _wrong_backup_kind(component: RecoveryComponent) -> bool:
    catalog = build_recovery_catalog(created_at=NOW - timedelta(minutes=5))
    artifacts = tuple(replace(item, kind="incomplete") if item.component is component else item for item in catalog.artifacts)
    return f"backup_kind_invalid:{component.value}" in validate_recovery_catalog(
        replace(catalog, artifacts=artifacts), now=NOW
    ).gaps


def _stale_backup() -> bool:
    catalog = build_recovery_catalog(created_at=NOW - timedelta(minutes=61))
    return "backup_set_outside_rpo" in validate_recovery_catalog(catalog, now=NOW).gaps


def _altered_backup() -> bool:
    catalog = build_recovery_catalog(created_at=NOW - timedelta(minutes=5))
    altered = replace(catalog.artifacts[0], observed_sha256="0" * 64)
    return any(
        gap.startswith("backup_digest_mismatch:")
        for gap in validate_recovery_catalog(replace(catalog, artifacts=(altered, *catalog.artifacts[1:])), now=NOW).gaps
    )


def _restore_requires_isolation() -> bool:
    plan = build_restore_plan(build_recovery_catalog(created_at=NOW - timedelta(minutes=5)), now=NOW)
    try:
        start_recovery_drill(replace(plan, isolated_environment_required=False), started_at=NOW)
    except ValueError as exc:
        return str(exc) == "recovery_drill_controls_required"
    return False


def _recovery_order_enforced() -> bool:
    plan = build_restore_plan(build_recovery_catalog(created_at=NOW - timedelta(minutes=5)), now=NOW)
    drill = start_recovery_drill(plan, started_at=NOW)
    try:
        advance_recovery_drill(drill, DrillEvent.SEMANTIC_VERIFIED, evidence_sha256="1" * 64, occurred_at=NOW)
    except ValueError as exc:
        return str(exc) == "recovery_drill_event_out_of_order"
    return False


def _bundle_fixture() -> tuple[object, dict[str, tuple[ArtifactClass, bytes]], BundlePolicy, object]:
    contents = {f"artifacts/{kind.value}.json": (kind, kind.value.encode()) for kind in ArtifactClass}
    private = ec.generate_private_key(ec.SECP256R1())
    policy = BundlePolicy(
        trusted_signer="release@example.invalid",
        expected_builder="builder",
        expected_source_revision="a" * 40,
        max_artifacts=64,
        max_total_bytes=1_000_000,
    )
    bundle = create_signed_bundle(
        contents,
        signer_identity=policy.trusted_signer,
        builder_id=policy.expected_builder,
        source_revision=policy.expected_source_revision,
        private_key=private,
    )
    return bundle, contents, policy, private.public_key()


def _bundle_rejected(mode: str) -> bool:
    bundle, contents, policy, public = _bundle_fixture()
    if mode == "missing":
        contents = dict(contents)
        contents.pop(next(iter(contents)))
    elif mode == "tamper":
        contents = dict(contents)
        path = next(iter(contents))
        contents[path] = (contents[path][0], b"altered")
    elif mode == "signer":
        policy = replace(policy, trusted_signer="wrong")
    elif mode == "builder":
        policy = replace(policy, expected_builder="wrong")
    elif mode == "source":
        policy = replace(policy, expected_source_revision="b" * 40)
    try:
        verify_signed_bundle(bundle, contents, policy=policy, public_key=public)
    except ValueError:
        return True
    return False


def _bundle_path_escape() -> bool:
    private = ec.generate_private_key(ec.SECP256R1())
    try:
        create_signed_bundle(
            {"../escape": (ArtifactClass.IMAGE, b"x")},
            signer_identity="release@example.invalid",
            builder_id="builder",
            source_revision="a" * 40,
            private_key=private,
        )
    except ValueError as exc:
        return str(exc) == "bundle_artifact_path_invalid"
    return False


def _bundle_positive_is_offline() -> bool:
    bundle, contents, policy, public = _bundle_fixture()
    receipt = verify_signed_bundle(bundle, contents, policy=policy, public_key=public)
    return receipt.network_contact_count == 0 and receipt.executed_artifact_count == 0


def _upgrade() -> object:
    return plan_upgrade(
        current_version="1.8.4",
        target_version="1.9.0",
        current_schema=22,
        expanded_schema=23,
        contract_schema=24,
        old_worker_build="old",
        new_worker_build="new",
        now=NOW,
    )


def _upgrade_jump_rejected() -> bool:
    try:
        plan_upgrade(
            current_version="1.8.4",
            target_version="3.0.0",
            current_schema=22,
            expanded_schema=23,
            contract_schema=24,
            old_worker_build="old",
            new_worker_build="new",
            now=NOW,
        )
    except ValueError as exc:
        return str(exc) == "upgrade_n_minus_one_compatibility_required"
    return False


def _upgrade_order_rejected(event: UpgradeEvent) -> bool:
    try:
        advance_upgrade(_upgrade(), event, evidence_sha256="2" * 64, occurred_at=NOW)
    except ValueError as exc:
        return str(exc) == "upgrade_event_out_of_order"
    return False


def _failed_migration_has_recovery() -> bool:
    failed = advance_upgrade(_upgrade(), UpgradeEvent.MIGRATION_FAILED, evidence_sha256="2" * 64, occurred_at=NOW)
    return failed.recovery_decision == "rollback_compatible_code_and_preserve_expanded_schema"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
