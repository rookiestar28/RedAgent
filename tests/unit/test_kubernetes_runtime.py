from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    cloud_posture,
    cloud_runtime,
    credentials,
    domain,
    evidence_chain,
    job_queue,
    kubernetes_runtime,
    supply_chain,
)
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.target_inventory import EnvironmentType


NOW = datetime(2026, 7, 9, 19, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.KUBERNETES_CLUSTER, value="cluster-1")


def cloud_scope(**overrides: object) -> cloud_posture.CloudScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.KUBERNETES,
        "environment": EnvironmentType.TEST,
        "account_ids": (),
        "project_ids": (),
        "subscription_ids": (),
        "cluster_ids": ("cluster-1",),
        "regions": (),
        "owner_approved_by_user_id": "lead-1",
        "credential_reference_id": "cred-ref-kube",
        "allowed_read_permissions": ("kube:read",),
        "monthly_cost_estimate_usd": 0.0,
        "blast_radius_reviewed": True,
    }
    values.update(overrides)
    return cloud_posture.CloudScope(**values)  # type: ignore[arg-type]


def posture_request(**overrides: object) -> cloud_posture.CloudPostureRequest:
    values = {
        "job_id": "kube-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.KUBERNETES,
        "mode": cloud_posture.CloudPostureMode.READ_ONLY_POSTURE,
        "requested_at": NOW,
        "target_id": "cluster-1",
        "requested_permissions": ("kube:read",),
        "credential_boundary": None,
    }
    values.update(overrides)
    return cloud_posture.CloudPostureRequest(**values)  # type: ignore[arg-type]


def cloud_profile(**overrides: object) -> cloud_runtime.CloudRuntimeProfile:
    values = {
        "profile_id": "kubernetes-cloud-runtime-profile",
        "module_id": "cloud-runtime",
        "allowed_providers": (cloud_posture.CloudProvider.KUBERNETES,),
        "allowed_modes": (cloud_posture.CloudPostureMode.READ_ONLY_POSTURE,),
        "max_monthly_cost_usd": 1.0,
        "max_api_calls": 10,
        "max_results": 20,
        "timeout_seconds": 120,
        "actions": (
            cloud_runtime.CloudRuntimeAction.READ_POSTURE,
            cloud_runtime.CloudRuntimeAction.IMPORT_RESULTS,
        ),
    }
    values.update(overrides)
    return cloud_runtime.CloudRuntimeProfile(**values)  # type: ignore[arg-type]


def lease(**overrides: object) -> credentials.CredentialLease:
    values = {
        "id": "lease-kube",
        "credential_reference_id": "cred-ref-kube",
        "job_id": "kube-job-1",
        "runner_id": "runner-1",
        "target": TARGET,
        "mode": domain.TestMode.CLOUD_TECHNIQUE,
        "scoped_permissions": ("kube:read",),
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "credential:kube-readonly",
    }
    values.update(overrides)
    return credentials.CredentialLease(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.CLOUD_TECHNIQUE,),
        "policy_token_reference": "policy-ref-kube",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "kubernetes_findings", "kubernetes_report_rows"),
        "cleanup_callback": "cleanup://runner-1/kubernetes-runtime",
        "credential_lease_id": "lease-kube",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def cloud_request(**overrides: object) -> cloud_runtime.CloudRuntimeRequest:
    values = {
        "runtime_id": "kubernetes-runtime-1:cloud",
        "profile": cloud_profile(),
        "scope": cloud_scope(),
        "posture_request": posture_request(),
        "runner": runner(),
        "credential_lease": lease(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return cloud_runtime.CloudRuntimeRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> kubernetes_runtime.KubernetesRuntimeProfile:
    values = {
        "profile_id": "kubernetes-runtime-profile",
        "module_id": "kubernetes-runtime",
        "allowed_cluster_ids": ("cluster-1",),
        "allowed_namespaces": ("default", "payments"),
        "allow_all_namespaces": False,
        "max_results": 20,
        "timeout_seconds": 120,
        "actions": (
            kubernetes_runtime.KubernetesRuntimeAction.IMPORT_BENCHMARK_RESULTS,
            kubernetes_runtime.KubernetesRuntimeAction.IMPORT_CONTAINER_METADATA,
            kubernetes_runtime.KubernetesRuntimeAction.IMPORT_IAC_RESULTS,
        ),
    }
    values.update(overrides)
    return kubernetes_runtime.KubernetesRuntimeProfile(**values)  # type: ignore[arg-type]


def repository(**overrides: object) -> supply_chain.RepositoryAllowlistEntry:
    values = {
        "repository_id": "repo-1",
        "repository_path": "B:/owned/repo",
        "owner_user_id": "owner-1",
        "trusted": True,
    }
    values.update(overrides)
    return supply_chain.RepositoryAllowlistEntry(**values)  # type: ignore[arg-type]


def iac_scope(**overrides: object) -> supply_chain.SupplyChainScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "repositories": (repository(),),
        "pipelines": (),
        "external_verification_approved": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainScope(**values)  # type: ignore[arg-type]


def iac_request(**overrides: object) -> supply_chain.SupplyChainAssessmentRequest:
    values = {
        "job_id": "iac-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "repository_id": "repo-1",
        "pipeline_id": None,
        "check_kinds": (supply_chain.SupplyChainCheckKind.STATIC_ANALYSIS,),
        "requested_at": NOW,
        "external_verification_requested": False,
    }
    values.update(overrides)
    return supply_chain.SupplyChainAssessmentRequest(**values)  # type: ignore[arg-type]


def runtime_request(**overrides: object) -> kubernetes_runtime.KubernetesRuntimeRequest:
    values = {
        "runtime_id": "kubernetes-runtime-1",
        "profile": profile(),
        "cloud_request": cloud_request(),
        "namespaces": ("default", "payments"),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "iac_scope": iac_scope(),
        "iac_request": iac_request(),
    }
    values.update(overrides)
    return kubernetes_runtime.KubernetesRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[kubernetes_runtime.KubernetesRuntimeResultItem, ...]:
    return (
        kubernetes_runtime.KubernetesRuntimeResultItem(
            item_id="bench-fail",
            kind=kubernetes_runtime.KubernetesRuntimeResultKind.BENCHMARK,
            resource_id="cluster-1:api-server",
            namespace=None,
            summary="Sanitized benchmark failure.",
            remediation_guidance="Set the API server audit policy according to the benchmark.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            contains_sensitive_material=True,
            benchmark_status=kubernetes_runtime.KubernetesBenchmarkStatus.FAIL,
            kubernetes_area=cloud_posture.KubernetesFindingArea.CONTROL_PLANE,
        ),
        kubernetes_runtime.KubernetesRuntimeResultItem(
            item_id="bench-warn",
            kind=kubernetes_runtime.KubernetesRuntimeResultKind.BENCHMARK,
            resource_id="cluster-1:namespace/payments",
            namespace="payments",
            summary="Sanitized benchmark warning.",
            remediation_guidance="Review namespace default limits.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            benchmark_status=kubernetes_runtime.KubernetesBenchmarkStatus.WARN,
            kubernetes_area=cloud_posture.KubernetesFindingArea.NAMESPACE,
        ),
        kubernetes_runtime.KubernetesRuntimeResultItem(
            item_id="image-1",
            kind=kubernetes_runtime.KubernetesRuntimeResultKind.CONTAINER_IMAGE,
            resource_id="cluster-1:deployment/payments/api",
            namespace="payments",
            summary="Sanitized image metadata.",
            remediation_guidance="Pin image digest and review base image provenance.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            severity=kubernetes_runtime.Severity.MEDIUM,
            image_ref="registry.example.test/payments/api@sha256:abc123",
        ),
        kubernetes_runtime.KubernetesRuntimeResultItem(
            item_id="iac-1",
            kind=kubernetes_runtime.KubernetesRuntimeResultKind.IAC_FILE,
            resource_id="repo-1:k8s/deployment.yaml",
            namespace="payments",
            summary="Sanitized IaC finding.",
            remediation_guidance="Set readOnlyRootFilesystem in the workload security context.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            contains_sensitive_material=True,
            severity=kubernetes_runtime.Severity.HIGH,
            iac_file_path="k8s/deployment.yaml",
            repository_id="repo-1",
        ),
    )


def test_plan_requires_cluster_allowlist_namespace_scope_and_read_only_credential() -> None:
    plan = kubernetes_runtime.build_kubernetes_runtime_plan(runtime_request())

    assert plan.cluster_id == "cluster-1"
    assert plan.namespaces == ("default", "payments")
    assert plan.cloud_plan.target == TARGET.normalized()

    with pytest.raises(ValueError, match="cloud_runtime_target_not_allowlisted"):
        kubernetes_runtime.build_kubernetes_runtime_plan(
            runtime_request(cloud_request=cloud_request(posture_request=posture_request(target_id="cluster-2")))
        )

    with pytest.raises(ValueError, match="kubernetes_namespace_not_allowlisted"):
        kubernetes_runtime.build_kubernetes_runtime_plan(runtime_request(namespaces=("kube-system",)))

    with pytest.raises(ValueError, match="cloud_runtime_read_only_credential_required"):
        kubernetes_runtime.build_kubernetes_runtime_plan(
            runtime_request(cloud_request=cloud_request(credential_lease=lease(scoped_permissions=("kube:update",))))
        )


def test_runtime_rejects_live_or_mutating_kubernetes_actions() -> None:
    with pytest.raises(ValueError, match="kubernetes_mutating_or_live_action_not_allowed"):
        kubernetes_runtime.build_kubernetes_runtime_plan(
            runtime_request(profile=profile(actions=(kubernetes_runtime.KubernetesRuntimeAction.RUN_KUBE_BENCH,)))
        )

    with pytest.raises(ValueError, match="kubernetes_all_namespaces_not_allowed"):
        kubernetes_runtime.build_kubernetes_runtime_plan(runtime_request(namespaces=("*",)))


def test_iac_checks_require_trusted_local_repository_unless_external_is_approved() -> None:
    with pytest.raises(ValueError, match="iac_assessment_denied:trusted_repository_required"):
        kubernetes_runtime.build_kubernetes_runtime_plan(
            runtime_request(iac_scope=iac_scope(repositories=(repository(trusted=False),)))
        )

    with pytest.raises(ValueError, match="iac_assessment_denied:external_verification_not_approved"):
        kubernetes_runtime.build_kubernetes_runtime_plan(
            runtime_request(iac_request=iac_request(external_verification_requested=True))
        )

    approved = kubernetes_runtime.build_kubernetes_runtime_plan(
        runtime_request(
            iac_scope=iac_scope(external_verification_approved=True),
            iac_request=iac_request(external_verification_requested=True),
        )
    )

    assert not approved.iac_local_only


def test_runtime_imports_benchmark_container_and_iac_results_with_report_mapping() -> None:
    request = runtime_request()
    plan = kubernetes_runtime.build_kubernetes_runtime_plan(request)
    result = kubernetes_runtime.execute_kubernetes_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.cloud_plan.job,)),
        runner=request.cloud_request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert len(result.imported_evidence_ids) == 4
    assert len(result.findings) == 4
    assert len(result.report_rows) == 4
    assert result.report_rows[0].benchmark_status is kubernetes_runtime.KubernetesBenchmarkStatus.FAIL
    assert result.report_rows[0].severity is kubernetes_runtime.Severity.HIGH
    assert result.report_rows[1].benchmark_status is kubernetes_runtime.KubernetesBenchmarkStatus.WARN
    assert result.report_rows[1].severity is kubernetes_runtime.Severity.MEDIUM
    assert result.report_rows[2].image_ref == "registry.example.test/payments/api@sha256:abc123"
    assert result.report_rows[3].iac_file_path == "k8s/deployment.yaml"
    assert result.report_rows[3].control_domain is cloud_posture.CloudControlDomain.IAC_CONFIGURATION
    assert result.findings[0].source == "kubernetes_runtime"


def test_sensitive_kubernetes_result_requires_redaction_before_import() -> None:
    request = runtime_request()
    plan = kubernetes_runtime.build_kubernetes_runtime_plan(request)
    unsafe_item = kubernetes_runtime.KubernetesRuntimeResultItem(
        item_id="unsafe",
        kind=kubernetes_runtime.KubernetesRuntimeResultKind.BENCHMARK,
        resource_id="cluster-1:secret-like-config",
        namespace="payments",
        summary="Sensitive benchmark output.",
        remediation_guidance="Remove sensitive values from benchmark evidence.",
        evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        contains_sensitive_material=True,
        benchmark_status=kubernetes_runtime.KubernetesBenchmarkStatus.INFO,
        kubernetes_area=cloud_posture.KubernetesFindingArea.SENSITIVE_CONFIGURATION,
    )

    with pytest.raises(ValueError, match="kubernetes_sensitive_result_requires_redaction"):
        kubernetes_runtime.execute_kubernetes_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.cloud_plan.job,)),
            runner=request.cloud_request.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(unsafe_item,),
        )


def test_kill_switch_blocks_dispatch_and_cancellation_revokes_kubeconfig_lease() -> None:
    request = runtime_request()
    plan = kubernetes_runtime.build_kubernetes_runtime_plan(request)
    blocked = kubernetes_runtime.execute_kubernetes_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.cloud_plan.job,)),
        runner=request.cloud_request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=kubernetes_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.CLOUD_TECHNIQUE,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = kubernetes_runtime.execute_kubernetes_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.cloud_plan.job,)),
        runner=request.cloud_request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
        credential_broker=credentials.CredentialBroker(),
        credential_lease=request.cloud_request.credential_lease,
    )

    assert cancelled.allowed
    assert cancelled.reason == "cancelled"
    assert cancelled.cancellation_evidence[0].credential_revoked
