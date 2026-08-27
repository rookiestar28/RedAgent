"""Closed current-fact assemblers for distributed policy boundaries."""

from __future__ import annotations

from datetime import datetime
import hashlib

from redagent_platform.policy_service.contracts import PolicyBoundary, PolicyDecisionInput
from redagent_platform.policy_service.enforcement import PolicyBoundaryEnforcer, PolicyEnforcementResult
from redagent_platform.policy_service.providers import PolicyProviderReadiness


class PolicyBoundarySDK:
    def __init__(self, enforcer: PolicyBoundaryEnforcer, *, required_revision: str) -> None:
        if enforcer is None or not isinstance(required_revision, str) or not required_revision:
            raise ValueError("policy_boundary_sdk_config_invalid")
        self._enforcer = enforcer
        self.required_revision = required_revision

    async def assess_readiness(self) -> PolicyProviderReadiness:
        return await self._enforcer.assess_readiness(required_revision=self.required_revision)

    async def enforce_api(
        self, *, tenant_id: str, subject_id: str, roles: tuple[str, ...],
        permissions: tuple[str, ...], action: str, resource_type: str, resource_id: str,
        resource_version: int | None, policy_reference: str, roe_version_id: str | None,
        correlation_id: str, requested_at: datetime,
    ) -> PolicyEnforcementResult:
        attributes: dict[str, object] = {"permission_count": len(permissions)}
        if resource_version is not None:
            attributes["resource_version"] = resource_version
        return await self._enforce(
            PolicyBoundary.API, action=action, tenant_id=tenant_id, subject_id=subject_id,
            roles=roles, permissions=permissions, resource_type=resource_type,
            resource_id=resource_id, policy_reference=policy_reference,
            roe_version_id=roe_version_id, correlation_id=correlation_id,
            requested_at=requested_at, attributes=attributes,
        )

    async def enforce_workflow(
        self, *, tenant_id: str, subject_id: str, action: str, job_id: str,
        job_status: str, expected_version: int, dispatch_blocked: bool,
        policy_reference: str, roe_version_id: str, roe_status: str,
        correlation_id: str, requested_at: datetime,
    ) -> PolicyEnforcementResult:
        return await self._enforce(
            PolicyBoundary.WORKFLOW, action=action, tenant_id=tenant_id,
            subject_id=subject_id, roles=("workflow-service",),
            permissions=("workflow:command",), resource_type="job", resource_id=job_id,
            policy_reference=policy_reference, roe_version_id=roe_version_id,
            correlation_id=correlation_id, requested_at=requested_at,
            attributes={
                "job_status": job_status, "expected_version": expected_version,
                "dispatch_blocked": dispatch_blocked, "roe_status": roe_status,
            },
        )

    async def enforce_evidence(
        self, *, tenant_id: str, subject_id: str, action: str, artifact_id: str,
        artifact_class: str, classification: str, legal_hold: bool,
        policy_reference: str, roe_version_id: str, correlation_id: str,
        requested_at: datetime,
    ) -> PolicyEnforcementResult:
        return await self._enforce(
            PolicyBoundary.EVIDENCE, action=action, tenant_id=tenant_id,
            subject_id=subject_id, roles=("evidence-service",),
            permissions=("evidence:write",), resource_type="evidence", resource_id=artifact_id,
            policy_reference=policy_reference, roe_version_id=roe_version_id,
            correlation_id=correlation_id, requested_at=requested_at,
            attributes={
                "artifact_class": artifact_class, "classification": classification,
                "legal_hold": legal_hold,
            },
        )

    async def enforce_secret(
        self, *, tenant_id: str, subject_id: str, action: str, lease_id: str,
        reference_status: str, lease_state: str, renewable: bool,
        revoke_pending: bool, permission_digest: str, permission_count: int,
        workload_client_status: str, policy_reference: str, roe_version_id: str,
        correlation_id: str, requested_at: datetime,
    ) -> PolicyEnforcementResult:
        return await self._enforce(
            PolicyBoundary.SECRET, action=action, tenant_id=tenant_id,
            subject_id=subject_id, roles=("secret-service",),
            permissions=("secret:lease",), resource_type="secret_lease", resource_id=lease_id,
            policy_reference=policy_reference, roe_version_id=roe_version_id,
            correlation_id=correlation_id, requested_at=requested_at,
            attributes={
                "reference_status": reference_status, "lease_state": lease_state,
                "renewable": renewable, "revoke_pending": revoke_pending,
                "permission_digest": permission_digest, "permission_count": permission_count,
                "workload_client_status": workload_client_status,
            },
        )

    async def enforce_runner(
        self, *, tenant_id: str, subject_id: str, action: str,
        permissions: tuple[str, ...], job_id: str, registration_state: str,
        capability_status: str, artifact_status: str, manifest_state: str,
        lease_state: str, identity_generation: int, runner_generation: int,
        sandbox_status: str, cleanup_required: bool,
        policy_reference: str, roe_version_id: str, correlation_id: str,
        requested_at: datetime,
    ) -> PolicyEnforcementResult:
        # CRITICAL: runner authorization is rebuilt from current state at every side-effect boundary.
        return await self._enforce(
            PolicyBoundary.RUNNER, action=action, tenant_id=tenant_id,
            subject_id=subject_id, roles=("runner-service",), permissions=permissions,
            resource_type="runner_job", resource_id=job_id,
            policy_reference=policy_reference, roe_version_id=roe_version_id,
            correlation_id=correlation_id, requested_at=requested_at,
            attributes={
                "registration_state": registration_state,
                "capability_status": capability_status,
                "artifact_status": artifact_status,
                "manifest_state": manifest_state,
                "lease_state": lease_state,
                "identity_generation": identity_generation,
                "runner_generation": runner_generation,
                "sandbox_status": sandbox_status,
                "cleanup_required": cleanup_required,
            },
        )

    async def _enforce(
        self, boundary: PolicyBoundary, *, action: str, tenant_id: str,
        subject_id: str, roles: tuple[str, ...], permissions: tuple[str, ...],
        resource_type: str, resource_id: str, policy_reference: str,
        roe_version_id: str | None, correlation_id: str, requested_at: datetime,
        attributes: dict[str, object],
    ) -> PolicyEnforcementResult:
        request = PolicyDecisionInput(
            boundary=boundary, action=action, tenant_id=tenant_id, subject_id=subject_id,
            roles=roles, permissions=permissions, resource_type=resource_type,
            resource_id=resource_id, policy_reference=policy_reference,
            roe_version_id=roe_version_id, correlation_id=correlation_id,
            requested_at=requested_at, attributes=attributes,
        )
        lineage = hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:24]
        operation = f"{boundary.value}.{action[:48]}.{lineage}"
        return await self._enforcer.enforce(
            request, required_revision=self.required_revision,
            operation=operation, now=requested_at,
        )
