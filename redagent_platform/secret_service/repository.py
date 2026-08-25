"""Transactional metadata boundary for compat_098 credential leases."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update

from redagent_platform.persistence.models import metadata
from redagent_platform.secret_service.contracts import (
    LeaseIssueRequest,
    ProviderLeaseEnvelope,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceStatus,
    WorkloadClient,
    effective_lease_expiry,
)


@dataclass(frozen=True, slots=True)
class LeaseReservation:
    operation_id: str
    role_reference: str
    workload_client_id: str
    attestation_fingerprint: str
    effective_expires_at: datetime
    replayed: bool
    lease: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class LeaseRenewalReservation:
    provider_lease_reference: str
    effective_expires_at: datetime
    lease: dict[str, object]


@dataclass(frozen=True, slots=True)
class LeaseRevocationReservation:
    provider_lease_reference: str
    lease: dict[str, object]
    already_terminal: bool


class SecretLeaseConflict(RuntimeError):
    """The requested lease operation conflicts with persisted control-plane truth."""


class TransactionalSecretLeaseStore:
    """Owns short PostgreSQL transactions; credential material never enters this type."""

    def __init__(self, session_factory) -> None:
        self.session_factory = session_factory

    async def current_issue_policy_facts(
        self, request: LeaseIssueRequest, *, actor_user_id: str,
    ) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, request.tenant_id)
            reference, workload = await _load_scope(session, request, actor_user_id)
            permission_digest = hashlib.sha256(
                "\n".join(sorted(request.requested_permissions)).encode("utf-8")
            ).hexdigest()
            return {
                "reference_status": reference.status.value,
                "lease_state": "pending",
                "renewable": True,
                "revoke_pending": False,
                "permission_digest": permission_digest,
                "permission_count": len(request.requested_permissions),
                "workload_client_status": "revoked" if workload.revoked_at is not None else "active",
            }

    async def current_lease_policy_facts(self, *, tenant_id: str, lease_id: str) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            lease = await _get_lease(session, tenant_id, lease_id)
            if lease is None:
                raise SecretLeaseConflict("secret_lease_not_found")
            references = metadata.tables["secret_references"]
            reference_status = await session.scalar(select(references.c.reference_status).where(
                references.c.tenant_id == tenant_id,
                references.c.id == lease["reference_id"],
            ))
            clients = metadata.tables["secret_workload_clients"]
            client = (
                await session.execute(select(clients).where(
                    clients.c.tenant_id == tenant_id,
                    clients.c.id == lease["workload_client_id"],
                ))
            ).mappings().one_or_none()
            return {
                "reference_status": str(reference_status or "missing"),
                "lease_state": str(lease["lease_state"]),
                "renewable": bool(lease["renewable"]),
                "revoke_pending": lease["lease_state"] == "revoke_pending",
                "permission_digest": str(lease["permission_digest"]),
                "permission_count": int(lease["permission_count"]),
                "workload_client_status": "missing" if client is None else "revoked" if client["revoked_at"] is not None else "active",
                "policy_reference": str(lease["policy_reference"]),
                "roe_version_id": str(lease["roe_version_id"]),
            }

    async def register_reference(
        self,
        reference: SecretReference,
        *,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, object]:
        if reference.owner_user_id != actor_user_id:
            raise SecretLeaseConflict("secret_reference_owner_mismatch")
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, reference.tenant_id)
            table = metadata.tables["secret_references"]
            existing = (
                await session.execute(select(table).where(table.c.tenant_id == reference.tenant_id, table.c.id == reference.reference_id))
            ).mappings().one_or_none()
            if existing is not None:
                return dict(existing)
            await session.execute(
                insert(table).values(
                    id=reference.reference_id, tenant_id=reference.tenant_id,
                    engagement_id=reference.engagement_id, owner_user_id=reference.owner_user_id,
                    reference_kind=reference.kind.value, provider_alias=reference.provider_alias,
                    role_reference=reference.role_reference,
                    allowed_capabilities=list(reference.allowed_capabilities),
                    allowed_permissions=list(reference.allowed_permissions), expires_at=reference.expires_at,
                    rotation_due_at=reference.rotation_due_at, reference_status=reference.status.value,
                    redaction_label=reference.redaction_label, version=1,
                    created_at=reference.created_at, updated_at=reference.created_at,
                )
            )
            await _audit_outbox(
                session, tenant_id=reference.tenant_id, actor_user_id=actor_user_id,
                correlation_id=correlation_id, subject_id=reference.reference_id,
                event_type="secret.reference.registered", details={"reference_kind": reference.kind.value},
                occurred_at=reference.created_at,
            )
            return {"id": reference.reference_id, "reference_status": reference.status.value, "version": 1}

    async def register_workload(
        self,
        workload: WorkloadClient,
        *,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, workload.tenant_id)
            jobs = metadata.tables["jobs"]
            if (
                await session.execute(
                    select(jobs.c.id).where(jobs.c.tenant_id == workload.tenant_id, jobs.c.id == workload.job_id)
                )
            ).scalar_one_or_none() is None:
                raise SecretLeaseConflict("secret_workload_job_not_found")
            table = metadata.tables["secret_workload_clients"]
            existing = (
                await session.execute(
                    select(table).where(table.c.tenant_id == workload.tenant_id, table.c.id == workload.client_id)
                )
            ).mappings().one_or_none()
            if existing is not None:
                if (
                    existing["job_id"] != workload.job_id
                    or existing["capability"] != workload.capability
                    or existing["attestation_fingerprint"] != workload.attestation_fingerprint
                ):
                    raise SecretLeaseConflict("secret_workload_registration_conflict")
                return {"id": workload.client_id, "version": int(existing["version"])}
            await session.execute(
                insert(table).values(
                    id=workload.client_id, tenant_id=workload.tenant_id, job_id=workload.job_id,
                    capability=workload.capability, attestation_fingerprint=workload.attestation_fingerprint,
                    expires_at=workload.expires_at, revoked_at=workload.revoked_at, last_seen_at=None,
                    version=1, created_at=occurred_at, updated_at=occurred_at,
                )
            )
            await _audit_outbox(
                session, tenant_id=workload.tenant_id, actor_user_id=actor_user_id,
                correlation_id=correlation_id, subject_id=workload.client_id,
                event_type="secret.workload.registered", details={"job_id": workload.job_id, "capability": workload.capability},
                occurred_at=occurred_at,
            )
            return {"id": workload.client_id, "version": 1}

    async def reserve_issue(
        self,
        request: LeaseIssueRequest,
        *,
        actor_user_id: str,
        correlation_id: str,
        provider_max_ttl_seconds: int,
    ) -> LeaseReservation:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, request.tenant_id)
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"secret-issue:{request.tenant_id}:{request.idempotency_key}"},
            )
            operations = metadata.tables["secret_lease_operations"]
            request_hash = _request_hash(request)
            existing = (
                await session.execute(
                    select(operations).where(
                        operations.c.tenant_id == request.tenant_id,
                        operations.c.idempotency_key == request.idempotency_key,
                    )
                )
            ).mappings().one_or_none()
            if existing is not None:
                if existing["request_hash"] != request_hash or existing["lease_id"] != request.lease_id:
                    raise SecretLeaseConflict("secret_lease_idempotency_mismatch")
                lease = await _get_lease(session, request.tenant_id, request.lease_id)
                if lease is None:
                    raise SecretLeaseConflict(f"secret_lease_operation_{existing['operation_state']}")
                reference, workload = await _load_scope(session, request, actor_user_id)
                expiry = effective_lease_expiry(reference, workload, request, provider_max_ttl_seconds=provider_max_ttl_seconds)
                return LeaseReservation(
                    str(existing["id"]), reference.role_reference, workload.client_id,
                    workload.attestation_fingerprint, expiry, True, lease,
                )
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": (
                    f"secret-scope:{request.tenant_id}:{request.reference_id}:{request.job_id}:"
                    f"{request.workload_client_id}:{request.capability}"
                )},
            )
            reference, workload = await _load_scope(session, request, actor_user_id)
            expiry = effective_lease_expiry(reference, workload, request, provider_max_ttl_seconds=provider_max_ttl_seconds)
            leases = metadata.tables["secret_leases"]
            active = await session.scalar(
                select(leases.c.id).where(
                    leases.c.tenant_id == request.tenant_id,
                    leases.c.reference_id == request.reference_id,
                    leases.c.job_id == request.job_id,
                    leases.c.workload_client_id == request.workload_client_id,
                    leases.c.capability == request.capability,
                    leases.c.lease_state.in_(("active", "revoke_pending")),
                )
            )
            if active is not None and active != request.lease_id:
                raise SecretLeaseConflict("secret_active_lease_scope_conflict")
            operation_id = f"secret-operation-{uuid4().hex}"
            await session.execute(
                insert(operations).values(
                    id=operation_id, tenant_id=request.tenant_id, lease_id=request.lease_id,
                    idempotency_key=request.idempotency_key, request_hash=request_hash,
                    operation_state="reserved", provider_lease_reference=None, failure_code=None,
                    version=1, created_at=request.requested_at, updated_at=request.requested_at,
                )
            )
            return LeaseReservation(
                operation_id, reference.role_reference, workload.client_id,
                workload.attestation_fingerprint, expiry, False, None,
            )

    async def mark_issued(
        self, operation_id: str, provider_lease_reference: str, *, tenant_id: str, occurred_at: datetime
    ) -> None:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            operations = metadata.tables["secret_lease_operations"]
            changed = (
                await session.execute(
                    update(operations).where(
                        operations.c.id == operation_id, operations.c.operation_state == "reserved"
                    ).values(
                        operation_state="issued", provider_lease_reference=provider_lease_reference,
                        version=operations.c.version + 1, updated_at=occurred_at,
                    ).returning(operations.c.id)
                )
            ).scalar_one_or_none()
            if changed is None:
                raise SecretLeaseConflict("secret_lease_mark_issued_conflict")

    async def finalize_issue(
        self,
        operation_id: str,
        request: LeaseIssueRequest,
        envelope: ProviderLeaseEnvelope,
        *,
        expires_at: datetime,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, request.tenant_id)
            operations = metadata.tables["secret_lease_operations"]
            operation = (
                await session.execute(
                    select(operations).where(
                        operations.c.tenant_id == request.tenant_id, operations.c.id == operation_id,
                        operations.c.lease_id == request.lease_id, operations.c.operation_state == "issued",
                        operations.c.provider_lease_reference == envelope.provider_lease_reference,
                    ).with_for_update()
                )
            ).mappings().one_or_none()
            if operation is None:
                raise SecretLeaseConflict("secret_lease_finalize_conflict")
            leases = metadata.tables["secret_leases"]
            permission_digest = hashlib.sha256("\n".join(sorted(request.requested_permissions)).encode()).hexdigest()
            resource = {
                "id": request.lease_id, "tenant_id": request.tenant_id,
                "reference_id": request.reference_id, "engagement_id": request.engagement_id,
                "job_id": request.job_id, "workload_client_id": request.workload_client_id,
                "capability": request.capability, "permission_digest": permission_digest,
                "permission_count": len(request.requested_permissions),
                "provider_lease_reference": envelope.provider_lease_reference,
                "issued_at": occurred_at, "expires_at": expires_at, "renewed_at": None,
                "revoked_at": None, "renewable": envelope.renewable, "renewal_count": 0,
                "lease_state": "active", "policy_reference": request.policy_reference,
                "roe_version_id": request.roe_version_id, "failure_code": None,
                "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
            }
            await session.execute(insert(leases).values(**resource))
            await session.execute(
                update(operations).where(operations.c.id == operation_id).values(
                    operation_state="active", version=operations.c.version + 1, updated_at=occurred_at,
                )
            )
            await session.execute(
                insert(metadata.tables["secret_lease_events"]).values(
                    id=f"secret-event-{uuid4().hex}", tenant_id=request.tenant_id,
                    lease_id=request.lease_id, event_type="issued", actor_id=actor_user_id,
                    details={"job_id": request.job_id, "capability": request.capability, "permission_count": len(request.requested_permissions)},
                    occurred_at=occurred_at, version=1, created_at=occurred_at, updated_at=occurred_at,
                )
            )
            await _audit_outbox(
                session, tenant_id=request.tenant_id, actor_user_id=actor_user_id,
                correlation_id=correlation_id, subject_id=request.lease_id,
                event_type="secret.lease.issued", details={"job_id": request.job_id, "capability": request.capability},
                occurred_at=occurred_at,
            )
            return resource

    async def compensate_issue(
        self,
        operation_id: str,
        provider_lease_reference: str,
        *,
        tenant_id: str,
        revoke_confirmed: bool,
        failure_code: str,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> None:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            operations = metadata.tables["secret_lease_operations"]
            operation = (
                await session.execute(select(operations).where(operations.c.id == operation_id).with_for_update())
            ).mappings().one_or_none()
            if operation is None or operation["provider_lease_reference"] != provider_lease_reference:
                raise SecretLeaseConflict("secret_lease_compensation_conflict")
            state = "failed" if revoke_confirmed else "revoke_pending"
            await session.execute(
                update(operations).where(operations.c.id == operation_id).values(
                    operation_state=state, failure_code=failure_code,
                    version=operations.c.version + 1, updated_at=occurred_at,
                )
            )
            await _audit_outbox(
                session, tenant_id=str(operation["tenant_id"]), actor_user_id=actor_user_id,
                correlation_id=correlation_id, subject_id=str(operation["lease_id"]),
                event_type=f"secret.lease.{state}", details={"failure_code": failure_code},
                occurred_at=occurred_at,
            )

    async def prepare_renew(
        self,
        request: LeaseIssueRequest,
        *,
        expected_version: int,
        actor_user_id: str,
        provider_max_ttl_seconds: int,
    ) -> LeaseRenewalReservation:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, request.tenant_id)
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"secret-renew:{request.tenant_id}:{request.lease_id}"},
            )
            reference, workload = await _load_scope(session, request, actor_user_id)
            effective = effective_lease_expiry(
                reference, workload, request, provider_max_ttl_seconds=provider_max_ttl_seconds
            )
            lease = await _get_lease(session, request.tenant_id, request.lease_id)
            digest = hashlib.sha256("\n".join(sorted(request.requested_permissions)).encode()).hexdigest()
            if (
                lease is None or lease["reference_id"] != request.reference_id
                or lease["job_id"] != request.job_id or lease["workload_client_id"] != request.workload_client_id
                or lease["capability"] != request.capability or lease["permission_digest"] != digest
                or lease["policy_reference"] != request.policy_reference or lease["roe_version_id"] != request.roe_version_id
                or lease["lease_state"] != "active" or not lease["renewable"]
                or int(lease["version"]) != expected_version or int(lease["renewal_count"]) >= 3
                or request.requested_at >= lease["expires_at"] - timedelta(seconds=5)
            ):
                raise SecretLeaseConflict("secret_lease_renew_denied")
            return LeaseRenewalReservation(str(lease["provider_lease_reference"]), effective, lease)

    async def finalize_renew(
        self,
        *,
        tenant_id: str,
        lease_id: str,
        expected_version: int,
        expires_at: datetime,
        renewable: bool,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            leases = metadata.tables["secret_leases"]
            row = (
                await session.execute(
                    update(leases).where(
                        leases.c.tenant_id == tenant_id, leases.c.id == lease_id,
                        leases.c.version == expected_version, leases.c.lease_state == "active",
                    ).values(
                        expires_at=expires_at, renewed_at=occurred_at, renewable=renewable,
                        renewal_count=leases.c.renewal_count + 1, version=leases.c.version + 1,
                        updated_at=occurred_at,
                    ).returning(leases)
                )
            ).mappings().one_or_none()
            if row is None:
                raise SecretLeaseConflict("secret_lease_renew_finalize_conflict")
            await _lease_event(session, tenant_id, lease_id, "renewed", actor_user_id, {"renewal_count": int(row["renewal_count"])}, occurred_at)
            await _audit_outbox(
                session, tenant_id=tenant_id, actor_user_id=actor_user_id, correlation_id=correlation_id,
                subject_id=lease_id, event_type="secret.lease.renewed",
                details={"renewal_count": int(row["renewal_count"])}, occurred_at=occurred_at,
            )
            return dict(row)

    async def prepare_revoke(
        self, *, tenant_id: str, lease_id: str, expected_version: int,
    ) -> LeaseRevocationReservation:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            lease = await _get_lease(session, tenant_id, lease_id)
            if lease is None:
                raise SecretLeaseConflict("secret_lease_not_found")
            terminal = lease["lease_state"] in {"revoked", "expired"}
            if not terminal and int(lease["version"]) != expected_version:
                raise SecretLeaseConflict("secret_lease_version_conflict")
            return LeaseRevocationReservation(str(lease["provider_lease_reference"]), lease, terminal)

    async def finalize_revoke(
        self,
        *,
        tenant_id: str,
        lease_id: str,
        expected_version: int | None,
        state: str,
        failure_code: str | None,
        actor_user_id: str,
        correlation_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if state not in {"revoked", "expired", "revoke_pending", "quarantined"}:
            raise ValueError("secret_lease_reconcile_state_invalid")
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            leases = metadata.tables["secret_leases"]
            condition = [leases.c.tenant_id == tenant_id, leases.c.id == lease_id]
            if expected_version is not None:
                condition.append(leases.c.version == expected_version)
            values: dict[str, object] = {
                "lease_state": state, "failure_code": failure_code,
                "version": leases.c.version + 1, "updated_at": occurred_at,
            }
            if state in {"revoked", "expired"}:
                values["revoked_at"] = occurred_at
                values["renewable"] = False
            row = (
                await session.execute(update(leases).where(*condition).values(**values).returning(leases))
            ).mappings().one_or_none()
            if row is None:
                raise SecretLeaseConflict("secret_lease_revoke_finalize_conflict")
            event_type = "revocation_pending" if state == "revoke_pending" else state
            await _lease_event(session, tenant_id, lease_id, event_type, actor_user_id, {"failure_code": failure_code}, occurred_at)
            await _audit_outbox(
                session, tenant_id=tenant_id, actor_user_id=actor_user_id, correlation_id=correlation_id,
                subject_id=lease_id, event_type=f"secret.lease.{state}",
                details={"failure_code": failure_code}, occurred_at=occurred_at,
            )
            return dict(row)

    async def get_lease(self, *, tenant_id: str, lease_id: str) -> dict[str, object] | None:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            return await _get_lease(session, tenant_id, lease_id)

    async def list_references(self, *, tenant_id: str, limit: int, offset: int) -> list[dict[str, object]]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            table = metadata.tables["secret_references"]
            rows = (
                await session.execute(
                    select(table).where(table.c.tenant_id == tenant_id).order_by(table.c.created_at, table.c.id).limit(limit).offset(offset)
                )
            ).mappings().all()
            return [dict(row) for row in rows]

    async def list_leases(self, *, tenant_id: str, limit: int, offset: int) -> list[dict[str, object]]:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            table = metadata.tables["secret_leases"]
            rows = (
                await session.execute(
                    select(table).where(table.c.tenant_id == tenant_id).order_by(table.c.created_at.desc(), table.c.id).limit(limit).offset(offset)
                )
            ).mappings().all()
            return [dict(row) for row in rows]

    async def issue_requested_at(self, *, tenant_id: str, idempotency_key: str) -> datetime | None:
        async with self.session_factory() as session, session.begin():
            await _tenant_context(session, tenant_id)
            table = metadata.tables["secret_lease_operations"]
            return await session.scalar(
                select(table.c.created_at).where(
                    table.c.tenant_id == tenant_id, table.c.idempotency_key == idempotency_key,
                )
            )


async def _load_scope(session, request: LeaseIssueRequest, actor_user_id: str) -> tuple[SecretReference, WorkloadClient]:
    references = metadata.tables["secret_references"]
    row = (
        await session.execute(
            select(references).where(references.c.tenant_id == request.tenant_id, references.c.id == request.reference_id)
        )
    ).mappings().one_or_none()
    if row is None or row["owner_user_id"] != actor_user_id:
        raise SecretLeaseConflict("secret_reference_not_found")
    clients = metadata.tables["secret_workload_clients"]
    client = (
        await session.execute(
            select(clients).where(clients.c.tenant_id == request.tenant_id, clients.c.id == request.workload_client_id)
        )
    ).mappings().one_or_none()
    if client is None:
        raise SecretLeaseConflict("secret_workload_not_found")
    jobs = metadata.tables["jobs"]
    job = (
        await session.execute(
            select(jobs).where(jobs.c.tenant_id == request.tenant_id, jobs.c.id == request.job_id)
        )
    ).mappings().one_or_none()
    if (
        job is None or job["engagement_id"] != request.engagement_id
        or job["roe_version_id"] != request.roe_version_id
        or job["policy_reference"] != request.policy_reference
        or job["status"] not in {"pending", "running"}
    ):
        raise SecretLeaseConflict("secret_job_scope_invalid")
    roe = metadata.tables["roe_versions"]
    roe_status = await session.scalar(
        select(roe.c.status).where(roe.c.tenant_id == request.tenant_id, roe.c.id == request.roe_version_id)
    )
    if roe_status != "approved":
        raise SecretLeaseConflict("secret_roe_not_approved")
    reference = SecretReference(
        tenant_id=str(row["tenant_id"]), reference_id=str(row["id"]), engagement_id=str(row["engagement_id"]),
        owner_user_id=str(row["owner_user_id"]), kind=SecretReferenceKind(str(row["reference_kind"])),
        provider_alias=str(row["provider_alias"]), role_reference=str(row["role_reference"]),
        allowed_capabilities=tuple(row["allowed_capabilities"]), allowed_permissions=tuple(row["allowed_permissions"]),
        created_at=row["created_at"], expires_at=row["expires_at"], rotation_due_at=row["rotation_due_at"],
        status=SecretReferenceStatus(str(row["reference_status"])), redaction_label=str(row["redaction_label"]),
    )
    workload = WorkloadClient(
        tenant_id=str(client["tenant_id"]), client_id=str(client["id"]), job_id=str(client["job_id"]),
        capability=str(client["capability"]), attestation_fingerprint=str(client["attestation_fingerprint"]),
        expires_at=client["expires_at"], revoked_at=client["revoked_at"],
    )
    return reference, workload


async def _get_lease(session, tenant_id: str, lease_id: str) -> dict[str, object] | None:
    table = metadata.tables["secret_leases"]
    row = (
        await session.execute(select(table).where(table.c.tenant_id == tenant_id, table.c.id == lease_id))
    ).mappings().one_or_none()
    return None if row is None else dict(row)


async def _tenant_context(session, tenant_id: str) -> None:
    await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"), {"tenant_id": tenant_id})


async def _audit_outbox(
    session, *, tenant_id: str, actor_user_id: str, correlation_id: str,
    subject_id: str, event_type: str, details: dict[str, object], occurred_at: datetime,
) -> None:
    await session.execute(
        insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=tenant_id, actor_user_id=actor_user_id,
            action=event_type, subject_type="secret_lease", subject_id=subject_id,
            correlation_id=correlation_id, details=details, version=1,
            created_at=occurred_at, updated_at=occurred_at,
        )
    )
    await session.execute(
        insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=tenant_id, event_type=event_type,
            aggregate_id=subject_id, payload={"subject_type": "secret_lease", "subject_id": subject_id, **details},
            published=False, version=1, created_at=occurred_at, updated_at=occurred_at,
        )
    )


async def _lease_event(
    session, tenant_id: str, lease_id: str, event_type: str, actor_user_id: str,
    details: dict[str, object], occurred_at: datetime,
) -> None:
    await session.execute(
        insert(metadata.tables["secret_lease_events"]).values(
            id=f"secret-event-{uuid4().hex}", tenant_id=tenant_id, lease_id=lease_id,
            event_type=event_type, actor_id=actor_user_id, details=details, occurred_at=occurred_at,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        )
    )


def _request_hash(request: LeaseIssueRequest) -> str:
    values = {
        key: value.isoformat() if isinstance(value, datetime) else list(value) if isinstance(value, tuple) else value
        for key, value in asdict(request).items()
    }
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
