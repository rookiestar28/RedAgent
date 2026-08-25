"""Transactional compat_100 runner registry, manifest reservation, and pull lease store."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import secrets
from uuid import uuid4

from sqlalchemy import func, insert, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.contracts import (
    ArtifactVerificationReceipt,
    ExecutionCapabilityManifest,
    PullLeaseGrant,
    RunnerClassDefinition,
    RunnerRegistration,
    SignedJobManifest,
    SignedJobManifestV2,
    canonical_capability_sha256,
    verify_job_manifest_v2_binding,
)
from redagent_platform.runner_service.identity import PeerCertificateIdentity, authorize_peer_identity


class RunnerRepositoryConflict(RuntimeError):
    pass


class RunnerRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str, token_factory=None) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id
        self._token_factory = token_factory or (lambda: bytearray(secrets.token_bytes(32)))

    async def register_runner_class(
        self,
        definition: RunnerClassDefinition,
        *,
        author_user_id: str,
        reviewer_user_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if author_user_id == reviewer_user_id:
            raise RunnerRepositoryConflict("runner_class_separation_required")
        await self._context()
        table = metadata.tables["runner_classes"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.class_id == definition.class_id,
                table.c.class_revision == definition.revision,
            ))
        ).mappings().one_or_none()
        row = {
            "id": f"runner-class-{uuid4().hex}", "tenant_id": self.tenant_id,
            "class_id": definition.class_id, "class_revision": definition.revision,
            "environment": definition.environment, "network_plane": definition.network_plane,
            "isolation_tier": definition.sandbox.isolation_tier.value,
            "runtime_name": definition.sandbox.runtime_name,
            "sandbox_profile_id": definition.sandbox.profile_id,
            "policy_revision": definition.policy_revision,
            "resource_limits": _limits(definition.sandbox.limits),
            "credential_classes": [item.value for item in definition.credential_classes],
            "evidence_schemas": list(definition.evidence_schemas), "class_status": definition.status,
            "author_user_id": author_user_id, "reviewer_user_id": reviewer_user_id,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        if existing is not None:
            if _class_identity(existing) != _class_identity(row):
                raise RunnerRepositoryConflict("runner_class_revision_immutable")
            return dict(existing)
        await self.session.execute(insert(table).values(**row))
        await self._audit("runner.class.certified", definition.class_id, {"revision": definition.revision}, occurred_at)
        return row

    async def register_artifact(
        self, receipt: ArtifactVerificationReceipt, *, signature_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        _sha256(signature_sha256, "runner_artifact_signature_hash_invalid")
        await self._context()
        table = metadata.tables["artifact_verification_receipts"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.image_digest == receipt.image_digest,
            ))
        ).mappings().one_or_none()
        row = {
            "id": f"runner-artifact-{uuid4().hex}", "tenant_id": self.tenant_id,
            "receipt_id": receipt.receipt_id,
            "image_digest": receipt.image_digest, "signature_verified": receipt.signature_verified,
            "signature_sha256": signature_sha256,
            "signer_identity": receipt.signer_identity, "provenance_sha256": receipt.provenance_sha256,
            "sbom_sha256": receipt.sbom_sha256, "vulnerability_review": receipt.vulnerability_review,
            "verifier": receipt.verifier, "verified_at": receipt.verified_at, "expires_at": receipt.expires_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        if existing is not None:
            if str(existing["receipt_id"]) != receipt.receipt_id:
                raise RunnerRepositoryConflict("runner_artifact_digest_immutable")
            return dict(existing)
        await self.session.execute(insert(table).values(**row))
        return row

    async def register_capability(
        self,
        capability: ExecutionCapabilityManifest,
        *,
        occurred_at: datetime,
    ) -> dict[str, object]:
        capability_sha256 = canonical_capability_sha256(capability)
        await self._context()
        artifacts = metadata.tables["artifact_verification_receipts"]
        artifact = (
            await self.session.execute(select(artifacts).where(
                artifacts.c.tenant_id == self.tenant_id,
                artifacts.c.receipt_id == capability.artifact_receipt_id,
                artifacts.c.image_digest == capability.image_digest,
            ))
        ).mappings().one_or_none()
        if artifact is None or not artifact["signature_verified"] or artifact["expires_at"] <= occurred_at:
            raise RunnerRepositoryConflict("runner_artifact_verification_required")
        table = metadata.tables["execution_capability_manifests"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.capability_id == capability.capability_id,
                table.c.capability_revision == capability.revision,
            ))
        ).mappings().one_or_none()
        row = {
            "id": f"runner-capability-{uuid4().hex}", "tenant_id": self.tenant_id,
            "capability_id": capability.capability_id, "capability_revision": capability.revision,
            "adapter_id": capability.adapter_id, "adapter_version": capability.adapter_version,
            "image_digest": capability.image_digest, "input_schema_id": capability.input_schema_id,
            "supported_modes": list(capability.supported_modes), "phases": list(capability.phases),
            "sandbox_profile_id": capability.sandbox_profile_id,
            "network_mode": capability.network_mode.value,
            "credential_class": capability.credential_class.value,
            "evidence_schema": list(capability.evidence_schema),
            "unsupported_features": list(capability.unsupported_features),
            "resource_limits": _limits(capability.limits),
            "artifact_receipt_id": capability.artifact_receipt_id,
            "manifest_sha256": capability_sha256, "reviewed_by_user_id": capability.reviewed_by,
            "capability_status": capability.status, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        if existing is not None:
            if str(existing["manifest_sha256"]) != capability_sha256:
                raise RunnerRepositoryConflict("runner_capability_revision_immutable")
            return dict(existing)
        await self.session.execute(insert(table).values(**row))
        return row

    async def register_runner(
        self,
        registration: RunnerRegistration,
        *,
        runner_class_record_id: str,
        attestation_sha256: str,
        identity: PeerCertificateIdentity,
        occurred_at: datetime,
    ) -> dict[str, object]:
        _sha256(attestation_sha256, "runner_attestation_sha256_invalid")
        if registration.tenant_id != self.tenant_id:
            raise RunnerRepositoryConflict("runner_registration_tenant_mismatch")
        await self._context()
        classes = metadata.tables["runner_classes"]
        runner_class = (
            await self.session.execute(select(classes).where(
                classes.c.tenant_id == self.tenant_id, classes.c.id == runner_class_record_id,
            ))
        ).mappings().one_or_none()
        if runner_class is None or any((
            runner_class["class_id"] != registration.runner_class_id,
            runner_class["environment"] != registration.environment,
            runner_class["network_plane"] != registration.network_plane,
            runner_class["policy_revision"] != registration.required_policy_revision,
            runner_class["class_status"] != "certified",
        )):
            raise RunnerRepositoryConflict("runner_registration_class_mismatch")
        table = metadata.tables["runner_registrations"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.runner_id == registration.runner_id,
                table.c.generation == registration.generation,
            ))
        ).mappings().one_or_none()
        row = {
            "id": f"runner-registration-{uuid4().hex}", "tenant_id": self.tenant_id,
            "runner_id": registration.runner_id, "runner_class_record_id": runner_class_record_id,
            "environment": registration.environment, "network_plane": registration.network_plane,
            "spiffe_id": registration.spiffe_id,
            "certificate_fingerprint": registration.certificate_fingerprint,
            "certificate_serial": registration.certificate_serial,
            "adapter_allowlist": list(registration.adapter_allowlist),
            "image_allowlist": list(registration.image_allowlist),
            "required_policy_revision": registration.required_policy_revision,
            "generation": registration.generation, "attestation_sha256": attestation_sha256,
            "registration_state": "active", "registered_at": registration.registered_at,
            "expires_at": registration.expires_at, "revoked_at": registration.revoked_at,
            "last_seen_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        if existing is not None:
            if str(existing["certificate_fingerprint"]) != registration.certificate_fingerprint:
                raise RunnerRepositoryConflict("runner_registration_generation_immutable")
            return dict(existing)
        await self.session.execute(insert(table).values(**row))
        await self.observe_identity(str(row["id"]), identity, occurred_at=occurred_at)
        await self._audit("runner.registered", registration.runner_id, {"generation": registration.generation}, occurred_at)
        return row

    async def observe_identity(
        self,
        registration_record_id: str,
        identity: PeerCertificateIdentity,
        *,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        registration = await self._registration(registration_record_id)
        if any((
            registration["runner_id"] != identity.runner_id,
            registration["spiffe_id"] != identity.spiffe_id,
            registration["certificate_fingerprint"] != identity.certificate_fingerprint,
            registration["certificate_serial"] != identity.certificate_serial,
        )):
            raise RunnerRepositoryConflict("runner_identity_registration_mismatch")
        table = metadata.tables["runner_identities"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
                table.c.certificate_fingerprint == identity.certificate_fingerprint,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            return dict(existing)
        row = {
            "id": f"runner-identity-{uuid4().hex}", "tenant_id": self.tenant_id,
            "registration_id": registration_record_id, "spiffe_id": identity.spiffe_id,
            "certificate_fingerprint": identity.certificate_fingerprint,
            "certificate_serial": identity.certificate_serial, "not_before": identity.not_before,
            "not_after": identity.not_after, "identity_state": "observed",
            "observed_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def issue_manifest(
        self,
        signed: SignedJobManifest,
        *,
        runner_registration_id: str,
        capability_revision: int,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise RunnerRepositoryConflict("runner_manifest_idempotency_key_invalid")
        request_hash = hashlib.sha256(f"{idempotency_key}\0{signed.manifest_sha256}".encode("utf-8")).hexdigest()
        await self._context()
        registration = await self._registration(runner_registration_id)
        manifest = signed.manifest
        if registration["registration_state"] != "active" or registration["revoked_at"] is not None or registration["expires_at"] <= occurred_at:
            raise RunnerRepositoryConflict("runner_registration_not_current")
        if any((
            registration["environment"] != manifest.environment,
            registration["network_plane"] != manifest.network_plane,
            registration["required_policy_revision"] != manifest.policy_revision,
            registration["runner_class_record_id"] is None,
            f"{manifest.adapter_id}:{manifest.adapter_version}" not in tuple(registration["adapter_allowlist"]),
            manifest.image_digest not in tuple(registration["image_allowlist"]),
        )):
            raise RunnerRepositoryConflict("runner_manifest_registration_mismatch")
        capabilities = metadata.tables["execution_capability_manifests"]
        capability = (
            await self.session.execute(select(capabilities).where(
                capabilities.c.tenant_id == self.tenant_id,
                capabilities.c.capability_id == manifest.adapter_id,
                capabilities.c.capability_revision == capability_revision,
            ))
        ).mappings().one_or_none()
        if capability is None or any((
            capability["manifest_sha256"] != manifest.capability_digest,
            capability["image_digest"] != manifest.image_digest,
            capability["artifact_receipt_id"] != manifest.artifact_receipt_id,
            capability["capability_status"] != "certified",
        )):
            raise RunnerRepositoryConflict("runner_manifest_capability_mismatch")
        jobs = metadata.tables["jobs"]
        job = (
            await self.session.execute(select(jobs).where(
                jobs.c.tenant_id == self.tenant_id, jobs.c.id == manifest.job_id,
            ))
        ).mappings().one_or_none()
        if job is None or job["engagement_id"] != manifest.engagement_id or job["roe_version_id"] != manifest.roe_version_id:
            raise RunnerRepositoryConflict("runner_manifest_job_mismatch")
        await self._assert_containment_inactive(
            job_id=manifest.job_id, capability_id=str(capability["capability_id"]),
        )
        table = metadata.tables["runner_job_manifests"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.job_id == manifest.job_id,
                table.c.idempotency_key == idempotency_key,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if existing["manifest_sha256"] != signed.manifest_sha256:
                raise RunnerRepositoryConflict("runner_manifest_idempotency_mismatch")
            return dict(existing)
        row = {
            "id": f"runner-manifest-{uuid4().hex}", "tenant_id": self.tenant_id,
            "manifest_id": manifest.manifest_id, "job_id": manifest.job_id,
            "runner_registration_id": runner_registration_id, "idempotency_key": idempotency_key,
            "request_hash": request_hash,
            "manifest_document": signed.to_public_dict(), "manifest_sha256": signed.manifest_sha256,
            "signature_sha256": hashlib.sha256(signed.signature.encode("ascii")).hexdigest(),
            "signing_key_id": signed.key_id, "capability_id": capability["capability_id"],
            "capability_revision": capability_revision, "capability_sha256": manifest.capability_digest,
            "image_digest": manifest.image_digest, "artifact_receipt_id": manifest.artifact_receipt_id,
            "policy_revision": manifest.policy_revision, "policy_decision_id": manifest.policy_decision_id,
            "nonce_hash": hashlib.sha256(manifest.nonce.encode("utf-8")).hexdigest(),
            "manifest_state": "issued", "issued_at": manifest.issued_at, "expires_at": manifest.expires_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("runner.manifest.issued", manifest.manifest_id, {"manifest_sha256": signed.manifest_sha256}, occurred_at)
        return row

    async def issue_manifest_v2(
        self,
        signed: SignedJobManifestV2,
        *,
        runner_registration_id: str,
        binding: object,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        """Persist an exact compat_123 v2 identity while preserving the v1 issuance path."""
        if not isinstance(signed, SignedJobManifestV2):
            raise RunnerRepositoryConflict("runner_manifest_v2_required")
        if not idempotency_key or len(idempotency_key) > 200:
            raise RunnerRepositoryConflict("runner_manifest_idempotency_key_invalid")
        try:
            verify_job_manifest_v2_binding(signed.manifest, binding)
        except ValueError as exc:
            raise RunnerRepositoryConflict("runner_manifest_v2_binding_mismatch") from exc
        request_hash = hashlib.sha256(
            f"{idempotency_key}\0{signed.manifest_sha256}".encode("utf-8")
        ).hexdigest()
        await self._context()
        registration = await self._registration(runner_registration_id)
        manifest_v2 = signed.manifest
        manifest = manifest_v2.v1
        if (
            registration["registration_state"] != "active"
            or registration["revoked_at"] is not None
            or registration["expires_at"] <= occurred_at
        ):
            raise RunnerRepositoryConflict("runner_registration_not_current")
        if any(
            (
                registration["environment"] != manifest.environment,
                registration["network_plane"] != manifest.network_plane,
                registration["required_policy_revision"] != manifest.policy_revision,
                registration["runner_class_record_id"] is None,
                f"{manifest.adapter_id}:{manifest.adapter_version}"
                not in tuple(registration["adapter_allowlist"]),
                manifest.image_digest not in tuple(registration["image_allowlist"]),
            )
        ):
            raise RunnerRepositoryConflict("runner_manifest_registration_mismatch")
        capabilities = metadata.tables["execution_capability_manifests"]
        capability = (
            await self.session.execute(
                select(capabilities).where(
                    capabilities.c.tenant_id == self.tenant_id,
                    capabilities.c.capability_id == manifest_v2.capability_id,
                    capabilities.c.capability_revision
                    == manifest_v2.capability_revision,
                )
            )
        ).mappings().one_or_none()
        if capability is None or any(
            (
                capability["manifest_sha256"]
                != manifest_v2.execution_manifest_sha256,
                capability["image_digest"] != manifest.image_digest,
                capability["artifact_receipt_id"] != manifest.artifact_receipt_id,
                capability["adapter_id"] != manifest.adapter_id,
                capability["adapter_version"] != manifest.adapter_version,
                capability["capability_status"] != "certified",
            )
        ):
            raise RunnerRepositoryConflict("runner_manifest_capability_mismatch")
        jobs = metadata.tables["jobs"]
        job = (
            await self.session.execute(
                select(jobs).where(
                    jobs.c.tenant_id == self.tenant_id,
                    jobs.c.id == manifest.job_id,
                )
            )
        ).mappings().one_or_none()
        if job is None or (
            job["engagement_id"] != manifest.engagement_id
            or job["roe_version_id"] != manifest.roe_version_id
        ):
            raise RunnerRepositoryConflict("runner_manifest_job_mismatch")
        await self._assert_containment_inactive(
            job_id=manifest.job_id,
            capability_id=manifest_v2.capability_id,
        )
        table = metadata.tables["runner_job_manifests"]
        existing = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.job_id == manifest.job_id,
                    table.c.idempotency_key == idempotency_key,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if existing["manifest_sha256"] != signed.manifest_sha256:
                raise RunnerRepositoryConflict("runner_manifest_idempotency_mismatch")
            return dict(existing)
        row = {
            "id": f"runner-manifest-{uuid4().hex}",
            "tenant_id": self.tenant_id,
            "manifest_id": manifest.manifest_id,
            "job_id": manifest.job_id,
            "runner_registration_id": runner_registration_id,
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
            "manifest_document": signed.to_public_dict(),
            "manifest_sha256": signed.manifest_sha256,
            "signature_sha256": hashlib.sha256(
                signed.signature.encode("ascii")
            ).hexdigest(),
            "signing_key_id": signed.key_id,
            "capability_id": manifest_v2.capability_id,
            "capability_revision": manifest_v2.capability_revision,
            "capability_sha256": manifest_v2.execution_manifest_sha256,
            "image_digest": manifest.image_digest,
            "artifact_receipt_id": manifest.artifact_receipt_id,
            "policy_revision": manifest.policy_revision,
            "policy_decision_id": manifest.policy_decision_id,
            "nonce_hash": hashlib.sha256(manifest.nonce.encode("utf-8")).hexdigest(),
            "manifest_state": "issued",
            "issued_at": manifest.issued_at,
            "expires_at": manifest.expires_at,
            "version": 1,
            "created_at": occurred_at,
            "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit(
            "runner.manifest.issued",
            manifest.manifest_id,
            {
                "manifest_sha256": signed.manifest_sha256,
                "manifest_contract_version": "redagent.r123-job-manifest/v2",
            },
            occurred_at,
        )
        return row

    async def claim_manifest(
        self,
        *,
        manifest_record_id: str,
        identity: PeerCertificateIdentity,
        claim_id: str,
        environment: str,
        runner_class_id: str,
        policy_revision: str,
        generation: int,
        occurred_at: datetime,
    ) -> PullLeaseGrant:
        await self._context()
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"runner-claim:{self.tenant_id}:{manifest_record_id}"},
        )
        manifests = metadata.tables["runner_job_manifests"]
        manifest = (
            await self.session.execute(select(manifests).where(
                manifests.c.tenant_id == self.tenant_id, manifests.c.id == manifest_record_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if manifest is None:
            raise RunnerRepositoryConflict("runner_claim_manifest_mismatch")
        await self._assert_containment_inactive(
            job_id=str(manifest["job_id"]), capability_id=str(manifest["capability_id"]),
        )
        registration_record_id = str(manifest["runner_registration_id"])
        registration = await self._registration(registration_record_id)
        classes = metadata.tables["runner_classes"]
        class_row = (
            await self.session.execute(select(classes).where(
                classes.c.tenant_id == self.tenant_id,
                classes.c.id == registration["runner_class_record_id"],
            ))
        ).mappings().one_or_none()
        if class_row is None or class_row["class_id"] != runner_class_id:
            raise RunnerRepositoryConflict("runner_class_mismatch")
        typed_registration = _registration_contract(
            registration, tenant_id=self.tenant_id, runner_class_id=str(class_row["class_id"]),
        )
        try:
            authorize_peer_identity(
                identity, typed_registration, environment=environment, runner_class_id=runner_class_id,
                policy_revision=policy_revision, generation=generation, now=occurred_at,
            )
        except ValueError as exc:
            raise RunnerRepositoryConflict(str(exc)) from exc
        if manifest["expires_at"] <= occurred_at or registration["expires_at"] <= occurred_at:
            raise RunnerRepositoryConflict("runner_claim_expired")
        if registration["registration_state"] != "active" or registration["revoked_at"] is not None:
            raise RunnerRepositoryConflict("runner_registration_not_current")
        leases = metadata.tables["runner_pull_leases"]
        existing = (
            await self.session.execute(select(leases).where(
                leases.c.tenant_id == self.tenant_id, leases.c.manifest_id == manifest_record_id,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if any((
                existing["runner_registration_id"] != registration_record_id,
                existing["claim_id"] != claim_id,
                int(existing["runner_generation"]) != generation,
                existing["manifest_sha256"] != manifest["manifest_sha256"],
            )):
                raise RunnerRepositoryConflict("runner_manifest_already_claimed")
            return PullLeaseGrant(
                lease_id=str(existing["id"]), manifest_record_id=manifest_record_id,
                claim_id=claim_id, expires_at=existing["expires_at"], lease_token=None,
            )
        lease_token = self._token_factory()
        if not isinstance(lease_token, bytearray) or not 16 <= len(lease_token) <= 256:
            raise RunnerRepositoryConflict("runner_lease_token_invalid")
        token_hash = hashlib.sha256(bytes(lease_token)).hexdigest()
        row = {
            "id": f"runner-lease-{uuid4().hex}", "tenant_id": self.tenant_id,
            "manifest_id": manifest_record_id, "runner_registration_id": registration_record_id,
            "claim_id": claim_id, "lease_token_hash": token_hash,
            "runner_generation": generation, "manifest_sha256": manifest["manifest_sha256"],
            "lease_state": "claimed", "claimed_at": occurred_at, "last_heartbeat_at": occurred_at,
            "expires_at": min(manifest["expires_at"], registration["expires_at"]),
            "finalized_at": None, "failure_code": None, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        try:
            await self.session.execute(insert(leases).values(**row))
        except IntegrityError as exc:
            raise RunnerRepositoryConflict("runner_claim_conflict") from exc
        await self.session.execute(update(manifests).where(manifests.c.id == manifest_record_id).values(
            manifest_state="claimed", version=manifests.c.version + 1, updated_at=occurred_at,
        ))
        await self._audit("runner.manifest.claimed", str(manifest["manifest_id"]), {"claim_id": claim_id}, occurred_at)
        return PullLeaseGrant(
            lease_id=str(row["id"]), manifest_record_id=manifest_record_id,
            claim_id=claim_id, expires_at=row["expires_at"], lease_token=lease_token,
        )

    async def heartbeat(
        self, *, lease_id: str, lease_token: bytearray, generation: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        lease = await self._current_lease(
            lease_id, lease_token=lease_token, generation=generation,
            occurred_at=occurred_at,
        )
        table = metadata.tables["runner_pull_leases"]
        await self.session.execute(update(table).where(
            table.c.tenant_id == self.tenant_id, table.c.id == lease_id,
            table.c.version == lease["version"],
        ).values(
            last_heartbeat_at=occurred_at, version=table.c.version + 1,
            updated_at=occurred_at,
        ))
        updated = dict(lease)
        updated.update(last_heartbeat_at=occurred_at, version=int(lease["version"]) + 1)
        return updated

    async def record_lifecycle_event(
        self, *, lease_id: str, lease_token: bytearray, generation: int,
        event_id: str, phase: str, phase_state: str, reason_code: str | None,
        metadata_values: dict[str, object], occurred_at: datetime,
    ) -> dict[str, object]:
        if phase not in {
            "preflight", "prepare", "execute", "monitor", "cancel", "collect",
            "normalize", "cleanup",
        } or phase_state not in {"started", "completed", "failed"}:
            raise RunnerRepositoryConflict("runner_lifecycle_event_invalid")
        if not event_id or len(event_id) > 100 or (reason_code is not None and len(reason_code) > 100):
            raise RunnerRepositoryConflict("runner_lifecycle_event_invalid")
        _lifecycle_metadata(metadata_values)
        await self._context()
        await self._current_lease(
            lease_id, lease_token=lease_token, generation=generation,
            occurred_at=occurred_at,
        )
        document = {
            "event_id": event_id, "lease_id": lease_id, "phase": phase,
            "phase_state": phase_state, "reason_code": reason_code,
            "metadata": metadata_values, "occurred_at": occurred_at.isoformat(),
        }
        event_sha256 = hashlib.sha256(json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        table = metadata.tables["runner_lifecycle_events"]
        existing = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.event_id == event_id,
            ))
        ).mappings().one_or_none()
        if existing is not None:
            if existing["event_sha256"] != event_sha256:
                raise RunnerRepositoryConflict("runner_lifecycle_event_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"runner-event-{uuid4().hex}", "tenant_id": self.tenant_id,
            "lease_id": lease_id, "event_id": event_id, "phase": phase,
            "event_sha256": event_sha256, "phase_state": phase_state,
            "reason_code": reason_code, "metadata": dict(metadata_values),
            "occurred_at": occurred_at, "version": 1, "created_at": occurred_at,
            "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def begin_execution(
        self, *, lease_id: str, lease_token: bytearray, generation: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        lease = await self._current_lease(
            lease_id, lease_token=lease_token, generation=generation,
            occurred_at=occurred_at,
        )
        manifests = metadata.tables["runner_job_manifests"]
        manifest = (
            await self.session.execute(select(manifests).where(
                manifests.c.tenant_id == self.tenant_id,
                manifests.c.id == lease["manifest_id"],
            ).with_for_update())
        ).mappings().one()
        await self._assert_containment_inactive(
            job_id=str(manifest["job_id"]), capability_id=str(manifest["capability_id"]),
        )
        if manifest["manifest_state"] == "running":
            return dict(manifest)
        if manifest["manifest_state"] != "claimed":
            raise RunnerRepositoryConflict("runner_manifest_not_claimed")
        await self.session.execute(update(manifests).where(
            manifests.c.id == manifest["id"], manifests.c.version == manifest["version"],
        ).values(
            manifest_state="running", version=manifests.c.version + 1,
            updated_at=occurred_at,
        ))
        updated = dict(manifest)
        updated.update(manifest_state="running", version=int(manifest["version"]) + 1)
        return updated

    async def finalize_execution(
        self, *, lease_id: str, lease_token: bytearray, generation: int,
        execution_id: str, evidence_artifact_id: str, outcome: str,
        final_phase: str, policy_decision_id: str, evidence_sha256: str,
        cleanup_completed: bool, residual_risk: str | None, occurred_at: datetime,
    ) -> dict[str, object]:
        if (
            not execution_id or len(execution_id) > 100
            or outcome not in {"succeeded", "failed"}
            or final_phase != "cleanup"
            or not policy_decision_id or len(policy_decision_id) > 100
            or not isinstance(cleanup_completed, bool)
            or (outcome == "succeeded" and (not cleanup_completed or residual_risk is not None))
            or (residual_risk is not None and (not residual_risk or len(residual_risk) > 100))
        ):
            raise RunnerRepositoryConflict("runner_execution_receipt_invalid")
        _sha256(evidence_sha256, "runner_evidence_sha256_invalid")
        await self._context()
        receipts = metadata.tables["runner_execution_receipts"]
        existing = (
            await self.session.execute(select(receipts).where(
                receipts.c.tenant_id == self.tenant_id,
                receipts.c.execution_id == execution_id,
            ))
        ).mappings().one_or_none()
        expected = (
            lease_id, evidence_artifact_id, outcome, final_phase, policy_decision_id,
            evidence_sha256, cleanup_completed, residual_risk,
        )
        if existing is not None:
            actual = tuple(existing[name] for name in (
                "lease_id", "evidence_artifact_id", "outcome", "final_phase",
                "policy_decision_id", "evidence_sha256", "cleanup_completed", "residual_risk",
            ))
            if actual != expected:
                raise RunnerRepositoryConflict("runner_execution_replay_mismatch")
            return dict(existing)
        duplicate = await self.session.scalar(select(receipts.c.id).where(
            receipts.c.tenant_id == self.tenant_id, receipts.c.lease_id == lease_id,
        ))
        if duplicate is not None:
            raise RunnerRepositoryConflict("runner_lease_already_finalized")
        lease = await self._current_lease(
            lease_id, lease_token=lease_token, generation=generation,
            occurred_at=occurred_at,
        )
        evidence = metadata.tables["evidence_artifacts"]
        evidence_row = (
            await self.session.execute(select(evidence).where(
                evidence.c.tenant_id == self.tenant_id,
                evidence.c.id == evidence_artifact_id,
            ))
        ).mappings().one_or_none()
        manifest = (
            await self.session.execute(select(metadata.tables["runner_job_manifests"]).where(
                metadata.tables["runner_job_manifests"].c.id == lease["manifest_id"],
                metadata.tables["runner_job_manifests"].c.tenant_id == self.tenant_id,
            ))
        ).mappings().one()
        if (
            evidence_row is None or evidence_row["job_id"] != manifest["job_id"]
            or evidence_row["content_sha256"] != evidence_sha256
            or evidence_row["quarantine_reason"] is not None
        ):
            raise RunnerRepositoryConflict("runner_evidence_receipt_mismatch")
        row = {
            "id": f"runner-receipt-{uuid4().hex}", "tenant_id": self.tenant_id,
            "lease_id": lease_id, "evidence_artifact_id": evidence_artifact_id,
            "execution_id": execution_id, "outcome": outcome,
            "final_phase": final_phase, "policy_decision_id": policy_decision_id,
            "evidence_sha256": evidence_sha256, "cleanup_completed": cleanup_completed,
            "residual_risk": residual_risk, "completed_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(receipts).values(**row))
        leases = metadata.tables["runner_pull_leases"]
        await self.session.execute(update(leases).where(
            leases.c.tenant_id == self.tenant_id, leases.c.id == lease_id,
            leases.c.version == lease["version"],
        ).values(
            lease_state="completed" if outcome == "succeeded" else "failed",
            finalized_at=occurred_at,
            failure_code=None if outcome == "succeeded" else residual_risk or "runner_execution_failed",
            version=leases.c.version + 1, updated_at=occurred_at,
        ))
        manifests = metadata.tables["runner_job_manifests"]
        await self.session.execute(update(manifests).where(
            manifests.c.id == lease["manifest_id"], manifests.c.tenant_id == self.tenant_id,
        ).values(
            manifest_state="completed" if outcome == "succeeded" else "failed",
            version=manifests.c.version + 1, updated_at=occurred_at,
        ))
        await self._audit(
            "runner.execution.finalized", execution_id,
            {"outcome": outcome, "evidence_artifact_id": evidence_artifact_id},
            occurred_at,
        )
        return row

    async def status(self) -> dict[str, int]:
        await self._context()
        registrations = metadata.tables["runner_registrations"]
        leases = metadata.tables["runner_pull_leases"]
        return {
            "registrations": int(await self.session.scalar(select(func.count()).select_from(registrations).where(
                registrations.c.tenant_id == self.tenant_id,
            )) or 0),
            "active_leases": int(await self.session.scalar(select(func.count()).select_from(leases).where(
                leases.c.tenant_id == self.tenant_id, leases.c.lease_state == "claimed",
            )) or 0),
        }

    async def fail_execution(
        self, *, lease_id: str, lease_token: bytearray, generation: int,
        execution_id: str, policy_decision_id: str, failure_code: str,
        cleanup_completed: bool, occurred_at: datetime,
    ) -> dict[str, object]:
        if (
            not execution_id or len(execution_id) > 100
            or not policy_decision_id or len(policy_decision_id) > 100
            or not failure_code or len(failure_code) > 100
            or not isinstance(cleanup_completed, bool)
        ):
            raise RunnerRepositoryConflict("runner_failure_receipt_invalid")
        await self._context()
        receipts = metadata.tables["runner_execution_receipts"]
        existing = (await self.session.execute(select(receipts).where(
            receipts.c.tenant_id == self.tenant_id,
            receipts.c.execution_id == execution_id,
        ))).mappings().one_or_none()
        expected = (lease_id, policy_decision_id, failure_code, cleanup_completed)
        if existing is not None:
            actual = (
                existing["lease_id"], existing["policy_decision_id"],
                existing["residual_risk"], existing["cleanup_completed"],
            )
            if actual != expected or existing["outcome"] != "failed" or existing["evidence_artifact_id"] is not None:
                raise RunnerRepositoryConflict("runner_execution_replay_mismatch")
            return dict(existing)
        lease = await self._current_lease(
            lease_id, lease_token=lease_token, generation=generation,
            occurred_at=occurred_at,
        )
        row = {
            "id": f"runner-receipt-{uuid4().hex}", "tenant_id": self.tenant_id,
            "lease_id": lease_id, "evidence_artifact_id": None,
            "execution_id": execution_id, "outcome": "failed", "final_phase": "cleanup",
            "policy_decision_id": policy_decision_id, "evidence_sha256": None,
            "cleanup_completed": cleanup_completed, "residual_risk": failure_code,
            "completed_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(receipts).values(**row))
        leases = metadata.tables["runner_pull_leases"]
        await self.session.execute(update(leases).where(
            leases.c.tenant_id == self.tenant_id, leases.c.id == lease_id,
            leases.c.version == lease["version"],
        ).values(
            lease_state="failed", finalized_at=occurred_at, failure_code=failure_code,
            version=leases.c.version + 1, updated_at=occurred_at,
        ))
        manifests = metadata.tables["runner_job_manifests"]
        await self.session.execute(update(manifests).where(
            manifests.c.id == lease["manifest_id"], manifests.c.tenant_id == self.tenant_id,
        ).values(
            manifest_state="failed", version=manifests.c.version + 1,
            updated_at=occurred_at,
        ))
        await self._audit(
            "runner.execution.failed", execution_id,
            {"failure_code": failure_code, "cleanup_completed": cleanup_completed},
            occurred_at,
        )
        return row

    async def operational_status(self) -> dict[str, object]:
        await self._context()
        registrations = metadata.tables["runner_registrations"]
        capabilities = metadata.tables["execution_capability_manifests"]
        manifests = metadata.tables["runner_job_manifests"]
        leases = metadata.tables["runner_pull_leases"]
        receipts = metadata.tables["runner_execution_receipts"]
        policy_revisions = tuple((await self.session.scalars(
            select(registrations.c.required_policy_revision).where(
                registrations.c.tenant_id == self.tenant_id,
                registrations.c.registration_state == "active",
            ).distinct().order_by(registrations.c.required_policy_revision)
        )).all())
        capability_rows = (await self.session.execute(select(
            capabilities.c.capability_id, capabilities.c.capability_revision,
            capabilities.c.image_digest,
        ).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_status == "certified",
        ).order_by(capabilities.c.capability_id, capabilities.c.capability_revision))).mappings().all()
        return {
            "registration_count": await self._count(registrations),
            "active_registration_count": await self._count(
                registrations, registrations.c.registration_state == "active",
            ),
            "certified_capability_count": await self._count(
                capabilities, capabilities.c.capability_status == "certified",
            ),
            "open_manifest_count": await self._count(
                manifests, manifests.c.manifest_state.in_(("issued", "claimed", "running")),
            ),
            "active_lease_count": await self._count(
                leases, leases.c.lease_state == "claimed",
            ),
            "succeeded_execution_count": await self._count(
                receipts, receipts.c.outcome == "succeeded",
            ),
            "failed_execution_count": await self._count(
                receipts, receipts.c.outcome != "succeeded",
            ),
            "last_heartbeat_at": await self.session.scalar(select(func.max(registrations.c.last_seen_at)).where(
                registrations.c.tenant_id == self.tenant_id,
            )),
            "policy_revisions": list(policy_revisions),
            "capability_revisions": [
                f"{row['capability_id']}:{row['capability_revision']}" for row in capability_rows
            ],
            "image_digests": sorted({str(row["image_digest"]) for row in capability_rows}),
        }

    async def list_registrations(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._context()
        registrations = metadata.tables["runner_registrations"]
        classes = metadata.tables["runner_classes"]
        rows = (await self.session.execute(select(
            registrations.c.runner_id, classes.c.class_id.label("runner_class_id"),
            registrations.c.environment, registrations.c.network_plane,
            registrations.c.required_policy_revision, registrations.c.generation,
            registrations.c.registration_state, registrations.c.registered_at,
            registrations.c.expires_at, registrations.c.revoked_at,
            registrations.c.last_seen_at, registrations.c.version,
        ).select_from(registrations.join(
            classes, registrations.c.runner_class_record_id == classes.c.id,
        )).where(
            registrations.c.tenant_id == self.tenant_id,
        ).order_by(registrations.c.runner_id, registrations.c.generation.desc()).limit(limit).offset(offset))).mappings().all()
        return [dict(row) for row in rows]

    async def list_manifests(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._context()
        table = metadata.tables["runner_job_manifests"]
        rows = (await self.session.execute(select(
            table.c.manifest_id, table.c.job_id, table.c.manifest_sha256,
            table.c.capability_id, table.c.capability_revision, table.c.image_digest,
            table.c.policy_revision, table.c.manifest_state, table.c.issued_at,
            table.c.expires_at, table.c.version,
        ).where(table.c.tenant_id == self.tenant_id).order_by(
            table.c.created_at.desc(), table.c.id,
        ).limit(limit).offset(offset))).mappings().all()
        return [dict(row) for row in rows]

    async def list_executions(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._context()
        receipts = metadata.tables["runner_execution_receipts"]
        leases = metadata.tables["runner_pull_leases"]
        manifests = metadata.tables["runner_job_manifests"]
        rows = (await self.session.execute(select(
            receipts.c.execution_id, manifests.c.job_id, manifests.c.manifest_sha256,
            receipts.c.evidence_artifact_id, receipts.c.outcome, receipts.c.final_phase,
            receipts.c.cleanup_completed, receipts.c.residual_risk,
            receipts.c.completed_at, receipts.c.version,
        ).select_from(receipts.join(
            leases, receipts.c.lease_id == leases.c.id,
        ).join(
            manifests, leases.c.manifest_id == manifests.c.id,
        )).where(receipts.c.tenant_id == self.tenant_id).order_by(
            receipts.c.completed_at.desc(), receipts.c.id,
        ).limit(limit).offset(offset))).mappings().all()
        return [dict(row) for row in rows]

    async def _count(self, table, *conditions) -> int:
        return int(await self.session.scalar(select(func.count()).select_from(table).where(
            table.c.tenant_id == self.tenant_id, *conditions,
        )) or 0)

    async def _registration(self, record_id: str):
        table = metadata.tables["runner_registrations"]
        row = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.id == record_id,
            ))
        ).mappings().one_or_none()
        if row is None:
            raise RunnerRepositoryConflict("runner_registration_not_found")
        return row

    async def _current_lease(
        self, lease_id: str, *, lease_token: bytearray, generation: int,
        occurred_at: datetime,
    ):
        if not isinstance(lease_token, bytearray) or not 16 <= len(lease_token) <= 256:
            raise RunnerRepositoryConflict("runner_lease_token_invalid")
        table = metadata.tables["runner_pull_leases"]
        row = (
            await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id, table.c.id == lease_id,
            ).with_for_update())
        ).mappings().one_or_none()
        if row is None:
            raise RunnerRepositoryConflict("runner_lease_not_found")
        token_hash = hashlib.sha256(bytes(lease_token)).hexdigest()
        if not secrets.compare_digest(str(row["lease_token_hash"]), token_hash):
            raise RunnerRepositoryConflict("runner_lease_token_mismatch")
        if int(row["runner_generation"]) != generation:
            raise RunnerRepositoryConflict("runner_lease_generation_mismatch")
        if row["lease_state"] != "claimed" or row["expires_at"] <= occurred_at:
            raise RunnerRepositoryConflict("runner_lease_not_current")
        return row

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id},
        )

    async def _assert_containment_inactive(self, *, job_id: str, capability_id: str) -> None:
        # CRITICAL: every manifest/claim/execute boundary must re-check current stop controls.
        jobs = metadata.tables["jobs"]
        job = (
            await self.session.execute(select(jobs.c.campaign_id).where(
                jobs.c.tenant_id == self.tenant_id, jobs.c.id == job_id,
            ))
        ).mappings().one_or_none()
        if job is None:
            raise RunnerRepositoryConflict("runner_manifest_job_mismatch")
        controls = metadata.tables["containment_controls"]
        predicates = [
            controls.c.scope_kind == "global",
            (controls.c.scope_kind == "tenant") & (controls.c.scope_id == self.tenant_id),
            (controls.c.scope_kind == "job") & (controls.c.scope_id == job_id),
            (controls.c.scope_kind == "capability") & (controls.c.scope_id == capability_id),
        ]
        if job["campaign_id"] is not None:
            predicates.append(
                (controls.c.scope_kind == "campaign") & (controls.c.scope_id == job["campaign_id"])
            )
        active = await self.session.scalar(select(controls.c.id).where(
            controls.c.tenant_id == self.tenant_id,
            controls.c.control_state == "active",
            or_(*predicates),
        ).limit(1))
        if active is not None:
            raise RunnerRepositoryConflict("runner_containment_active")

    async def _audit(self, event_type: str, subject_id: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event_type,
            subject_type="runner", subject_id=subject_id,
            correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id,
            event_type=event_type, aggregate_id=subject_id,
            payload=details, published=False, version=1,
            created_at=occurred_at, updated_at=occurred_at,
        ))


def _limits(value) -> dict[str, int]:
    return {
        "cpu_millis": value.cpu_millis, "memory_mib": value.memory_mib,
        "pids": value.pids, "timeout_seconds": value.timeout_seconds,
        "evidence_bytes": value.evidence_bytes,
    }


def _class_identity(row) -> tuple[object, ...]:
    return tuple(row[name] for name in (
        "class_id", "class_revision", "environment", "network_plane", "isolation_tier",
        "runtime_name", "sandbox_profile_id", "policy_revision", "class_status",
    ))


def _sha256(value: str, reason: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RunnerRepositoryConflict(reason)


def _lifecycle_metadata(values: dict[str, object]) -> None:
    if not isinstance(values, dict) or len(values) > 8:
        raise RunnerRepositoryConflict("runner_lifecycle_metadata_invalid")
    allowed = {"duration_ms", "artifact_bytes", "artifact_sha256", "cleanup_completed"}
    for key, value in values.items():
        if key not in allowed:
            raise RunnerRepositoryConflict("runner_lifecycle_metadata_invalid")
        if key in {"duration_ms", "artifact_bytes"} and (
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2_147_483_647
        ):
            raise RunnerRepositoryConflict("runner_lifecycle_metadata_invalid")
        if key == "artifact_sha256":
            _sha256(str(value), "runner_lifecycle_metadata_invalid")
        if key == "cleanup_completed" and not isinstance(value, bool):
            raise RunnerRepositoryConflict("runner_lifecycle_metadata_invalid")


def _registration_contract(row, *, tenant_id: str, runner_class_id: str) -> RunnerRegistration:
    return RunnerRegistration(
        runner_id=str(row["runner_id"]), tenant_id=tenant_id,
        environment=str(row["environment"]), runner_class_id=runner_class_id,
        network_plane=str(row["network_plane"]), spiffe_id=str(row["spiffe_id"]),
        certificate_fingerprint=str(row["certificate_fingerprint"]),
        certificate_serial=str(row["certificate_serial"]),
        adapter_allowlist=tuple(row["adapter_allowlist"]), image_allowlist=tuple(row["image_allowlist"]),
        required_policy_revision=str(row["required_policy_revision"]), generation=int(row["generation"]),
        registered_at=row["registered_at"], expires_at=row["expires_at"], revoked_at=row["revoked_at"],
    )
