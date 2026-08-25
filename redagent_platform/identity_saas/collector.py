"""Bounded, field-minimizing compat_109 identity snapshot collector."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Mapping, Protocol

from redagent_platform.identity_saas.compiler import CompiledIdentityPlan
from redagent_platform.identity_saas.contracts import IdentityProviderProfile


@dataclass(frozen=True, kw_only=True)
class IdentityBinding:
    provider: str; tenant_id: str; audience: str; consent_mode: str


@dataclass(frozen=True, kw_only=True)
class IdentityCollectionPage:
    operation_id: str; page_index: int; next_cursor: str | None
    resources: tuple[Mapping[str, object], ...]; response_bytes: int; partial_reason: str | None = None


class IdentityCollectionTransport(Protocol):
    def verify_binding(self) -> IdentityBinding: ...
    def fetch_page(self, *, operation_id: str, cursor: str | None) -> IdentityCollectionPage: ...


@dataclass(frozen=True, kw_only=True)
class IdentitySnapshotResource:
    resource_id: str; operation_id: str; attributes: Mapping[str, object]


@dataclass(frozen=True, kw_only=True)
class IdentitySnapshot:
    provider: str; tenant_id: str; audience: str; consent_mode: str; collector_id: str
    collected_at: datetime; plan_sha256: str; granted_scopes: tuple[str, ...]
    effective_role_permissions: tuple[str, ...]; complete: bool; partial_reasons: tuple[str, ...]
    page_count: int; resource_count: int; resources: tuple[IdentitySnapshotResource, ...]
    redaction_sha256: str; snapshot_sha256: str


def collect_identity_snapshot(*, plan: CompiledIdentityPlan, profile: IdentityProviderProfile, transport: IdentityCollectionTransport, collected_at: datetime) -> IdentitySnapshot:
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("identity_time_invalid")
    binding = transport.verify_binding()
    if (binding.provider, binding.tenant_id, binding.audience, binding.consent_mode) != (plan.provider.value, plan.tenant_id, plan.audience, plan.consent_mode):
        raise ValueError("identity_provider_binding_mismatch")
    operations = {item.operation_id: item for item in profile.operations}
    pages = 0; calls = 1; total_bytes = 0; rows: list[IdentitySnapshotResource] = []; partial: set[str] = set()
    for operation_id in plan.operation_ids:
        cursor = None; seen: set[str | None] = set(); page_index = 0
        while True:
            if cursor in seen: raise ValueError("identity_pagination_loop")
            seen.add(cursor)
            if calls >= plan.max_calls or pages >= plan.max_pages: raise ValueError("identity_collection_budget_exceeded")
            page = transport.fetch_page(operation_id=operation_id, cursor=cursor)
            calls += 1; pages += 1; total_bytes += page.response_bytes
            if page.operation_id != operation_id or page.page_index != page_index: raise ValueError("identity_page_contract_mismatch")
            if total_bytes > plan.max_bytes: raise ValueError("identity_response_budget_exceeded")
            if page.partial_reason: partial.add(page.partial_reason)
            selected = set(operations[operation_id].selected_fields)
            for value in page.resources:
                if set(value) - selected: raise ValueError("identity_unselected_field_denied")
                resource_id = value.get("id")
                if not isinstance(resource_id, str) or not resource_id.strip(): raise ValueError("identity_resource_id_required")
                rows.append(IdentitySnapshotResource(resource_id=resource_id, operation_id=operation_id, attributes=dict(sorted(value.items()))))
                if len(rows) > plan.max_resources: raise ValueError("identity_resource_budget_exceeded")
            if page.next_cursor is None: break
            if page.next_cursor in seen: raise ValueError("identity_pagination_loop")
            cursor = page.next_cursor; page_index += 1
    resources = tuple(sorted(rows, key=lambda item: (item.operation_id, item.resource_id)))
    redaction = hashlib.sha256(json.dumps(sorted(plan.selected_fields), separators=(",", ":")).encode()).hexdigest()
    material = {"schema": "redagent.r109-identity-snapshot/v1", "provider": plan.provider.value, "tenant": plan.tenant_id,
        "audience": plan.audience, "consent": plan.consent_mode, "collector": "redagent-r109-emulator",
        "collected_at": collected_at.isoformat(), "plan": plan.plan_sha256, "scopes": list(plan.scopes),
        "roles": list(plan.effective_role_permissions), "partial": sorted(partial), "redaction": redaction,
        "resources": [[item.operation_id, item.resource_id, dict(item.attributes)] for item in resources]}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return IdentitySnapshot(provider=plan.provider.value, tenant_id=plan.tenant_id, audience=plan.audience,
        consent_mode=plan.consent_mode, collector_id="redagent-r109-emulator", collected_at=collected_at,
        plan_sha256=plan.plan_sha256, granted_scopes=plan.scopes, effective_role_permissions=plan.effective_role_permissions,
        complete=not partial, partial_reasons=tuple(sorted(partial)), page_count=pages, resource_count=len(resources),
        resources=resources, redaction_sha256=redaction, snapshot_sha256=digest)
