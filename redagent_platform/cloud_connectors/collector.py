"""Bounded compat_108 collection engine over an injected closed transport."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Mapping, Protocol

from redagent_platform.cloud_connectors.compiler import CompiledCollectionPlan
from redagent_platform.cloud_connectors.contracts import ProviderIdentity


@dataclass(frozen=True, kw_only=True)
class CollectionPage:
    operation_id: str
    page_index: int
    next_cursor: str | None
    resources: tuple[Mapping[str, object], ...]
    response_bytes: int
    partial_reason: str | None = None


class CollectionTransport(Protocol):
    def verify_identity(self) -> ProviderIdentity: ...

    def fetch_page(self, *, operation_id: str, cursor: str | None) -> CollectionPage: ...


@dataclass(frozen=True, kw_only=True)
class SnapshotResource:
    resource_id: str
    operation_id: str
    attributes: Mapping[str, object]


@dataclass(frozen=True, kw_only=True)
class CollectionSnapshot:
    identity: ProviderIdentity
    collected_at: datetime
    plan_sha256: str
    complete: bool
    partial_reasons: tuple[str, ...]
    page_count: int
    resource_count: int
    resources: tuple[SnapshotResource, ...]
    snapshot_sha256: str


def collect_snapshot(
    *, plan: CompiledCollectionPlan, transport: CollectionTransport, collected_at: datetime
) -> CollectionSnapshot:
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("cloud_time_invalid")
    identity = transport.verify_identity()
    if identity != plan.expected_identity:
        raise ValueError("cloud_provider_identity_mismatch")

    pages = 0
    calls = 1  # identity verification consumes one bounded provider call.
    response_bytes = 0
    raw_resources: list[SnapshotResource] = []
    partial: set[str] = set()
    for operation_id in plan.operation_ids:
        cursor: str | None = None
        seen: set[str | None] = set()
        page_index = 0
        while True:
            if cursor in seen:
                raise ValueError("cloud_pagination_loop")
            seen.add(cursor)
            if calls >= plan.max_api_calls or pages >= plan.max_pages:
                raise ValueError("cloud_collection_budget_exceeded")
            page = transport.fetch_page(operation_id=operation_id, cursor=cursor)
            calls += 1
            pages += 1
            if page.next_cursor is not None and page.next_cursor in seen:
                raise ValueError("cloud_pagination_loop")
            if page.operation_id != operation_id or page.page_index != page_index:
                raise ValueError("cloud_page_contract_mismatch")
            if page.response_bytes < 0:
                raise ValueError("cloud_page_contract_mismatch")
            response_bytes += page.response_bytes
            if response_bytes > plan.max_response_bytes:
                raise ValueError("cloud_response_budget_exceeded")
            if page.partial_reason:
                partial.add(page.partial_reason)
            for value in page.resources:
                resource_id = value.get("resource_id")
                if not isinstance(resource_id, str) or not resource_id.strip():
                    raise ValueError("cloud_resource_identity_required")
                attributes = {key: item for key, item in value.items() if key != "resource_id"}
                raw_resources.append(
                    SnapshotResource(
                        resource_id=resource_id.strip(), operation_id=operation_id, attributes=attributes
                    )
                )
                if len(raw_resources) > plan.max_resources:
                    raise ValueError("cloud_resource_budget_exceeded")
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
            page_index += 1

    resources = tuple(sorted(raw_resources, key=lambda item: (item.operation_id, item.resource_id)))
    material = {
        "schema": "redagent.r108-snapshot/v1",
        "identity": [identity.provider.value, identity.tenant, identity.parent],
        "collected_at": collected_at.isoformat(),
        "plan_sha256": plan.plan_sha256,
        "partial_reasons": sorted(partial),
        "resources": [
            [item.operation_id, item.resource_id, dict(sorted(item.attributes.items()))] for item in resources
        ],
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return CollectionSnapshot(
        identity=identity,
        collected_at=collected_at,
        plan_sha256=plan.plan_sha256,
        complete=not partial,
        partial_reasons=tuple(sorted(partial)),
        page_count=pages,
        resource_count=len(resources),
        resources=resources,
        snapshot_sha256=digest,
    )
