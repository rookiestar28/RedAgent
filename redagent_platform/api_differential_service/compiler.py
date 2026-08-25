"""Closed compat_106 compiler: promoted identities in, immutable cases out."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Mapping

from redagent_platform.api_differential_service.contracts import (
    ApiDifferentialAuthorization,
    ApiDifferentialProfileId,
    GATEWAY_ORIGIN,
    IdentityRelation,
    IdentityState,
    OperationRisk,
    certified_profiles,
)
from redagent_platform.api_differential_service.specification import OpenApiSnapshot


@dataclass(frozen=True, kw_only=True)
class CompiledDifferentialCase:
    case_id: str
    operation_id: str
    method: str
    path_template: str
    risk: OperationRisk
    relation: IdentityRelation
    privileged_identity_handle: str
    lower_identity_handle: str
    gateway_origin: str
    expected_lower_outcomes: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class CompiledDifferentialPlan:
    profile_id: ApiDifferentialProfileId
    spec_sha256: str
    seed: int
    cases: tuple[CompiledDifferentialCase, ...]
    max_requests: int
    request_rate_per_second: int
    concurrency: int
    timeout_seconds: int
    plan_sha256: str


def compile_differential_plan(
    *,
    profile_id: ApiDifferentialProfileId,
    snapshot: OpenApiSnapshot,
    authorization: ApiDifferentialAuthorization,
    identity_handles: Mapping[IdentityState, str],
    seed: int,
    now: datetime,
) -> CompiledDifferentialPlan:
    profile = certified_profiles()[profile_id]
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("api_time_invalid")
    if now < authorization.approved_at or now >= authorization.expires_at:
        raise ValueError("api_authorization_inactive")
    if profile_id not in authorization.approved_profile_ids:
        raise ValueError("api_profile_not_authorized")
    if snapshot.spec_sha256 != authorization.approved_spec_sha256:
        raise ValueError("api_spec_not_authorized")
    if not isinstance(seed, int) or seed < 0 or seed > 2**63 - 1:
        raise ValueError("api_seed_invalid")
    required = {
        IdentityState.OWNER, IdentityState.PEER, IdentityState.TENANT_ADMIN,
        IdentityState.OTHER_TENANT, IdentityState.EXPIRED, IdentityState.REVOKED,
    }
    if set(identity_handles) != required or any(not _safe_handle(value) for value in identity_handles.values()):
        raise ValueError("api_identity_handle_inventory_invalid")
    cases: list[CompiledDifferentialCase] = []
    for operation in snapshot.operations:
        if operation.operation_id == "getDocument":
            relation = IdentityRelation.CROSS_OWNER
            privileged = identity_handles[IdentityState.OWNER]
            lower = identity_handles[IdentityState.PEER]
            outcomes = ("403", "404", "200_filtered")
        elif operation.operation_id == "getAudit":
            relation = IdentityRelation.LOWER_ROLE
            privileged = identity_handles[IdentityState.TENANT_ADMIN]
            lower = identity_handles[IdentityState.PEER]
            outcomes = ("403",)
        elif operation.operation_id == "getProfile":
            relation = IdentityRelation.PROPERTY_RESTRICTED
            privileged = identity_handles[IdentityState.OWNER]
            lower = identity_handles[IdentityState.PEER]
            outcomes = ("200_filtered", "403", "404")
        elif operation.operation_id == "createDocument":
            relation = IdentityRelation.CROSS_OWNER
            privileged = identity_handles[IdentityState.OWNER]
            lower = identity_handles[IdentityState.PEER]
            outcomes = ("201",)
        elif operation.operation_id in {"transferDocument", "deleteDocument"}:
            relation = IdentityRelation.CROSS_OWNER
            privileged = identity_handles[IdentityState.OWNER]
            lower = identity_handles[IdentityState.PEER]
            outcomes = ("403", "404")
        else:  # pragma: no cover - snapshot promotion prevents this branch
            raise ValueError("api_operation_not_compilable")
        cases.append(CompiledDifferentialCase(
            case_id=f"r106:{operation.operation_id}:{relation.value}",
            operation_id=operation.operation_id,
            method=operation.method,
            path_template=operation.path_template,
            risk=operation.risk,
            relation=relation,
            privileged_identity_handle=privileged,
            lower_identity_handle=lower,
            gateway_origin=GATEWAY_ORIGIN,
            expected_lower_outcomes=outcomes,
        ))
    material = {
        "schema": "redagent.r106-plan/v1", "profile_id": profile_id.value,
        "spec_sha256": snapshot.spec_sha256, "seed": seed,
        "cases": [case.__dict__ | {"risk": case.risk.value, "relation": case.relation.value} for case in cases],
        "limits": [profile.max_requests, profile.request_rate_per_second, profile.concurrency, profile.timeout_seconds],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledDifferentialPlan(
        profile_id=profile_id, spec_sha256=snapshot.spec_sha256, seed=seed,
        cases=tuple(cases), max_requests=profile.max_requests,
        request_rate_per_second=profile.request_rate_per_second,
        concurrency=profile.concurrency, timeout_seconds=profile.timeout_seconds,
        plan_sha256=digest,
    )


def _safe_handle(value: object) -> bool:
    return isinstance(value, str) and value.startswith("identity-") and len(value) <= 100
