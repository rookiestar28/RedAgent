"""Typed stop-control hierarchy independent of adapters and models."""

from __future__ import annotations

from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind


_DUAL_CONTROL_SCOPES = frozenset(
    {
        ControlScopeKind.GLOBAL,
        ControlScopeKind.TENANT,
        ControlScopeKind.CAMPAIGN,
        ControlScopeKind.CAPABILITY,
    }
)


def activation_requires_dual_control(kind: ControlScopeKind) -> bool:
    if not isinstance(kind, ControlScopeKind):
        raise ValueError("control_scope_kind_invalid")
    return kind in _DUAL_CONTROL_SCOPES


def scope_matches(
    scope: ControlScope,
    *,
    tenant_id: str,
    campaign_id: str | None,
    job_id: str,
    capability_id: str,
) -> bool:
    values = {
        ControlScopeKind.TENANT: tenant_id,
        ControlScopeKind.CAMPAIGN: campaign_id,
        ControlScopeKind.JOB: job_id,
        ControlScopeKind.CAPABILITY: capability_id,
    }
    if scope.kind is ControlScopeKind.GLOBAL:
        return True
    return scope.scope_id == values[scope.kind]
