from __future__ import annotations

from redagent_platform.containment_service.control import activation_requires_dual_control, scope_matches
from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind


def test_control_hierarchy_matches_only_typed_exact_context() -> None:
    context = {
        "tenant_id": "tenant-1", "campaign_id": "campaign-1",
        "job_id": "job-1", "capability_id": "capability-1",
    }
    assert scope_matches(ControlScope(ControlScopeKind.GLOBAL, None), **context)
    assert scope_matches(ControlScope(ControlScopeKind.TENANT, "tenant-1"), **context)
    assert scope_matches(ControlScope(ControlScopeKind.CAMPAIGN, "campaign-1"), **context)
    assert scope_matches(ControlScope(ControlScopeKind.JOB, "job-1"), **context)
    assert scope_matches(ControlScope(ControlScopeKind.CAPABILITY, "capability-1"), **context)
    assert not scope_matches(ControlScope(ControlScopeKind.JOB, "job-2"), **context)
    assert not scope_matches(ControlScope(ControlScopeKind.TENANT, "tenant-2"), **context)


def test_exact_job_cancel_is_immediate_but_broad_controls_require_dual_control() -> None:
    assert not activation_requires_dual_control(ControlScopeKind.JOB)
    for kind in (
        ControlScopeKind.GLOBAL, ControlScopeKind.TENANT,
        ControlScopeKind.CAMPAIGN, ControlScopeKind.CAPABILITY,
    ):
        assert activation_requires_dual_control(kind)
