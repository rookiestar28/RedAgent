"""Fully assembled relational metadata and deterministic persistence invariants."""

from __future__ import annotations

from ._base import metadata
from . import agent as _agent  # noqa: F401
from . import api_differential as _api_differential  # noqa: F401
from . import artifact as _artifact  # noqa: F401
from . import campaign_loop as _campaign_loop  # noqa: F401
from . import campaign_admission as _campaign_admission  # noqa: F401
from . import campaign_admission_start as _campaign_admission_start  # noqa: F401
from . import campaign_application as _campaign_application  # noqa: F401
from . import campaign_child_replanning as _campaign_child_replanning  # noqa: F401
from . import campaign_execution as _campaign_execution  # noqa: F401
from . import campaign_replanning as _campaign_replanning  # noqa: F401
from . import cloud as _cloud  # noqa: F401
from . import containment as _containment  # noqa: F401
from . import control_plane as _control_plane  # noqa: F401
from . import enterprise_identity as _enterprise_identity  # noqa: F401
from . import evidence as _evidence  # noqa: F401
from . import finding_operations as _finding_operations  # noqa: F401
from . import human_simulation as _human_simulation  # noqa: F401
from . import identity_saas as _identity_saas  # noqa: F401
from . import lab as _lab  # noqa: F401
from . import mcp_workbench as _mcp_workbench  # noqa: F401
from . import network as _network  # noqa: F401
from . import nuclei as _nuclei  # noqa: F401
from . import observability as _observability  # noqa: F401
from . import policy as _policy  # noqa: F401
from . import purple as _purple  # noqa: F401
from . import runner as _runner  # noqa: F401
from . import secrets as _secrets  # noqa: F401
from . import zap as _zap  # noqa: F401
from .invariants import JobStatus, assert_job_transition, compute_issue_fingerprint


TENANT_TABLE_NAMES = frozenset(set(metadata.tables) - {"tenants"})

__all__ = (
    "JobStatus",
    "TENANT_TABLE_NAMES",
    "assert_job_transition",
    "compute_issue_fingerprint",
    "metadata",
)
