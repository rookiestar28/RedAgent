"""Runner-side last-mile compat_103 target guard placed immediately before contact."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import TypeVar

from redagent_platform.lab_service.contracts import (
    LabBundleManifest, LabTargetAttestation, LabTargetLease, enforce_runner_target,
)


T = TypeVar("T")


async def contact_guarded_lab_target(
    *, manifest: LabBundleManifest, attestation: LabTargetAttestation,
    lease: LabTargetLease, observed_endpoint: str, observed_ip: str,
    occurred_at: datetime, contact: Callable[[], Awaitable[T]],
) -> T:
    # CRITICAL: runner-side enforcement must remain immediately before the only contact callback.
    enforce_runner_target(
        manifest=manifest, attestation=attestation, lease=lease,
        observed_endpoint=observed_endpoint, observed_ip=observed_ip,
        occurred_at=occurred_at,
    )
    return await contact()
