"""Sandbox-safe contracts for the R173 inert Temporal start bridge."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re


ADMISSION_START_BRIDGE_SCHEMA_VERSION = "redagent.autonomous-campaign-start-bridge/v1"
ADMISSION_START_BRIDGE_WORKFLOW_NAME = "redagent.autonomous-campaign-start-bridge.v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AutonomousCampaignStartBridgeState(str, Enum):
    EXECUTION_QUEUED = "execution_queued"
    FAILED_BEFORE_IO = "failed_before_io"


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignStartBridgeWorkflowInputV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    execution_run_id: str
    input_sha256: str
    approval_receipt_sha256: str
    admission_receipt_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_START_BRIDGE_SCHEMA_VERSION:
            raise ValueError("start_bridge_schema_unsupported")
        for name, maximum in (
            ("tenant_id", 64),
            ("campaign_id", 64),
            ("execution_run_id", 64),
        ):
            _identifier(f"start_bridge_{name}", getattr(self, name), maximum)
        for name in (
            "input_sha256",
            "approval_receipt_sha256",
            "admission_receipt_sha256",
        ):
            _digest(f"start_bridge_{name}", getattr(self, name))


@dataclass(frozen=True, slots=True, kw_only=True)
class AutonomousCampaignStartBridgeSnapshotV1:
    schema_version: str
    execution_run_id: str
    workflow_request_sha256: str
    state: AutonomousCampaignStartBridgeState
    revision: int

    def __post_init__(self) -> None:
        if self.schema_version != ADMISSION_START_BRIDGE_SCHEMA_VERSION:
            raise ValueError("start_bridge_snapshot_schema_unsupported")
        _identifier("start_bridge_snapshot_execution_run_id", self.execution_run_id, 64)
        _digest("start_bridge_snapshot_request_sha256", self.workflow_request_sha256)
        if not isinstance(self.state, AutonomousCampaignStartBridgeState):
            raise ValueError("start_bridge_snapshot_state_invalid")
        if type(self.revision) is not int or not 1 <= self.revision <= 2_147_483_647:
            raise ValueError("start_bridge_snapshot_revision_invalid")


def admission_start_bridge_request_sha256(
    request: AutonomousCampaignStartBridgeWorkflowInputV1,
) -> str:
    if not isinstance(request, AutonomousCampaignStartBridgeWorkflowInputV1):
        raise ValueError("start_bridge_request_invalid")
    # CRITICAL: keep this module dependency-light; importing campaign admission pulls native
    # cryptography bindings into Temporal's sandbox and prevents Workflow registration.
    canonical = json.dumps(
        asdict(request),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def deterministic_admission_start_bridge_workflow_id(
    tenant_id: str,
    execution_run_id: str,
) -> str:
    _identifier("start_bridge_workflow_tenant_id", tenant_id, 64)
    _identifier("start_bridge_workflow_execution_run_id", execution_run_id, 64)
    stable = hashlib.sha256(
        f"autonomous-campaign-start-bridge-v1\0{tenant_id}\0{execution_run_id}".encode(
            "utf-8"
        )
    ).hexdigest()[:40]
    return f"redagent-autonomous-start-{stable}"


def _identifier(name: str, value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")
