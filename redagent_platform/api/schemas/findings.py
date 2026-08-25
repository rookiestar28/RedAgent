"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    Field,
    Literal,
    OPAQUE_ID,
)

from redagent_platform.api.schemas.common import (
    StrictModel,
)

class FindingIngestRequest(StrictModel):
    finding_id: str = Field(min_length=1, max_length=64, pattern=OPAQUE_ID)
    tool: str = Field(min_length=1, max_length=100)
    rule_id: str = Field(min_length=1, max_length=200)
    tool_version: str = Field(min_length=1, max_length=100)
    database_version: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: Literal["tentative", "firm", "confirmed"]
    affected_resource: str = Field(min_length=1, max_length=500)
    location: str = Field(min_length=1, max_length=1000)
    evidence_reference: str = Field(min_length=1, max_length=500)
    redaction_state: Literal["sanitized", "restricted", "pending"]

__all__ = (
    "FindingIngestRequest",
)
