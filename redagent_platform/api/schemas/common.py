"""Domain-owned strict public API schemas."""

from __future__ import annotations

from redagent_platform.api.schemas._support import (
    BaseModel,
    ConfigDict,
    Field,
)

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

class PaginationQuery(StrictModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=100000)
    query: str | None = Field(default=None, min_length=1, max_length=100)

class PageData(StrictModel):
    limit: int
    offset: int
    returned: int
    next_offset: int | None = Field(default=None, ge=0, le=100500)

class MutationMeta(StrictModel):
    replayed: bool
    audit_id: str
    outbox_id: str

__all__ = (
    "StrictModel",
    "PaginationQuery",
    "PageData",
    "MutationMeta",
)
