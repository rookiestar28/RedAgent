"""Closed provider-neutral compat_113 model, tool, context, and budget contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import Mapping, Protocol


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TrustLabel(str, Enum):
    TRUSTED_REGENERATED = "trusted_regenerated"
    UNTRUSTED_USER = "untrusted_user"
    UNTRUSTED_MODEL = "untrusted_model"
    UNTRUSTED_TOOL = "untrusted_tool"
    REVIEWED_FACT = "reviewed_fact"


class ToolKind(str, Enum):
    READ_ONLY = "read_only"
    PROPOSAL = "proposal"


@dataclass(frozen=True, kw_only=True)
class ModelBudget:
    max_turns: int
    max_tool_calls: int
    max_elapsed_seconds: int
    max_input_tokens: int
    max_output_tokens: int
    max_cost_microunits: int
    max_result_bytes: int

    def __post_init__(self) -> None:
        _bounded("budget_max_turns", self.max_turns, 1, 16)
        _bounded("budget_max_tool_calls", self.max_tool_calls, 0, 32)
        _bounded("budget_max_elapsed_seconds", self.max_elapsed_seconds, 1, 300)
        _bounded("budget_max_input_tokens", self.max_input_tokens, 1, 1_000_000)
        _bounded("budget_max_output_tokens", self.max_output_tokens, 1, 128_000)
        _bounded("budget_max_cost_microunits", self.max_cost_microunits, 0, 1_000_000_000)
        _bounded("budget_max_result_bytes", self.max_result_bytes, 1, 10 * 1024 * 1024)


@dataclass(frozen=True, kw_only=True)
class ContextItem:
    item_id: str
    content: str
    trust_label: TrustLabel
    provenance_sha256: str

    def __post_init__(self) -> None:
        _identifier("context_item_id", self.item_id)
        if not isinstance(self.content, str) or not 1 <= len(self.content.encode("utf-8")) <= 16_384:
            raise ValueError("context_content_invalid")
        if not isinstance(self.trust_label, TrustLabel):
            raise ValueError("context_trust_label_invalid")
        _sha256("context_provenance_sha256", self.provenance_sha256)


@dataclass(frozen=True, kw_only=True)
class ProjectedTool:
    fully_qualified_name: str
    tool_kind: ToolKind
    description: str
    description_sha256: str
    input_schema: dict[str, object]
    input_schema_sha256: str
    output_schema_sha256: str
    source_capability_id: str
    source_capability_revision: int
    source_capability_sha256: str
    adapter_id: str
    adapter_version: str
    network_mode: str
    credential_class: str
    approval_tier: str
    budget: ModelBudget
    unsupported_features: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("tool_fully_qualified_name", self.fully_qualified_name),
            ("tool_source_capability_id", self.source_capability_id),
            ("tool_adapter_id", self.adapter_id),
            ("tool_adapter_version", self.adapter_version),
        ):
            _identifier(name, value)
        for name, value in (
            ("tool_description_sha256", self.description_sha256),
            ("tool_input_schema_sha256", self.input_schema_sha256),
            ("tool_output_schema_sha256", self.output_schema_sha256),
            ("tool_source_capability_sha256", self.source_capability_sha256),
        ):
            _sha256(name, value)
        _bounded("tool_source_capability_revision", self.source_capability_revision, 1, 2_147_483_647)
        if not isinstance(self.description, str) or not 1 <= len(self.description) <= 500:
            raise ValueError("tool_description_invalid")
        if not isinstance(self.tool_kind, ToolKind):
            raise ValueError("tool_kind_invalid")
        if self.approval_tier not in {"none", "low", "high", "critical"}:
            raise ValueError("tool_approval_tier_invalid")


@dataclass(frozen=True, kw_only=True)
class ModelRequest:
    request_id: str
    tenant_id: str
    run_id: str
    instructions: tuple[ContextItem, ...]
    tools: tuple[ProjectedTool, ...]
    budget: ModelBudget
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name, value in (("model_request_id", self.request_id), ("model_tenant_id", self.tenant_id), ("model_run_id", self.run_id)):
            _identifier(name, value)
        _aware(self.issued_at)
        _aware(self.expires_at)
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("model_request_expiry_invalid")
        if not self.instructions or len(self.instructions) > 32 or len(self.tools) > 16:
            raise ValueError("model_request_collections_invalid")


@dataclass(frozen=True, kw_only=True)
class ModelToolCall:
    call_id: str
    tool_name: str
    arguments: Mapping[str, object]

    def __post_init__(self) -> None:
        _identifier("model_call_id", self.call_id)
        _identifier("model_tool_name", self.tool_name)
        if not isinstance(self.arguments, Mapping):
            raise ValueError("model_tool_arguments_invalid")


@dataclass(frozen=True, kw_only=True)
class ModelUsage:
    input_tokens: int
    output_tokens: int
    cost_microunits: int

    def __post_init__(self) -> None:
        _bounded("usage_input_tokens", self.input_tokens, 0, 10_000_000)
        _bounded("usage_output_tokens", self.output_tokens, 0, 10_000_000)
        _bounded("usage_cost_microunits", self.cost_microunits, 0, 10_000_000_000)


@dataclass(frozen=True, kw_only=True)
class ModelResult:
    response_id: str
    finish_reason: str
    tool_calls: tuple[ModelToolCall, ...]
    output_text: str | None
    usage: ModelUsage

    def __post_init__(self) -> None:
        _identifier("model_response_id", self.response_id)
        if self.finish_reason not in {"tool_call", "completed", "refused", "cancelled", "limit", "error"}:
            raise ValueError("model_finish_reason_invalid")
        if len(self.tool_calls) > 1:
            # Provider adapters may parse the response, but the kernel never accepts parallel calls.
            pass
        if self.output_text is not None and len(self.output_text.encode("utf-8")) > 1_048_576:
            raise ValueError("model_output_too_large")


class ModelGateway(Protocol):
    def complete(self, request: ModelRequest) -> ModelResult: ...


def _bounded(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
