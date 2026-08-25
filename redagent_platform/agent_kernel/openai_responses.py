"""Optional thin OpenAI Responses translation; never an authorization boundary."""

from __future__ import annotations

import re
from typing import Mapping, Protocol

from redagent_platform.agent_kernel.contracts import ModelRequest, ModelResult


_MODEL_SNAPSHOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,99}$")
_MUTABLE_ALIASES = {"latest", "default", "recommended", "chat-latest"}


class ResponsesTransport(Protocol):
    def create(self, payload: Mapping[str, object]) -> ModelResult: ...


class OpenAIResponsesAdapter:
    def __init__(self, *, model: str, transport: ResponsesTransport | None) -> None:
        if not _MODEL_SNAPSHOT.fullmatch(model) or model.lower() in _MUTABLE_ALIASES:
            raise ValueError("openai_model_snapshot_required")
        self.model = model
        self.transport = transport

    def build_payload(self, request: ModelRequest) -> dict[str, object]:
        # CRITICAL: do not inherit provider defaults for storage, parallel tools, or hosted tools.
        tools: list[dict[str, object]] = []
        for tool in request.tools:
            schema = tool.input_schema
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise ValueError("openai_tool_schema_not_strict")
            properties = schema.get("properties")
            required = schema.get("required")
            if not isinstance(properties, dict) or not isinstance(required, list) or set(properties) != set(required):
                raise ValueError("openai_tool_schema_not_strict")
            tools.append({
                "type": "function",
                "name": tool.fully_qualified_name,
                "description": tool.description,
                "parameters": schema,
                "strict": True,
            })
        return {
            "model": self.model,
            "input": [
                {"role": "developer", "content": item.content}
                for item in request.instructions
                if item.trust_label.value == "trusted_regenerated"
            ],
            "tools": tools,
            "parallel_tool_calls": False,
            "store": False,
            "background": False,
            "max_output_tokens": request.budget.max_output_tokens,
        }

    def complete(self, request: ModelRequest) -> ModelResult:
        if self.transport is None:
            raise ValueError("openai_transport_required")
        return self.transport.create(self.build_payload(request))
