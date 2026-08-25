"""Fail-closed validation between untrusted model calls and durable proposals."""

from __future__ import annotations

from collections.abc import Mapping

from redagent_platform.agent_kernel.contracts import ModelToolCall


_FORBIDDEN_ARGUMENTS = frozenset({
    "command", "argv", "shell", "script", "code", "url", "browser", "credential", "secret",
    "token", "password", "policy", "approval", "evidence_export", "runner", "dispatch",
})


def validate_model_tool_calls(
    calls: tuple[ModelToolCall, ...],
    *,
    allowed_tools: Mapping[str, set[str]],
) -> ModelToolCall | None:
    if len(calls) > 1:
        raise ValueError("parallel_tool_calls_forbidden")
    if not calls:
        return None
    call = calls[0]
    expected_fields = allowed_tools.get(call.tool_name)
    if expected_fields is None:
        raise ValueError("unknown_tool")
    fields = {str(key) for key in call.arguments}
    if fields != expected_fields or fields.intersection(_FORBIDDEN_ARGUMENTS):
        raise ValueError("proposal_arguments_invalid")
    return call
