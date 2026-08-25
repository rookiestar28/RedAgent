"""Deterministic provider implementations for compat_113 qualification."""

from __future__ import annotations

from redagent_platform.agent_kernel.contracts import ModelRequest, ModelResult


class DeterministicFakeModelGateway:
    def __init__(self, scripted_results: tuple[ModelResult, ...]) -> None:
        if not scripted_results:
            raise ValueError("fake_provider_script_required")
        self._results = scripted_results
        self.request_count = 0
        self.external_contact_count = 0

    def complete(self, request: ModelRequest) -> ModelResult:
        if self.request_count >= len(self._results):
            raise ValueError("fake_provider_script_exhausted")
        result = self._results[self.request_count]
        self.request_count += 1
        return result
