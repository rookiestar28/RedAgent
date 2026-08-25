"""Finite aggregate model/tool budget enforcement."""

from __future__ import annotations

from datetime import datetime

from redagent_platform.agent_kernel.contracts import ModelBudget, ModelUsage


class BudgetLedger:
    def __init__(self, budget: ModelBudget, *, started_at: datetime) -> None:
        self.budget = budget
        self.started_at = started_at
        self.turns = self.tool_calls = self.input_tokens = self.output_tokens = self.cost_microunits = self.result_bytes = 0

    def record_turn(self, *, usage: ModelUsage, result_bytes: int, tool_calls: int, now: datetime) -> None:
        self.turns += 1
        self.tool_calls += tool_calls
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cost_microunits += usage.cost_microunits
        self.result_bytes += result_bytes
        checks = (
            (self.turns > self.budget.max_turns, "turns"),
            (self.tool_calls > self.budget.max_tool_calls, "tool_calls"),
            (self.input_tokens > self.budget.max_input_tokens, "input_tokens"),
            (self.output_tokens > self.budget.max_output_tokens, "output_tokens"),
            (self.cost_microunits > self.budget.max_cost_microunits, "cost"),
            (self.result_bytes > self.budget.max_result_bytes, "result_bytes"),
            ((now - self.started_at).total_seconds() > self.budget.max_elapsed_seconds, "elapsed"),
        )
        for exceeded, name in checks:
            if exceeded:
                raise ValueError(f"budget_{name}_exceeded")
