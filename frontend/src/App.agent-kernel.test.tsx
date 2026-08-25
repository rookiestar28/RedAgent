import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/agent"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("renders exact proposal approval budget and cancel truth without prompt or direct tool controls", async () => {
  const tool = {tool_fqn: "redagent.human-simulation-sink.propose.v1", capability_id: "human-simulation-sink",
    capability_revision: 1, capability_sha256: "a".repeat(64), input_schema_sha256: "b".repeat(64),
    output_schema_sha256: "c".repeat(64), approval_tier: "high", network_class: "none", access_class: "none",
    max_turns: 3, max_tool_calls: 1, max_elapsed_seconds: 30, max_input_tokens: 4000, max_output_tokens: 500,
    max_cost_microunits: 10000, max_result_bytes: 4096,
    unsupported_features: ["arbitrary_command", "plugin_loading", "human_delivery"]};
  const run = {run_id: "run-r113", campaign_id: "campaign-r113", provider_id: "deterministic-fake",
    registry_sha256: "d".repeat(64), run_state: "awaiting_model", cancel_requested: false, failure_code: null,
    started_at: "2026-07-12T04:00:00Z", expires_at: "2026-07-12T04:05:00Z", completed_at: null, version: 1};
  const proposal = {proposal_id: "proposal-run-r113", run_id: "run-r113", tool_fqn: tool.tool_fqn,
    proposal_sha256: "e".repeat(64), argument_sha256: "f".repeat(64), target_sha256: "1".repeat(64),
    side_effect_classes: ["proposal_only"], roe_version_id: "roe-r113-approved", policy_revision: "r099-v1",
    policy_decision_id: "r113-deterministic-policy-allow", proposal_state: "awaiting_approval",
    expires_at: "2026-07-12T04:02:00Z", version: 1};
  const budget = {ledger_id: "budget-run-r113", run_id: "run-r113", turn_count: 1, tool_call_count: 1,
    input_token_count: 100, result_token_count: 20, cost_microunits: 50, result_bytes: 128,
    elapsed_millis: 500, ledger_state: "within_budget", version: 2};
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-reviewer", tenant_id: "tenant-r113", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/agent/tools") return json({data: [tool]});
    if (path === "/api/v1/agent/dashboard") return json({data: {tools: [tool], runs: [run], proposals: [proposal], approvals: [], budgets: [budget], traces: []}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Supervised agent proposal kernel"})).toBeInTheDocument();
  expect(await screen.findByText(/deterministic-fake · awaiting_model/i)).toBeInTheDocument();
  expect(screen.getByText(/proposal_only · awaiting_approval/i)).toBeInTheDocument();
  expect(screen.getByText(/1 turns · 1 tool calls · 50 µunits · 128 bytes/i)).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Approve exact proposal hash"})).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Cancel and block progression"})).toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/prompt|instructions|message|command|shell|url|browser|provider|model|api key|credential|policy|raw evidence|runner|dispatch|budget/i)).not.toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally when agent kernel read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {
      subject: "operator-reviewer", tenant_id: "tenant-r113", roles: ["operator"], permissions: [],
    }});
    return json({error: {code: "unexpected_request", message: "Unexpected request"}});
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("approves only the stored proposal hash and cancels the exact run version", async () => {
  const tool = agentTool(); const run = agentRun(); const proposal = agentProposal(tool.tool_fqn); const budget = agentBudget();
  const payloads: Array<{path: string; body: Record<string, unknown>}> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-reviewer", tenant_id: "tenant-r113", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/agent/tools") return json({data: [tool]});
    if (path === "/api/v1/agent/dashboard") return json({data: {tools: [tool], runs: [run], proposals: [proposal], approvals: [], budgets: [budget], traces: []}});
    if (path === "/api/v1/agent/proposals/proposal-run-r113/approve" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>; payloads.push({path, body});
      return json({data: {...proposal, proposal_state: "approved", version: 2}});
    }
    if (path === "/api/v1/agent/runs/run-r113/cancel" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>; payloads.push({path, body});
      return json({data: {...run, run_state: "cancelled", cancel_requested: true, completed_at: "2026-07-12T04:01:00Z", version: 2}});
    }
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); vi.spyOn(window, "confirm").mockReturnValue(true);
  const user = userEvent.setup(); render(<App />);
  await user.click(await screen.findByRole("button", {name: "Approve exact proposal hash"}));
  expect(await screen.findByText(/Exact proposal hash approved.*no tool was dispatched/i)).toBeVisible();
  expect(payloads[0]?.body.approval_id).toMatch(/^approval-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({expected_proposal_sha256: proposal.proposal_sha256, confirmation: "--confirm-r113-exact-proposal"});
  await user.click(screen.getByRole("button", {name: "Cancel and block progression"}));
  expect(await screen.findByText(/Further progression blocked for run-r113/)).toBeVisible();
  expect(payloads[1]?.body).toEqual({expected_version: 1, reason: "operator_cancelled_from_agent_console"});
});

test("projects a correlated agent outage and retries without inferring proposal state", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-reviewer", tenant_id: "tenant-r113", roles: ["operator"], permissions: ["job:read", "audit:read"]}});
    if (path === "/api/v1/agent/tools") return json({data: [agentTool()]});
    if (path === "/api/v1/agent/dashboard" && attempts++ === 0) return json({error: {code: "agent_kernel_unavailable", message: "Agent kernel unavailable", correlation_id: "corr-agent"}}, 503);
    if (path === "/api/v1/agent/dashboard") return json({data: {tools: [agentTool()], runs: [], proposals: [], approvals: [], budgets: [], traces: []}});
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  expect(await screen.findByRole("alert", {name: "Agent kernel unavailable"})).toBeVisible();
  expect(screen.getByText("Correlation: corr-agent")).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No stored proposals require review.")).toBeVisible();
  expect(attempts).toBe(2);
});

function agentTool() { return {tool_fqn: "redagent.human-simulation-sink.propose.v1", capability_id: "human-simulation-sink", capability_revision: 1, capability_sha256: "a".repeat(64), input_schema_sha256: "b".repeat(64), output_schema_sha256: "c".repeat(64), approval_tier: "high", network_class: "none", access_class: "none", max_turns: 3, max_tool_calls: 1, max_elapsed_seconds: 30, max_input_tokens: 4000, max_output_tokens: 500, max_cost_microunits: 10000, max_result_bytes: 4096, unsupported_features: ["arbitrary_command", "plugin_loading", "human_delivery"]}; }
function agentRun() { return {run_id: "run-r113", campaign_id: "campaign-r113", provider_id: "deterministic-fake", registry_sha256: "d".repeat(64), run_state: "awaiting_model", cancel_requested: false, failure_code: null, started_at: "2026-07-12T04:00:00Z", expires_at: "2099-07-12T04:05:00Z", completed_at: null, version: 1}; }
function agentProposal(toolFqn: string) { return {proposal_id: "proposal-run-r113", run_id: "run-r113", tool_fqn: toolFqn, proposal_sha256: "e".repeat(64), argument_sha256: "f".repeat(64), target_sha256: "1".repeat(64), side_effect_classes: ["proposal_only"], roe_version_id: "roe-r113-approved", policy_revision: "r099-v1", policy_decision_id: "r113-deterministic-policy-allow", proposal_state: "awaiting_approval", expires_at: "2099-07-12T04:02:00Z", version: 1}; }
function agentBudget() { return {ledger_id: "budget-run-r113", run_id: "run-r113", turn_count: 1, tool_call_count: 1, input_token_count: 100, result_token_count: 20, cost_microunits: 50, result_bytes: 128, elapsed_millis: 500, ledger_state: "within_budget", version: 2}; }

function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})); }
