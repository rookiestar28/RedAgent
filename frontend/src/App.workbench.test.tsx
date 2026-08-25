import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/workbench"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("separates trust lanes exact disclosure inventory review and freeze without transport inputs", async () => {
  const now = "2026-07-12T09:00:00Z";
  const registration = {registration_id: "r114-fixture-registration", server_id: "redagent-fixture",
    protocol_version: "2025-11-25", transport_kind: "in_process", inventory_sha256: "a".repeat(64),
    risk_class: "high", data_class: "internal", registration_state: "attested-fixture-only",
    issued_at: now, expires_at: "2026-07-12T09:10:00Z", version: 1};
  const draft = {draft_id: "draft-r114", campaign_id: "campaign-r114", draft_revision: 1,
    predecessor_draft_id: null, proposal_sha256: "b".repeat(64), authority_sha256: "c".repeat(64),
    draft_state: "awaiting_review", created_by: "operator-r114", expires_at: "2026-07-12T09:02:00Z", version: 1};
  const trust = ["immutable_authority", "untrusted_external", "ai_suggestion"].map((trust_lane, index) => ({
    draft_id: draft.draft_id, item_id: `item-${index}`, trust_lane, summary_sha256: `${index + 1}`.repeat(64),
    provenance_sha256: `${index + 4}`.repeat(64), item_state: "visible-minimized", version: 1}));
  const disclosure = {disclosure_id: "disclosure-r114", draft_id: draft.draft_id,
    sanitized_fields_sha256: "d".repeat(64), target_scope_sha256: "e".repeat(64), access_class: "none",
    egress_class: "none", side_effects_sha256: "f".repeat(64), budget_sha256: "1".repeat(64),
    disclosure_state: "review-required", version: 1};
  const data = {binding_options: [fixtureBinding()], registrations: [registration], attestations: [{attestation_id: "attestation-r114",
    registration_id: registration.registration_id, transport_kind: "in_process", identity_sha256: "2".repeat(64),
    authorization_profile_sha256: "3".repeat(64), boundary_controls_sha256: "4".repeat(64),
    transport_enabled: false, attestation_state: "qualified-no-io", attested_at: now, version: 1}],
    inventories: [], items: [{item_id: "tool-r114", inventory_id: "inventory-r114", item_name: "campaign.propose",
      item_kind: "tool", description_sha256: "5".repeat(64), request_schema_sha256: "6".repeat(64),
      result_schema_sha256: "7".repeat(64), risk_class: "high", data_class: "internal",
      tool_mode: "proposal_only", item_state: "pinned", version: 1}], freezes: [], drafts: [draft],
    trust_items: trust, disclosures: [disclosure], decisions: [], lifecycle: []};
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r114", tenant_id: "tenant-r114",
      roles: ["operator"], permissions: ["engagement:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/workbench/dashboard") return json({data});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Supervised campaign workbench"})).toBeInTheDocument();
  expect(await screen.findByText(/2025-11-25 · in_process · attested-fixture-only/i)).toBeInTheDocument();
  expect(screen.getByText(/immutable authority/i)).toBeInTheDocument();
  expect(screen.getByText(/untrusted external/i)).toBeInTheDocument();
  expect(screen.getByText(/AI suggestion/i)).toBeInTheDocument();
  expect(screen.getByText(/none · none · review-required/i)).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Approve exact proposal"})).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Create successor and invalidate approval"})).toBeInTheDocument();
  expect(screen.getByRole("button", {name: "Freeze server and invalidate approvals"})).toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/draft id|campaign id|stored plan id|target id/i)).not.toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/prompt|message|url|server url|command|args|environment|header|token|credential|raw evidence|reasoning|dispatch/i)).not.toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally without Workbench read authority", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-r114", tenant_id: "tenant-r114",
      roles: ["operator"], permissions: []}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("binds create review successor and freeze to exact server-owned fixture truth", async () => {
  const binding = fixtureBinding(); const data = fixtureDashboard(binding); const payloads: Array<{path: string; body: Record<string, unknown>}> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r114", tenant_id: "tenant-r114",
      roles: ["operator"], permissions: ["audit:read", "job:create", "job:stop"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/workbench/dashboard") return json({data});
    if (request.method === "POST") {
      const body = await request.json() as Record<string, unknown>; payloads.push({path, body});
      if (path === "/api/v1/workbench/drafts") return json({data: {draft_id: body.draft_id, draft_state: "awaiting_review", proposal_sha256: "8".repeat(64), version: 1}}, 202);
      if (path.endsWith("/review")) return json({data: {draft_id: "draft-r114", decision_id: body.decision_id, decision: "approve_exact", proposal_sha256: "b".repeat(64), draft_state: "approved", version: 1}});
      if (path.endsWith("/successors")) return json({data: {draft_id: body.successor_draft_id, predecessor_draft_id: "draft-r114", proposal_sha256: "9".repeat(64), draft_state: "awaiting_review", approval_invalidated: true, version: 1}}, 202);
      if (path.endsWith("/freeze")) return json({data: {registration_id: "r114-fixture-registration", expected_inventory_sha256: "a".repeat(64), freeze_state: "active", invalidated_approval_count: 1, version: 1}});
    }
    throw new Error(`unexpected ${request.method} ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); vi.spyOn(window, "confirm").mockReturnValue(true);
  const user = userEvent.setup(); render(<App />);
  await user.click(await screen.findByRole("button", {name: "Create fixture-only structured draft"}));
  await user.click(screen.getByRole("button", {name: "Approve exact proposal"}));
  await user.click(screen.getByRole("button", {name: "Create successor and invalidate approval"}));
  await user.click(screen.getByRole("button", {name: "Freeze server and invalidate approvals"}));
  await waitFor(() => expect(payloads).toHaveLength(4));
  expect(payloads[0]?.body).toMatchObject({campaign_id: binding.campaign_id, plan_id: binding.plan_id,
    target_id: binding.target_id, tool_fqn: binding.tool_fqn, confirmation: "--confirm-r114-structured-draft"});
  expect(payloads[0]?.body.draft_id).toMatch(/^draft-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({expected_proposal_sha256: "b".repeat(64), decision: "approve_exact"});
  expect(payloads[1]?.body.decision_id).toMatch(/^review-[0-9a-f-]+$/);
  expect(payloads[2]?.body).toMatchObject({plan_id: binding.successor_plan_id,
    confirmation: "--confirm-r114-successor-invalidates-approval"});
  expect(payloads[2]?.body.successor_draft_id).toMatch(/^successor-[0-9a-f-]+$/);
  expect(payloads[3]?.body).toEqual({expected_inventory_sha256: "a".repeat(64), confirmation: "--confirm-r114-freeze-and-invalidate"});
});

test("projects a correlated Workbench outage and retries without inferring draft state", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r114", tenant_id: "tenant-r114",
      roles: ["operator"], permissions: ["audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/workbench/dashboard" && attempts++ === 0) return json({error: {code: "workbench_unavailable", message: "Workbench unavailable", correlation_id: "corr-workbench"}}, 503);
    if (path === "/api/v1/workbench/dashboard") return json({data: fixtureDashboard(fixtureBinding(), false)});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  expect(await screen.findByRole("alert", {name: "Workbench unavailable"})).toBeVisible();
  expect(screen.getByText("Correlation: corr-workbench")).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No stored drafts require review.")).toBeVisible();
  expect(attempts).toBe(2);
});

function fixtureBinding() { return {binding_id: "binding-r114-fixture", campaign_id: "campaign-r114",
  campaign_label: "compat_114 synthetic campaign", plan_id: "plan-r114-stored", plan_label: "Stored fixture plan",
  successor_plan_id: "plan-r114-successor", successor_plan_label: "Revised fixture plan",
  target_id: "target-r114-owned", target_label: "Owned synthetic target",
  tool_fqn: "redagent.r114-mcp-fixture.propose.v1", binding_state: "available", fixture_only: true,
  egress_class: "none"}; }

function fixtureDashboard(binding: ReturnType<typeof fixtureBinding>, includeDraft = true) {
  const now = "2026-07-12T09:00:00Z"; const registration = {registration_id: "r114-fixture-registration",
    server_id: "redagent-fixture", protocol_version: "2025-11-25", transport_kind: "in_process",
    inventory_sha256: "a".repeat(64), risk_class: "high", data_class: "internal",
    registration_state: "attested-fixture-only", issued_at: now, expires_at: "2099-07-12T09:10:00Z", version: 1};
  const draft = {draft_id: "draft-r114", campaign_id: binding.campaign_id, draft_revision: 1,
    predecessor_draft_id: null, proposal_sha256: "b".repeat(64), authority_sha256: "c".repeat(64),
    draft_state: "awaiting_review", created_by: "operator-r114", expires_at: "2099-07-12T09:02:00Z", version: 1};
  return {binding_options: [binding], registrations: [registration], attestations: [], inventories: [], items: [],
    freezes: [], drafts: includeDraft ? [draft] : [], trust_items: [], disclosures: [], decisions: [], lifecycle: []};
}

function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status,
  headers: {"content-type": "application/json"}})); }
