import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/human-simulation"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("renders consent minimization and deletion truth without people or delivery content inputs", async () => {
  const campaign = {campaign_id: "r112-sink-email-canary-v1", purpose: "synthetic-security-awareness-sink-qualification",
    recipient_class: "synthetic-invalid-owned", sink_id: "sink-r112-owned", template_sha256: "a".repeat(64),
    canary_id: "canary-r112-owned-0001", max_deliveries: 1, rate_per_minute: 1, retention_seconds: 300,
    consent_required: true, suppression_required: true, privacy_review_required: true, deletion_required: true,
    human_delivery: false, external_delivery: false, raw_submission_retention: false, production_qualified: false};
  const run = {run_id: "run-r112", plan_id: "plan-r112", job_id: "job-r112", runner_id: "runner-r112",
    run_state: "sink_delivered", new_delivery_blocked: false, human_delivery_count: 0,
    external_delivery_count: 0, deletion_verified: false, failure_code: null, version: 1};
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r112", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/human-simulation/campaigns") return json({data: [campaign]});
    if (path === "/api/v1/human-simulation/dashboard") return json({data: {campaigns: [campaign], rosters: [{}], suppressions: [{}], privacy_reviews: [{}], templates: [{}], approvals: [{}], plans: [], runs: [run], deliveries: [{}], events: [{}], canaries: [{}], stops: [], deletions: [], rehearsals: []}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Controlled human simulation sink"})).toBeInTheDocument();
  expect(await screen.findByText(/synthetic-invalid-owned · sink-r112-owned/i)).toBeInTheDocument();
  expect(screen.getByText(/Human delivery: no · external delivery: no · raw submission retention: no/i)).toBeInTheDocument();
  expect(screen.getByText("Human / external deliveries")).toBeInTheDocument();
  expect(screen.getByText(/1 exact approvals · 1 sink captures · 1 minimized events · 1 canary correlations/i)).toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/recipient|domain|sender|subject|body|template content|url|attachment|provider|token|password|tracking|command/i)).not.toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Plan ID$|Exact approval ID|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID|Delivery lease ID|Stop switch ID|Quota ID/i)).toHaveLength(0);
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Run ID$|Compiled plan ID|^Job ID$|Exact runner ID/i)).toHaveLength(0);
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally when human simulation read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {
      subject: "operator-1", tenant_id: "tenant-r112", roles: ["operator"], permissions: [],
    }});
    return json({error: {code: "unexpected_request", message: "Unexpected request"}});
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("derives exact synthetic-sink compilation and queue bindings with generated correlations", async () => {
  const payloads: Array<{path: string; body: Record<string, unknown>; roe: string | null}> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r112", roles: ["operator"], permissions: ["job:read", "audit:read", "job:create", "policy:read"]}});
    if (path === "/api/v1/human-simulation/campaigns") return json({data: [humanCampaign()]});
    if (path === "/api/v1/policy/decisions") return json({data: [humanPolicyDecision()], page: page(1)});
    if (path === "/api/v1/human-simulation/dashboard") return json({data: {
      campaigns: [humanCampaign()], rosters: [], suppressions: [], privacy_reviews: [], templates: [], approvals: [], plans: [], runs: [], deliveries: [], events: [], canaries: [], stops: [], deletions: [], rehearsals: [],
      approval_options: [{approval_id: "approval-r112", campaign_id: "r112-sink-email-canary-v1", approval_state: "send-approved-exact", expires_at: "2099-01-01T00:00:00Z"}],
      runner_options: [{runner_id: "runner-r112", environment: "in-process-synthetic-sink", network_plane: "none", required_policy_revision: "r112-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z"}],
      job_options: [{job_id: "job-r112", engagement_id: "engagement-r112", roe_version_id: "roe-r112", status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false}],
      reservation_options: [{reservation_id: "reservation-r112", reserved_amount: 1, consumed_amount: 0, released_amount: 0, remaining_amount: 1, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z"}],
    }});
    if (path === "/api/v1/human-simulation/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({path, body, roe: request.headers.get("X-RedAgent-ROE-Version")});
      return json({data: {plan_id: body.plan_id, campaign_id: body.campaign_id, approval_id: body.approval_id,
        policy_decision_id: body.policy_decision_id, roe_revision: body.roe_version_id,
        reservation_id: body.reservation_id, delivery_lease_id: body.delivery_lease_id,
        stop_switch_id: body.stop_switch_id, plan_sha256: "a".repeat(64), plan_state: "compiled-synthetic-sink",
        expires_at: "2099-01-01T00:00:00Z", version: 1}}, 201);
    }
    if (path === "/api/v1/human-simulation/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({path, body, roe: request.headers.get("X-RedAgent-ROE-Version")});
      return json({data: {...body, run_state: "delivery_pending", new_delivery_blocked: false,
        human_delivery_count: 0, external_delivery_count: 0, deletion_verified: false, failure_code: null, version: 1}}, 202);
    }
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", {name: "Signed sink campaign"}), "r112-sink-email-canary-v1");
  const jobs = screen.getAllByRole("combobox", {name: "Authorized simulation job"});
  await user.selectOptions(jobs[0]!, "job-r112");
  await user.selectOptions(screen.getByRole("combobox", {name: "Current policy decision"}), "decision-r112");
  await user.selectOptions(screen.getByRole("combobox", {name: "Exact three-party approval"}), "approval-r112");
  await user.selectOptions(screen.getByRole("combobox", {name: "Active quota reservation"}), "reservation-r112");
  await user.click(screen.getByRole("button", {name: "Compile synthetic sink plan"}));
  expect(await screen.findByText(/Compiled r112-sink-email-canary-v1 for its exact synthetic-sink approval/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^human-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body.delivery_lease_id).toMatch(/^human-lease-[0-9a-f-]+$/);
  expect(payloads[0]?.body.stop_switch_id).toMatch(/^human-stop-[0-9a-f-]+$/);
  expect(payloads[0]?.body.quota_id).toMatch(/^human-quota-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({campaign_id: "r112-sink-email-canary-v1", approval_id: "approval-r112",
    policy_decision_id: "decision-r112", policy_revision: "r112-v1", roe_version_id: "roe-r112",
    reservation_id: "reservation-r112", confirmation: "--confirm-r112-synthetic-sink-only"});
  expect(payloads[0]?.roe).toBe("roe-r112");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", {name: "Compiled sink plan"}), planId);
  await user.selectOptions(screen.getByRole("combobox", {name: "ROE-matched simulation job"}), "job-r112");
  await user.selectOptions(screen.getByRole("combobox", {name: "Certified in-process sink runner"}), "runner-r112");
  await user.click(screen.getByRole("button", {name: "Queue synthetic sink rehearsal"}));
  expect(await screen.findByText(/Queued .* ROE-matched synthetic-sink job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^human-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({plan_id: planId, job_id: "job-r112", runner_id: "runner-r112",
    confirmation: "--confirm-r112-synthetic-sink-only"});
});

test("projects a correlated synthetic-sink outage and retries without inferring delivery truth", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r112", roles: ["operator"], permissions: ["job:read", "audit:read"]}});
    if (path === "/api/v1/human-simulation/campaigns") return json({data: [humanCampaign()]});
    if (path === "/api/v1/human-simulation/dashboard" && attempts++ === 0) return json({error: {code: "human_simulation_unavailable", message: "Human simulation sink unavailable", correlation_id: "corr-human"}}, 503);
    if (path === "/api/v1/human-simulation/dashboard") return json({data: {campaigns: [humanCampaign()], rosters: [], suppressions: [], privacy_reviews: [], templates: [], approvals: [], plans: [], runs: [], deliveries: [], events: [], canaries: [], stops: [], deletions: [], rehearsals: [], approval_options: [], runner_options: [], job_options: [], reservation_options: []}});
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  expect(await screen.findByRole("alert", {name: "Human simulation sink unavailable"})).toBeVisible();
  expect(screen.getByText("Correlation: corr-human")).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No human-simulation sink run recorded")).toBeVisible();
  expect(attempts).toBe(2);
});

function humanCampaign() { return {campaign_id: "r112-sink-email-canary-v1", purpose: "synthetic-security-awareness-sink-qualification", recipient_class: "synthetic-invalid-owned", sink_id: "sink-r112-owned", template_sha256: "a".repeat(64), canary_id: "canary-r112-owned-0001", max_deliveries: 1, rate_per_minute: 1, retention_seconds: 300, consent_required: true, suppression_required: true, privacy_review_required: true, deletion_required: true, human_delivery: false, external_delivery: false, raw_submission_retention: false, production_qualified: false}; }
function humanPolicyDecision() { return {decision_id: "decision-r112", bundle_revision: "r112-v1", input_hash: "a".repeat(64), boundary: "api", action: "human_simulation.plan.compile", subject_id: "operator-1", resource_type: "human_campaign", resource_id: "r112-sink-email-canary-v1", allowed: true, reason_code: "r112_sink_approved", obligations: ["synthetic_sink_only"], issued_at: "2026-08-25T00:00:00Z", valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy"}; }
function page(total: number) { return {limit: 50, offset: 0, total, has_more: false}; }
function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})); }
