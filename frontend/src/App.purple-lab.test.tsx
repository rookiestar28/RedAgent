import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/purple-lab"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("renders ATT&CK detection cleanup truth without command or target inputs", async () => {
  const ability = {ability_id: "r111-file-stage-marker-v1", attack_version: "enterprise-v18", attack_technique_id: "T1074.001",
    phases: ["prepare", "execute", "telemetry", "cleanup", "verify"], detection_strategy_id: "DET-r111-file-create",
    analytic_id: "AN-r111-owned-marker", event_schema: "redagent.r111-owned-file-event-v1", timeout_seconds: 5,
    lab_only: true, network_allowed: false, subprocess_allowed: false, external_content_allowed: false, production_qualified: false};
  const run = {run_id: "run-r111", plan_id: "plan-r111", job_id: "job-r111", runner_id: "runner-r111", run_state: "succeeded",
    dispatch_blocked: true, detection_observed: true, cleanup_complete: true, teardown_verified: true, failure_code: null, version: 2};
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r111", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/purple-lab/abilities") return json({data: [ability]});
    if (path === "/api/v1/purple-lab/dashboard") return json({data: {abilities: [ability], labs: [], approvals: [], plans: [], runs: [run], detections: [], telemetry: [{event_sha256: "a".repeat(64)}], cleanups: [{receipt_id: "cleanup-r111"}], teardowns: [{receipt_id: "teardown-r111"}], rehearsals: [{rehearsal_id: "rehearsal-r111"}]}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Lab-only purple-team runtime"})).toBeInTheDocument();
  expect(await screen.findByText(/T1074.001 · lab only/i)).toBeInTheDocument();
  expect(screen.getByText(/Expected detection: DET-r111-file-create/i)).toBeInTheDocument();
  expect(screen.getByText(/External frameworks and content.*disabled/i)).toBeInTheDocument();
  expect(screen.getByText("Expected telemetry observed")).toBeInTheDocument();
  expect(screen.getByText(/1 correlated telemetry events.*1 cleanup receipts.*1 teardown receipts/i)).toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/command|payload|target address|path|content|credential|network/i)).not.toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Plan ID$|Disposable lab binding ID|Independent approval ID|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID|Execution lease ID|Kill switch ID|Quota ID/i)).toHaveLength(0);
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Run ID$|Compiled plan ID|^Job ID$|Exact runner ID/i)).toHaveLength(0);
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally when purple lab read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {
      subject: "operator-1", tenant_id: "tenant-r111", roles: ["operator"], permissions: [],
    }});
    return json({error: {code: "unexpected_request", message: "Unexpected request"}});
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("derives exact owned-lab compilation and queue bindings with generated correlation identities", async () => {
  const payloads: Array<{path: string; body: Record<string, unknown>; roe: string | null}> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r111", roles: ["operator"], permissions: ["job:read", "audit:read", "job:create", "policy:read"]}});
    if (path === "/api/v1/purple-lab/abilities") return json({data: [purpleAbility()]});
    if (path === "/api/v1/policy/decisions") return json({data: [purplePolicyDecision()], page: page(1)});
    if (path === "/api/v1/purple-lab/dashboard") return json({data: {
      abilities: [purpleAbility()], labs: [], approvals: [], plans: [], runs: [], detections: [], telemetry: [], cleanups: [], teardowns: [], rehearsals: [],
      lab_options: [{binding_id: "lab-r111", runner_id: "runner-r111", disposable: true, production: false, egress_allowed: false, binding_state: "active-disposable-owned", expires_at: "2099-01-01T00:00:00Z"}],
      approval_options: [{approval_id: "approval-r111", ability_id: "r111-file-stage-marker-v1", lab_binding_id: "lab-r111", approval_state: "approved-exact", expires_at: "2099-01-01T00:00:00Z"}],
      runner_options: [{runner_id: "runner-r111", environment: "owned-disposable-lab", network_plane: "none", required_policy_revision: "r111-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z"}],
      job_options: [{job_id: "job-r111", engagement_id: "engagement-r111", roe_version_id: "roe-r111", status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false}],
      reservation_options: [{reservation_id: "reservation-r111", reserved_amount: 4, consumed_amount: 0, released_amount: 0, remaining_amount: 4, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z"}],
    }});
    if (path === "/api/v1/purple-lab/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({path, body, roe: request.headers.get("X-RedAgent-ROE-Version")});
      return json({data: {plan_id: body.plan_id, ability_id: body.ability_id, lab_binding_id: body.lab_binding_id,
        approval_id: body.approval_id, policy_decision_id: body.policy_decision_id, roe_revision: body.roe_version_id,
        reservation_id: body.reservation_id, lease_id: body.lease_id, kill_switch_id: body.kill_switch_id,
        plan_sha256: "a".repeat(64), plan_state: "compiled-owned-lab", expires_at: "2099-01-01T00:00:00Z", version: 1}}, 201);
    }
    if (path === "/api/v1/purple-lab/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({path, body, roe: request.headers.get("X-RedAgent-ROE-Version")});
      return json({data: {...body, run_state: "dispatch_pending", dispatch_blocked: false, detection_observed: false,
        cleanup_complete: false, teardown_verified: false, failure_code: null, version: 1}}, 202);
    }
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", {name: "Signed ability"}), "r111-file-stage-marker-v1");
  const jobs = screen.getAllByRole("combobox", {name: "Authorized purple lab job"});
  await user.selectOptions(jobs[0]!, "job-r111");
  await user.selectOptions(screen.getByRole("combobox", {name: "Current policy decision"}), "decision-r111");
  await user.selectOptions(screen.getByRole("combobox", {name: "Owned disposable lab"}), "lab-r111");
  await user.selectOptions(screen.getByRole("combobox", {name: "Exact independent approval"}), "approval-r111");
  await user.selectOptions(screen.getByRole("combobox", {name: "Active quota reservation"}), "reservation-r111");
  await user.click(screen.getByRole("button", {name: "Compile lab-only plan"}));
  expect(await screen.findByText(/Compiled T1074.001 for the exact owned disposable lab/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^purple-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body.lease_id).toMatch(/^purple-lease-[0-9a-f-]+$/);
  expect(payloads[0]?.body.kill_switch_id).toMatch(/^purple-kill-[0-9a-f-]+$/);
  expect(payloads[0]?.body.quota_id).toMatch(/^purple-quota-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ability_id: "r111-file-stage-marker-v1", lab_binding_id: "lab-r111",
    approval_id: "approval-r111", policy_decision_id: "decision-r111", policy_revision: "r111-v1",
    roe_version_id: "roe-r111", reservation_id: "reservation-r111", confirmation: "--confirm-r111-owned-disposable-lab"});
  expect(payloads[0]?.roe).toBe("roe-r111");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", {name: "Compiled plan"}), planId);
  await user.selectOptions(screen.getByRole("combobox", {name: "ROE-matched purple lab job"}), "job-r111");
  await user.selectOptions(screen.getByRole("combobox", {name: "Lab-bound compatible runner"}), "runner-r111");
  await user.click(screen.getByRole("button", {name: "Queue owned-lab rehearsal"}));
  expect(await screen.findByText(/Queued .* ROE-matched purple lab job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^purple-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({plan_id: planId, job_id: "job-r111", runner_id: "runner-r111",
    confirmation: "--confirm-r111-owned-disposable-lab"});
});

test("projects a correlated purple lab outage and retries without inferring execution truth", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r111", roles: ["operator"], permissions: ["job:read", "audit:read"]}});
    if (path === "/api/v1/purple-lab/abilities") return json({data: [purpleAbility()]});
    if (path === "/api/v1/purple-lab/dashboard" && attempts++ === 0) return json({error: {code: "purple_lab_unavailable", message: "Purple lab runtime unavailable", correlation_id: "corr-purple"}}, 503);
    if (path === "/api/v1/purple-lab/dashboard") return json({data: {abilities: [purpleAbility()], labs: [], approvals: [], plans: [], runs: [], detections: [], telemetry: [], cleanups: [], teardowns: [], rehearsals: [], lab_options: [], approval_options: [], runner_options: [], job_options: [], reservation_options: []}});
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  expect(await screen.findByRole("alert", {name: "Purple lab runtime unavailable"})).toBeVisible();
  expect(screen.getByText("Correlation: corr-purple")).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No purple-team run recorded")).toBeVisible();
  expect(attempts).toBe(2);
});

function purpleAbility() { return {ability_id: "r111-file-stage-marker-v1", attack_version: "enterprise-v18", attack_technique_id: "T1074.001", phases: ["prepare", "execute", "telemetry", "cleanup", "verify"], detection_strategy_id: "DET-r111-file-create", analytic_id: "AN-r111-owned-marker", event_schema: "redagent.r111-owned-file-event-v1", timeout_seconds: 5, lab_only: true, network_allowed: false, subprocess_allowed: false, external_content_allowed: false, production_qualified: false}; }
function purplePolicyDecision() { return {decision_id: "decision-r111", bundle_revision: "r111-v1", input_hash: "a".repeat(64), boundary: "api", action: "purple.plan.compile", subject_id: "operator-1", resource_type: "purple_ability", resource_id: "r111-file-stage-marker-v1", allowed: true, reason_code: "r111_ability_approved", obligations: ["owned_disposable_lab_only"], issued_at: "2026-08-25T00:00:00Z", valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy"}; }
function page(total: number) { return {limit: 50, offset: 0, total, has_more: false}; }
function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})); }
