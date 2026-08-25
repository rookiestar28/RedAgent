import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";


beforeEach(() => { window.history.replaceState({}, "", "/identity-posture"); });
afterEach(() => { vi.unstubAllGlobals(); });


test("renders exact identity permissions, partial truth, exception and graph isolation", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {subject: "operator-1", tenant_id: "tenant-r109", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]} });
    if (path === "/api/v1/engagements") return json({ data: [], page: {limit: 50, offset: 0, total: 0} });
    if (path === "/api/v1/identity-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/identity-posture/dashboard") return json({ data: {profiles: [profile()], plans: [],
      runs: [{run_id: "run-r109", plan_id: "plan-r109", job_id: "job-r109", runner_id: "runner-r109", run_state: "succeeded", complete: false, partial_reasons: ["directory_throttled"], snapshot_sha256: "a".repeat(64), version: 2}],
      evaluations: [], exceptions: [{exception_id: "exception-r109"}], graphs: [{approval_id: "graph-r109", restricted_role: "identity-graph-reviewer"}], cleanups: [{receipt_id: "cleanup-r109"}]}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", { name: "Identity and SaaS posture" })).toBeInTheDocument();
  expect(screen.getByText(/repo-owned loopback Microsoft 365/i)).toBeInTheDocument();
  expect(await screen.findByText(/org-r109-okta · okta-api-r109/i)).toBeInTheDocument();
  expect(screen.getByText(/okta.groups.read \/ okta.groups.read/i)).toBeInTheDocument();
  expect(screen.getByText(/directory_throttled/)).toBeInTheDocument();
  expect(screen.getByText(/1 exception annotations · 1 separately approved restricted graphs · 1 cleanup receipts/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/endpoint|token|query|scope|graph export/i)).not.toBeInTheDocument();
  expect(screen.queryAllByLabelText(/^Plan ID$|Tenant binding ID|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID|Opaque credential lease ID/i)).toHaveLength(0);
  expect(screen.queryAllByLabelText(/^Run ID$|Compiled plan ID|^Job ID$|^Runner ID$/i)).toHaveLength(0);
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});


test("fails closed locally when identity posture read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r109", roles: ["operator"], permissions: [],
    }});
    return json({ error: { code: "unexpected_request", message: "Unexpected request" } });
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});


test("derives emulator tenant compilation and queue bindings with generated identities", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r109", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read"],
    }});
    if (path === "/api/v1/identity-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/identity-posture/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], evaluations: [], exceptions: [], graphs: [], cleanups: [],
      binding_options: [{ binding_id: "binding-r109", profile_id: "r109-okta-emulator-v1",
        provider_tenant_id: "org-r109-okta", audience: "okta-api-r109", consent_mode: "application",
        permission_digest: "permission-r109", binding_state: "active-local-emulator" }],
      runner_options: [{ runner_id: "runner-r109", environment: "local-conformance", network_plane: "r109-loopback",
        required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
      job_options: [{ job_id: "job-r109", engagement_id: "engagement-r109", roe_version_id: "roe-r109",
        status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false }],
      reservation_options: [{ reservation_id: "reservation-r109", reserved_amount: 8, consumed_amount: 0,
        released_amount: 0, remaining_amount: 8, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z" }],
      lease_options: [{ lease_id: "lease-r109", job_id: "job-r109", roe_version_id: "roe-r109",
        permission_digest: "permission-r109", lease_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
    }});
    if (path === "/api/v1/identity-posture/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id,
        tenant_binding_id: body.tenant_binding_id, policy_decision_id: body.policy_decision_id,
        reservation_id: body.reservation_id, credential_lease_id: body.credential_lease_id,
        plan_sha256: "a".repeat(64), plan_state: "compiled-local-lab",
        expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/identity-posture/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { ...body, run_state: "dispatch_pending", complete: false,
        partial_reasons: [], snapshot_sha256: null, version: 1 } }, 202);
    }
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();

  render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "r109-okta-emulator-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized identity job" });
  await user.selectOptions(jobChoices[0]!, "job-r109");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r109");
  await user.selectOptions(screen.getByRole("combobox", { name: "Emulator tenant binding" }), "binding-r109");
  await user.selectOptions(screen.getByRole("combobox", { name: "Active quota reservation" }), "reservation-r109");
  await user.selectOptions(screen.getByRole("combobox", { name: "Read-only credential lease" }), "lease-r109");
  await user.click(screen.getByRole("button", { name: "Compile approved collection" }));
  expect(await screen.findByText(/Compiled protected emulator collection/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^identity-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ profile_id: "r109-okta-emulator-v1", tenant_binding_id: "binding-r109",
    policy_decision_id: "decision-r109", policy_revision: "r099-v1", roe_version_id: "roe-r109",
    reservation_id: "reservation-r109", credential_lease_id: "lease-r109", confirmation: "--confirm-r109-local-lab" });
  expect(payloads[0]?.roe).toBe("roe-r109");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), planId);
  await user.selectOptions(jobChoices[1]!, "job-r109");
  await user.selectOptions(screen.getByRole("combobox", { name: "Certified emulator runner" }), "runner-r109");
  await user.click(screen.getByRole("button", { name: "Queue local run" }));
  expect(await screen.findByText(/Queued .* through the selected identity posture job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^identity-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planId, job_id: "job-r109", runner_id: "runner-r109",
    confirmation: "--confirm-r109-local-lab" });
});


test("projects a correlated identity outage and retries without inferring posture state", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r109", roles: ["operator"], permissions: ["job:read", "audit:read"],
    }});
    if (path === "/api/v1/identity-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/identity-posture/dashboard" && attempts++ === 0) return json({ error: {
      code: "identity_posture_unavailable", message: "Identity posture runtime unavailable",
      correlation_id: "corr-identity",
    }}, 503);
    if (path === "/api/v1/identity-posture/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], evaluations: [], exceptions: [], graphs: [], cleanups: [],
      binding_options: [], runner_options: [], job_options: [], reservation_options: [], lease_options: [],
    }});
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Identity posture runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-identity")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No identity posture runs recorded")).toBeVisible();
  expect(attempts).toBe(2);
});


function profile() {
  return {profile_id: "r109-okta-emulator-v1", provider: "okta", provider_tenant_id: "org-r109-okta", audience: "okta-api-r109", consent_mode: "application",
    operations: [{operation_id: "okta-groups-list-v1", method: "GET", api_version: "v1", permission_scope: "okta.groups.read", effective_role_permission: "okta.groups.read", selected_fields: ["id", "type", "created"], data_class: "directory_metadata", graph_eligible: true}],
    retention_days: 7, profile_state: "certified-local-lab", emulator_only: true, production_qualified: false};
}


function policyDecision() {
  return {
    decision_id: "decision-r109", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "identity.plan.compile", subject_id: "operator-1", resource_type: "identity_profile",
    resource_id: "r109-okta-emulator-v1", allowed: true, reason_code: "r109_profile_approved",
    obligations: ["local_emulator_only"], issued_at: "2026-08-25T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}


function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}


function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})); }
