import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";


beforeEach(() => { window.history.replaceState({}, "", "/network-assessment"); });

afterEach(() => { vi.unstubAllGlobals(); });


test("renders closed local-lab network operations and normalized partial truth", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r107", roles: ["operator"],
      permissions: ["job:read", "job:create", "job:stop", "audit:read"],
    }});
    if (path === "/api/v1/engagements") return json({ data: [], page: { limit: 50, offset: 0, total: 0 } });
    if (path === "/api/v1/network-assessment/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/network-assessment/dashboard") return json({ data: {
      profiles: [profile()], plans: [],
      runs: [{ run_id: "run-r107", plan_id: "plan-r107", job_id: "job-r107", runner_id: "runner-r107", run_state: "succeeded", completed_tuples: 1, total_tuples: 2, partial: true, reason_code: "network_run_complete", version: 2 }],
      observations: [{ observation_id: "obs-r107", tuple_id: "tuple-r107", connection_state: "open", latency_bucket: "lt_10ms", service_class: "http", sample_sha256: "b".repeat(64), uncertainty: "low", redaction_state: "redacted-hash-only", evidence_instance_id: null }],
      cleanups: [{ receipt_id: "cleanup-r107", residual_resource_count: 0, completed_at: "2026-07-11T12:05:00Z" }],
    }});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Network assessment" })).toBeInTheDocument();
  expect(await screen.findByText(/literal IP\/port tuples from the attested local fixture/i)).toBeInTheDocument();
  expect(await screen.findByText(/1 of 2 tuples/)).toBeInTheDocument();
  expect(screen.getByText(/partial coverage/i)).toBeInTheDocument();
  expect(screen.getByText(/0 residual resources/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/^Plan ID$|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Run ID$|Compiled plan ID|Network job ID|Certified runner ID/i)).not.toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});


test("fails closed locally when network assessment read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r107", roles: ["operator"], permissions: [],
    }});
    return json({ error: { code: "unexpected_request", message: "Unexpected request" } });
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});


test("derives isolated compilation and queue bindings with generated identities", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r107", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read"],
    }});
    if (path === "/api/v1/network-assessment/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/network-assessment/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], observations: [], cleanups: [],
      target_options: [{ target_set_id: "r107-local-fixture", target_set_state: "active-local-lab",
        non_production: true, no_public_route: true, no_direct_target_route: true, expires_at: "2099-01-01T00:00:00Z" }],
      runner_options: [{ runner_id: "runner-r107", environment: "local-conformance", network_plane: "r107-owned-gateway",
        required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
      job_options: [{ job_id: "job-r107", engagement_id: "engagement-r107", roe_version_id: "roe-r107",
        status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false }],
      reservation_options: [{ reservation_id: "reservation-r107", reserved_amount: 64, consumed_amount: 0,
        released_amount: 0, remaining_amount: 64, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z" }],
    }});
    if (path === "/api/v1/network-assessment/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id, target_set_id: body.target_set_id,
        policy_decision_id: body.policy_decision_id, policy_revision: body.policy_revision, roe_version_id: body.roe_version_id,
        reservation_id: body.reservation_id, plan_sha256: "a".repeat(64), tuple_count: 2,
        budgets: { attempts: 2 }, plan_state: "compiled-local-lab", expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/network-assessment/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { ...body, run_state: "dispatch_pending", completed_tuples: 0, total_tuples: 2,
        partial: false, reason_code: "network_run_accepted", version: 1 } }, 202);
    }
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();

  render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "tcp-connect-discovery-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized network job" });
  await user.selectOptions(jobChoices[0]!, "job-r107");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r107");
  await user.selectOptions(screen.getByRole("combobox", { name: "Isolated target set" }), "r107-local-fixture");
  await user.selectOptions(screen.getByRole("combobox", { name: "Active quota reservation" }), "reservation-r107");
  await user.click(screen.getByRole("button", { name: "Compile approved scope" }));
  expect(await screen.findByText(/Compiled isolated literal-tuple plan/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^network-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ profile_id: "tcp-connect-discovery-v1", target_set_id: "r107-local-fixture",
    policy_decision_id: "decision-r107", policy_revision: "r099-v1", roe_version_id: "roe-r107",
    reservation_id: "reservation-r107", confirmation: "--confirm-r107-local-lab" });
  expect(payloads[0]?.roe).toBe("roe-r107");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), planId);
  await user.selectOptions(jobChoices[1]!, "job-r107");
  await user.selectOptions(screen.getByRole("combobox", { name: "Compatible isolated runner" }), "runner-r107");
  await user.click(screen.getByRole("button", { name: "Queue local run" }));
  expect(await screen.findByText(/Queued .* through the selected authorized job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^network-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planId, job_id: "job-r107", runner_id: "runner-r107",
    confirmation: "--confirm-r107-local-lab" });
});


test("projects a correlated network outage and retries without inferring observation state", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r107", roles: ["operator"], permissions: ["job:read", "audit:read"],
    }});
    if (path === "/api/v1/network-assessment/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/network-assessment/dashboard" && attempts++ === 0) return json({ error: {
      code: "network_assessment_unavailable", message: "Network assessment runtime unavailable",
      correlation_id: "corr-network",
    }}, 503);
    if (path === "/api/v1/network-assessment/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], observations: [], cleanups: [],
      target_options: [], runner_options: [], job_options: [], reservation_options: [],
    }});
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Network assessment runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-network")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No network observations recorded")).toBeVisible();
  expect(attempts).toBe(2);
});


function profile() {
  return { profile_id: "tcp-connect-discovery-v1", profile_revision: 1, engine_id: "redagent-stdlib-tcp-connect", category: "low-risk-connect-discovery", max_targets: 8, max_ports_per_target: 16, max_attempts: 64, rate_per_second: 4, concurrency_limit: 4, max_retries: 0, connect_timeout_seconds: 1, run_timeout_seconds: 30, banner_bytes: 256, output_bytes: 65536, profile_state: "certified-local-lab", production_qualified: false };
}


function policyDecision() {
  return {
    decision_id: "decision-r107", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "network.plan.compile", subject_id: "operator-1", resource_type: "network_profile",
    resource_id: "tcp-connect-discovery-v1", allowed: true, reason_code: "r107_profile_approved",
    obligations: ["local_fixture_only"], issued_at: "2026-08-25T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}


function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}


function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}
