import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";


beforeEach(() => { window.history.replaceState({}, "", "/cloud-posture"); });

afterEach(() => { vi.unstubAllGlobals(); });


test("renders exact cloud identity, partial truth, evidence, lease-first cancel, and cleanup", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r108", roles: ["operator"],
      permissions: ["job:read", "job:create", "job:stop", "audit:read"],
    }});
    if (path === "/api/v1/engagements") return json({ data: [], page: { limit: 50, offset: 0, total: 0 } });
    if (path === "/api/v1/cloud-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/cloud-posture/dashboard") return json({ data: {
      profiles: [profile()], plans: [],
      runs: [{ run_id: "run-r108", plan_id: "plan-r108", job_id: "job-r108", runner_id: "runner-r108", run_state: "succeeded", complete: false, partial_reasons: ["iam_throttled"], snapshot_sha256: "a".repeat(64), version: 2 }],
      results: [{ result_id: "result-r108", control_pack_id: "r108-cloud-baseline-v1", check_id: "R108-AWS-001", resource_id: "role/admin", passed: false, severity: "high", evidence_instance_id: "evidence-r108" }],
      cleanups: [{ receipt_id: "cleanup-r108", lease_revoked: true, new_requests_blocked: true, residual_resource_count: 0, completed_at: "2026-07-11T16:05:00Z" }],
    }});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Cloud and Kubernetes posture" })).toBeInTheDocument();
  expect(screen.getByText(/repo-owned loopback provider emulators/i)).toBeInTheDocument();
  expect(await screen.findByText(/aws:123456789012/)).toBeInTheDocument();
  expect(screen.getByText(/iam_throttled/)).toBeInTheDocument();
  expect(screen.getByText(/evidence-r108/)).toBeInTheDocument();
  expect(screen.getByText(/cleanup verified: lease revoked; 0 residual resources/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/endpoint|token|kubeconfig|scanner flags/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Plan ID$|Identity binding ID|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID|Opaque read-only lease ID/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Run ID$|Compiled plan ID|Cloud posture job ID|Certified runner ID/i)).not.toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});


test("fails closed locally when cloud posture read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r108", roles: ["operator"], permissions: [],
    }});
    return json({ error: { code: "unexpected_request", message: "Unexpected request" } });
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});


test("derives emulator-only compilation and queue bindings with generated identities", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r108", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read"],
    }});
    if (path === "/api/v1/cloud-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/cloud-posture/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], results: [], cleanups: [],
      identity_options: [{ binding_id: "binding-r108", profile_id: "r108-aws-emulator-v1", provider: "aws",
        expected_identity: "aws:123456789012", permission_digest: "permission-r108", binding_state: "active-local-emulator" }],
      runner_options: [{ runner_id: "runner-r108", environment: "local-conformance", network_plane: "r108-loopback",
        required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
      job_options: [{ job_id: "job-r108", engagement_id: "engagement-r108", roe_version_id: "roe-r108",
        status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false }],
      reservation_options: [{ reservation_id: "reservation-r108", reserved_amount: 8, consumed_amount: 0,
        released_amount: 0, remaining_amount: 8, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z" }],
      lease_options: [{ lease_id: "lease-r108", job_id: "job-r108", roe_version_id: "roe-r108",
        permission_digest: "permission-r108", lease_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
    }});
    if (path === "/api/v1/cloud-posture/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id,
        identity_binding_id: body.identity_binding_id, policy_decision_id: body.policy_decision_id,
        policy_revision: body.policy_revision, reservation_id: body.reservation_id,
        credential_lease_id: body.credential_lease_id, plan_sha256: "a".repeat(64),
        plan_state: "compiled-local-lab", expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/cloud-posture/runs" && request.method === "POST") {
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
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "r108-aws-emulator-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized cloud job" });
  await user.selectOptions(jobChoices[0]!, "job-r108");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r108");
  await user.selectOptions(screen.getByRole("combobox", { name: "Emulator identity binding" }), "binding-r108");
  await user.selectOptions(screen.getByRole("combobox", { name: "Active quota reservation" }), "reservation-r108");
  await user.selectOptions(screen.getByRole("combobox", { name: "Read-only credential lease" }), "lease-r108");
  await user.click(screen.getByRole("button", { name: "Compile approved collection" }));
  expect(await screen.findByText(/Compiled read-only emulator collection/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^cloud-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ profile_id: "r108-aws-emulator-v1", identity_binding_id: "binding-r108",
    policy_decision_id: "decision-r108", policy_revision: "r099-v1", roe_version_id: "roe-r108",
    reservation_id: "reservation-r108", credential_lease_id: "lease-r108", confirmation: "--confirm-r108-local-lab" });
  expect(payloads[0]?.roe).toBe("roe-r108");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), planId);
  await user.selectOptions(jobChoices[1]!, "job-r108");
  await user.selectOptions(screen.getByRole("combobox", { name: "Compatible isolated runner" }), "runner-r108");
  await user.click(screen.getByRole("button", { name: "Queue local run" }));
  expect(await screen.findByText(/Queued .* through the selected cloud posture job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^cloud-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planId, job_id: "job-r108", runner_id: "runner-r108",
    confirmation: "--confirm-r108-local-lab" });
});


test("projects a correlated cloud outage and retries without inferring posture state", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-r108", roles: ["operator"], permissions: ["job:read", "audit:read"],
    }});
    if (path === "/api/v1/cloud-posture/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/cloud-posture/dashboard" && attempts++ === 0) return json({ error: {
      code: "cloud_posture_unavailable", message: "Cloud posture runtime unavailable",
      correlation_id: "corr-cloud",
    }}, 503);
    if (path === "/api/v1/cloud-posture/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], results: [], cleanups: [], identity_options: [],
      runner_options: [], job_options: [], reservation_options: [], lease_options: [],
    }});
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Cloud posture runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-cloud")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No normalized posture results")).toBeVisible();
  expect(attempts).toBe(2);
});


function profile() {
  return {
    profile_id: "r108-aws-emulator-v1", provider: "aws", expected_identity: "aws:123456789012",
    operations: [{ operation_id: "aws-iam-list-roles-v1", action: "iam:ListRoles", resource_scope: "arn:aws:iam::123456789012:role/*", data_class: "security_configuration", mutation: false }],
    max_api_calls: 8, max_pages: 6, max_resources: 32, max_response_bytes: 32768,
    profile_state: "certified-local-lab", emulator_only: true, production_qualified: false,
  };
}


function policyDecision() {
  return {
    decision_id: "decision-r108", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "cloud.plan.compile", subject_id: "operator-1", resource_type: "cloud_profile",
    resource_id: "r108-aws-emulator-v1", allowed: true, reason_code: "r108_profile_approved",
    obligations: ["local_emulator_only"], issued_at: "2026-08-25T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}


function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}


function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}
