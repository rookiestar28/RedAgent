import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/zap");
});

it("shows only certified ZAP profiles, durable state, and controlled cancellation without target or scanner overrides", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:create", "job:read", "job:stop", "audit:read"],
    }}));
    if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/jobs") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/zap/profiles") return Promise.resolve(json({ data: [profile()] }));
    if (path === "/api/v1/zap/dashboard") return Promise.resolve(json({ data: {
      profiles: [profile()],
      plans: [{
        plan_id: "plan-r104", profile_id: "zap-passive-v1", target_id: "r104-owned-web-fixture",
        policy_decision_id: "decision-r104", roe_version_id: "roe-r104",
        plan_sha256: "c".repeat(64), scope_sha256: "d".repeat(64),
        expires_at: "2026-07-11T16:00:00Z", version: 1,
      }],
      runs: [{
        run_id: "run-r104", plan_id: "plan-r104", job_id: "job-r104", runner_id: "runner-r104",
        run_state: "running", current_step: 2, progress_percent: 40, passive_queue_size: 1,
        reason_code: "zap_run_active", version: 2,
      }],
      cleanups: [{
        receipt_id: "cleanup-r104", residual_resource_count: 0,
        cleanup_complete: true, completed_at: "2026-07-11T15:00:00Z",
      }],
    }}));
    return Promise.reject(new Error(`unexpected request ${path}`));
  });

  render(<App />);
  expect(await screen.findByRole("heading", { name: "Controlled ZAP runtime" })).toBeVisible();
  expect(await screen.findByText(/URLs, YAML, scripts, add-ons, flags, and native API calls are not accepted/)).toBeVisible();
  expect((await screen.findAllByText("zap-passive-v1")).length).toBeGreaterThan(0);
  expect(await screen.findByText(/r104-owned-web-fixture/)).toBeVisible();
  expect(await screen.findByRole("button", { name: "Cancel and contain" })).toBeEnabled();
  expect(await screen.findByText(/Cleanup verified: 0 residual resources/)).toBeVisible();
  expect(screen.queryByLabelText(/target url/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/yaml|script|add-on|flags|native api/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Plan ID$/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/Target attestation SHA-256/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/Policy decision ID|Policy revision|Approved ROE version ID/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/Credential reference \(authenticated profile only\)/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Run ID$|Compiled plan ID|ZAP capability job ID|Certified runner ID/i)).not.toBeInTheDocument();
});

it("fails closed locally when ZAP read authority is absent", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: [],
    }}));
    return Promise.resolve(json({ error: { code: "unexpected_request", message: "Unexpected request" } }, 500));
  }) as typeof fetch;

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
});

it("derives a compiled plan and queued run from authoritative choices with generated identities", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read", "secret:read"],
    }});
    if (path === "/api/v1/zap/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/zap/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], cleanups: [],
      target_options: [{ target_id: "r104-owned-web-fixture", attestation_sha256: "d".repeat(64), attestation_state: "active", non_production: true, expires_at: "2099-01-01T00:00:00Z" }],
      runner_options: [{ runner_id: "runner-r104", environment: "local-conformance", network_plane: "r104-owned-gateway", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
    }});
    if (path === "/api/v1/jobs") return json({ data: [zapJob()], page: page(1) });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/secret-references") return json({ data: [], page: page(0) });
    if (path === "/api/v1/zap/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id, target_id: body.target_id,
        policy_decision_id: body.policy_decision_id, roe_version_id: body.roe_version_id,
        plan_sha256: "e".repeat(64), scope_sha256: "f".repeat(64), expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/zap/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { ...body, run_state: "dispatch_pending", current_step: 0, progress_percent: 0,
        passive_queue_size: 0, reason_code: "zap_run_accepted", version: 1 } }, 202);
    }
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  const user = userEvent.setup();

  render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "zap-passive-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized ZAP job" });
  await user.selectOptions(jobChoices[0]!, "job-r104");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r104");
  await user.selectOptions(screen.getByRole("combobox", { name: "Owned target attestation" }), "d".repeat(64));
  await user.click(screen.getByRole("button", { name: "Compile plan" }));
  expect(await screen.findByText(/Compiled zap-passive-v1 plan/)).toBeVisible();
  const planPayload = payloads[0]?.body;
  expect(planPayload?.plan_id).toMatch(/^zap-plan-[0-9a-f-]+$/);
  expect(planPayload).toMatchObject({ profile_id: "zap-passive-v1", target_id: "r104-owned-web-fixture",
    target_attestation_sha256: "d".repeat(64), policy_decision_id: "decision-r104",
    policy_revision: "r099-v1", roe_version_id: "roe-r104", credential_reference_ids: [] });
  expect(payloads[0]?.roe).toBe("roe-r104");

  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), String(planPayload?.plan_id));
  await user.selectOptions(jobChoices[1]!, "job-r104");
  await user.selectOptions(screen.getByRole("combobox", { name: "Compatible runner" }), "runner-r104");
  await user.click(screen.getByRole("button", { name: "Queue run" }));
  expect(await screen.findByText(/Queued .* through the selected authorized job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^zap-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planPayload?.plan_id, job_id: "job-r104", runner_id: "runner-r104" });
});

it("projects a correlated ZAP outage and retries without inferring execution state", async () => {
  let dashboardAttempts = 0;
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["job:read", "audit:read"],
    }}));
    if (path === "/api/v1/zap/profiles") return Promise.resolve(json({ data: [profile()] }));
    if (path === "/api/v1/zap/dashboard" && dashboardAttempts++ === 0) return Promise.resolve(json({ error: {
      code: "zap_unavailable", message: "ZAP runtime unavailable", correlation_id: "corr-zap",
    } }, 503));
    if (path === "/api/v1/zap/dashboard") return Promise.resolve(json({ data: {
      profiles: [profile()], plans: [], runs: [], cleanups: [], target_options: [], runner_options: [],
    }}));
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }) as typeof fetch;
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "ZAP runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-zap")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No ZAP runs recorded")).toBeVisible();
  expect(dashboardAttempts).toBe(2);
});

function profile() {
  return {
    profile_id: "zap-passive-v1", profile_revision: 1, image_version: "2.17.0",
    image_digest: `sha256:${"a".repeat(64)}`, addon_inventory_sha256: "b".repeat(64),
    profile_sha256: "c".repeat(64), risk_class: "low_risk",
    passive_rule_ids: ["10021"], active_rule_ids: [], request_limit: 60,
    request_rate_per_second: 3, concurrency_limit: 2, timeout_seconds: 180,
    response_bytes_limit: 15728640, profile_state: "certified",
  };
}

function zapJob() {
  return {
    job_id: "job-r104", tenant_id: "tenant-1", engagement_id: "engagement-r104", roe_version_id: "roe-r104",
    created_by_user_id: "operator-1", campaign_id: null, status: "approved",
    request: { capability: "zap-controlled-runtime", approval_timeout_seconds: 600, max_activity_attempts: 1, budget_reference: "budget-r104" },
    policy_reference: "policy:r099-v1", workflow_id: "workflow-r104", workflow_run_id: "workflow-run-r104",
    orchestration_state: "ready", orchestration_revision: 1, current_gate: "runner_dispatch", failure_code: null,
    retry_count: 0, dispatch_blocked: false, stop_requested: false, version: 1,
  };
}

function policyDecision() {
  return {
    decision_id: "decision-r104", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "zap.plan.compile", subject_id: "operator-1", resource_type: "zap_profile", resource_id: "zap-passive-v1",
    allowed: true, reason_code: "r104_profile_approved", obligations: ["owned_fixture_only"],
    issued_at: "2026-08-25T00:00:00Z", valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}

function json(value: object, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}
