import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/nuclei");
});

it("shows signed bundle state and blocks the legacy raw-ID compiler without scanner passthrough", async () => {
  const compiledBodies: unknown[] = [];
  globalThis.fetch = vi.fn(async (
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:create", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json({ data: [], page: page(0) });
    if (path === "/api/v1/nuclei/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/nuclei/dashboard") return json({ data: {
      profiles: [profile()],
      plans: [{
        plan_id: "plan-r105", profile_id: "nuclei-http-header-v1",
        bundle_id: "r105-http-header-bundle", target_id: "r105-owned-http-fixture",
        policy_decision_id: "decision-r105", roe_version_id: "roe-r105",
        plan_sha256: "c".repeat(64), scope_sha256: "d".repeat(64),
        expires_at: "2026-07-11T16:00:00Z", version: 1,
      }],
      runs: [{
        run_id: "run-r105", plan_id: "plan-r105", job_id: "job-r105", runner_id: "runner-r105",
        run_state: "running", progress_percent: 50, request_count: 1,
        response_bytes: 700, result_count: 1, reason_code: "nuclei_run_active", version: 2,
      }],
      results: [{
        result_id: "result-r105", template_id: "redagent-r105-missing-header",
        matcher_name: "missing-security-header", severity: "low",
        affected_resource: "/nuclei/missing-header", fingerprint: "e".repeat(64),
        evidence_instance_id: "evidence-r105",
      }],
      cleanups: [{ receipt_id: "cleanup-r105", residual_resource_count: 0,
        cleanup_complete: true, completed_at: "2026-07-11T15:00:00Z" }],
    } });
    if (path === "/api/v1/nuclei/plans") {
      let body: unknown;
      if (input instanceof Request) {
        body = await input.clone().json();
      } else {
        if (typeof init?.body !== "string") throw new Error("expected JSON request body");
        body = JSON.parse(init.body) as unknown;
      }
      compiledBodies.push(body);
      return json({ data: {} });
    }
    throw new Error(`unexpected request ${path}`);
  });

  render(<App />);
  expect(await screen.findByRole("heading", { name: "Trusted Nuclei runtime" })).toBeVisible();
  expect(await screen.findByText(/Template text, URLs, workflows, payloads, protocols, flags/)).toBeVisible();
  expect((await screen.findAllByText("nuclei-http-header-v1")).length).toBeGreaterThan(0);
  expect(screen.getAllByText(/r105-http-header-bundle/).length).toBeGreaterThan(0);
  expect(screen.getByText("redagent-r105-missing-header")).toBeVisible();
  expect(screen.getByText(/missing-security-header/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Cancel and contain" })).toBeEnabled();
  expect(screen.getByText(/Cleanup verified: 0 residual resources/)).toBeVisible();
  expect(screen.queryByLabelText(/template|url|workflow|payload|protocol|flags|environment|oast/i)).not.toBeInTheDocument();

  expect(screen.queryByLabelText(/^Plan ID$|Target attestation SHA-256|Policy decision ID|Policy revision|Approved ROE version ID/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Run ID$|Compiled plan ID|Nuclei capability job ID|Certified runner ID/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/legacy mutation is disabled until authorized resource selection/i)).not.toBeInTheDocument();
  expect(compiledBodies).toEqual([]);
});

it("fails closed locally when Nuclei read authority is absent", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: [],
    } }));
    return Promise.resolve(json({ error: { code: "unexpected_request", message: "Unexpected request" } }, 500));
  }) as typeof fetch;

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
});

it("derives signed compilation and queue bindings with generated identities", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read"],
    } });
    if (path === "/api/v1/nuclei/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/nuclei/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], results: [], cleanups: [],
      target_options: [{ target_id: "r105-owned-http-fixture", attestation_sha256: "c".repeat(64), attestation_state: "active", non_production: true, expires_at: "2099-01-01T00:00:00Z" }],
      runner_options: [{ runner_id: "runner-r105", environment: "local-conformance", network_plane: "r105-owned-gateway", required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
      job_options: [{ job_id: "job-r105", engagement_id: "engagement-r105", roe_version_id: "roe-r105", status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false }],
    } });
    if (path === "/api/v1/nuclei/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id, bundle_id: body.bundle_id,
        target_id: body.target_id, policy_decision_id: body.policy_decision_id, policy_revision: body.policy_revision, roe_version_id: body.roe_version_id,
        plan_sha256: "d".repeat(64), scope_sha256: "e".repeat(64), expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/nuclei/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { ...body, run_state: "dispatch_pending", progress_percent: 0, request_count: 0,
        response_bytes: 0, result_count: 0, reason_code: "nuclei_run_accepted", version: 1 } }, 202);
    }
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  const user = userEvent.setup();

  render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "nuclei-http-header-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized Nuclei job" });
  await user.selectOptions(jobChoices[0]!, "job-r105");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r105");
  await user.selectOptions(screen.getByRole("combobox", { name: "Owned target attestation" }), "c".repeat(64));
  await user.click(screen.getByRole("button", { name: "Compile plan" }));
  expect(await screen.findByText(/Compiled signed r105-http-header-bundle plan/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^nuclei-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ profile_id: "nuclei-http-header-v1", bundle_id: "r105-http-header-bundle",
    bundle_revision: 3, target_id: "r105-owned-http-fixture", target_attestation_sha256: "c".repeat(64),
    policy_decision_id: "decision-r105", policy_revision: "r099-v1", roe_version_id: "roe-r105" });
  expect(payloads[0]?.roe).toBe("roe-r105");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), planId);
  await user.selectOptions(jobChoices[1]!, "job-r105");
  await user.selectOptions(screen.getByRole("combobox", { name: "Compatible runner" }), "runner-r105");
  await user.click(screen.getByRole("button", { name: "Queue run" }));
  expect(await screen.findByText(/Queued .* through the selected authorized job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^nuclei-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planId, job_id: "job-r105", runner_id: "runner-r105" });
});

it("projects a correlated Nuclei outage and retries without inferring finding state", async () => {
  let attempts = 0;
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["job:read", "audit:read"],
    } }));
    if (path === "/api/v1/nuclei/profiles") return Promise.resolve(json({ data: [profile()] }));
    if (path === "/api/v1/nuclei/dashboard" && attempts++ === 0) return Promise.resolve(json({ error: {
      code: "nuclei_unavailable", message: "Nuclei runtime unavailable", correlation_id: "corr-nuclei",
    } }, 503));
    if (path === "/api/v1/nuclei/dashboard") return Promise.resolve(json({ data: {
      profiles: [profile()], plans: [], runs: [], results: [], cleanups: [], target_options: [], runner_options: [], job_options: [],
    } }));
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }) as typeof fetch;
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Nuclei runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-nuclei")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No accepted Nuclei findings")).toBeVisible();
  expect(attempts).toBe(2);
});

function profile() {
  return {
    profile_id: "nuclei-http-header-v1", profile_revision: 2, engine_version: "3.11.1",
    image_digest: `sha256:${"a".repeat(64)}`, bundle_id: "r105-http-header-bundle",
    bundle_revision: 3, profile_sha256: "b".repeat(64), risk_class: "low",
    allowed_protocols: ["http"], allowed_methods: ["GET"],
    allowed_paths: ["/nuclei/missing-header"], request_limit: 20,
    request_rate_per_second: 2, concurrency_limit: 1, timeout_seconds: 60,
    response_bytes_limit: 2097152, result_limit: 10, profile_state: "certified-local-lab",
  };
}

function policyDecision() {
  return {
    decision_id: "decision-r105", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "nuclei.plan.compile", subject_id: "operator-1", resource_type: "nuclei_profile", resource_id: "nuclei-http-header-v1",
    allowed: true, reason_code: "r105_profile_approved", obligations: ["signed_bundle_only"],
    issued_at: "2026-08-25T00:00:00Z", valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}

function json(value: object, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}
