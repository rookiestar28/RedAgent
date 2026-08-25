import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/api-differential");
});

it("shows the fixed identity matrix, findings, replay, cancellation, and cleanup without transport passthrough", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:create", "job:read", "job:stop", "audit:read"],
    } }));
    if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/api-differential/profiles") return Promise.resolve(json({ data: [profile()] }));
    if (path === "/api/v1/api-differential/dashboard") return Promise.resolve(json({ data: {
      profiles: [profile()],
      plans: [{
        plan_id: "plan-r106", profile_id: "openapi-authorization-differential-v1",
        target_id: "r106-owned-api-fixture", policy_decision_id: "decision-r106",
        roe_version_id: "roe-r106", spec_sha256: "a".repeat(64), plan_sha256: "b".repeat(64),
        seed: 10620260711, case_count: 19, expires_at: "2026-07-11T16:00:00Z", version: 1,
      }],
      runs: [{
        run_id: "run-r106", plan_id: "plan-r106", job_id: "job-r106", runner_id: "runner-r106",
        run_state: "running", progress_percent: 60, request_count: 14,
        response_bytes: 4096, finding_count: 1, reason_code: "api_diff_run_active", version: 2,
      }],
      observations: [{ observation_id: "obs-r106", case_id: "case-bola", finding_type: "bola",
        violated: true, evidence_instance_id: "evidence-r106", reason_code: "object_access_exposed" }],
      replays: [{ replay_id: "replay-r106", case_id: "case-bola",
        minimized_replay_sha256: "c".repeat(64), semantic_predicate: "owner_only",
        replay_state: "accepted" }],
      cleanups: [{ receipt_id: "cleanup-r106", compensation_complete: true, lease_revoked: true,
        residual_resource_count: 0, completed_at: "2026-07-11T15:00:00Z" }],
    } }));
    return Promise.reject(new Error(`unexpected request ${path}`));
  }) as typeof fetch;

  render(<App />);
  expect(await screen.findByRole("heading", { name: "API authorization differential" })).toBeVisible();
  expect(await screen.findByText(/signed compat_106 specification, reviewed operation inventory/)).toBeVisible();
  expect((await screen.findAllByText(/openapi-authorization-differential-v1/)).length).toBeGreaterThan(0);
  expect(await screen.findByText(/OWNER, PEER, TENANT_ADMIN/)).toBeVisible();
  expect(screen.getByText("bola")).toBeVisible();
  expect(screen.getByText("owner_only")).toBeVisible();
  expect(screen.getByRole("button", { name: "Cancel and contain" })).toBeEnabled();
  expect(screen.getByText(/Cleanup verified: 0 residual resources; lease revoked/)).toBeVisible();
  expect(screen.queryByLabelText(/url|specification|request|header|cookie|credential|body|callback|plugin|flag/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Plan ID$|Target attestation SHA-256|Policy decision ID|Policy revision|Approved ROE version ID/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Run ID$|Compiled plan ID|API differential job ID|Certified runner ID/i)).not.toBeInTheDocument();
});

it("fails closed locally when API differential read authority is absent", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: [],
    } }));
    return Promise.resolve(json({ error: { code: "unexpected_request", message: "Unexpected request" } }));
  }) as typeof fetch;

  render(<App />);
  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
});

it("derives signed compilation and queue bindings with generated identities while retaining the bounded seed", async () => {
  const payloads: Array<{ path: string; body: Record<string, unknown>; roe: string | null }> = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["job:read", "audit:read", "job:create", "policy:read"],
    } });
    if (path === "/api/v1/api-differential/profiles") return json({ data: [profile()] });
    if (path === "/api/v1/policy/decisions") return json({ data: [policyDecision()], page: page(1) });
    if (path === "/api/v1/api-differential/dashboard") return json({ data: {
      profiles: [profile()], plans: [], runs: [], observations: [], replays: [], cleanups: [],
      target_options: [{ target_id: "r106-owned-api-fixture", attestation_sha256: "c".repeat(64), attestation_state: "active", non_production: true, expires_at: "2099-01-01T00:00:00Z" }],
      runner_options: [{ runner_id: "runner-r106", environment: "local-conformance", network_plane: "r106-owned-gateway", required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z" }],
      job_options: [{ job_id: "job-r106", engagement_id: "engagement-r106", roe_version_id: "roe-r106", status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false }],
    } });
    if (path === "/api/v1/api-differential/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { plan_id: body.plan_id, profile_id: body.profile_id, target_id: body.target_id,
        policy_decision_id: body.policy_decision_id, policy_revision: body.policy_revision, roe_version_id: body.roe_version_id,
        spec_sha256: "a".repeat(64), plan_sha256: "b".repeat(64), seed: body.seed, case_count: 19,
        expires_at: "2099-01-01T00:00:00Z", version: 1 } }, 201);
    }
    if (path === "/api/v1/api-differential/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      payloads.push({ path, body, roe: request.headers.get("X-RedAgent-ROE-Version") });
      return json({ data: { ...body, run_state: "dispatch_pending", progress_percent: 0, request_count: 0,
        response_bytes: 0, finding_count: 0, reason_code: "api_run_accepted", version: 1 } }, 202);
    }
    return json({ error: { code: "not_found", message: "Not found" } }, 404);
  });
  const user = userEvent.setup();

  render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", { name: "Certified profile" }), "openapi-authorization-differential-v1");
  const jobChoices = screen.getAllByRole("combobox", { name: "Authorized API differential job" });
  await user.selectOptions(jobChoices[0]!, "job-r106");
  await user.selectOptions(screen.getByRole("combobox", { name: "Current policy decision" }), "decision-r106");
  await user.selectOptions(screen.getByRole("combobox", { name: "Owned target attestation" }), "c".repeat(64));
  await user.clear(screen.getByRole("spinbutton", { name: "Deterministic public seed" }));
  await user.type(screen.getByRole("spinbutton", { name: "Deterministic public seed" }), "10620260711");
  await user.click(screen.getByRole("button", { name: "Compile plan" }));
  expect(await screen.findByText(/Compiled signed API authorization matrix/)).toBeVisible();
  expect(payloads[0]?.body.plan_id).toMatch(/^api-diff-plan-[0-9a-f-]+$/);
  expect(payloads[0]?.body).toMatchObject({ profile_id: "openapi-authorization-differential-v1",
    target_id: "r106-owned-api-fixture", target_attestation_sha256: "c".repeat(64),
    policy_decision_id: "decision-r106", policy_revision: "r099-v1", roe_version_id: "roe-r106", seed: 10620260711 });
  expect(payloads[0]?.roe).toBe("roe-r106");
  const planId = String(payloads[0]?.body.plan_id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Compiled plan" }), planId);
  await user.selectOptions(jobChoices[1]!, "job-r106");
  await user.selectOptions(screen.getByRole("combobox", { name: "Compatible runner" }), "runner-r106");
  await user.click(screen.getByRole("button", { name: "Queue run" }));
  expect(await screen.findByText(/Queued .* through the selected authorized job/)).toBeVisible();
  expect(payloads[1]?.body.run_id).toMatch(/^api-diff-run-[0-9a-f-]+$/);
  expect(payloads[1]?.body).toMatchObject({ plan_id: planId, job_id: "job-r106", runner_id: "runner-r106" });
});

it("projects a correlated API differential outage and retries without inferring finding state", async () => {
  let attempts = 0;
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["job:read", "audit:read"],
    } }));
    if (path === "/api/v1/api-differential/profiles") return Promise.resolve(json({ data: [profile()] }));
    if (path === "/api/v1/api-differential/dashboard" && attempts++ === 0) return Promise.resolve(json({ error: {
      code: "api_differential_unavailable", message: "API differential runtime unavailable", correlation_id: "corr-api-diff",
    } }, 503));
    if (path === "/api/v1/api-differential/dashboard") return Promise.resolve(json({ data: {
      profiles: [profile()], plans: [], runs: [], observations: [], replays: [], cleanups: [],
      target_options: [], runner_options: [], job_options: [],
    } }));
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }) as typeof fetch;
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("alert", { name: "API differential runtime unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: corr-api-diff")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No normalized authorization observations")).toBeVisible();
  expect(attempts).toBe(2);
});

function profile() {
  return {
    profile_id: "openapi-authorization-differential-v1", profile_revision: 1,
    engine_version: "4.22.4", artifact_digest: `sha256:${"d".repeat(64)}`,
    bundle_id: "r106-owned-api-differential", spec_sha256: "a".repeat(64),
    operation_ids: ["createDocument", "getDocument", "getProfile", "getAudit", "deleteDocument", "transferDocument"],
    identity_states: ["OWNER", "PEER", "TENANT_ADMIN", "OTHER_TENANT", "EXPIRED", "REVOKED"],
    max_requests: 64, request_rate_per_second: 2, concurrency_limit: 1,
    timeout_seconds: 60, total_data_bytes: 2097152,
    profile_state: "certified-local-lab", production_qualified: false,
  };
}

function policyDecision() {
  return {
    decision_id: "decision-r106", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api",
    action: "api_diff.plan.compile", subject_id: "operator-1", resource_type: "api_diff_profile",
    resource_id: "openapi-authorization-differential-v1", allowed: true, reason_code: "r106_profile_approved",
    obligations: ["owned_fixture_only"], issued_at: "2026-08-25T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy",
  };
}

function json(value: object, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}
