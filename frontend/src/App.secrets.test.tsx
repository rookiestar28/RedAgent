import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";


describe("credential lease console", () => {
  it("renders metadata-only state and performs an exact revoke", async () => {
    window.history.replaceState({}, "", "/secrets");
    const lease = leaseRow();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1",
        permissions: ["secret:read", "secret:issue", "secret:revoke", "job:read"], roles: ["operator"],
      }}));
      if (path === "/api/v1/jobs") return Promise.resolve(json({ data: [jobRow()], page: page(1) }));
      if (path === "/api/v1/secret-references") return Promise.resolve(json({ data: [], page: page(0) }));
      if (path === "/api/v1/secret-leases" && request.method === "GET") {
        return Promise.resolve(json({ data: [lease], page: page(1) }));
      }
      if (path === `/api/v1/secret-leases/${lease.lease_id}/revoke` && request.method === "POST") {
        return Promise.resolve(json({ data: { ...lease, lease_state: "revoked", revoked_at: "2026-07-10T12:01:00Z", renewable: false, version: 2 }, meta: { replayed: false } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    expect(await screen.findByText(lease.lease_id)).toBeVisible();
    expect(screen.getByText("active")).toBeVisible();
    expect(screen.queryByText("R098-SYNTHETIC-MATERIAL")).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Authorized job" })).toBeVisible();
    expect(screen.queryByLabelText(/Reference ID|Lease ID|Job ID|ROE version ID|Workload client ID/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Revoke exact lease" }));
    expect(await screen.findByText(`Exact lease ${lease.lease_id} is revoked.`)).toBeVisible();
    expect(screen.getByText("revoked")).toBeVisible();
  });

  it("fails closed locally without secret read authority", async () => {
    window.history.replaceState({}, "", "/secrets");
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1", permissions: [], roles: ["operator"],
      }}));
      return Promise.resolve(json({ error: { code: "unexpected_request", message: "Unexpected request" } }, 500));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("issues only a generated synthetic binding for an authorized job", async () => {
    window.history.replaceState({}, "", "/secrets");
    const payloads: Array<Record<string, unknown>> = [];
    const roeHeaders: Array<string | null> = [];
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/context") return json({ data: {
        subject: "operator-1", tenant_id: "tenant-1",
        permissions: ["secret:read", "secret:issue", "job:read"], roles: ["operator"],
      }});
      if (path === "/api/v1/jobs") return json({ data: [jobRow()], page: page(1) });
      if (path === "/api/v1/secret-references") return json({ data: [], page: page(0) });
      if (path === "/api/v1/secret-leases" && request.method === "GET") return json({ data: [], page: page(0) });
      if (path === "/api/v1/secret-leases/synthetic" && request.method === "POST") {
        const payload = await request.json() as Record<string, unknown>;
        payloads.push(payload); roeHeaders.push(request.headers.get("X-RedAgent-ROE-Version"));
        return json({ data: { ...leaseRow(), ...payload, lease_state: "active" }, meta: { replayed: false } }, 201);
      }
      return json({ error: { code: "not_found", message: "Not found" } }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await user.selectOptions(await screen.findByRole("combobox", { name: "Authorized job" }), "job-1");
    await user.click(screen.getByRole("button", { name: "Issue to synthetic workload" }));
    expect(await screen.findByText(/delivered once to the attested synthetic workload/)).toBeVisible();
    expect(payloads[0]).toMatchObject({ engagement_id: "engagement-1", job_id: "job-1", ttl_seconds: 300 });
    expect(payloads[0]?.reference_id).toMatch(/^synthetic-reference-[0-9a-f-]+$/);
    expect(payloads[0]?.lease_id).toMatch(/^synthetic-lease-[0-9a-f-]+$/);
    expect(payloads[0]?.workload_client_id).toMatch(/^synthetic-workload-[0-9a-f-]+$/);
    expect(roeHeaders).toEqual(["roe-1"]);
    expect(screen.queryByText("R098-SYNTHETIC-MATERIAL")).not.toBeInTheDocument();
  });

  it("projects a correlated credential outage and retries without inferring lease state", async () => {
    window.history.replaceState({}, "", "/secrets");
    let leaseAttempts = 0;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1", permissions: ["secret:read"], roles: ["operator"],
      }}));
      if (path === "/api/v1/secret-references") return Promise.resolve(json({ data: [], page: page(0) }));
      if (path === "/api/v1/secret-leases" && leaseAttempts++ === 0) return Promise.resolve(json({ error: {
        code: "secret_provider_unavailable", message: "Credential service unavailable", correlation_id: "corr-secret",
      } }, 503));
      if (path === "/api/v1/secret-leases") return Promise.resolve(json({ data: [], page: page(0) }));
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    expect(await screen.findByRole("alert", { name: "Credential service unavailable" })).toBeVisible();
    expect(screen.getByText("Correlation: corr-secret")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route data" }));
    expect(await screen.findByText("No credential leases")).toBeVisible();
    expect(leaseAttempts).toBe(2);
  });
});


function leaseRow() {
  return {
    lease_id: "lease-1", tenant_id: "tenant-1", reference_id: "reference-1",
    engagement_id: "engagement-1", job_id: "job-1", workload_client_id: "client-1",
    capability: "synthetic-noop", permission_count: 1, issued_at: "2026-07-10T12:00:00Z",
    expires_at: "2026-07-10T12:05:00Z", renewed_at: null, revoked_at: null,
    renewable: true, renewal_count: 0, lease_state: "active", policy_reference: "policy:compat_098:1",
    roe_version_id: "roe-1", failure_code: null, version: 1,
  } as const;
}

function jobRow() {
  return {
    job_id: "job-1", campaign_id: null, engagement_id: "engagement-1", tenant_id: "tenant-1",
    created_by_user_id: "operator-1", current_gate: "authorized", dispatch_blocked: false,
    failure_code: null, orchestration_revision: 1, orchestration_state: "accepted",
    policy_reference: "policy:1", request: {}, retry_count: 0, roe_version_id: "roe-1",
    status: "running", stop_requested: false, version: 1, workflow_id: "workflow-1", workflow_run_id: "run-1",
  };
}

function page(returned: number) { return { limit: 50, offset: 0, returned }; }
function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
