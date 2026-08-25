import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/runners");
});

it("shows metadata-only runner readiness, lineage, evidence, cleanup, and failures", async () => {
  const user = userEvent.setup();
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = new URL(input instanceof Request ? input.url : String(input), "http://localhost");
    const path = url.pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "runner:read"],
    } }));
    if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/runners/status") return Promise.resolve(json({ data: {
      registration_count: 1, active_registration_count: 1, certified_capability_count: 1,
      open_manifest_count: 0, active_lease_count: 0, succeeded_execution_count: 1,
      failed_execution_count: 0, last_heartbeat_at: "2026-07-10T17:00:00Z",
      policy_revisions: ["r099-v1"], capability_revisions: ["synthetic-conformance:1"],
      image_digests: [`sha256:${"a".repeat(64)}`],
    } }));
    if (path === "/api/v1/runners/registrations") {
      const second = url.searchParams.get("offset") === "1";
      return Promise.resolve(json({ data: [{
      runner_id: second ? "runner-2" : "runner-1", runner_class_id: "synthetic-standard", environment: "local-conformance",
      network_plane: "isolated-none", required_policy_revision: "r099-v1", generation: 2,
      registration_state: "active", registered_at: "2026-07-10T16:00:00Z",
      expires_at: "2026-07-10T18:00:00Z", revoked_at: null,
      last_seen_at: "2026-07-10T17:00:00Z", version: 1,
    }], page: page(1, second ? 1 : 0, second ? null : 1) }));
    }
    if (path === "/api/v1/runner-manifests") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/runner-executions") return Promise.resolve(json({ data: [{
      execution_id: "execution-1", job_id: "job-1", manifest_sha256: "b".repeat(64),
      evidence_artifact_id: "evidence-1", outcome: "succeeded", final_phase: "cleanup",
      cleanup_completed: true, residual_risk: null, completed_at: "2026-07-10T17:01:00Z", version: 1,
    }], page: page(1) }));
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));

  render(<App />);
  await screen.findByRole("heading", { name: "Runner fleet" });
  expect(await screen.findByText("Ready", { exact: true })).toBeVisible();
  expect(await screen.findByText("execution-1")).toBeVisible();
  expect(screen.getByText(/evidence-1/)).toBeVisible();
  expect(screen.getByText(/cleanup verified/i)).toBeVisible();
  expect(screen.queryByText(/certificate-fingerprint-canary|signature-canary|lease-token-canary/i)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Next registrations" }));
  expect(await screen.findByText("runner-2")).toBeVisible();
  expect(screen.getByText("Registration page 2")).toBeVisible();
  await waitFor(() => expect(fetch).toHaveBeenCalled());
});

it("renders runner-inventory correlation evidence and retries", async () => {
  const user = userEvent.setup();
  let statusReads = 0;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "runner:read"],
    } }));
    if (path === "/api/v1/runners/status") {
      statusReads += 1;
      if (statusReads === 1) return Promise.resolve(json({ error: {
        code: "runner_inventory_unavailable", message: "Runner inventory unavailable",
        correlation_id: "correlation-runner-unavailable",
      } }, 503));
      return Promise.resolve(json({ data: {
        registration_count: 0, active_registration_count: 0, certified_capability_count: 0,
        open_manifest_count: 0, active_lease_count: 0, succeeded_execution_count: 0,
        failed_execution_count: 0, last_heartbeat_at: null, policy_revisions: [],
        capability_revisions: [], image_digests: [],
      } }));
    }
    if (path === "/api/v1/runners/registrations" || path === "/api/v1/runner-manifests"
      || path === "/api/v1/runner-executions") {
      return Promise.resolve(json({ data: [], page: page(0) }));
    }
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Runner inventory unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: correlation-runner-unavailable")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByRole("heading", { name: "Runner fleet" })).toBeVisible();
  expect(screen.getByText("Unhealthy", { exact: true })).toBeVisible();
  expect(statusReads).toBe(2);
});

it("denies runner inventory locally without runner read authority", async () => {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json({ data: {
    subject: "viewer-1", tenant_id: "tenant-1", roles: ["viewer"],
    permissions: ["engagement:read"],
  } }));
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
function page(returned: number, offset = 0, nextOffset: number | null = null) {
  return { limit: 50, offset, returned, next_offset: nextOffset };
}
