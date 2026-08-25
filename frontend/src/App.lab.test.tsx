import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/lab");
});

it("shows fixed safe-lab identity, golden outcomes, teardown, and emergency controls without target input", async () => {
  globalThis.fetch = vi.fn((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["audit:read"],
    }}));
    if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/lab/dashboard") return Promise.resolve(json({ data: {
      bundle: {
        bundle_id: "r103-synthetic-lab", bundle_revision: 1,
        fixture_digest: `sha256:${"a".repeat(64)}`, network_id: "redagent-r103-lab",
        bundle_state: "active", expires_at: "2026-07-11T16:00:00Z",
      },
      scenarios: [{
        run_id: "run-1", scenario_id: "authorize_deny", scenario_state: "succeeded",
        reason_code: "scenario_succeeded", current_step: 2, version: 3,
      }],
      measurements: [{
        measurement_id: "metric-1", metric_id: "target-contact-count", comparison: "lte",
        observed_millionths: 0, threshold_millionths: 0, unit: "requests",
        sample_count: 1, result_state: "passed",
      }],
      latest_teardown: {
        receipt_id: "teardown-1", residual_resource_count: 0, teardown_complete: true,
        inventory_sha256: "b".repeat(64), completed_at: "2026-07-11T15:00:00Z",
      },
      emergency_stop_path: "/jobs/{job_id}/emergency-stop", arbitrary_target_input_allowed: false,
    }}));
    return Promise.reject(new Error(`unexpected request ${path}`));
  }) as typeof fetch;

  render(<App />);
  expect(await screen.findByRole("heading", { name: "Safe local lab" })).toBeVisible();
  expect(await screen.findByText(/Arbitrary target input is disabled/)).toBeVisible();
  expect(screen.getByText("authorize_deny")).toBeVisible();
  expect(screen.getByText(/Teardown verified: 0 residual resources/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Emergency stop controls" })).toHaveAttribute("href", "/jobs");
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  expect(screen.getByText("Qualification ready")).toBeVisible();
});

it("renders safe-lab correlation evidence and retries without inferring qualification", async () => {
  const user = userEvent.setup();
  let dashboardReads = 0;
  vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "auditor-1", tenant_id: "tenant-1", roles: ["auditor"],
      permissions: ["engagement:read", "audit:read"],
    } }));
    if (path === "/api/v1/lab/dashboard") {
      dashboardReads += 1;
      if (dashboardReads === 1) return Promise.resolve(json({ error: {
        code: "safe_lab_unavailable", message: "Safe lab unavailable",
        correlation_id: "correlation-lab-unavailable",
      } }, 503));
      return Promise.resolve(json({ data: {
        bundle: null, scenarios: [], measurements: [], latest_teardown: null,
        emergency_stop_path: "/jobs/{job_id}/emergency-stop", arbitrary_target_input_allowed: false,
      } }));
    }
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Safe lab unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: correlation-lab-unavailable")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No lab bundle is registered")).toBeVisible();
  expect(screen.getByText("Qualification incomplete")).toBeVisible();
  expect(dashboardReads).toBe(2);
});

it("denies safe-lab truth locally without audit read authority", async () => {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json({ data: {
    subject: "viewer-1", tenant_id: "tenant-1", roles: ["viewer"],
    permissions: ["engagement:read"],
  } }));
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

function json(value: object, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

function page(total: number) {
  return { limit: 50, offset: 0, total, has_more: false };
}
