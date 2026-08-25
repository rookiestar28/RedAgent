import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("activity console", () => {
  it("pages through the redacted metadata-only audit projection", async () => {
    window.history.replaceState({}, "", "/activity");
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "auditor-1", tenant_id: "tenant-1",
        permissions: ["engagement:read", "audit:read"], roles: ["auditor"],
      } }));
      if (url.pathname === "/api/v1/activity") {
        const second = url.searchParams.get("offset") === "1";
        return Promise.resolve(json({ data: [{
          event_id: second ? "event-2" : "event-1",
          actor_user_id: second ? "operator-2" : "operator-1",
          action: second ? "policy.bundle.promoted" : "job.created",
          subject_type: second ? "policy_bundle" : "job",
          subject_id: second ? "r099-v2" : "job-1",
          occurred_at: second ? "2026-08-25T04:01:00Z" : "2026-08-25T04:00:00Z",
          correlation_id: second ? "correlation-2" : "correlation-1",
          sensitive_details: "must-not-render",
        }], page: { limit: 50, offset: second ? 1 : 0, returned: 1, next_offset: second ? null : 1 } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    }));

    render(<App />);

    expect(await screen.findByText("job.created")).toBeVisible();
    expect(screen.getByText("Redacted metadata-only audit projection")).toBeVisible();
    expect(screen.getByText("correlation-1")).toBeVisible();
    expect(screen.queryByText("must-not-render")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next activity" }));
    expect(await screen.findByText("policy.bundle.promoted")).toBeVisible();
    expect(screen.getByText("Page 2")).toBeVisible();
  });

  it("renders audit-unavailable correlation evidence and retries", async () => {
    window.history.replaceState({}, "", "/activity");
    const user = userEvent.setup();
    let activityReads = 0;
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "auditor-1", tenant_id: "tenant-1",
        permissions: ["engagement:read", "audit:read"], roles: ["auditor"],
      } }));
      if (url.pathname === "/api/v1/activity") {
        activityReads += 1;
        if (activityReads === 1) return Promise.resolve(json({ error: {
          code: "audit_unavailable", message: "Audit projection unavailable",
          correlation_id: "correlation-audit-unavailable",
        } }, 503));
        return Promise.resolve(json({ data: [], page: {
          limit: 50, offset: 0, returned: 0, next_offset: null,
        } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    }));

    render(<App />);

    expect(await screen.findByRole("alert", { name: "Audit unavailable" })).toBeVisible();
    expect(screen.getByText("Correlation: correlation-audit-unavailable")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route data" }));
    expect(await screen.findByText("No visible activity")).toBeVisible();
    expect(activityReads).toBe(2);
  });

  it("denies activity locally without audit read authority", async () => {
    window.history.replaceState({}, "", "/activity");
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json({ data: {
      subject: "viewer-1", tenant_id: "tenant-1",
      permissions: ["engagement:read"], roles: ["viewer"],
    } }));
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
