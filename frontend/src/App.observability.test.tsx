import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";

import { App } from "./App";


beforeEach(() => {
  window.history.replaceState({}, "", "/observability");
});

it("shows SLO/export/incident truth, correlation, timeline, and confirmed acknowledgement", async () => {
  let incident = fixtureIncident();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url, "http://localhost");
    const path = url.pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "audit:read"],
    } }));
    if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/observability/dashboard") return Promise.resolve(json({ data: {
      export_state_counts: { pending: 1 }, incident_state_counts: { open: 1 },
      slo_state_counts: { breaching: 1 }, open_alerts: 1, unreplayed_dead_letters: 0,
    } }));
    if (path === "/api/v1/incidents" && request.method === "GET") {
      const second = url.searchParams.get("offset") === "1";
      return Promise.resolve(json({ data: [second ? { ...fixtureIncident(), incident_id: "incident-2", source_id: "export-2" } : incident], page: page(1, second ? 1 : 0, second ? null : 1) }));
    }
    if (path === "/api/v1/incidents/runbooks") return Promise.resolve(json({ data: [runbook()] }));
    if (path === "/api/v1/observability/correlations/correlation-1") {
      const second = url.searchParams.get("offset") === "1";
      return Promise.resolve(json({ data: [{
      operation_id: second ? "export-2" : "export-1", event_id: second ? "event-2" : "event-1", correlation_id: "correlation-1",
      signal_kind: "event", priority: "security", export_state: "pending",
      reason_code: null, occurred_at: "2026-07-11T07:00:00Z",
    }], page: page(1, second ? 1 : 0, second ? null : 1) }));
    }
    if (path === "/api/v1/incidents/incident-1/timeline") return Promise.resolve(json({ data: [{
      event_id: "timeline-1", event_type: incident.state === "open" ? "opened" : "acknowledge",
      actor_user_id: "operator-1", reason_code: "incident_acknowledge",
      occurred_at: "2026-07-11T07:00:00Z",
    }] }));
    if (path === "/api/v1/incidents/incident-1/actions" && request.method === "POST") {
      incident = { ...incident, state: "acknowledged", acknowledged_by_user_id: "operator-1", version: 2 };
      return Promise.resolve(json({ data: incident }));
    }
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));
  const user = userEvent.setup();

  render(<App />);
  expect(await screen.findByRole("heading", { name: "Observability and SLOs" })).toBeVisible();
  expect(await screen.findByText("breaching: 1")).toBeVisible();
  expect(await screen.findByText("incident-1")).toBeVisible();
  expect(await screen.findByText("telemetry_outage")).toBeVisible();
  await user.type(screen.getByLabelText("Correlation ID"), "correlation-1");
  await user.click(screen.getByRole("button", { name: "Look up correlation" }));
  expect(await screen.findByText("export-1")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Timeline" }));
  expect(await screen.findByText(/opened · operator-1/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Acknowledge" }));
  expect(window.confirm).toHaveBeenCalled();
  expect(await screen.findByText(/high · acknowledged/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Next correlation results" }));
  expect(await screen.findByText("export-2")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Next incidents" }));
  expect(await screen.findByText("incident-2")).toBeVisible();
  expect(screen.queryByText(/authorization bearer|cookie-canary|prompt-canary/i)).not.toBeInTheDocument();
});

it("renders observability correlation evidence and retries", async () => {
  const user = userEvent.setup();
  let dashboardReads = 0;
  vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "auditor-1", tenant_id: "tenant-1", roles: ["auditor"],
      permissions: ["engagement:read", "audit:read"],
    } }));
    if (path === "/api/v1/observability/dashboard") {
      dashboardReads += 1;
      if (dashboardReads === 1) return Promise.resolve(json({ error: {
        code: "observability_unavailable", message: "Observability unavailable",
        correlation_id: "correlation-observability-unavailable",
      } }, 503));
      return Promise.resolve(json({ data: {
        export_state_counts: {}, incident_state_counts: {}, slo_state_counts: {},
        open_alerts: 0, unreplayed_dead_letters: 0,
      } }));
    }
    if (path === "/api/v1/incidents") return Promise.resolve(json({ data: [], page: page(0) }));
    if (path === "/api/v1/incidents/runbooks") return Promise.resolve(json({ data: [] }));
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Observability unavailable" })).toBeVisible();
  expect(screen.getByText("Correlation: correlation-observability-unavailable")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Retry route data" }));
  expect(await screen.findByText("No incidents")).toBeVisible();
  expect(dashboardReads).toBe(2);
});

it("denies observability locally without audit read authority", async () => {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json({ data: {
    subject: "viewer-1", tenant_id: "tenant-1", roles: ["viewer"],
    permissions: ["engagement:read"],
  } }));
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);

  expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});


type FixtureIncident = {
  incident_id: string; source_kind: string; source_id: string; severity: "high";
  state: "open" | "acknowledged"; reason_code: string; opened_by_user_id: string;
  assigned_to_user_id: string | null; acknowledged_by_user_id: string | null;
  contained_by_user_id: string | null; recovered_by_user_id: string | null;
  reviewed_by_user_id: string | null; evidence_preserved: boolean;
  containment_verified: boolean; opened_at: string; closed_at: string | null; version: number;
};

function fixtureIncident(): FixtureIncident {
  return {
    incident_id: "incident-1", source_kind: "telemetry", source_id: "export-1",
    severity: "high", state: "open", reason_code: "telemetry_degraded",
    opened_by_user_id: "system", assigned_to_user_id: null, acknowledged_by_user_id: null,
    contained_by_user_id: null, recovered_by_user_id: null, reviewed_by_user_id: null,
    evidence_preserved: false, containment_verified: false,
    opened_at: "2026-07-11T07:00:00Z", closed_at: null, version: 1,
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
function page(returned: number, offset = 0, nextOffset: number | null = null) {
  return { limit: 50, offset, returned, next_offset: nextOffset };
}
function runbook() {
  return {
    runbook_id: "telemetry_outage", owner: "security-operations",
    triage: ["Confirm authoritative audit."], containment: ["Apply reviewed containment."],
    evidence: ["Preserve references."], recovery: ["Verify prerequisites."],
    review: ["Record independent review."],
  };
}
