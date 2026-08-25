import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { JobsPage } from "./features/residual/command/JobsPage";
import { createConsoleClient } from "./lib/apiClient";

describe("live durable jobs console", () => {
  it("shows workflow truth, accepted commands, immutable revision, and compat_101 stop ownership", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.method === "POST" && request.url.endsWith("/commands")) {
        return Promise.resolve(json({ data: fixture(), meta: { replayed: false, command_id: "generated" } }));
      }
      if (request.method === "POST" && request.url.endsWith("/emergency-stop")) {
        return Promise.resolve(json({ data: { job_id: "job-1", workflow_id: "workflow-1", stop_id: "stop-1", control_id: "control-1", state: "stop_requested", containment_complete: false, completion_owner: "compat_101" } }, 202));
      }
      if (request.method === "POST" && request.url.endsWith("/api/v1/jobs")) {
        return Promise.resolve(json({ data: fixture("job-created"), meta: { replayed: false, audit_id: "audit-job", outbox_id: "outbox-job" } }, 201));
      }
      if (request.method === "POST" && request.url.endsWith("/containment-controls")) {
        return Promise.resolve(json({ data: {
          control_id: "control-created", stop_id: "stop-created", scope_kind: "job", scope_id: "job-1",
          control_mode: "immediate", control_state: "active", initiated_by_user_id: "approver-1",
          approved_by_user_id: "approver-1", requested_at: "2026-07-10T19:00:00Z",
          activated_at: "2026-07-10T19:00:00Z", recovered_at: null,
          ack_deadline: "2026-07-10T19:00:10Z", request_hash: "a".repeat(64), version: 1,
        } }));
      }
      if (request.method === "GET" && request.url.endsWith("/containment")) {
        return Promise.resolve(json({ data: containmentFixture() }));
      }
      if (request.method === "GET" && request.url.includes("/containment-controls")) {
        return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0 } }));
      }
      if (request.method === "GET" && request.url.endsWith("/quotas/status")) {
        return Promise.resolve(json({ data: [{
          policy_record_id: "quota-policy-1", policy_id: "quota-1", revision: 1,
          scope_kind: "tenant", scope_id: "tenant-1", dimension: "concurrent_jobs",
          hard_limit: 3, reserved: 0, consumed: 1, remaining: 2,
          window_start: null, window_end: null, extension_name: null,
        }] }));
      }
      if (request.method === "GET" && request.url.includes("/roe-versions")) {
        return Promise.resolve(json({ data: [{
          roe_version_id: "roe-1", engagement_id: "engagement-1", tenant_id: "tenant-1",
          revision: 1, document: {}, policy_reference: null, status: "approved", approval_id: "approval-1", version: 2,
        }], page: { limit: 50, offset: 0, returned: 1 } }));
      }
      if (request.method === "GET" && request.url.includes("/api/v1/engagements")) {
        return Promise.resolve(json({ data: [{
          engagement_id: "engagement-1", tenant_id: "tenant-1", name: "Synthetic scope",
          owner_user_id: "operator-1", version: 1,
        }], page: { limit: 50, offset: 0, returned: 1 } }));
      }
      return Promise.resolve(json({ data: [fixture()], page: { limit: 50, offset: 0, returned: 1 } }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => "csrf" });
    const user = userEvent.setup();

    render(<JobsPage client={client} context={{
      subject: "approver-1", tenant_id: "tenant-1", roles: ["approver"],
      permissions: ["engagement:read", "roe:read", "job:read", "job:create", "job:approve", "job:update", "job:stop"],
      operator_shell: { schema_version: "1", environment: "local", safety_profile: "synthetic-local", status: "ready" },
    }} />);

    expect(await screen.findByText("workflow-1")).toBeVisible();
    expect(screen.queryByLabelText("Job ID")).toBeNull();
    expect(screen.queryByLabelText("Approved ROE version ID")).toBeNull();
    expect(screen.queryByLabelText("Budget reference")).toBeNull();
    expect(screen.queryByLabelText("Scope ID")).toBeNull();
    expect(screen.getByText("Revision 2 · Record version 2")).toBeVisible();
    expect(screen.getByText("operator_approval")).toBeVisible();
    expect(screen.getByText(/compat_101 owns containment completion/)).toBeVisible();

    await screen.findByRole("option", { name: "Revision 1 · approved" });
    await user.selectOptions(screen.getByLabelText("Approved ROE"), "roe-1");
    await user.selectOptions(screen.getByLabelText("Budget authority"), "quota-policy-1");
    await user.click(screen.getByRole("button", { name: "Start job" }));
    const jobRequest = findRequest(fetchMock, "POST", "/api/v1/jobs");
    const jobPayload = await readRequestRecord(jobRequest);
    expect(readString(jobPayload, "job_id")).toMatch(/^job-/);
    expect(jobPayload).toMatchObject({
      engagement_id: "engagement-1", roe_version_id: "roe-1",
      request: { capability: "synthetic-noop", budget_reference: "quota-policy-1" },
    });

    await user.selectOptions(screen.getByLabelText("Containment target"), "job-1");
    await user.type(screen.getByLabelText("Reason"), "Contain this synthetic workflow");
    await user.click(screen.getByRole("button", { name: "Request containment" }));
    await expect(readRequestRecord(findRequest(fetchMock, "POST", "/containment-controls"))).resolves.toMatchObject({
      scope_kind: "job", scope_id: "job-1", reason: "Contain this synthetic workflow",
    });

    await user.click(screen.getByRole("button", { name: "Approve job-1" }));
    expect(fetchMock.mock.calls.some(([input]) => (input as Request).url.endsWith("/commands"))).toBe(true);
    await user.click(screen.getByRole("button", { name: "Emergency stop job-1" }));
    expect(await screen.findByText(/phase receipts now determine containment/)).toBeVisible();
    expect(screen.getByText("Containment unresolved")).toBeVisible();
    expect(screen.getByText("dispatch_block")).toBeVisible();
  });
});

function fixture(jobId = "job-1") {
  return {
    job_id: jobId, tenant_id: "tenant-1", engagement_id: "engagement-1", roe_version_id: "roe-1",
    created_by_user_id: "operator-1", campaign_id: null, status: "pending",
    request: { capability: "synthetic-noop", approval_timeout_seconds: 3600, max_activity_attempts: 3, budget_reference: "budget:compat_096:console" },
    policy_reference: "console:job-create:1", workflow_id: "workflow-1", workflow_run_id: "run-1",
    orchestration_state: "awaiting_approval", orchestration_revision: 2, current_gate: "operator_approval",
    failure_code: null, retry_count: 0, dispatch_blocked: true, stop_requested: false, version: 2,
  };
}

function findRequest(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>, method: string, suffix: string): Request | undefined {
  return fetchMock.mock.calls
    .map(([input, init]) => input instanceof Request ? input : new Request(input, init))
    .find((request) => request.method === method && request.url.endsWith(suffix));
}

async function readRequestRecord(request: Request | undefined): Promise<Record<string, unknown>> {
  if (!request) throw new Error("Expected request");
  const value = JSON.parse(await request.clone().text()) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected JSON object");
  return value as Record<string, unknown>;
}

function readString(value: Record<string, unknown>, key: string): string {
  const entry = value[key];
  if (typeof entry !== "string") throw new Error(`Expected ${key} string`);
  return entry;
}

function containmentFixture() {
  return {
    job_id: "job-1", stop_id: "stop-1", control_id: "control-1", control_state: "active",
    requested_at: "2026-07-10T19:00:00Z", ack_deadline: "2026-07-10T19:00:10Z",
    action_state: "running", outcome: null, containment_complete: false,
    phases: [{ phase: "dispatch_block", state: "verified", reason_code: "dispatch_block_verified", duration_ms: 2, occurred_at: "2026-07-10T19:00:01Z" }],
    residual_risk_codes: [], open_incident_ids: [],
  };
}

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
