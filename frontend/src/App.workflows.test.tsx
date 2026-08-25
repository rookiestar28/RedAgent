import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("operational console workflows", () => {
  it("treats the authenticated wildcard as engagement read and create authority", async () => {
    window.history.replaceState({}, "", "/engagements");
    const user = userEvent.setup();
    let created: Record<string, unknown> | null = null;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const pathname = new URL(request.url).pathname;
      if (pathname === "/api/v1/context") {
        return Promise.resolve(json({ data: {
          subject: "wildcard-operator",
          tenant_id: "tenant-wildcard",
          permissions: ["*"],
          roles: ["operator"],
        } }));
      }
      if (pathname === "/api/v1/engagements" && request.method === "POST") {
        return request.json().then((body: unknown) => {
          created = { ...(body as Record<string, unknown>), tenant_id: "tenant-wildcard", version: 1 };
          return json({ data: created, meta: { replayed: false, audit_id: "audit-wildcard", outbox_id: "outbox-wildcard" } }, 201);
        });
      }
      if (pathname === "/api/v1/engagements") {
        return Promise.resolve(json({ data: created ? [created] : [], page: { limit: 50, offset: 0, returned: created ? 1 : 0, next_offset: null } }));
      }
      if (pathname.endsWith("/targets") || pathname.endsWith("/roe-versions")) {
        return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByRole("heading", { level: 2, name: "Engagements" })).toBeVisible();
    expect(screen.queryByRole("alert", { name: "Route access denied" })).toBeNull();
    expect(screen.getByRole("button", { name: "Create engagement" })).toBeEnabled();
    await user.type(screen.getByLabelText("Engagement name"), "Wildcard synthetic engagement");
    await user.click(screen.getByRole("button", { name: "Create engagement" }));
    expect(await screen.findByRole("heading", { name: "Wildcard synthetic engagement" })).toBeVisible();
  });

  it("uses generated bindings and authoritative pages for engagement scope", async () => {
    window.history.replaceState({}, "", "/engagements");
    const user = userEvent.setup();
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url.includes("/api/v1/context")) {
        return Promise.resolve(json({
          data: {
            subject: "operator-1",
            tenant_id: "tenant-1",
            permissions: ["engagement:read", "engagement:create", "target:read", "target:create", "roe:read", "roe:create", "roe:approve"],
            roles: ["operator"],
          },
        }));
      }
      if (request.url.endsWith("/api/v1/engagements") && request.method === "POST") {
        return Promise.resolve(json({
          data: {
            engagement_id: "engagement-generated",
            tenant_id: "tenant-1",
            name: "Synthetic perimeter",
            owner_user_id: "operator-1",
            version: 1,
          },
          meta: { replayed: false, audit_id: "audit-1", outbox_id: "outbox-1" },
        }, 201));
      }
      if (request.url.includes("/targets") && request.method === "POST") {
        return Promise.resolve(json({
          data: {
            target_id: "target-generated", engagement_id: "engagement-1", tenant_id: "tenant-1",
            target_type: "hostname", normalized_value: "owned.example.test", version: 1,
          },
          meta: { replayed: false, audit_id: "audit-target", outbox_id: "outbox-target" },
        }, 201));
      }
      if (request.url.includes("/targets")) {
        return Promise.resolve(json({
          data: [{
            target_id: "target-legacy",
            engagement_id: "engagement-1",
            tenant_id: "tenant-1",
            target_type: "needs_review",
            normalized_value: "legacy synthetic target",
            version: 1,
          }],
          page: { limit: 50, offset: 0, returned: 1 },
        }));
      }
      if (request.url.includes("/approve") && request.method === "POST") {
        return Promise.resolve(json({
          data: {
            roe_version_id: "roe-1", engagement_id: "engagement-1", tenant_id: "tenant-1",
            revision: 1, document: {}, policy_reference: null, status: "approved", approval_id: "approval-1", version: 2,
          },
          meta: { replayed: false, audit_id: "audit-approve", outbox_id: "outbox-approve" },
        }));
      }
      if (request.url.includes("/roe-versions") && request.method === "POST") {
        return Promise.resolve(json({
          data: {
            roe_version_id: "roe-generated", engagement_id: "engagement-1", tenant_id: "tenant-1",
            revision: 2, document: {}, policy_reference: null, status: "draft", approval_id: null, version: 1,
          },
          meta: { replayed: false, audit_id: "audit-roe", outbox_id: "outbox-roe" },
        }, 201));
      }
      if (request.url.includes("/roe-versions")) {
        return Promise.resolve(json({
          data: [{
            roe_version_id: "roe-1", engagement_id: "engagement-1", tenant_id: "tenant-1",
            revision: 1, document: {}, policy_reference: null, status: "draft", approval_id: null, version: 1,
          }],
          page: { limit: 50, offset: 0, returned: 1 },
        }));
      }
      if (request.url.includes("/api/v1/engagements")) {
        const offset = new URL(request.url).searchParams.get("offset");
        return Promise.resolve(offset === "1"
          ? json({
            data: [{
              engagement_id: "engagement-2", tenant_id: "tenant-1", name: "Second scope",
              owner_user_id: "operator-2", version: 1,
            }],
            page: { limit: 1, offset: 1, returned: 1, next_offset: null },
          })
          : json({
            data: [{
              engagement_id: "engagement-1", tenant_id: "tenant-1", name: "First scope",
              owner_user_id: "operator-1", version: 1,
            }],
            page: { limit: 1, offset: 0, returned: 1, next_offset: 1 },
          }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    expect((await screen.findAllByText("First scope")).length).toBeGreaterThan(0);
    expect(screen.queryByLabelText("Engagement ID")).toBeNull();
    expect(screen.queryByLabelText("Target ID")).toBeNull();
    expect(screen.queryByLabelText("ROE version ID")).toBeNull();
    expect(await screen.findByText(/Needs review.*unavailable/i)).toBeVisible();

    await user.type(screen.getByLabelText("Normalized target"), "owned.example.test");
    await user.click(screen.getByRole("button", { name: "Add target" }));
    const targetMutation = fetchMock.mock.calls
      .map(([input, requestInit]) => input instanceof Request ? input : new Request(input, requestInit))
      .find((request) => request.method === "POST" && request.url.endsWith("/targets"));
    const targetPayload = await readRequestRecord(targetMutation);
    expect(readString(targetPayload, "target_id")).toMatch(/^target-/);
    expect(targetPayload).toMatchObject({
      target_type: "hostname",
      normalized_value: "owned.example.test",
    });

    await user.type(screen.getByLabelText("Objective"), "Bounded synthetic validation");
    await user.type(screen.getByLabelText("Request budget"), "5");
    await user.click(screen.getByRole("button", { name: "Draft ROE" }));
    const roeMutation = fetchMock.mock.calls
      .map(([input, requestInit]) => input instanceof Request ? input : new Request(input, requestInit))
      .find((request) => request.method === "POST" && request.url.endsWith("/roe-versions"));
    const roePayload = await readRequestRecord(roeMutation);
    expect(readString(roePayload, "roe_version_id")).toMatch(/^roe-/);
    expect(roePayload).toMatchObject({
      revision: 2,
      document: { objective: "Bounded synthetic validation", request_budget: 5, execution_enabled: false },
    });

    await user.click(screen.getByRole("button", { name: "Approve revision 1" }));
    expect(fetchMock.mock.calls.some(([input, requestInit]) => {
      const request = input instanceof Request ? input : new Request(input, requestInit);
      return request.method === "POST" && request.url.endsWith("/roe-versions/roe-1/approve");
    })).toBe(true);

    await user.type(screen.getByLabelText("Engagement name"), "Synthetic perimeter");
    await user.click(screen.getByRole("button", { name: "Create engagement" }));
    const mutation = fetchMock.mock.calls
      .map(([input, requestInit]) => input instanceof Request ? input : new Request(input, requestInit))
      .find((request) => request.method === "POST" && request.url.endsWith("/api/v1/engagements"));
    expect(mutation).toBeDefined();
    const engagementPayload = await readRequestRecord(mutation);
    expect(readString(engagementPayload, "engagement_id")).toMatch(/^engagement-/);
    expect(engagementPayload).toMatchObject({
      name: "Synthetic perimeter",
      owner_user_id: "operator-1",
    });

    await user.click(screen.getByRole("button", { name: "Next engagements" }));
    expect((await screen.findAllByText("Second scope")).length).toBeGreaterThan(0);
  });

  it("shows access requests with immutable version and an explicit approval action", async () => {
    window.history.replaceState({}, "", "/access");
    const user = userEvent.setup();
    vi.stubGlobal("confirm", vi.fn(() => true));
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (request.url.includes("/api/v1/context")) {
        return Promise.resolve(json({
          data: {
            subject: "approver-1",
            tenant_id: "tenant-1",
            permissions: ["engagement:read", "jit:read", "jit:request", "jit:approve", "jit:revoke", "jit:review"],
            roles: ["approver"],
          },
        }));
      }
      if (request.method === "POST" && url.pathname.endsWith("/jit-grants/grant-1/approve")) {
        return Promise.resolve(json({ data: {
          grant_id: "grant-1", requester_user_id: "operator-1", approver_user_id: "approver-1",
          role: "operator", permission: "engagement:update", scope_type: "engagement", scope_id: "engagement-1",
          reason: "Bounded synthetic request", approved_at: "2026-08-25T04:00:00Z",
          expires_at: "2099-07-10T18:00:00Z", revoked_at: null, break_glass: false, version: 2,
        }, meta: { idempotency_key: "approve-1", replayed: false } }));
      }
      if (request.method === "POST" && url.pathname.endsWith("/jit-grants/grant-active/revoke")) {
        return Promise.resolve(json({ data: {
          grant_id: "grant-active", requester_user_id: "operator-1", approver_user_id: "approver-2",
          role: "operator", permission: "target:create", scope_type: "engagement", scope_id: "engagement-1",
          reason: "Active synthetic request", approved_at: "2026-08-25T04:00:00Z",
          expires_at: "2099-07-10T18:00:00Z", revoked_at: "2026-08-25T04:10:00Z", break_glass: false, version: 2,
        }, meta: { idempotency_key: "revoke-1", replayed: false } }));
      }
      if (request.method === "POST" && url.pathname.endsWith("/jit-grants/grant-breakglass/review")) {
        return Promise.resolve(json({ data: {
          grant_id: "grant-breakglass", requester_user_id: "operator-2", approver_user_id: "approver-2",
          role: "operator", permission: "roe:create", scope_type: "engagement", scope_id: "engagement-1",
          reason: "Break-glass synthetic request", approved_at: "2026-08-25T04:00:00Z",
          expires_at: "2099-07-10T18:00:00Z", revoked_at: null, break_glass: true, version: 2,
        }, meta: { idempotency_key: "review-1", replayed: false } }));
      }
      if (request.method === "POST" && url.pathname.endsWith("/api/v1/jit-grants")) {
        return Promise.resolve(json({ data: {
          grant_id: "grant-server-created", requester_user_id: "approver-1", approver_user_id: null,
          role: "operator", permission: "target:create", scope_type: "engagement", scope_id: "engagement-1",
          reason: "Need bounded target maintenance", approved_at: null,
          expires_at: "2099-07-10T18:00:00Z", revoked_at: null, break_glass: false, version: 1,
        }, meta: { idempotency_key: "request-1", replayed: false } }, 201));
      }
      if (request.method === "GET" && url.pathname.endsWith("/api/v1/jit-grants")) {
        if (url.searchParams.get("offset") === "6") {
          return Promise.resolve(json({ data: [{
            grant_id: "grant-page-2", requester_user_id: "operator-3", approver_user_id: null,
            role: "operator", permission: "engagement:update", scope_type: "engagement", scope_id: "engagement-1",
            reason: "Second authoritative grant page", approved_at: null,
            expires_at: "2099-07-10T18:00:00Z", revoked_at: null, break_glass: false, version: 1,
          }], page: { limit: 50, offset: 6, returned: 1, next_offset: null } }));
        }
        return Promise.resolve(json({
          data: [{
            grant_id: "grant-1",
            requester_user_id: "operator-1",
            approver_user_id: null,
            role: "operator",
            permission: "engagement:update",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Bounded synthetic request",
            approved_at: null,
            expires_at: "2099-07-10T18:00:00Z",
            revoked_at: null,
            break_glass: false,
            version: 1,
          }, {
            grant_id: "grant-sod",
            requester_user_id: "approver-1",
            approver_user_id: null,
            role: "operator",
            permission: "target:create",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Independent approval must be enforced",
            approved_at: null,
            expires_at: "2099-07-10T18:00:00Z",
            revoked_at: null,
            break_glass: false,
            version: 1,
          }, {
            grant_id: "grant-active",
            requester_user_id: "operator-1",
            approver_user_id: "approver-2",
            role: "operator",
            permission: "target:create",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Active synthetic request",
            approved_at: "2026-08-25T04:00:00Z",
            expires_at: "2099-07-10T18:00:00Z",
            revoked_at: null,
            break_glass: false,
            version: 1,
          }, {
            grant_id: "grant-breakglass",
            requester_user_id: "operator-2",
            approver_user_id: "approver-2",
            role: "operator",
            permission: "roe:create",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Break-glass synthetic request",
            approved_at: "2026-08-25T04:00:00Z",
            expires_at: "2099-07-10T18:00:00Z",
            revoked_at: null,
            break_glass: true,
            version: 1,
          }, {
            grant_id: "grant-expired",
            requester_user_id: "operator-3",
            approver_user_id: null,
            role: "operator",
            permission: "engagement:update",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Expired synthetic request",
            approved_at: null,
            expires_at: "2026-07-10T18:00:00Z",
            revoked_at: null,
            break_glass: false,
            version: 1,
          }, {
            grant_id: "grant-revoked",
            requester_user_id: "operator-4",
            approver_user_id: "approver-2",
            role: "operator",
            permission: "target:create",
            scope_type: "engagement",
            scope_id: "engagement-1",
            reason: "Revoked synthetic request",
            approved_at: "2026-08-25T03:00:00Z",
            expires_at: "2099-07-10T18:00:00Z",
            revoked_at: "2026-08-25T03:30:00Z",
            break_glass: false,
            version: 1,
          }],
          page: { limit: 50, offset: 0, returned: 6, next_offset: 6 },
        }));
      }
      if (request.url.includes("/api/v1/engagements")) {
        return Promise.resolve(json({
          data: [{
            engagement_id: "engagement-1",
            tenant_id: "tenant-1",
            name: "Authorized engagement",
            owner_user_id: "operator-1",
            state: "active",
            version: 1,
          }],
          page: { limit: 50, offset: 0, returned: 1, next_offset: null },
        }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("grant-1")).toBeVisible();
    expect(screen.getAllByText("Version 1")).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Approve grant-1" })).toBeEnabled();
    expect(screen.getAllByText("Pending approval")).toHaveLength(2);
    expect(screen.getAllByText("Active")).toHaveLength(2);
    expect(screen.getByText("Expired")).toBeVisible();
    expect(screen.getByText("Revoked")).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve grant-sod" })).toBeDisabled();
    expect(screen.getByText("Separation of duties: requester cannot approve.")).toBeVisible();
    expect(screen.queryByLabelText("Grant ID")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Engagement"), "engagement-1");
    await user.selectOptions(screen.getByLabelText("Permission"), "target:create");
    await user.type(screen.getByLabelText("Business reason"), "Need bounded target maintenance");
    await user.click(screen.getByRole("button", { name: "Request JIT access" }));
    expect(await screen.findByText("grant-server-created")).toBeVisible();
    const requestMutation = fetchMock.mock.calls
      .map(([input, requestInit]) => input instanceof Request ? input : new Request(input, requestInit))
      .find((request) => request.method === "POST" && new URL(request.url).pathname.endsWith("/api/v1/jit-grants"));
    const requestPayload = await readRequestRecord(requestMutation);
    expect(readString(requestPayload, "grant_id")).toMatch(/^grant-[0-9a-f]{32}$/);
    expect(requestPayload).toMatchObject({
      permission: "target:create",
      scope_type: "engagement",
      scope_id: "engagement-1",
      reason: "Need bounded target maintenance",
    });

    await user.click(screen.getByRole("button", { name: "Approve grant-1" }));
    await user.click(screen.getByRole("button", { name: "Revoke grant-active" }));
    await user.click(screen.getByRole("button", { name: "Review grant-breakglass" }));
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Approve grant-1" })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Revoke grant-active" })).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Review grant-breakglass" })).toBeDisabled();
    });

    await user.click(screen.getByRole("button", { name: "Next access requests" }));
    expect(await screen.findByText("grant-page-2")).toBeVisible();
    expect(screen.getByText("Page 2")).toBeVisible();
    expect(screen.getByRole("button", { name: "Previous access requests" })).toBeEnabled();
  });

  it("denies Access locally when the authenticated context lacks JIT read authority", async () => {
    window.history.replaceState({}, "", "/access");
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url.includes("/api/v1/context")) {
        return Promise.resolve(json({ data: {
          subject: "viewer-1",
          tenant_id: "tenant-1",
          permissions: ["engagement:read"],
          roles: ["viewer"],
        } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
    expect(fetchMock.mock.calls.some(([input, requestInit]) => {
      const request = input instanceof Request ? input : new Request(input, requestInit);
      return request.url.includes("/api/v1/jit-grants");
    })).toBe(false);
  });

  it("keeps Access fail-closed when route data fails and retries the authoritative projection", async () => {
    window.history.replaceState({}, "", "/access");
    const user = userEvent.setup();
    let grantReads = 0;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname.endsWith("/api/v1/context")) {
        return Promise.resolve(json({ data: {
          subject: "approver-1",
          tenant_id: "tenant-1",
          permissions: ["engagement:read", "jit:read"],
          roles: ["approver"],
        } }));
      }
      if (request.method === "GET" && url.pathname.endsWith("/api/v1/jit-grants")) {
        grantReads += 1;
        return Promise.resolve(grantReads === 1
          ? json({ error: {
            code: "projection_unavailable",
            message: "Access projection unavailable",
            correlation_id: "correlation-access-1",
          } }, 503)
          : json({ data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } }));
      }
      if (request.method === "GET" && url.pathname.endsWith("/api/v1/engagements")) {
        return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByRole("alert", { name: "Route data unavailable" })).toBeVisible();
    expect(screen.getByText("Correlation: correlation-access-1")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route data" }));
    expect(await screen.findByText("No JIT grants")).toBeVisible();
    expect(grantReads).toBe(2);
  });
});

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function readRequestRecord(request: Request | undefined): Promise<Record<string, unknown>> {
  if (!request) throw new Error("Expected mutation request");
  const value = JSON.parse(await request.clone().text()) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected JSON object");
  return value as Record<string, unknown>;
}

function readString(value: Record<string, unknown>, key: string): string {
  const entry = value[key];
  if (typeof entry !== "string") throw new Error(`Expected ${key} string`);
  return entry;
}
