import { describe, expect, it, vi } from "vitest";

import { createConsoleClient } from "./apiClient";

describe("normal autonomous campaign client", () => {
  it("uses server tokens, distinct stage keys and strict bodies without client authority", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      requests.push(new Request(input, init));
      return Promise.resolve(new Response(JSON.stringify({ data: {} }), {
        status: 200, headers: { "Content-Type": "application/json" },
      }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => "csrf-fixture" });
    await client.getAutonomousCampaignAvailability();
    await client.createAutonomousCampaignIntent({ engagement_binding: "opaque-e", target_binding: "opaque-t",
      objective: "Assess HTTP security posture", risk_profile: "opaque-r" }, "intent-key");
    await client.getAutonomousCampaignStatus("server-campaign");
    await client.prepareAutonomousCampaignPlan("server-campaign", 1, '"server-application-token"', "prepare-key");
    await client.decideAutonomousCampaignPlan("approve", "server-campaign", {
      preview_id: "server-preview", preview_sha256: "a".repeat(64),
    }, '"server-preview-token"', "approval-key");
    await client.admitAutonomousCampaign("server-campaign", {
      approval_receipt_id: "server-approval", approval_receipt_sha256: "b".repeat(64),
    }, '"server-approval-token"', "admission-key");
    await client.prepareAutonomousCampaignChild("server-campaign", 7, "server-roe", "child-key");
    await client.recoverAutonomousCampaign("stop", "server-campaign", 7,
      '"server-current-token"', "Operator requests safe containment", "stop-key");
    expect(requests.map((r) => new URL(r.url).pathname)).toEqual([
      "/api/v1/campaign-core/operator-availability", "/api/v1/autonomous-campaigns",
      "/api/v1/autonomous-campaigns/server-campaign", "/api/v1/autonomous-campaigns/server-campaign/prepare-plan",
      "/api/v1/autonomous-campaigns/server-campaign/plan-approval",
      "/api/v1/autonomous-campaigns/server-campaign/admission-start",
      "/api/v1/autonomous-campaigns/server-campaign/child-replan",
      "/api/v1/autonomous-campaigns/server-campaign/stop",
    ]);
    expect(requests.filter((r) => r.method === "POST").map((r) => r.headers.get("Idempotency-Key")))
      .toEqual(["intent-key", "prepare-key", "approval-key", "admission-key", "child-key", "stop-key"]);
    for (const request of requests) {
      expect(request.credentials).toBe("include");
      expect(request.headers.has("Authorization")).toBe(false);
      expect(request.headers.get("X-CSRF-Token")).toBe(request.method === "POST" ? "csrf-fixture" : null);
    }
    expect(requests[3]?.headers.get("If-Match")).toBe('"server-application-token"');
    expect(requests[4]?.headers.get("If-Match")).toBe('"server-preview-token"');
    expect(requests[5]?.headers.get("If-Match")).toBe('"server-approval-token"');
    expect(requests[7]?.headers.get("If-Match")).toBe('"server-current-token"');
    expect(requests[6]?.headers.get("X-RedAgent-ROE-Version")).toBe("server-roe");
    expect(await requests[3]?.json()).toEqual({ expected_revision: 1 });
    expect(await requests[4]?.json()).toEqual({ preview_id: "server-preview", preview_sha256: "a".repeat(64) });
    expect(await requests[6]?.json()).toEqual({ expected_revision: 7 });
    expect(await requests[7]?.json()).toEqual({ expected_revision: 7, reason: "Operator requests safe containment" });
  });

  it("returns stale mutation conflicts once, without retry or legacy fallback", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ error: {
      code: "application_revision_conflict", message: "Refresh before confirming again.",
    } }), { status: 409, headers: { "Content-Type": "application/json" } }));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => "csrf-fixture" });
    await expect(client.recoverAutonomousCampaign("revoke", "server-campaign", 3, '"current-token"',
      "Operator revokes future authority", "revoke-key")).rejects.toMatchObject({ status: 409 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("console API client", () => {
  it("uses same-origin credentials and adds CSRF only to mutations", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockImplementation(() => Promise.resolve(new Response(
        JSON.stringify({ data: { tenant_id: "tenant-1" } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => "csrf-fixture" });

    await client.getContext();
    await client.createEngagement({
      engagement_id: "engagement-1",
      name: "Synthetic engagement",
      owner_user_id: "user-1",
    });

    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ credentials: "include" });
    const mutation = fetchMock.mock.calls[1]?.[1];
    expect(new Headers(mutation?.headers).get("X-CSRF-Token")).toBe("csrf-fixture");
    expect(new Headers(mutation?.headers).has("Authorization")).toBe(false);
    expect(localStorage).toHaveLength(0);
    expect(sessionStorage).toHaveLength(0);
  });

  it("projects stable API errors without echoing response internals", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: "permission_denied",
            message: "The operation is denied.",
            correlation_id: "correlation-1",
            internal: "must-not-project",
          },
        }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      ),
    );
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    await expect(client.getContext()).rejects.toMatchObject({
      code: "permission_denied",
      correlationId: "correlation-1",
      status: 403,
    });
    await expect(client.getContext()).rejects.not.toHaveProperty("internal");
  });

  it("uses the generated job lifecycle contract with ROE and policy headers", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const body = request.method === "GET"
        ? { data: [], page: { limit: 50, offset: 0, returned: 0 } }
        : request.url.endsWith("/commands")
          ? { data: jobFixture(), meta: { replayed: false, command_id: "command-1" } }
          : request.url.endsWith("/emergency-stop")
            ? { data: { job_id: "job-1", workflow_id: "workflow-1", state: "stop_requested", containment_complete: false, completion_owner: "compat_101" } }
            : { data: jobFixture(), meta: { replayed: false, audit_id: "audit-1", outbox_id: "outbox-1" } };
      return Promise.resolve(new Response(JSON.stringify(body), {
        status: request.url.endsWith("/emergency-stop") ? 202 : request.method === "POST" ? 201 : 200,
        headers: { "Content-Type": "application/json" },
      }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => "csrf-fixture" });

    await client.listJobs();
    await client.createJob({
      job_id: "job-1",
      engagement_id: "engagement-1",
      roe_version_id: "roe-1",
      request: {
        capability: "synthetic-noop",
        approval_timeout_seconds: 3600,
        max_activity_attempts: 3,
        budget_reference: "budget:compat_096:console",
      },
    });
    await client.commandJob("job-1", "roe-1", {
      command_id: "command-1",
      action: "approve",
      expected_revision: 2,
      reason: "Independent approval for synthetic workflow",
    });
    await client.emergencyStopJob("job-1", "roe-1", "Stop this synthetic workflow immediately");

    const mutations = fetchMock.mock.calls.map(([input]) => input as Request).filter((request) => request.method === "POST");
    expect(new Headers(mutations[0]?.headers).get("X-RedAgent-ROE-Version")).toBe("roe-1");
    expect(new Headers(mutations[1]?.headers).get("X-RedAgent-Policy-Reference")).toBe("console:job-command:1");
    expect(new Headers(mutations[2]?.headers).get("X-RedAgent-Policy-Reference")).toBe("console:job-stop:1");
  });

  it("preserves authoritative page metadata and requests a later engagement page", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      data: [{
        engagement_id: "engagement-3",
        tenant_id: "tenant-1",
        name: "Third synthetic engagement",
        owner_user_id: "operator-1",
        status: "draft",
        version: 1,
      }],
      page: { limit: 2, offset: 2, returned: 1, next_offset: null },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const result = await client.listEngagementsPage(2, 2);

    expect(result.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    expect(result.data[0]?.engagement_id).toBe("engagement-3");
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    const url = new URL((request as Request).url);
    expect(url.searchParams.get("limit")).toBe("2");
    expect(url.searchParams.get("offset")).toBe("2");
  });

  it("preserves authoritative page metadata and requests a later JIT grant page", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      data: [{
        grant_id: "grant-3", requester_user_id: "operator-1", approver_user_id: null,
        role: "operator", permission: "engagement:update", scope_type: "engagement",
        scope_id: "engagement-1", reason: "Bounded access request", approved_at: null,
        expires_at: "2099-07-10T18:00:00Z", revoked_at: null, break_glass: false, version: 1,
      }],
      page: { limit: 2, offset: 2, returned: 1, next_offset: null },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const result = await client.listJitGrantsPage(2, 2);

    expect(result.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    expect(result.data[0]?.grant_id).toBe("grant-3");
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    const url = new URL((request as Request).url);
    expect(url.searchParams.get("limit")).toBe("2");
    expect(url.searchParams.get("offset")).toBe("2");
  });

  it("preserves later policy decision and bundle page metadata", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      const data = path.endsWith("/decisions")
        ? [{
          decision_id: "decision-3", bundle_revision: "r099-v2", input_hash: "a".repeat(64),
          boundary: "api", action: "job.create", subject_id: "operator-1", resource_type: "job",
          resource_id: "job-3", allowed: false, reason_code: "policy_denied", obligations: ["audit"],
          issued_at: "2026-08-25T04:00:00Z", valid_until: "2026-08-25T04:00:30Z",
          correlation_id: "correlation-3",
        }]
        : [{
          revision: "r099-v2", artifact_sha256: "b".repeat(64), artifact_size: 2048,
          author_user_id: "author-1", reviewer_user_id: "reviewer-1", rego_version: 1,
          coverage_basis_points: 10000, signing_key_id: "key-1", status: "accepted",
          created_at: "2026-08-25T03:00:00Z", version: 3,
        }];
      return Promise.resolve(new Response(JSON.stringify({
        data,
        page: { limit: 2, offset: 2, returned: 1, next_offset: null },
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const decisions = await client.listPolicyDecisionsPage(2, 2);
    const bundles = await client.listPolicyBundlesPage(2, 2);

    expect(decisions.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    expect(decisions.data[0]?.decision_id).toBe("decision-3");
    expect(bundles.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    expect(bundles.data[0]?.revision).toBe("r099-v2");
    for (const [input] of fetchMock.mock.calls) {
      const url = new URL((input as Request).url);
      expect(url.searchParams.get("limit")).toBe("2");
      expect(url.searchParams.get("offset")).toBe("2");
    }
  });

  it("preserves authoritative activity page metadata and requests a later offset", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      data: [{
        event_id: "event-3", actor_user_id: "operator-1", action: "job.created",
        subject_type: "job", subject_id: "job-3", occurred_at: "2026-08-25T04:00:00Z",
        correlation_id: "correlation-3",
      }],
      page: { limit: 2, offset: 2, returned: 1, next_offset: null },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const result = await client.listActivityPage(2, 2);

    expect(result.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    expect(result.data[0]?.event_id).toBe("event-3");
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    const url = new URL((request as Request).url);
    expect(url.pathname).toBe("/api/v1/activity");
    expect(url.searchParams.get("limit")).toBe("2");
    expect(url.searchParams.get("offset")).toBe("2");
  });

  it("preserves independent runner list continuations", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input) => {
      const request = input as Request;
      const path = new URL(request.url).pathname;
      const data = path.endsWith("/registrations")
        ? [{ runner_id: "runner-3" }]
        : path.endsWith("/runner-manifests")
          ? [{ manifest_id: "manifest-3" }]
          : [{ execution_id: "execution-3" }];
      return Promise.resolve(new Response(JSON.stringify({
        data, page: { limit: 2, offset: 2, returned: 1, next_offset: null },
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const registrations = await client.listRunnerRegistrationsPage(2, 2);
    const manifests = await client.listRunnerManifestsPage(2, 2);
    const executions = await client.listRunnerExecutionsPage(2, 2);

    expect(registrations.page.next_offset).toBeNull();
    expect(registrations.data[0]?.runner_id).toBe("runner-3");
    expect(manifests.data[0]?.manifest_id).toBe("manifest-3");
    expect(executions.data[0]?.execution_id).toBe("execution-3");
    for (const [input] of fetchMock.mock.calls) {
      const url = new URL((input as Request).url);
      expect(url.searchParams.get("limit")).toBe("2");
      expect(url.searchParams.get("offset")).toBe("2");
    }
  });

  it("preserves independent incident and correlation continuations", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input) => {
      const request = input as Request;
      const path = new URL(request.url).pathname;
      const data = path === "/api/v1/incidents"
        ? [{ incident_id: "incident-3" }]
        : [{ operation_id: "operation-3" }];
      return Promise.resolve(new Response(JSON.stringify({
        data, page: { limit: 2, offset: 2, returned: 1, next_offset: null },
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const incidents = await client.listIncidentsPage(2, 2);
    const correlation = await client.lookupCorrelationPage("correlation-1", 2, 2);

    expect(incidents.data[0]?.incident_id).toBe("incident-3");
    expect(correlation.data[0]?.operation_id).toBe("operation-3");
    for (const [input] of fetchMock.mock.calls) {
      const url = new URL((input as Request).url);
      expect(url.searchParams.get("limit")).toBe("2");
      expect(url.searchParams.get("offset")).toBe("2");
    }
  });

  it("preserves authoritative evidence continuation metadata", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
      data: [{ artifact_id: "artifact-3" }],
      page: { limit: 2, offset: 2, returned: 1, next_offset: null },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const result = await client.listEvidencePage(2, 2);

    expect(result.data[0]?.artifact_id).toBe("artifact-3");
    expect(result.page).toEqual({ limit: 2, offset: 2, returned: 1, next_offset: null });
    const request = fetchMock.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    const url = new URL((request as Request).url);
    expect(url.pathname).toBe("/api/v1/evidence/artifacts");
    expect(url.searchParams.get("limit")).toBe("2");
    expect(url.searchParams.get("offset")).toBe("2");
  });

  it("preserves independent secret reference and lease continuations", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input) => {
      const request = input as Request;
      const path = new URL(request.url).pathname;
      const data = path.endsWith("secret-references")
        ? [{ reference_id: "reference-3" }]
        : [{ lease_id: "lease-3" }];
      return Promise.resolve(new Response(JSON.stringify({
        data, page: { limit: 2, offset: 2, returned: 1, next_offset: null },
      }), { status: 200, headers: { "Content-Type": "application/json" } }));
    });
    const client = createConsoleClient({ fetch: fetchMock, readCsrf: () => null });

    const references = await client.listSecretReferencesPage(2, 2);
    const leases = await client.listSecretLeasesPage(2, 2);

    expect(references.data[0]?.reference_id).toBe("reference-3");
    expect(leases.data[0]?.lease_id).toBe("lease-3");
    for (const [input] of fetchMock.mock.calls) {
      const url = new URL((input as Request).url);
      expect(url.searchParams.get("limit")).toBe("2");
      expect(url.searchParams.get("offset")).toBe("2");
    }
  });
});

function jobFixture() {
  return {
    job_id: "job-1", tenant_id: "tenant-1", engagement_id: "engagement-1", roe_version_id: "roe-1",
    created_by_user_id: "operator-1", campaign_id: null, status: "pending",
    request: { capability: "synthetic-noop", approval_timeout_seconds: 3600, max_activity_attempts: 3, budget_reference: "budget:compat_096:console" },
    policy_reference: "console:job-create:1", workflow_id: "workflow-1", workflow_run_id: "run-1",
    orchestration_state: "awaiting_approval", orchestration_revision: 2, current_gate: "operator_approval",
    failure_code: null, retry_count: 0, dispatch_blocked: true, stop_requested: false, version: 2,
  };
}
