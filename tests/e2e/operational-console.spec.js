import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("engagement creation generates an opaque identity without exposing raw ID input", async ({ page }) => {
  let engagement = null;
  let createRequests = 0;
  let createBody = null;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, {
      data: { subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: [
        "engagement:read", "engagement:create", "target:read", "target:create", "roe:read", "roe:create"
      ] }
    });
    if (path === "/api/v1/engagements" && request.method() === "POST") {
      createRequests += 1;
      const body = request.postDataJSON();
      createBody = body;
      engagement = { ...body, tenant_id: "tenant-1", version: 1 };
      return json(route, { data: engagement, meta: meta() }, 201);
    }
    if (path === "/api/v1/engagements") return json(route, { data: engagement ? [engagement] : [], page: pageMeta(engagement ? 1 : 0) });
    if (path.endsWith("/targets") || path.endsWith("/roe-versions")) return json(route, { data: [], page: pageMeta(0) });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/engagements");
  await expect(page.getByLabel("Engagement ID")).toHaveCount(0);
  await page.getByLabel("Engagement name").fill("compat_128 synthetic engagement");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await expect(page.getByRole("heading", { name: "compat_128 synthetic engagement" })).toBeVisible();
  expect(createRequests).toBe(1);
  expect(createBody).toMatchObject({ name: "compat_128 synthetic engagement", owner_user_id: "operator-1" });
  expect(createBody.engagement_id).toMatch(/^engagement-[0-9a-f]{32}$/);
  await expect(page.getByText("Execution remains disabled until policy-approved")).toBeVisible();
  await expect(page.getByRole("button", { name: /run|scan|execute/i })).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("server-generated engagement identity and stale-version denial remain actionable", async ({ page }) => {
  let mode = "engagement-create";
  let createRequests = 0;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, {
      data: { subject: "approver-1", tenant_id: "tenant-1", roles: ["approver"], permissions: [
        "engagement:read", "engagement:create", "jit:read", "jit:approve"
      ] }
    });
    if (path === "/api/v1/engagements" && request.method() === "POST") {
      createRequests += 1;
      return json(route, { error: { code: "csrf_rejected", message: "Browser request failed CSRF validation.", correlation_id: "csrf-e2e" } }, 403);
    }
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/jit-grants" && request.method() === "GET") return json(route, { data: [{
      grant_id: "grant-e2e", requester_user_id: "approver-1", approver_user_id: null,
      role: "operator", permission: "engagement:update", scope_type: "engagement", scope_id: "engagement-e2e",
      reason: "Synthetic separated request", approved_at: null, expires_at: "2099-07-10T18:00:00Z",
      revoked_at: null, break_glass: false, version: 1
    }, {
      grant_id: "grant-stale", requester_user_id: "operator-1", approver_user_id: null,
      role: "operator", permission: "target:create", scope_type: "engagement", scope_id: "engagement-e2e",
      reason: "Synthetic stale request", approved_at: null, expires_at: "2099-07-10T18:00:00Z",
      revoked_at: null, break_glass: false, version: 1
    }], page: pageMeta(1) });
    if (path.endsWith("/approve")) return json(route, { error: { code: "version_conflict", message: "The resource version is stale.", correlation_id: "stale-e2e" } }, 409);
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/engagements");
  await expect(page.getByLabel("Engagement ID")).toHaveCount(0);
  await page.getByLabel("Engagement name").fill("Rejected synthetic engagement");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await expect(page.getByRole("alert")).toContainText("CSRF");
  await expect(page.getByRole("alert")).toContainText("csrf-e2e");
  expect(createRequests).toBe(1);

  mode = "sod";
  await page.goto("/access");
  await expect(page.getByText("Pending approval").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve grant-e2e" })).toBeDisabled();
  await page.getByRole("button", { name: "Approve grant-stale" }).click();
  await expect(page.getByRole("alert")).toContainText("stale");
  await expect(page.getByRole("alert")).toContainText("stale-e2e");
  expect(mode).toBe("sod");
});

test("expired session and API outage fail closed with retry guidance", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => json(route, {
    error: { code: "security_context_required", message: "Session expired.", correlation_id: "session-e2e" }
  }, 401));
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText("Session expired");
  await expect(page.getByRole("button", { name: "Retry" })).toBeEnabled();
  await expect(page.getByRole("alert")).toContainText("session-e2e");
  await expect(page.getByLabel("Tenant ID")).toBeVisible();
});

test("the deleted lifecycle diagnostics route renders the accepted 404 at 320px", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: { subject: "reviewer-1", tenant_id: "tenant-1", roles: ["reviewer"], permissions: ["engagement:read"] } });
    return json(route, { data: [], page: pageMeta(0) });
  });
  await page.goto("/states");
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await expect(page.getByLabel("Breadcrumb").getByText("Unknown route", { exact: true })).toBeVisible();
  await expect(page.getByText("Approval required", { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("durable job approval and emergency stop never claim containment completion", async ({ page }) => {
  let job = durableJob();
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "approver-1", tenant_id: "tenant-1", roles: ["approver"],
      permissions: ["engagement:read", "job:read", "job:approve", "job:update", "job:stop"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/jobs" && request.method() === "GET") return json(route, { data: [job], page: pageMeta(1) });
    if (path === "/api/v1/containment-controls" && request.method() === "GET") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/quotas/status") return json(route, { data: [] });
    if (path.endsWith("/commands")) {
      job = { ...job, orchestration_state: "running", current_gate: "synthetic_activity", orchestration_revision: 3, version: 3 };
      return json(route, { data: job, meta: { replayed: false, command_id: "command-e2e" } });
    }
    if (path.endsWith("/emergency-stop")) return json(route, { data: {
      job_id: job.job_id, workflow_id: job.workflow_id, state: "stop_requested",
      stop_id: "stop-e2e", control_id: "control-e2e",
      containment_complete: false, completion_owner: "compat_101",
    } }, 202);
    if (path.endsWith("/containment")) return json(route, { data: {
      job_id: job.job_id, stop_id: "stop-e2e", control_id: "control-e2e",
      control_state: "active", requested_at: "2026-07-10T19:00:00Z",
      ack_deadline: "2026-07-10T19:00:10Z", action_state: "running", outcome: null,
      containment_complete: false,
      phases: [{ phase: "dispatch_block", state: "verified", reason_code: "dispatch_block_verified", duration_ms: 2, occurred_at: "2026-07-10T19:00:01Z" }],
      residual_risk_codes: [], open_incident_ids: [],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/jobs");
  await expect(page.getByText("workflow-e2e")).toBeVisible();
  await expect(page.getByText("Revision 2 · Record version 2")).toBeVisible();
  await page.getByRole("button", { name: "Approve job-e2e" }).click();
  await expect(page.getByText("synthetic_activity")).toBeVisible();
  await page.getByRole("button", { name: "Emergency stop job-e2e" }).click();
  await expect(page.getByText(/phase receipts now determine containment/i)).toBeVisible();
  await expect(page.getByText("Containment unresolved")).toBeVisible();
  await expect(page.getByText("dispatch_block", { exact: true })).toBeVisible();
  await expect(page.getByText(/contained|containment complete/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("containment hierarchy requires approval and exposes hard quota metadata without runtime handles", async ({ page }) => {
  let requestBody = null;
  let control = {
    control_id: "control-e2e", stop_id: "stop-e2e", scope_kind: "campaign", scope_id: "campaign-e2e",
    control_mode: "emergency_stop", request_hash: "a".repeat(64),
    initiated_by_user_id: "operator-e2e", approved_by_user_id: null,
    control_state: "pending_approval", requested_at: "2026-07-10T19:00:00Z",
    activated_at: null, ack_deadline: "2026-07-10T19:00:10Z", recovered_at: null, version: 1,
  };
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "approver-e2e", tenant_id: "tenant-e2e", roles: ["approver", "reviewer"],
      permissions: ["engagement:read", "job:read", "job:stop", "job:approve", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/jobs") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/containment-controls" && request.method() === "GET") {
      return json(route, { data: [control], page: pageMeta(1) });
    }
    if (path === "/api/v1/containment-controls" && request.method() === "POST") {
      const body = request.postDataJSON();
      requestBody = body;
      control = {
        ...control, control_id: "control-global-e2e", stop_id: body.stop_id,
        scope_kind: "global", scope_id: null, initiated_by_user_id: "approver-e2e",
        approved_by_user_id: null, control_state: "pending_approval", activated_at: null, version: 1,
      };
      return json(route, { data: control }, 202);
    }
    if (path.endsWith("/approve")) {
      control = { ...control, approved_by_user_id: "approver-e2e", control_state: "active", activated_at: "2026-07-10T19:00:02Z", version: 2 };
      return json(route, { data: control });
    }
    if (path === "/api/v1/quotas/status") return json(route, { data: [{
      policy_record_id: "quota-record-e2e", policy_id: "quota-e2e", revision: 1,
      dimension: "operations", extension_name: null, scope_kind: "campaign", scope_id: "campaign-e2e",
      hard_limit: 10, reserved: 2, consumed: 3, remaining: 5,
      window_start: "2026-07-10T19:00:00Z", window_end: "2026-07-10T20:00:00Z",
    }] });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/jobs");
  const panel = page.locator("section").filter({ has: page.getByRole("heading", { name: "Containment controls and quotas" }) });
  await expect(panel.locator("strong").filter({ hasText: "campaign:campaign-e2e" })).toBeVisible();
  await expect(page.getByText(/5 remaining of 10/)).toBeVisible();
  await page.getByRole("button", { name: "Approve control" }).click();
  await expect(page.getByText(/activated by independent approval/i)).toBeVisible();
  await expect(panel.getByText("active", { exact: true })).toBeVisible();
  await page.locator('select[name="scope_kind"]').selectOption("global");
  await expect(page.locator('select[name="scope_binding"]')).toHaveCount(0);
  await page.locator('textarea[name="reason"]').fill("Synthetic global containment request");
  await page.getByRole("button", { name: "Request containment" }).click();
  await expect(page.getByText(/control-global-e2e is pending_approval/i)).toBeVisible();
  expect(requestBody).toMatchObject({ scope_kind: "global", scope_id: null, expected_version: 1,
    reason: "Synthetic global containment request" });
  expect(requestBody.stop_id).toMatch(/^stop-[0-9a-f]{32}$/);
  await expect(page.getByText("command", { exact: true })).toHaveCount(0);
  await expect(page.getByText("container_id", { exact: true })).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("persistent evidence exposes custody metadata, exact verification, and version-specific hold without bytes", async ({ page }) => {
  let artifact = evidenceArtifact();
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "custodian-1", tenant_id: "tenant-1", roles: ["custodian"],
      permissions: ["engagement:read", "evidence:read", "evidence:verify", "evidence:derive", "evidence:retention-admin"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/evidence/artifacts") return json(route, { data: [artifact], page: pageMeta(1) });
    if (path.endsWith("/verify")) return json(route, { data: {
      artifact_id: artifact.artifact_id, object_version_id: artifact.object_version_id,
      verified: true, reason: "verified",
    } });
    if (path.endsWith("/legal-hold")) {
      artifact = { ...artifact, legal_hold: true, version: 2 };
      return json(route, { data: artifact });
    }
    if (path === `/api/v1/evidence/artifacts/${artifact.artifact_id}`) return json(route, { data: {
      ...artifact, source_artifact_id: null, transform_name: null, transform_version: null,
      transform_config_hash: null, custody_event_count: artifact.legal_hold ? 5 : 4,
      verification_count: 1, last_verified: true, last_verified_at: "2026-07-10T20:00:00Z",
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/evidence");
  await page.getByRole("button", { name: /artifact-e2e/ }).click();
  await expect(page.getByText(artifact.content_sha256)).toBeVisible();
  await expect(page.getByText("4 events · 1 checks · Passing")).toBeVisible();
  await expect(page.getByText("raw-secret-evidence-bytes")).toHaveCount(0);
  await page.getByRole("button", { name: "Verify exact version" }).click();
  await expect(page.getByText(/version-e2e verified/i)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Place legal hold" }).click();
  await expect(page.getByText("ON", { exact: true })).toBeVisible();
  await expect(page.getByText(/legal hold placed on exact object version version-e2e/i)).toBeVisible();
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("credential lease console exposes metadata and exact revoke without credential material", async ({ page }) => {
  let lease = secretLease();
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "secret:read", "secret:revoke"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/secret-references") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/secret-leases" && request.method() === "GET") return json(route, { data: [lease], page: pageMeta(1) });
    if (path === `/api/v1/secret-leases/${lease.lease_id}/revoke`) {
      lease = { ...lease, lease_state: "revoked", revoked_at: "2026-07-10T12:01:00Z", renewable: false, version: 2 };
      return json(route, { data: lease, meta: { replayed: false } });
    }
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/secrets");
  await expect(page.getByText(lease.lease_id)).toBeVisible();
  await expect(page.getByText("R098-SYNTHETIC-MATERIAL")).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Revoke exact lease" }).click();
  await expect(page.getByText(/exact lease lease-e2e is revoked/i)).toBeVisible();
  await expect(page.getByText("revoked", { exact: true })).toBeVisible();
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("policy console shows convergence and permits only fixed simulation inputs", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "policy:read", "policy:simulate"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/policy/status") return json(route, { data: {
      required_revision: "r099-v1", previous_revision: "r099-v0", promotion_state: "promoted",
      required_agents: ["api-pdp", "workflow-pdp"], acknowledged_agents: ["api-pdp", "workflow-pdp"], converged: true,
    } });
    if (path === "/api/v1/policy/bundles") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/policy/decisions") return json(route, { data: [{
      decision_id: "decision-e2e", bundle_revision: "r099-v1", input_hash: "a".repeat(64),
      boundary: "workflow", action: "job.command", subject_id: "operator-1",
      resource_type: "job", resource_id: "job-e2e", allowed: true,
      reason_code: "boundary_authorized", obligations: ["audit"],
      issued_at: "2026-07-10T14:00:00Z", valid_until: "2026-07-10T14:00:30Z",
      correlation_id: "policy-e2e",
    }], page: pageMeta(1) });
    if (path === "/api/v1/policy/simulations") return json(route, { data: {
      fixture: "api-job-create", decision_id: "simulation-e2e", receipt_id: "receipt-e2e",
      bundle_revision: "r099-v1", input_hash: "b".repeat(64), obligations: ["audit"],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/policy");
  await expect(page.getByRole("heading", { name: "Policy decisions" })).toBeVisible();
  await expect(page.getByText("Converged", { exact: true })).toBeVisible();
  await expect(page.getByText("job.command", { exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/rego|policy text|bundle url|decision input/i)).toHaveCount(0);
  await page.getByRole("button", { name: "Run fixed fixture" }).click();
  await expect(page.getByRole("main").getByRole("status")).toContainText("receipt-e2e");
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("runner console exposes readiness, evidence lineage, cleanup, and failures without control material", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "runner:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/runners/status") return json(route, { data: {
      registration_count: 1, active_registration_count: 1, certified_capability_count: 1,
      open_manifest_count: 0, active_lease_count: 0, succeeded_execution_count: 1,
      failed_execution_count: 0, last_heartbeat_at: "2026-07-10T17:00:00Z",
      policy_revisions: ["r099-v1"], capability_revisions: ["synthetic-conformance:1"],
      image_digests: [`sha256:${"a".repeat(64)}`],
    } });
    if (path === "/api/v1/runners/registrations") return json(route, { data: [{
      runner_id: "runner-e2e", runner_class_id: "synthetic-standard", environment: "local-conformance",
      network_plane: "isolated-none", required_policy_revision: "r099-v1", generation: 2,
      registration_state: "active", registered_at: "2026-07-10T16:00:00Z",
      expires_at: "2026-07-10T18:00:00Z", revoked_at: null,
      last_seen_at: "2026-07-10T17:00:00Z", version: 1,
    }], page: pageMeta(1) });
    if (path === "/api/v1/runner-manifests") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/runner-executions") return json(route, { data: [{
      execution_id: "execution-e2e", job_id: "job-e2e", manifest_sha256: "b".repeat(64),
      evidence_artifact_id: "evidence-e2e", outcome: "succeeded", final_phase: "cleanup",
      cleanup_completed: true, residual_risk: null, completed_at: "2026-07-10T17:01:00Z", version: 1,
    }], page: pageMeta(1) });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/runners");
  await expect(page.getByRole("heading", { name: "Runner fleet" })).toBeVisible();
  await expect(page.getByText("Ready", { exact: true })).toBeVisible();
  await expect(page.getByText("execution-e2e")).toBeVisible();
  await expect(page.getByText(/evidence-e2e/)).toBeVisible();
  await expect(page.getByText(/cleanup verified/i)).toBeVisible();
  await expect(page.getByText(/certificate-fingerprint-canary|signature-canary|lease-token-canary/i)).toHaveCount(0);
  await expect(page.getByRole("button", { name: /execute|shell|command/i })).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("observability console shows SLO, correlation, and confirmed incident response without sensitive content", async ({ page }) => {
  let state = "open";
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/observability/dashboard") return json(route, { data: {
      export_state_counts: { pending: 1 }, incident_state_counts: { [state]: 1 },
      slo_state_counts: { breaching: 1 }, open_alerts: 1, unreplayed_dead_letters: 0,
    } });
    if (path === "/api/v1/incidents" && request.method() === "GET") {
      return json(route, { data: [incidentFixture(state)], page: pageMeta(1) });
    }
    if (path === "/api/v1/incidents/runbooks") return json(route, { data: [{
      runbook_id: "telemetry_outage", owner: "security-operations",
      triage: ["Confirm authoritative audit."], containment: ["Apply reviewed containment."],
      evidence: ["Preserve references."], recovery: ["Verify prerequisites."],
      review: ["Record independent review."],
    }] });
    if (path === "/api/v1/observability/correlations/correlation-e2e") return json(route, { data: [{
      operation_id: "export-e2e", event_id: "event-e2e", correlation_id: "correlation-e2e",
      signal_kind: "event", priority: "security", export_state: "pending",
      reason_code: null, occurred_at: "2026-07-11T07:00:00Z",
    }], page: pageMeta(1) });
    if (path === "/api/v1/incidents/incident-e2e/timeline") return json(route, { data: [{
      event_id: "timeline-e2e", event_type: state === "open" ? "opened" : "acknowledge",
      actor_user_id: "operator-1", reason_code: "incident_acknowledge",
      occurred_at: "2026-07-11T07:00:00Z",
    }] });
    if (path === "/api/v1/incidents/incident-e2e/actions" && request.method() === "POST") {
      state = "acknowledged";
      return json(route, { data: incidentFixture(state) });
    }
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/observability");
  await expect(page.getByRole("heading", { name: "Observability and SLOs" })).toBeVisible();
  await expect(page.getByText("breaching: 1")).toBeVisible();
  await expect(page.getByText("telemetry_outage")).toBeVisible();
  await page.getByLabel("Correlation ID").fill("correlation-e2e");
  await page.getByRole("button", { name: "Look up correlation" }).click();
  await expect(page.getByText("export-e2e")).toBeVisible();
  await page.getByRole("button", { name: "Timeline" }).click();
  await expect(page.getByText("opened · operator-1")).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expect(page.getByText("high · acknowledged")).toBeVisible();
  await expect(page.getByText(/bearer-canary|cookie-canary|prompt-canary|tool-result-canary/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("safe lab shows attested golden outcomes, verified teardown, and no arbitrary target surface", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "audit:read", "job:read", "job:stop"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/lab/dashboard") return json(route, { data: {
      bundle: {
        bundle_id: "r103-synthetic-lab", bundle_revision: 1,
        fixture_digest: `sha256:${"a".repeat(64)}`, network_id: "redagent-r103-lab",
        bundle_state: "active", expires_at: "2026-07-11T16:00:00Z",
      },
      scenarios: [{
        run_id: "run-e2e", scenario_id: "authorize_deny", scenario_state: "succeeded",
        reason_code: "scenario_succeeded", current_step: 2, version: 3,
      }, {
        run_id: "run-e2e", scenario_id: "verified_teardown", scenario_state: "succeeded",
        reason_code: "scenario_succeeded", current_step: 2, version: 3,
      }],
      measurements: [{
        measurement_id: "contact-e2e", metric_id: "unsafe-target-contact-count", comparison: "lte",
        observed_millionths: 0, threshold_millionths: 0, unit: "requests",
        sample_count: 1, result_state: "passed",
      }],
      latest_teardown: {
        receipt_id: "teardown-e2e", residual_resource_count: 0, teardown_complete: true,
        inventory_sha256: "b".repeat(64), completed_at: "2026-07-11T15:00:00Z",
      },
      emergency_stop_path: "/jobs/{job_id}/emergency-stop", arbitrary_target_input_allowed: false,
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/lab");
  await expect(page.getByRole("heading", { name: "Safe local lab" })).toBeVisible();
  await expect(page.getByText(/Arbitrary target input is disabled/)).toBeVisible();
  await expect(page.getByText("authorize_deny")).toBeVisible();
  await expect(page.getByText("verified_teardown")).toBeVisible();
  await expect(page.getByText(/Teardown verified: 0 residual resources/)).toBeVisible();
  await expect(page.getByRole("textbox")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Emergency stop controls" })).toHaveAttribute("href", "/jobs");
  await expect(page.getByText(/example\.com|public target|bearer-canary|cookie-canary/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("controlled ZAP console exposes certified profiles and native-stop workflow without scanner overrides", async ({ page }) => {
  let run = {
    run_id: "run-r104-e2e", plan_id: "plan-r104-e2e", job_id: "job-r104-e2e",
    runner_id: "runner-r104-e2e", run_state: "running", current_step: 2,
    progress_percent: 40, passive_queue_size: 1, reason_code: "zap_run_active", version: 1,
  };
  const profile = {
    profile_id: "zap-passive-v1", profile_revision: 1, image_version: "2.17.0",
    image_digest: `sha256:${"a".repeat(64)}`, addon_inventory_sha256: "b".repeat(64),
    profile_sha256: "c".repeat(64), risk_class: "low_risk",
    passive_rule_ids: ["10021"], active_rule_ids: [], request_limit: 60,
    request_rate_per_second: 3, concurrency_limit: 2, timeout_seconds: 180,
    response_bytes_limit: 15728640, profile_state: "certified",
  };
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/zap/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/zap/runs/${run.run_id}/cancel`) {
      run = { ...run, run_state: "cancel_requested", reason_code: "operator_cancel_requested", version: 2 };
      return json(route, { data: run });
    }
    if (path === "/api/v1/zap/dashboard") return json(route, { data: {
      profiles: [profile], plans: [{
        plan_id: "plan-r104-e2e", profile_id: profile.profile_id,
        target_id: "r104-owned-web-fixture", policy_decision_id: "decision-r104-e2e",
        roe_version_id: "roe-r104-e2e", plan_sha256: "d".repeat(64),
        scope_sha256: "e".repeat(64), expires_at: "2026-07-11T16:00:00Z", version: 1,
      }], runs: [run], cleanups: [{
        receipt_id: "cleanup-r104-e2e", residual_resource_count: 0,
        cleanup_complete: true, completed_at: "2026-07-11T15:00:00Z",
      }],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/zap");
  await expect(page.getByRole("heading", { name: "Controlled ZAP runtime" })).toBeVisible();
  await expect(page.getByText(/URLs, YAML, scripts, add-ons, flags, and native API calls are not accepted/)).toBeVisible();
  await expect(page.getByText("zap-passive-v1").first()).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/target url|scanner flags|yaml|script|add-on|native api/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Cancel and contain" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText(/Cleanup verified: 0 residual resources/)).toBeVisible();
  await expect(page.getByText(/example\.com|public target|api key|authorization bearer/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("trusted Nuclei console exposes signed bundle findings and native-stop workflow without template passthrough", async ({ page }) => {
  let run = {
    run_id: "run-r105-e2e", plan_id: "plan-r105-e2e", job_id: "job-r105-e2e",
    runner_id: "runner-r105-e2e", run_state: "running", progress_percent: 50,
    request_count: 1, response_bytes: 700, result_count: 1,
    reason_code: "nuclei_run_active", version: 1,
  };
  const profile = {
    profile_id: "nuclei-http-header-v1", profile_revision: 1, engine_version: "3.8.0",
    image_digest: `sha256:${"a".repeat(64)}`, bundle_id: "r105-http-header-bundle",
    bundle_revision: 1, profile_sha256: "b".repeat(64), risk_class: "low",
    allowed_protocols: ["http"], allowed_methods: ["GET"],
    allowed_paths: ["/nuclei/missing-header"], request_limit: 20,
    request_rate_per_second: 2, concurrency_limit: 1, timeout_seconds: 60,
    response_bytes_limit: 2097152, result_limit: 10, profile_state: "certified-local-lab",
  };
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/nuclei/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/nuclei/runs/${run.run_id}/cancel`) {
      run = { ...run, run_state: "cancel_requested", reason_code: "operator_cancel_requested", version: 2 };
      return json(route, { data: run });
    }
    if (path === "/api/v1/nuclei/dashboard") return json(route, { data: {
      profiles: [profile], plans: [{
        plan_id: "plan-r105-e2e", profile_id: profile.profile_id,
        bundle_id: "r105-http-header-bundle", target_id: "r105-owned-http-fixture",
        policy_decision_id: "decision-r105-e2e", roe_version_id: "roe-r105-e2e",
        plan_sha256: "d".repeat(64), scope_sha256: "e".repeat(64),
        expires_at: "2026-07-11T16:00:00Z", version: 1,
      }], runs: [run], results: [{
        result_id: "result-r105-e2e", template_id: "redagent-r105-missing-header",
        matcher_name: "missing-security-header", severity: "low",
        affected_resource: "/nuclei/missing-header", fingerprint: "f".repeat(64),
        evidence_instance_id: "evidence-r105-e2e",
      }], cleanups: [{ receipt_id: "cleanup-r105-e2e", residual_resource_count: 0,
        cleanup_complete: true, completed_at: "2026-07-11T15:00:00Z" }],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/nuclei");
  await expect(page.getByRole("heading", { name: "Trusted Nuclei runtime" })).toBeVisible();
  await expect(page.getByText(/Template text, URLs, workflows, payloads, protocols, flags/)).toBeVisible();
  await expect(page.getByText("nuclei-http-header-v1").first()).toBeVisible();
  await expect(page.getByText("redagent-r105-missing-header")).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/template|url|workflow|payload|protocol|flags|environment|oast/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Cancel and contain" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText(/Cleanup verified: 0 residual resources/)).toBeVisible();
  await expect(page.getByText(/example\.com|public target|api key|authorization bearer/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("API authorization console exposes fixed matrix findings and cleanup without transport passthrough", async ({ page }) => {
  let run = {
    run_id: "run-r106-e2e", plan_id: "plan-r106-e2e", job_id: "job-r106-e2e",
    runner_id: "runner-r106-e2e", run_state: "running", progress_percent: 60,
    request_count: 14, response_bytes: 4096, finding_count: 1,
    reason_code: "api_diff_run_active", version: 1,
  };
  const profile = {
    profile_id: "openapi-authorization-differential-v1", profile_revision: 1,
    engine_version: "4.22.4", artifact_digest: `sha256:${"a".repeat(64)}`,
    bundle_id: "r106-owned-api-differential", spec_sha256: "b".repeat(64),
    operation_ids: ["createDocument", "getDocument", "getProfile", "getAudit", "deleteDocument", "transferDocument"],
    identity_states: ["OWNER", "PEER", "TENANT_ADMIN", "OTHER_TENANT", "EXPIRED", "REVOKED"],
    max_requests: 64, request_rate_per_second: 2, concurrency_limit: 1,
    timeout_seconds: 60, total_data_bytes: 2097152,
    profile_state: "certified-local-lab", production_qualified: false,
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/api-differential/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/api-differential/runs/${run.run_id}/cancel`) {
      run = { ...run, run_state: "cancel_requested", reason_code: "operator_cancel_requested", version: 2 };
      return json(route, { data: run });
    }
    if (path === "/api/v1/api-differential/dashboard") return json(route, { data: {
      profiles: [profile], plans: [{
        plan_id: "plan-r106-e2e", profile_id: profile.profile_id,
        target_id: "r106-owned-api-fixture", policy_decision_id: "decision-r106-e2e",
        roe_version_id: "roe-r106-e2e", spec_sha256: "b".repeat(64),
        plan_sha256: "c".repeat(64), seed: 10620260711, case_count: 19,
        expires_at: "2026-07-11T16:00:00Z", version: 1,
      }], runs: [run], observations: [{
        observation_id: "observation-r106-e2e", case_id: "case-bola", finding_type: "bola",
        violated: true, evidence_instance_id: "evidence-r106-e2e", reason_code: "object_access_exposed",
      }], replays: [{
        replay_id: "replay-r106-e2e", case_id: "case-bola", minimized_replay_sha256: "d".repeat(64),
        semantic_predicate: "owner_only", replay_state: "accepted",
      }], cleanups: [{
        receipt_id: "cleanup-r106-e2e", compensation_complete: true, lease_revoked: true,
        residual_resource_count: 0, completed_at: "2026-07-11T15:00:00Z",
      }],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/api-differential");
  await expect(page.getByRole("heading", { name: "API authorization differential" })).toBeVisible();
  await expect(page.getByText(/URLs, specifications, requests, headers, cookies, credentials/)).toBeVisible();
  await expect(page.getByText(profile.profile_id).first()).toBeVisible();
  await expect(page.getByText(/OWNER, PEER, TENANT_ADMIN/)).toBeVisible();
  await expect(page.getByText("bola", { exact: true })).toBeVisible();
  await expect(page.getByText("owner_only")).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/target url|specification|request|header|cookie|credential|body|callback|plugin|flag/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Cancel and contain" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText(/Cleanup verified: 0 residual resources; lease revoked/)).toBeVisible();
  await expect(page.getByText(/example\.com|public target|api key|authorization bearer/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("network assessment console exposes only promoted local tuples and gateway-first cancellation", async ({ page }) => {
  let run = {
    run_id: "run-r107-e2e", plan_id: "plan-r107-e2e", job_id: "job-r107-e2e",
    runner_id: "runner-r107-e2e", run_state: "running", completed_tuples: 1,
    total_tuples: 2, partial: true, reason_code: "network_run_partial", version: 1,
  };
  const profile = {
    profile_id: "tcp-connect-discovery-v1", profile_revision: 1,
    engine_id: "redagent-stdlib-tcp-connect", category: "low-risk-connect-discovery",
    max_targets: 8, max_ports_per_target: 16, max_attempts: 64,
    rate_per_second: 4, concurrency_limit: 4, max_retries: 0,
    connect_timeout_seconds: 1, run_timeout_seconds: 30,
    banner_bytes: 256, output_bytes: 65536,
    profile_state: "certified-local-lab", production_qualified: false,
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/network-assessment/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/network-assessment/runs/${run.run_id}/cancel`) {
      run = { ...run, run_state: "cancel_requested", reason_code: "network_gateway_block_required", version: 2 };
      return json(route, { data: run });
    }
    if (path === "/api/v1/network-assessment/dashboard") return json(route, { data: {
      profiles: [profile], plans: [], runs: [run], observations: [{
        observation_id: "observation-r107-e2e", tuple_id: "tuple-r107-e2e",
        connection_state: "open", latency_bucket: "lt_10ms", service_class: "http",
        sample_sha256: "a".repeat(64), uncertainty: "low",
        redaction_state: "redacted-hash-only", evidence_instance_id: null,
      }], cleanups: [{
        receipt_id: "cleanup-r107-e2e", residual_resource_count: 0,
        completed_at: "2026-07-11T16:00:00Z",
      }],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/network-assessment");
  await expect(page.getByRole("heading", { name: "Network assessment" })).toBeVisible();
  await expect(page.getByText(/Only literal IP\/port tuples from the attested local fixture/)).toBeVisible();
  await expect(page.getByText(/Partial coverage/)).toBeVisible();
  await expect(page.getByText(/low uncertainty/)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/hostname|cidr|port range|flags|command|script|proxy|resolver/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Block gateway and cancel" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText("network_gateway_block_required", { exact: true })).toBeVisible();
  await expect(page.getByText(/Cleanup verified: 0 residual resources/)).toBeVisible();
  await expect(page.getByText(/example\.com|public target|api key|authorization bearer/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("cloud posture console exposes exact identity, partial evidence, lease-first cancel, and cleanup", async ({ page }) => {
  let run = {
    run_id: "run-r108-e2e", plan_id: "plan-r108-e2e", job_id: "job-r108-e2e",
    runner_id: "runner-r108-e2e", run_state: "collecting", complete: false,
    partial_reasons: ["iam_throttled"], snapshot_sha256: "a".repeat(64), version: 1,
  };
  const profile = {
    profile_id: "r108-aws-emulator-v1", provider: "aws", expected_identity: "aws:123456789012",
    operations: [{ operation_id: "aws-iam-list-roles-v1", action: "iam:ListRoles", resource_scope: "arn:aws:iam::123456789012:role/*", data_class: "security_configuration", mutation: false }],
    max_api_calls: 8, max_pages: 6, max_resources: 32, max_response_bytes: 32768,
    profile_state: "certified-local-lab", emulator_only: true, production_qualified: false,
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"],
      permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"],
    } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/cloud-posture/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/cloud-posture/runs/${run.run_id}/cancel`) {
      run = { ...run, run_state: "cancel_requested", version: 2 };
      return json(route, { data: run });
    }
    if (path === "/api/v1/cloud-posture/dashboard") return json(route, { data: {
      profiles: [profile], plans: [], runs: [run], results: [{
        result_id: "result-r108-e2e", control_pack_id: "r108-cloud-baseline-v1",
        check_id: "R108-AWS-001", resource_id: "role/admin", passed: false,
        severity: "high", evidence_instance_id: "evidence-r108-e2e",
      }], cleanups: [{
        receipt_id: "cleanup-r108-e2e", lease_revoked: true, new_requests_blocked: true,
        residual_resource_count: 0, completed_at: "2026-07-11T16:00:00Z",
      }],
    } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });

  await page.goto("/cloud-posture");
  await expect(page.getByRole("heading", { name: "Cloud and Kubernetes posture" })).toBeVisible();
  await expect(page.getByText(/Only repo-owned loopback provider emulators/)).toBeVisible();
  await expect(page.getByText("aws:123456789012", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("iam_throttled", { exact: true })).toBeVisible();
  await expect(page.getByText(/evidence-r108-e2e/)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/endpoint|token|password|kubeconfig|path|flags|command|module|registry/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Revoke lease and cancel" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText(/Cleanup verified: lease revoked; 0 residual resources/)).toBeVisible();
  await expect(page.getByText(/example\.com|authorization bearer|private key/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("identity posture console isolates exact permissions, exceptions, graphs, and lease-first cancel", async ({ page }) => {
  let run = { run_id: "run-r109-e2e", plan_id: "plan-r109-e2e", job_id: "job-r109-e2e", runner_id: "runner-r109-e2e",
    run_state: "collecting", complete: false, partial_reasons: ["directory_throttled"], snapshot_sha256: "a".repeat(64), version: 1 };
  const profile = { profile_id: "r109-okta-emulator-v1", provider: "okta", provider_tenant_id: "org-r109-okta", audience: "okta-api-r109", consent_mode: "application",
    operations: [{ operation_id: "okta-groups-list-v1", method: "GET", api_version: "v1", permission_scope: "okta.groups.read", effective_role_permission: "okta.groups.read", selected_fields: ["id", "type", "created"], data_class: "directory_metadata", graph_eligible: true }],
    retention_days: 7, profile_state: "certified-local-lab", emulator_only: true, production_qualified: false };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: { subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"] } });
    if (path === "/api/v1/engagements") return json(route, { data: [], page: pageMeta(0) });
    if (path === "/api/v1/identity-posture/profiles") return json(route, { data: [profile] });
    if (path === `/api/v1/identity-posture/runs/${run.run_id}/cancel`) { run = { ...run, run_state: "cancel_requested", version: 2 }; return json(route, { data: run }); }
    if (path === "/api/v1/identity-posture/dashboard") return json(route, { data: { profiles: [profile], plans: [], runs: [run], evaluations: [],
      exceptions: [{ exception_id: "exception-r109-e2e" }], graphs: [{ approval_id: "graph-r109-e2e", restricted_role: "identity-graph-reviewer" }], cleanups: [{ receipt_id: "cleanup-r109-e2e" }] } });
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });
  await page.goto("/identity-posture");
  await expect(page.getByRole("heading", { name: "Identity and SaaS posture" })).toBeVisible();
  await expect(page.getByText(/Only repo-owned loopback Microsoft 365/)).toBeVisible();
  await expect(page.getByText(/org-r109-okta · okta-api-r109/)).toBeVisible();
  await expect(page.getByText(/okta.groups.read \/ okta.groups.read/)).toBeVisible();
  await expect(page.getByText("directory_throttled", { exact: true })).toBeVisible();
  await expect(page.getByText(/1 exception annotations · 1 separately approved restricted graphs · 1 cleanup receipts/)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/endpoint|token|password|query|scope|graph export|command/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Revoke lease and cancel" }).click();
  await expect(page.getByText("cancel_requested", { exact: true })).toBeVisible();
  await expect(page.getByText(/authorization bearer|private key|refresh token/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("artifact posture console proves zero execution, redaction, partial truth, and lease-first cancel", async ({ page }) => {
  let run = {run_id: "run-r110-e2e", plan_id: "plan-r110-e2e", job_id: "job-r110-e2e", runner_id: "runner-r110-e2e", run_state: "checking", complete: false, partial_reasons: ["component-identity-incomplete"], result_sha256: "a".repeat(64), untrusted_execution_count: 0, version: 1};
  const profile = {profile_id: "r110-repository-snapshot-v1", artifact_kind: "repository_snapshot", stages: ["manifest_validate", "sbom", "license", "credential_pattern", "structural", "ci_workflow"], max_files: 64, max_bytes: 262144, max_depth: 8, max_expansion_ratio: 20, profile_state: "certified-local-lab", zero_execution: true, production_qualified: false};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path === "/api/v1/artifact-posture/profiles") return json(route, {data: [profile]});
    if (path === `/api/v1/artifact-posture/runs/${run.run_id}/cancel`) { run = {...run, run_state: "cancel_requested", version: 2}; return json(route, {data: run}); }
    if (path === "/api/v1/artifact-posture/dashboard") return json(route, {data: {profiles: [profile], plans: [], runs: [run], components: [{component_id: "component-r110"}], vulnerabilities: [{advisory_id: "R110-ADVISORY-1"}], credential_findings: [{fingerprint: "b".repeat(64), redacted_fragment: "[REDACTED]"}], static_findings: [{rule_id: "ci-dangerous-checkout"}], mobile: [{control_id: "mobile-debuggable"}], cleanups: [{receipt_id: "cleanup-r110"}]}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/artifact-posture");
  await expect(page.getByRole("heading", {name: "Repository, CI, and mobile posture"})).toBeVisible();
  await expect(page.getByText(/Only repo-owned canonical data fixtures/)).toBeVisible();
  await expect(page.getByText(/repository_snapshot · zero execution/)).toBeVisible();
  await expect(page.getByText("component-identity-incomplete", {exact: true})).toBeVisible();
  await expect(page.getByText("Untrusted executions", {exact: true})).toBeVisible();
  await expect(page.getByText(/1 fully redacted credential findings/)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/repository url|archive path|content|token|command|scanner|rule|workflow|mobile binary/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Block reads and cancel"}).click();
  await expect(page.getByText("cancel_requested", {exact: true})).toBeVisible();
  await expect(page.getByText(/private key|authorization bearer|qualification-canary-material/i)).toHaveCount(0);
  const violations = await new AxeBuilder({ page }).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("purple lab console requires detection cleanup teardown and provides immediate lease-first kill", async ({ page }) => {
  let run = {run_id: "run-r111-e2e", plan_id: "plan-r111-e2e", job_id: "job-r111-e2e", runner_id: "runner-r111-e2e",
    run_state: "observing", dispatch_blocked: false, detection_observed: false, cleanup_complete: false,
    teardown_verified: false, failure_code: null, version: 1};
  const ability = {ability_id: "r111-file-stage-marker-v1", attack_version: "enterprise-v18", attack_technique_id: "T1074.001",
    phases: ["prepare", "execute", "telemetry", "cleanup", "verify"], detection_strategy_id: "DET-r111-file-create",
    analytic_id: "AN-r111-owned-marker", event_schema: "redagent.r111-owned-file-event-v1", timeout_seconds: 5,
    lab_only: true, network_allowed: false, subprocess_allowed: false, external_content_allowed: false, production_qualified: false};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path === "/api/v1/purple-lab/abilities") return json(route, {data: [ability]});
    if (path === `/api/v1/purple-lab/runs/${run.run_id}/kill`) { run = {...run, run_state: "kill_requested", dispatch_blocked: true, version: 2}; return json(route, {data: run}); }
    if (path === "/api/v1/purple-lab/dashboard") return json(route, {data: {abilities: [ability], labs: [{binding_id: "lab-r111"}], approvals: [{approval_id: "approval-r111"}], plans: [], runs: [run], detections: [{analytic_id: ability.analytic_id}], telemetry: [], cleanups: [], teardowns: [], rehearsals: []}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/purple-lab");
  await expect(page.getByRole("heading", {name: "Lab-only purple-team runtime"})).toBeVisible();
  await expect(page.getByText(/T1074.001 · lab only/)).toBeVisible();
  await expect(page.getByText(/Expected detection: DET-r111-file-create/)).toBeVisible();
  await expect(page.getByText("Expected telemetry observed", {exact: true})).toBeVisible();
  await expect(page.getByText("No", {exact: true})).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/command|payload|target address|path|content|credential|network/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Revoke lease and kill now"}).click();
  await expect(page.getByText("kill_requested", {exact: true})).toBeVisible();
  await expect(page.getByText("Blocked", {exact: true})).toBeVisible();
  await expect(page.getByText(/private key|authorization bearer|caldera command|atomic payload/i)).toHaveCount(0);
  const violations = await new AxeBuilder({page}).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("human simulation console proves sink-only minimization and lease-first stop without recall claims", async ({ page }) => {
  let run = {run_id: "run-r112-e2e", plan_id: "plan-r112-e2e", job_id: "job-r112-e2e", runner_id: "runner-r112-e2e",
    run_state: "sink_delivered", new_delivery_blocked: false, human_delivery_count: 0,
    external_delivery_count: 0, deletion_verified: false, failure_code: null, version: 1};
  const campaign = {campaign_id: "r112-sink-email-canary-v1", purpose: "synthetic-security-awareness-sink-qualification",
    recipient_class: "synthetic-invalid-owned", sink_id: "sink-r112-owned", template_sha256: "a".repeat(64),
    canary_id: "canary-r112-owned-0001", max_deliveries: 1, rate_per_minute: 1, retention_seconds: 300,
    consent_required: true, suppression_required: true, privacy_review_required: true, deletion_required: true,
    human_delivery: false, external_delivery: false, raw_submission_retention: false, production_qualified: false};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "operator-1", tenant_id: "tenant-1", roles: ["operator"], permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path === "/api/v1/human-simulation/campaigns") return json(route, {data: [campaign]});
    if (path === `/api/v1/human-simulation/runs/${run.run_id}/stop`) { run = {...run, run_state: "stop_requested", new_delivery_blocked: true, version: 2}; return json(route, {data: run}); }
    if (path === "/api/v1/human-simulation/dashboard") return json(route, {data: {campaigns: [campaign], rosters: [{}], suppressions: [{}], privacy_reviews: [{}], templates: [{}], approvals: [{}], plans: [], runs: [run], deliveries: [{}], events: [{}], canaries: [{}], stops: [], deletions: [], rehearsals: []}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/human-simulation");
  await expect(page.getByRole("heading", {name: "Controlled human simulation sink"})).toBeVisible();
  await expect(page.getByText(/synthetic-invalid-owned · sink-r112-owned/)).toBeVisible();
  await expect(page.getByText(/Human delivery: no · external delivery: no · raw submission retention: no/)).toBeVisible();
  await expect(page.getByText(/1 exact approvals · 1 sink captures · 1 minimized events · 1 canary correlations/)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/recipient|domain|sender|subject|body|url|attachment|provider|token|password|tracking|command/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Block delivery, revoke lease, and stop"}).click();
  await expect(page.getByText("stop_requested", {exact: true})).toBeVisible();
  await expect(page.getByText("Blocked", {exact: true})).toBeVisible();
  await expect(page.getByText(/recalled|recall succeeded/i)).toHaveCount(0);
  await expect(page.getByText(/private key|authorization bearer|REDAGENT-R112-SYNTHETIC-ONLY/i)).toHaveCount(0);
  const violations = await new AxeBuilder({page}).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("agent kernel binds exact proposal review and cancellation without prompt or direct dispatch", async ({ page }) => {
  const tool = {tool_fqn: "redagent.human-simulation-sink.propose.v1", capability_id: "human-simulation-sink",
    capability_revision: 1, capability_sha256: "a".repeat(64), input_schema_sha256: "b".repeat(64),
    output_schema_sha256: "c".repeat(64), approval_tier: "high", network_class: "none", access_class: "none",
    max_turns: 3, max_tool_calls: 1, max_elapsed_seconds: 30, max_input_tokens: 4000, max_output_tokens: 500,
    max_cost_microunits: 10000, max_result_bytes: 4096,
    unsupported_features: ["arbitrary_command", "plugin_loading", "human_delivery"]};
  let run = {run_id: "run-r113-e2e", campaign_id: "campaign-r113", provider_id: "deterministic-fake",
    registry_sha256: "d".repeat(64), run_state: "awaiting_model", cancel_requested: false, failure_code: null,
    started_at: "2026-07-12T04:00:00Z", expires_at: "2099-07-12T04:05:00Z", completed_at: null, version: 1};
  let proposal = {proposal_id: "proposal-r113-e2e", run_id: run.run_id, tool_fqn: tool.tool_fqn,
    proposal_sha256: "e".repeat(64), argument_sha256: "f".repeat(64), target_sha256: "1".repeat(64),
    side_effect_classes: ["proposal_only"], roe_version_id: "roe-r113-approved", policy_revision: "r099-v1",
    policy_decision_id: "r113-deterministic-policy-allow", proposal_state: "awaiting_approval",
    expires_at: "2099-07-12T04:02:00Z", version: 1};
  const budget = {ledger_id: "budget-r113-e2e", run_id: run.run_id, turn_count: 1, tool_call_count: 1,
    input_token_count: 100, result_token_count: 20, cost_microunits: 50, result_bytes: 128,
    elapsed_millis: 500, ledger_state: "within_budget", version: 2};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "reviewer-r113", tenant_id: "tenant-1", roles: ["operator"], permissions: ["engagement:read", "job:create", "job:read", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path === "/api/v1/agent/tools") return json(route, {data: [tool]});
    if (path === `/api/v1/agent/proposals/${proposal.proposal_id}/approve`) {
      proposal = {...proposal, proposal_state: "approved", version: 2}; return json(route, {data: proposal});
    }
    if (path === `/api/v1/agent/runs/${run.run_id}/cancel`) {
      run = {...run, run_state: "cancelled", cancel_requested: true, version: 2}; return json(route, {data: run});
    }
    if (path === "/api/v1/agent/dashboard") return json(route, {data: {tools: [tool], runs: [run], proposals: [proposal], approvals: [], budgets: [budget], traces: []}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/agent");
  await expect(page.getByRole("heading", {name: "Supervised agent proposal kernel"})).toBeVisible();
  await expect(page.getByText(/Deterministic fake only/i)).toBeVisible();
  await expect(page.getByText(/proposal_only · awaiting_approval/i)).toBeVisible();
  await expect(page.getByText(/1 turns · 1 tool calls · 50 µunits · 128 bytes/i)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/prompt|instructions|message|command|shell|url|browser|provider|model|api key|credential|raw evidence|runner|dispatch/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Approve exact proposal hash"}).click();
  await expect(page.getByText(/proposal_only · approved/i)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Cancel and block progression"}).click();
  await expect(page.getByText(/deterministic-fake · cancelled/i)).toBeVisible();
  await expect(page.getByRole("button", {name: "Approve all"})).toHaveCount(0);
  await expect(page.getByText(/authorization bearer|private key|sk-[a-z0-9]/i)).toHaveCount(0);
  const violations = await new AxeBuilder({page}).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("supervised workbench separates provenance and invalidates exact approval on successor and freeze", async ({page}) => {
  const now = "2026-07-12T09:00:00Z";
  let registration = {registration_id: "r114-fixture-registration", server_id: "redagent-fixture",
    protocol_version: "2025-11-25", transport_kind: "in_process", inventory_sha256: "a".repeat(64),
    risk_class: "high", data_class: "internal", registration_state: "attested-fixture-only",
    issued_at: now, expires_at: "2026-07-12T09:10:00Z", version: 1};
  let drafts = [{draft_id: "draft-r114-e2e", campaign_id: "campaign-r114", draft_revision: 1,
    predecessor_draft_id: null, proposal_sha256: "b".repeat(64), authority_sha256: "c".repeat(64),
    draft_state: "awaiting_review", created_by: "operator-r114", expires_at: "2026-07-12T09:02:00Z", version: 1}];
  let decisions = [];
  const trustItems = ["immutable_authority", "untrusted_external", "ai_suggestion"].map((trust_lane, index) => ({
    draft_id: drafts[0].draft_id, item_id: `trust-${index}`, trust_lane, summary_sha256: `${index + 1}`.repeat(64),
    provenance_sha256: `${index + 4}`.repeat(64), item_state: "visible-minimized", version: 1}));
  let disclosures = [{disclosure_id: "disclosure-r114", draft_id: drafts[0].draft_id,
    sanitized_fields_sha256: "d".repeat(64), target_scope_sha256: "e".repeat(64), access_class: "none",
    egress_class: "none", side_effects_sha256: "f".repeat(64), budget_sha256: "1".repeat(64),
    disclosure_state: "review-required", version: 1}];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "reviewer-r114", tenant_id: "tenant-r114",
      roles: ["operator"], permissions: ["engagement:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path.endsWith("/review")) {
      drafts = drafts.map((draft) => draft.draft_id === "draft-r114-e2e" ? {...draft, draft_state: "approved", version: 2} : draft);
      decisions = [{decision_id: "review-r114", draft_id: "draft-r114-e2e", decision_kind: "approve_exact",
        proposal_sha256: "b".repeat(64), actor_id: "reviewer-r114", rationale_sha256: "8".repeat(64),
        decision_state: "active", decided_at: now, version: 1}];
      return json(route, {data: {draft_id: "draft-r114-e2e", decision_id: "review-r114", decision: "approve_exact",
        proposal_sha256: "b".repeat(64), draft_state: "approved", version: 1}});
    }
    if (path.endsWith("/successors")) {
      drafts = [{...drafts[0], draft_state: "superseded", version: 3}, {draft_id: "successor-bbbbbbbbbbbbbbbbbbbb",
        campaign_id: "campaign-r114", draft_revision: 2, predecessor_draft_id: "draft-r114-e2e",
        proposal_sha256: "9".repeat(64), authority_sha256: "c".repeat(64), draft_state: "awaiting_review",
        created_by: "reviewer-r114", expires_at: "2026-07-12T09:03:00Z", version: 1}];
      decisions = decisions.map((item) => ({...item, decision_state: "invalidated-by-successor", version: 2}));
      disclosures = [...disclosures, {...disclosures[0], disclosure_id: "disclosure-successor",
        draft_id: "successor-bbbbbbbbbbbbbbbbbbbb", sanitized_fields_sha256: "9".repeat(64)}];
      return json(route, {data: {draft_id: drafts[1].draft_id, predecessor_draft_id: drafts[0].draft_id,
        proposal_sha256: drafts[1].proposal_sha256, draft_state: "awaiting_review", approval_invalidated: true, version: 1}}, 202);
    }
    if (path.endsWith("/freeze")) {
      registration = {...registration, registration_state: "frozen", version: 2};
      decisions = decisions.map((item) => ({...item, decision_state: "invalidated-by-freeze", version: 3}));
      return json(route, {data: {registration_id: registration.registration_id,
        expected_inventory_sha256: registration.inventory_sha256, freeze_state: "active",
        invalidated_approval_count: 1, version: 1}});
    }
    if (path === "/api/v1/workbench/dashboard") return json(route, {data: {registrations: [registration],
      binding_options: [{binding_id: "binding-r114-fixture", binding_state: "available",
        campaign_id: "campaign-r114", campaign_label: "compat_114 synthetic campaign",
        plan_id: "plan-r114-stored", plan_label: "Stored fixture plan",
        successor_plan_id: "plan-r114-successor", successor_plan_label: "Revised fixture plan",
        target_id: "target-r114-owned", target_label: "Owned synthetic target",
        tool_fqn: "redagent.r114-mcp-fixture.propose.v1", fixture_only: true, egress_class: "none"}],
      attestations: [{attestation_id: "attestation-r114", registration_id: registration.registration_id,
        transport_kind: "in_process", identity_sha256: "2".repeat(64), authorization_profile_sha256: "3".repeat(64),
        boundary_controls_sha256: "4".repeat(64), transport_enabled: false, attestation_state: "qualified-no-io",
        attested_at: now, version: 1}], inventories: [], items: [], freezes: [], drafts, trust_items: trustItems,
      disclosures, decisions, lifecycle: []}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/workbench");
  await expect(page.getByRole("heading", {name: "Supervised campaign workbench"})).toBeVisible();
  await expect(page.getByText("Immutable Authority", {exact: true})).toBeVisible();
  await expect(page.getByText("Untrusted External", {exact: true})).toBeVisible();
  await expect(page.getByText("AI Suggestion", {exact: true})).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/prompt|message|url|server url|command|args|environment|header|token|credential|raw evidence|reasoning|dispatch/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Approve exact proposal"}).click();
  await expect(page.getByText(/approve_exact · active/)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Create successor and invalidate approval"}).click();
  await expect(page.getByText(/approve_exact · invalidated-by-successor/)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Freeze server and invalidate approvals"}).click();
  await expect(page.getByText(/2025-11-25 · in_process · frozen/)).toBeVisible();
  await expect(page.getByRole("button", {name: /approve all/i})).toHaveCount(0);
  const violations = await new AxeBuilder({page}).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("finding operations preserve reviewed lineage and gate deterministic fixture delivery", async ({page}) => {
  const now = "2026-07-12T14:00:00Z";
  let issue = {issue_id: "issue-r115-e2e", issue_fingerprint: "a".repeat(64), title: "Missing HSTS",
    severity: "medium", confidence: "confirmed", disposition: "needs_review", disposition_revision: 1,
    owner_id: null, sla_due_at: null, first_seen_at: now, last_seen_at: now, issue_state: "active", version: 1};
  const occurrence = {occurrence_id: "occurrence-r115-e2e", issue_id: issue.issue_id, tool_id: "r115-fixture",
    tool_version: "1.0.0", rule_id: "fixture-missing-hsts", rule_version: "r115-closed-v1",
    database_version: "fixture-db-1", coverage_state: "complete", occurrence_state: "observed",
    evidence_id: "evidence-r115", evidence_sha256: "b".repeat(64), redaction_state: "report_safe",
    observed_at: now, version: 1};
  let reports = [];
  let publications = [];
  let deliveries = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, {data: {subject: "reviewer-r115", tenant_id: "tenant-r115",
      roles: ["reviewer"], permissions: ["engagement:read", "finding:read", "finding:ingest", "finding:review",
        "report:create", "report:publish", "connector:deliver"]}});
    if (path === "/api/v1/engagements") return json(route, {data: [], page: pageMeta(0)});
    if (path.endsWith("/review")) {
      issue = {...issue, disposition: "confirmed", disposition_revision: 2, version: 2};
      return json(route, {data: issue});
    }
    if (path === "/api/v1/finding-operations/reports" && request.method() === "POST") {
      reports = [{report_id: `report-${issue.issue_id}`, audience: "technical",
        reviewed_snapshot_sha256: issue.issue_fingerprint, policy_revision: "r099-v1",
        roe_version_id: "roe-r115-reviewed", coverage_state: "complete", report_sha256: "c".repeat(64),
        generation_profile: "deterministic-json-v1", report_state: "publishable", generated_by: "generator-r115",
        generated_at: now, version: 1}];
      return json(route, {data: reports[0]}, 201);
    }
    if (path.endsWith("/publish") && request.method() === "POST") {
      publications = [{publication_id: `publication-${reports[0].report_id}`, report_id: reports[0].report_id,
        report_sha256: reports[0].report_sha256, reviewer_id: reports[0].generated_by,
        publisher_id: "reviewer-r115", publication_state: "published", published_at: now, version: 1}];
      return json(route, {data: publications[0]});
    }
    if (path === "/api/v1/finding-operations/deliveries" && request.method() === "POST") {
      deliveries = [{delivery_id: `delivery-${reports[0].report_id}`, profile_id: "fixture-ticket-v1",
        report_id: reports[0].report_id, snapshot_sha256: reports[0].report_sha256, delivery_state: "queued",
        attempt_count: 0, network_contact_count: 0, next_attempt_at: now, version: 1}];
      return json(route, {data: deliveries[0]}, 202);
    }
    if (path === "/api/v1/finding-operations/dashboard") return json(route, {data: {
      issues: [issue], occurrences: [occurrence], reports, publications, deliveries}});
    return json(route, {error: {code: "resource_not_found", message: "Not found"}}, 404);
  });
  await page.goto("/finding-operations");
  await expect(page.getByRole("heading", {name: "Finding and remediation operations"})).toBeVisible();
  await expect(page.getByText(/needs_review · revision 1/i)).toBeVisible();
  await expect(page.getByText(/report_safe/i)).toBeVisible();
  await expect(page.getByRole("main").getByLabel(/raw evidence|payload|url|command|args|environment|header|token|credential|prompt|reasoning|scanner flags/i)).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Confirm reviewed issue"}).click();
  await expect(page.getByText(/confirmed · revision 2/i)).toBeVisible();
  await page.getByRole("button", {name: "Create deterministic technical report"}).click();
  await expect(page.getByText(/publishable · deterministic-json-v1/i)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Independently publish exact report"}).click();
  await expect(page.getByText(/published · reviewer generator-r115 · publisher reviewer-r115/i)).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", {name: "Queue fixture ticket delivery"}).click();
  await expect(page.getByText(/queued · 0 attempts · 0 network contacts/i)).toBeVisible();
  await expect(page.getByRole("button", {name: /publish with AI|approve all|send arbitrary/i})).toHaveCount(0);
  const violations = await new AxeBuilder({page}).analyze();
  expect(violations.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}
function pageMeta(returned) { return { limit: 50, offset: 0, returned }; }
function incidentFixture(state) {
  return {
    incident_id: "incident-e2e", source_kind: "telemetry", source_id: "export-e2e",
    severity: "high", state, reason_code: "telemetry_degraded", opened_by_user_id: "system",
    assigned_to_user_id: null, acknowledged_by_user_id: state === "acknowledged" ? "operator-1" : null,
    contained_by_user_id: null, recovered_by_user_id: null, reviewed_by_user_id: null,
    evidence_preserved: false, containment_verified: false,
    opened_at: "2026-07-11T07:00:00Z", closed_at: null, version: state === "open" ? 1 : 2,
  };
}
function meta() { return { replayed: false, audit_id: "audit-e2e", outbox_id: "outbox-e2e" }; }
function durableJob() {
  return {
    job_id: "job-e2e", tenant_id: "tenant-1", engagement_id: "engagement-e2e", roe_version_id: "roe-e2e",
    created_by_user_id: "operator-1", campaign_id: null, status: "pending",
    request: { capability: "synthetic-noop", approval_timeout_seconds: 3600, max_activity_attempts: 3, budget_reference: "budget:compat_096:e2e" },
    policy_reference: "console:job-create:1", workflow_id: "workflow-e2e", workflow_run_id: "run-e2e",
    orchestration_state: "awaiting_approval", orchestration_revision: 2, current_gate: "operator_approval",
    failure_code: null, retry_count: 0, dispatch_blocked: true, stop_requested: false, version: 2,
  };
}
function evidenceArtifact() {
  return {
    artifact_id: "artifact-e2e", tenant_id: "tenant-1", engagement_id: "engagement-e2e", job_id: "job-e2e",
    producer_id: "runner-e2e", object_key: "tenants/tenant-1/evidence/artifact-e2e", object_version_id: "version-e2e",
    content_sha256: "a".repeat(64), provider_checksum: "provider-e2e", size_bytes: 42,
    content_type: "text/plain", artifact_class: "redacted", classification: "confidential",
    redaction_state: "redacted", retention_mode: "GOVERNANCE", retain_until: "2026-08-10T00:00:00Z",
    legal_hold: false, kms_reference: "kms:fixture", attestation_hash: "b".repeat(64),
    policy_reference: "policy:compat_097:1", quarantine_reason: null, version: 1,
  };
}
function secretLease() {
  return {
    lease_id: "lease-e2e", tenant_id: "tenant-1", reference_id: "reference-e2e",
    engagement_id: "engagement-e2e", job_id: "job-e2e", workload_client_id: "client-e2e",
    capability: "synthetic-noop", permission_count: 1, issued_at: "2026-07-10T12:00:00Z",
    expires_at: "2026-07-10T12:05:00Z", renewed_at: null, revoked_at: null,
    renewable: true, renewal_count: 0, lease_state: "active", policy_reference: "policy:compat_098:1",
    roe_version_id: "roe-e2e", failure_code: null, version: 1,
  };
}
