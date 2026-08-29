import { test, expect } from "@playwright/test";


for (const fixture of [
  { name: "desktop-pointer", viewport: { width: 1440, height: 900 }, inputMode: "pointer" },
  { name: "mobile-keyboard", viewport: { width: 390, height: 844 }, inputMode: "keyboard" },
]) {
  test(`compat_124 standing Tier-1 flow stays within five activations (${fixture.name})`, async ({ page }) => {
    await page.setViewportSize(fixture.viewport);
    const evidence = {
      fixtureRevision: "r124-owned-loopback-multiple-options-v1",
      browser: "chromium",
      inputMode: fixture.inputMode,
      startState: "/campaigns/new:authorized-options-loaded:no-objective-entered",
      events: [],
      endState: "authorized-start-accepted",
    };
    let startRequest;
    await campaignRoutes(page, async (request) => { startRequest = request; });
    await page.goto("/campaigns/new");

    await page.getByLabel("Authorized engagement").selectOption("opaque-engagement-b");
    evidence.events.push("engagement-selection");
    await page.getByLabel("Authorized target").selectOption("opaque-target-b");
    evidence.events.push("target-selection");
    await page.getByLabel("Objective").selectOption("Assess HTTP security posture");
    evidence.events.push("objective-selection");
    await page.getByLabel("Risk profile").selectOption("opaque-risk-tier1");
    evidence.events.push("risk-selection");
    await page.getByRole("button", { name: "Start authorized campaign" }).click();
    evidence.events.push("authorized-start");

    await expect(page.getByRole("heading", { name: "Owned loopback posture" })).toBeVisible();
    await expect(page.getByLabel("Owned loopback posture").getByRole("button", { name: "Request containment" })).toBeVisible();
    expect(evidence.events).toHaveLength(5);
    expect(startRequest).toBeDefined();
    expect(startRequest.headers()["idempotency-key"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(await startRequest.postDataJSON()).toEqual({
      engagement_binding: "opaque-engagement-b",
      target_binding: "opaque-target-b",
      objective: "Assess HTTP security posture",
      risk_profile: "opaque-risk-tier1",
    });
    await expect(page.getByRole("main").getByLabel(/(?:campaign|engagement|target|job|runner|workflow) id/i)).toHaveCount(0);
    await expect(page.getByRole("main").getByLabel(/url|command|adapter|provider|credential|lease|hash|revision/i)).toHaveCount(0);
    await test.info().attach("r124-activation-evidence", {
      body: JSON.stringify({ ...evidence, deliberateActivationCount: evidence.events.length }),
      contentType: "application/json",
    });
  });
}

test("compat_124 attention and recovery surfaces expose guidance without raw-ID entry", async ({ page }) => {
  await campaignRoutes(page);
  await page.goto("/campaigns/attention");

  await expect(page.getByRole("heading", { name: "Campaign attention queue" })).toBeVisible();
  await expect(page.getByText(/effect requires reconciliation/i)).toBeVisible();
  await expect(page.getByText(/automatic redispatch remains blocked/i)).toBeVisible();
  await expect(page.getByText("opaque-attention-binding")).toHaveCount(0);
});

test("R162 campaign operations renders server truth and keeps export unavailable", async ({ page }) => {
  await campaignRoutes(page);
  await page.goto("/campaigns");

  await page.getByRole("button", { name: "View current status" }).click();
  await expect(page.getByRole("heading", { name: "Autonomous campaign operations" })).toBeVisible();
  await expect(page.getByText("75 of 100 requests remaining")).toBeVisible();
  await expect(page.getByText("1 invalidated · 1 retained · 1 substitution")).toBeVisible();
  await page.getByText("Exact authority binding").click();
  await expect(page.getByText("a".repeat(64))).toBeVisible();
  await expect(page.getByText(/verified retained bundle is not available/i)).toBeVisible();
  await expect(page.getByRole("button", { name: /export/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Request containment" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke future authority" })).toBeVisible();
  await expect(page.getByRole("main")).not.toContainText(/campaign-server-generated|node-internal|target-internal|operator-internal/i);
});

test("R162 missing inspect authorization fails closed with actionable feedback", async ({ page }) => {
  await campaignRoutes(page, async () => {}, {
    operationsError: {
      status: 403,
      body: { error: { code: "permission_denied", message: "Campaign inspect permission is required." } },
    },
  });
  await page.goto("/campaigns");
  await page.getByRole("button", { name: "View current status" }).click();

  await expect(page.getByRole("alert")).toContainText("Campaign inspect permission is required");
  await expect(page.getByRole("heading", { name: "Autonomous campaign operations" })).toHaveCount(0);
});

test("R162 policy denial and unsafe expansion remain explicit and non-executable", async ({ page }) => {
  const operations = campaignOperations();
  operations.preparation_state = "denied";
  operations.validation = {
    result: "invalid",
    reason: "expansion_requires_new_authority",
    counterexample_codes: ["scope-expansion-denied"],
  };
  operations.admission = {
    outcome: "denied",
    reason: "policy_denied",
    receipt_sha256: "9".repeat(64),
  };
  operations.execution = {
    state: "unavailable", transition_count: 0, max_transitions: 0,
    stop_requested: false, terminal_reason: null, frontier: {},
  };
  await campaignRoutes(page, async () => {}, { operations });
  await page.goto("/campaigns");
  await page.getByRole("button", { name: "View current status" }).click();

  await expect(page.getByText("Scope expansion denied")).toBeVisible();
  await expect(page.getByText("Policy denied")).toBeVisible();
  await expect(page.getByText("Expansion requires new authority")).toBeVisible();
  await expect(page.getByRole("button", { name: /start|approve|dispatch/i })).toHaveCount(0);
});

test("R162 revocation and ambiguous execution stay prominent", async ({ page }) => {
  const operations = campaignOperations();
  operations.authority.state = "revoked";
  operations.authority.kill_switch_epoch = 1;
  operations.execution.state = "manual_review_required";
  operations.execution.terminal_reason = "ambiguous_effect_state";
  operations.execution.frontier = { ambiguous: 1 };
  await campaignRoutes(page, async () => {}, { operations });
  await page.goto("/campaigns");
  await page.getByRole("button", { name: "View current status" }).click();

  await expect(page.getByText("Revoked", { exact: true })).toBeVisible();
  await expect(page.getByText(/Frontier: 1 ambiguous/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Request containment" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke future authority" })).toHaveCount(0);
});

test("R162 stale containment revision is rejected without hiding current truth", async ({ page }) => {
  let recoveryRequest;
  await campaignRoutes(page, async () => {}, {
    onRecover: async (request) => {
      recoveryRequest = request;
      return {
        status: 409,
        body: { error: { code: "etag_conflict", message: "Campaign revision is stale.", correlation_id: "stale-campaign-e2e" } },
      };
    },
  });
  await page.goto("/campaigns");
  await page.getByRole("button", { name: "View current status" }).click();
  await page.getByRole("button", { name: "Request containment" }).click();
  await page.getByRole("button", { name: "Confirm containment request" }).click();

  await expect(page.getByRole("alert")).toContainText("Campaign revision is stale");
  await expect(page.getByRole("alert")).toContainText("stale-campaign-e2e");
  await expect(page.getByRole("heading", { name: "Autonomous campaign operations" })).toBeVisible();
  expect(recoveryRequest.headers()["if-match"]).toBe('"campaign-server-generated:2"');
  expect(recoveryRequest.headers()["idempotency-key"]).toBeTruthy();
});

test("R162 containment request refreshes to pending server truth without claiming completion", async ({ page }) => {
  let containmentRequested = false;
  await campaignRoutes(page, async () => {}, {
    onRecover: async () => {
      containmentRequested = true;
      return {
        status: 202,
        body: { data: {
          campaign_id: "campaign-server-generated", status: "containment_pending",
          aggregate_sequence: 3, etag: '"campaign-server-generated:3"', replayed: false,
        } },
      };
    },
    campaignTruth: () => containmentRequested ? {
      ...campaignTruth(), status: "containment_pending", aggregate_sequence: 3,
      etag: '"campaign-server-generated:3"',
      recovery: {
        stop_visible: true, revoke_visible: true, cleanup_required: true,
        guidance: "Containment is pending server reconciliation.",
      },
    } : campaignTruth(),
    operations: () => {
      const operations = campaignOperations();
      if (containmentRequested) {
        operations.aggregate_version = 8;
        operations.etag = '"campaign-server-generated:8"';
        operations.execution.state = "stopping";
        operations.execution.stop_requested = true;
      }
      return operations;
    },
  });
  await page.goto("/campaigns");
  await page.getByRole("button", { name: "View current status" }).click();
  await page.getByRole("button", { name: "Request containment" }).click();
  await page.getByRole("button", { name: "Confirm containment request" }).click();

  await expect(page.getByText("containment pending", { exact: true })).toBeVisible();
  await expect(page.getByText("Stopping", { exact: true })).toBeVisible();
  await expect(page.getByText(/pending server reconciliation/i)).toBeVisible();
  await expect(page.getByText(/containment complete/i)).toHaveCount(0);
});

test("R129 repository posture uses only server-projected opaque selections", async ({ page }) => {
  let startRequest;
  await campaignRoutes(page, async (request) => { startRequest = request; });
  await page.goto("/campaigns/new");

  await page.getByLabel("Authorized engagement").selectOption("opaque-engagement-a");
  await page.getByLabel("Authorized target").selectOption("opaque-artifact-binding");
  await page.getByLabel("Objective").selectOption("Assess repository snapshot posture");
  await page.getByLabel("Risk profile").selectOption("opaque-risk-tier1");
  await page.getByRole("button", { name: "Start authorized campaign" }).click();

  expect(await startRequest.postDataJSON()).toEqual({
    engagement_binding: "opaque-engagement-a",
    target_binding: "opaque-artifact-binding",
    objective: "Assess repository snapshot posture",
    risk_profile: "opaque-risk-tier1",
  });
  await expect(page.getByRole("main").getByLabel(/repository|artifact receipt|path|url|command|credential/i)).toHaveCount(0);
  await expect(page.getByText("Stop remains available.")).toBeVisible();
});

test("compat_124 create denial keeps CSRF feedback actionable without exposing raw IDs", async ({ page }) => {
  await campaignRoutes(page, async () => ({
    body: {
      error: {
        code: "csrf_rejected",
        message: "Browser request failed CSRF validation.",
        correlation_id: "csrf-r124-e2e",
      },
    },
    status: 403,
  }));
  await page.goto("/campaigns/new");

  await page.getByLabel("Authorized engagement").selectOption("opaque-engagement-b");
  await page.getByLabel("Authorized target").selectOption("opaque-target-b");
  await page.getByLabel("Objective").selectOption("Assess HTTP security posture");
  await page.getByLabel("Risk profile").selectOption("opaque-risk-tier1");
  await page.getByRole("button", { name: "Start authorized campaign" }).click();

  await expect(page.getByRole("alert")).toContainText("CSRF");
  await expect(page.getByRole("alert")).toContainText("csrf-r124-e2e");
  await expect(page.getByRole("main").getByLabel(/(?:campaign|engagement|target|job|runner|workflow) id/i)).toHaveCount(0);
});


async function campaignRoutes(page, onStart = async () => {}, options = {}) {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-r124", tenant_id: "tenant-r124",
      permissions: ["engagement:read", "campaign:read", "campaign:inspect", "campaign:create", "campaign:stop"],
      roles: ["operator"],
    } });
    if (path === "/api/v1/engagements") {
      return json(route, { data: [], page: { limit: 50, offset: 0, returned: 0 } });
    }
    if (path === "/api/v1/campaign-core/options/engagements") {
      return json(route, optionPage([
        option("opaque-engagement-a", "Owned loopback alpha"),
        option("opaque-engagement-b", "Owned loopback beta"),
      ]));
    }
    if (path === "/api/v1/campaign-core/options/targets") {
      return json(route, optionPage([
        option("opaque-target-a", "HTTP fixture alpha"),
        option("opaque-target-b", "HTTP fixture beta"),
        option("opaque-artifact-binding", "Repository snapshot: canonical data-only binding"),
      ]));
    }
    if (path === "/api/v1/campaign-core/options/risk-profiles") {
      return json(route, optionPage([option("opaque-risk-tier1", "Tier 1 passive")]));
    }
    if (path === "/api/v1/campaign-core/campaigns" && request.method() === "POST") {
      const override = await onStart(request);
      if (override) return json(route, override.body, override.status);
      return json(route, { data: {
        campaign_id: "campaign-server-generated", status: "dispatch_pending",
        aggregate_sequence: 1, etag: '"campaign-server-generated:1"', replayed: false,
      } }, 202);
    }
    if (path === "/api/v1/campaign-core/campaigns" && request.method() === "GET") {
      return json(route, {
        data: [{
          campaign_id: "campaign-server-generated", label: "Owned loopback posture",
          status: "workflow_started", authority_state: "current_at_last_resolution",
          attention_reason: null, aggregate_sequence: 2,
        }],
        page: { limit: 50, next_cursor: null },
      });
    }
    if (path === "/api/v1/campaign-core/campaigns/campaign-server-generated/operations") {
      if (options.operationsError) {
        return json(route, options.operationsError.body, options.operationsError.status);
      }
      const operations = typeof options.operations === "function"
        ? options.operations() : options.operations ?? campaignOperations();
      return json(route, { data: operations });
    }
    if (
      path === "/api/v1/campaign-core/campaigns/campaign-server-generated/stop"
      || path === "/api/v1/campaign-core/campaigns/campaign-server-generated/revoke"
    ) {
      const override = await options.onRecover?.(request);
      if (override) return json(route, override.body, override.status);
      return json(route, { error: { code: "recovery_not_configured", message: "Recovery not configured" } }, 503);
    }
    if (path === "/api/v1/campaign-core/campaigns/campaign-server-generated") {
      const truth = typeof options.campaignTruth === "function" ? options.campaignTruth() : campaignTruth();
      return json(route, { data: truth });
    }
    if (path === "/api/v1/campaign-core/attention") {
      return json(route, {
        data: [{
          binding: "opaque-attention-binding",
          campaign_label: "Owned loopback posture",
          category: "reconciliation",
          reason: "effect_requires_reconciliation",
          next_safe_action: "Inspect the bounded receipt; automatic redispatch remains blocked.",
          occurred_at: "2026-08-24T12:00:00Z",
        }],
        page: { limit: 50, next_cursor: null },
      });
    }
    return json(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
}

function option(binding, label) {
  return { binding, label, revision: "1", freshness: "current", eligible: true, unavailable_reason: null };
}

function optionPage(data) {
  return { data, page: { limit: 50, next_cursor: null } };
}

function campaignTruth() {
  return {
    campaign_id: "campaign-server-generated",
    label: "Owned loopback posture",
    status: "workflow_started",
    aggregate_sequence: 2,
    etag: '"campaign-server-generated:2"',
    authority: { state: "current_at_last_resolution", attention_reason: null },
    context: {
      schema: "redagent.r119-context/v1",
      coverage: "Canonical authority and two-capability snapshot",
      freshness: "Resolved at campaign start; mutations recheck authority",
    },
    decision: { outcome: "planned", reason: "primary_selected", candidates: [] },
    plan: {
      primary: "Primary web posture assessment", successor: null, successor_condition: null,
      depth: 1, risk: "Tier 1 passive, owned-loopback only",
      cost: "At most 2 operations in 300 seconds", evidence: "1 reviewed schema expected",
      cleanup: "cleanup_receipt_required", approval: "standing Tier 1 authority",
    },
    effects: [], findings: [],
    recovery: {
      stop_visible: true, revoke_visible: true, cleanup_required: false,
      guidance: "Stop remains available.",
    },
  };
}

function campaignOperations() {
  return {
    schema_version: "redagent.campaign-operations/v1", aggregate_version: 7,
    etag: '"campaign-server-generated:7"', preparation_state: "executing",
    authority: {
      state: "admitted", signed_authority_sha256: "a".repeat(64), authority_sha256: "b".repeat(64),
      lifecycle_epoch: 4, policy_revocation_epoch: 2, roe_revocation_epoch: 1, kill_switch_epoch: 0,
      expires_at: "2026-08-29T13:00:00Z",
    },
    plan: {
      revision_label: "Current revision", parent_revision_present: false,
      nodes: [{ label: "Step 1", capability: "HTTP posture", state: "running", order: 0 }], edges: [],
    },
    validation: { result: "valid", reason: null, counterexample_codes: [] },
    admission: { outcome: "admitted", reason: "admitted", receipt_sha256: "c".repeat(64) },
    budget: { state: "available", dimensions: {
      requests: { authorized: 100, committed: 25, residual: 75, unit: "requests" },
    } },
    execution: {
      state: "running", transition_count: 3, max_transitions: 20, stop_requested: false,
      terminal_reason: null, frontier: { running: 1 },
    },
    observations: [{
      fact: "HTTP header present", producer_kind: "dag_runner_result",
      observation_sha256: "d".repeat(64), provenance_sha256: "e".repeat(64), freshness: "current",
    }],
    revisions: [{
      label: "Revision 1", state: "proposed", proposal_sha256: "f".repeat(64),
      invalidated_count: 1, retained_count: 1, substitution_count: 1,
    }],
    audit: [{
      action: "campaign.dag.start.requested", occurred_at: "2026-08-29T12:00:00Z",
      correlation_id: "safe-correlation", details_sha256: "1".repeat(64),
    }],
    evidence: {
      effect_count: 1, evidence_count: 1, cleanup_state: "complete",
      terminal_receipt_present: false, export_state: "unavailable_without_verified_bundle",
    },
  };
}

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}
