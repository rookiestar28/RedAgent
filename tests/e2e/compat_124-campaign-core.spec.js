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
    await expect(page.getByLabel("Owned loopback posture").getByRole("button", { name: "Stop & revoke" })).toBeVisible();
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


async function campaignRoutes(page, onStart = async () => {}) {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-r124", tenant_id: "tenant-r124",
      permissions: ["engagement:read", "campaign:read", "campaign:create", "campaign:stop"],
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
    if (path === "/api/v1/campaign-core/campaigns/campaign-server-generated") {
      return json(route, { data: campaignTruth() });
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

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}
