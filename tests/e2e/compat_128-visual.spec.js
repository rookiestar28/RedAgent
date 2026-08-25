import { expect, test } from "@playwright/test";

const CASES = [
  ["overview", "/", "Overview"],
  ["engagements", "/engagements", "Engagements"],
  ["agent", "/agent", "Agent kernel"],
  ["workbench", "/workbench", "Campaign workbench"],
  ["deleted-states", "/states", "Page not found"],
];

for (const [label, routePath, heading] of CASES) {
  for (const viewport of [
    { label: "desktop", width: 1440, height: 900 },
    { label: "mobile", width: 320, height: 800 },
  ]) {
    test(`${label} ${viewport.label} matches the reviewed compat_128 baseline`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
      await installFixture(page);
      await page.goto(routePath, { waitUntil: "networkidle" });
      await expect(page.getByRole("heading", { level: 1, name: heading, exact: true })).toBeVisible();
      await expect(page.getByText("Loading route", { exact: true })).toHaveCount(0);
      await expect(page).toHaveScreenshot(`compat_128-${label}-${viewport.label}.png`, {
        fullPage: true,
        animations: "disabled",
        maxDiffPixelRatio: 0.001,
      });
    });
  }
}

async function installFixture(page) {
  await page.route("**/api/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/api/v1/context") return json(route, { data: {
      subject: "visual-reviewer-r128", tenant_id: "tenant-r128", roles: ["reviewer"],
      permissions: ["engagement:read", "audit:read", "job:read", "job:stop"],
      operator_shell: { schema_version: "1", environment: "local", safety_profile: "local-conformance", status: "ready" },
    } });
    if (pathname === "/api/v1/engagements") return json(route, { data: [], page: pageMeta() });
    if (pathname === "/api/v1/agent/tools") return json(route, { data: [] });
    if (pathname === "/api/v1/agent/dashboard") return json(route, { data: {
      tools: [], runs: [], proposals: [], approvals: [], budgets: [], traces: [],
    } });
    if (pathname === "/api/v1/workbench/dashboard") return json(route, { data: {
      registrations: [], attestations: [], inventories: [], items: [], freezes: [], binding_options: [],
      drafts: [], trust_items: [], disclosures: [], decisions: [], lifecycle: [],
    } });
    return json(route, { error: { code: "fixture_not_available", message: "Deterministic empty fixture" } }, 404);
  });
}

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function pageMeta() { return { limit: 50, offset: 0, returned: 0 }; }
