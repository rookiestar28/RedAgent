import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import path from "node:path";

// Only the opt-in test server has an identity issuer/synthetic signed authority.
// All campaign mutations below cross the stock HTTP guards and native owners.
const backend = "http://127.0.0.1:4311";
let child;
let fixture;
test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  const root = process.cwd();
  // Match the OS gate's local venv; a Windows path causes ENOENT on Ubuntu.
  const python = process.platform === "win32"
    ? path.join(root, ".venv", "Scripts", "python.exe")
    : path.join(root, ".venv-wsl", "bin", "python");
  if (!existsSync(python)) throw new Error(`project_local_python_missing: ${python}`);
  child = spawn(python, ["-m", "tests.integration.operator_browser_server"], {
    cwd: root, windowsHide: true, shell: false,
    env: { ...process.env, REDAGENT_OPERATOR_BROWSER_TEST: "plan-only-v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stderr.on("data", (value) => { output += value.toString(); });
  // Await spawn with error rejection before polling; ENOENT otherwise escapes setup.
  await once(child, "spawn");
  await expect(async () => {
    if (child.exitCode !== null) throw new Error(`Owned test API exited: ${output}`);
    const response = await request.get(`${backend}/__test_fixture__`);
    expect(response.ok()).toBeTruthy();
    fixture = await response.json();
  }).toPass({ timeout: 15_000 });
  expect(fixture.scope).toBe("synthetic-plan-only-native-postgres");
});

test.afterAll(async ({ request }) => {
  if (child?.pid && child.exitCode === null) {
    // Subscribe before stop: the child can exit before the HTTP response resolves.
    const exited = once(child, "exit");
    await request.post(`${backend}/__test_fixture__/stop`);
    await exited;
  }
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 320, height: 780 }]) {
  test(`normal PLAN_ONLY browser approval and persisted status at ${viewport.width}px`, async ({ page, request }) => {
    await page.setViewportSize(viewport);
    const mutations = [];
    await page.route("**/api/v1/**", async (route) => {
      const incoming = route.request();
      const url = new URL(incoming.url());
      if (incoming.method() === "POST") mutations.push({ path: url.pathname, body: incoming.postDataJSON() });
      const response = await route.fetch({ url: `${backend}${url.pathname}${url.search}`,
        headers: { ...incoming.headers(), ...fixture.headers }, maxRedirects: 0 });
      await route.fulfill({ response });
    });
    await page.goto("/campaigns/new");
    await expect(page.getByLabel("Authorized engagement").locator("option")).toHaveCount(2);
    await page.getByLabel("Authorized engagement").selectOption({ index: 1 });
    await expect(page.getByLabel("Authorized target").locator("option")).toHaveCount(2);
    await page.getByLabel("Authorized target").selectOption({ index: 1 });
    await page.getByLabel("Objective").selectOption("Assess HTTP security posture");
    await expect(page.getByLabel("Risk profile").locator("option")).toHaveCount(2);
    await page.getByLabel("Risk profile").selectOption({ index: 1 });
    await page.getByRole("button", { name: "Prepare plan", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Immutable plan", exact: true })).toBeVisible();
    await expect(page.getByText("PLAN_ONLY prepares and records human decisions with zero execution I/O.")).toBeVisible();
    expect(mutations.map((item) => item.path)).toHaveLength(2);
    await page.getByRole("button", { name: "Approve plan", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Confirm plan approval" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
    await expect(page.locator("#root")).toHaveAttribute("inert", "");
    await expect(dialog.getByText("Assess HTTP security posture", { exact: true })).toBeVisible();
    await expect(dialog.getByLabel("Plan total bounds")).toBeVisible();
    await expect(dialog.getByLabel("Authorized campaign bounds")).toBeVisible();
    await expect(dialog.getByText("url: http://127.0.0.1:41731", { exact: true })).toBeVisible();
    const accessibility = await new AxeBuilder({ page }).include('[role="dialog"]').analyze();
    expect(accessibility.violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
    await expect(page.getByRole("button", { name: "Approve plan", exact: true })).toBeFocused();
    expect(mutations).toHaveLength(2);
    await page.getByRole("button", { name: "Approve plan", exact: true }).click();
    await dialog.getByRole("button", { name: "Confirm plan approval", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: /^APPROVED$/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Admit and start" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Export evidence" })).toBeDisabled();
    expect(mutations).toHaveLength(3);
    expect(Object.keys(mutations[0].body).sort()).toEqual(["engagement_binding", "objective", "risk_profile", "target_binding"]);
    await page.goto("/campaigns");
    const rows = page.getByRole("button", { name: "View current status" });
    await expect(rows).toHaveCount(viewport.width === 1440 ? 1 : 2);
    await rows.first().click();
    await expect(page.getByRole("heading", { name: "Immutable plan", exact: true })).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: /^APPROVED$/ })).toBeVisible();
    const counts = await (await request.get(`${backend}/__test_fixture__/counts`)).json();
    for (const key of ["campaign_execution_runs", "campaign_effects", "campaign_budget_reservations", "autonomous_campaign_execution_starts"]) {
      expect(counts[key]).toBe(0);
    }
    expect(counts.autonomous_campaign_applications).toBe(viewport.width === 1440 ? 1 : 2);
    expect(counts.autonomous_campaign_plan_previews).toBe(counts.autonomous_campaign_applications);
    expect(counts.autonomous_campaign_plan_approval_receipts).toBe(counts.autonomous_campaign_applications);
  });
}

for (const boundary of ["permission", "tenant", "stale-preview"]) {
  test(`normal HTTP ${boundary} denial refetches without approval retry or execution`, async ({ page, request }) => {
    let attempts = 0;
    const before = await (await request.get(`${backend}/__test_fixture__/counts`)).json();
    await page.route("**/api/v1/**", async (route) => {
      const incoming = route.request();
      const url = new URL(incoming.url());
      const headers = { ...incoming.headers(), ...fixture.headers };
      if (url.pathname.endsWith("/plan-approval")) {
        attempts += 1;
        if (boundary === "permission") headers["X-RedAgent-Test-Permissions"] = "campaign:read";
        else if (boundary === "tenant") headers["X-RedAgent-Test-Tenant"] = "tenant-unowned";
        else headers["if-match"] = '"changed-preview"';
      }
      const response = await route.fetch({ url: `${backend}${url.pathname}${url.search}`, headers, maxRedirects: 0 });
      if (url.pathname.endsWith("/plan-approval")) expect(response.status()).toBe(boundary === "permission" ? 403 : boundary === "tenant" ? 404 : 409);
      await route.fulfill({ response });
    });
    await page.goto("/campaigns/new");
    await expect(page.getByLabel("Authorized engagement").locator("option")).toHaveCount(2);
    await page.getByLabel("Authorized engagement").selectOption({ index: 1 });
    await expect(page.getByLabel("Authorized target").locator("option")).toHaveCount(2);
    await page.getByLabel("Authorized target").selectOption({ index: 1 });
    await page.getByLabel("Objective").selectOption("Assess HTTP security posture");
    await expect(page.getByLabel("Risk profile").locator("option")).toHaveCount(2);
    await page.getByLabel("Risk profile").selectOption({ index: 1 });
    await page.getByRole("button", { name: "Prepare plan", exact: true }).click();
    await page.getByRole("button", { name: "Approve plan", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Confirm plan approval" }).click();
    await expect(page.getByRole("alert")).toContainText("Review the refreshed state and confirm again");
    await expect(page.getByRole("status").filter({ hasText: /^AWAITING APPROVAL$/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Admit and start" })).toHaveCount(0);
    expect(attempts).toBe(1);
    const after = await (await request.get(`${backend}/__test_fixture__/counts`)).json();
    expect(after.autonomous_campaign_plan_approval_receipts).toBe(before.autonomous_campaign_plan_approval_receipts);
    for (const key of ["campaign_execution_runs", "campaign_effects", "campaign_budget_reservations", "autonomous_campaign_execution_starts"]) expect(after[key]).toBe(0);
  });
}
