import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const enabled = process.env.REDAGENT_OPERATOR_LIVE_TEST === "owned-operator-v1";
const backend = "http://127.0.0.1:4311";
test.skip(!enabled, "requires explicit confined owned operator runtime authority");

test("normal owned intent, fresh human gates, native stop and current results", async ({ page, request }) => {
  test.setTimeout(210_000);
  const fixture = await (await request.get(`${backend}/__test_fixture__`)).json();
  expect(fixture.scope).toBe("synthetic-authority-real-owned-operator");
  const mutations = [];
  await page.route("**/api/v1/**", async (route) => {
    const incoming = route.request();
    const url = new URL(incoming.url());
    const response = await route.fetch({ url: `${backend}${url.pathname}${url.search}`,
      headers: { ...incoming.headers(), ...fixture.headers }, maxRedirects: 0 });
    if (incoming.method() === "POST") mutations.push({ path: url.pathname, body: incoming.postDataJSON(), status: response.status() });
    await route.fulfill({ response });
  });
  const ready = async (key, timeout = 30_000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const state = await (await request.get(`${backend}/__test_fixture__`)).json();
      if (state.failed) throw new Error("Owned native test owner failed; teardown required");
      if (state[key] === true) return;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`Owned native owner readiness timed out: ${key}`);
  };
  const refresh = () => page.getByRole("button", { name: "Refresh current status", exact: true }).click();
  const confirm = async (action, label) => {
    const trigger = page.getByRole("button", { name: action, exact: true });
    await expect(trigger).toBeVisible();
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: label, exact: true });
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
    await dialog.getByRole("button", { name: label, exact: true }).click();
    await expect(dialog).toHaveCount(0);
  };
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
  await expect(page.getByRole("button", { name: "Admit and start", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Approve plan", exact: true }).click();
  const approvalDialog = page.getByRole("dialog", { name: "Confirm plan approval", exact: true });
  await expect(approvalDialog.getByText("url: http://127.0.0.1:41731", { exact: true })).toBeVisible();
  expect((await new AxeBuilder({ page }).include('[role="dialog"]').analyze()).violations).toEqual([]);
  await approvalDialog.getByRole("button", { name: "Confirm plan approval", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: /^APPROVED$/ })).toBeVisible();
  await ready("worker_ready");
  await confirm("Admit and start", "Confirm admission and start");
  if (fixture.mode === "bounded_replan") {
    await ready("stop_ready", 90_000);
    await refresh();
    await confirm("Request containment", "Confirm containment request");
    await expect(page.getByText("A stop request does not prove containment or cleanup. Refresh the native execution and result owners.")).toBeVisible();
    await ready("parent_terminal");
    await refresh();
    await expect(page.getByRole("status").filter({ hasText: /^FAILED CONTAINED$/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Export evidence", exact: true })).toBeDisabled();
    const early = page.waitForResponse((response) => response.request().method() === "POST" && response.url().endsWith("/child-replan"));
    await confirm("Prepare child plan", "Confirm child plan preparation");
    expect((await early).ok()).toBe(false);
    await expect(page.getByRole("alert")).toBeVisible();
    // Native receipt fixes the original cooldown. Observe the window once, then make a NEW explicit request.
    await page.waitForTimeout(60_000);
    await refresh();
    await confirm("Prepare child plan", "Confirm child plan preparation");
    await expect(page.getByText("Child revision 1 requires its own exact approval and admission. Parent receipts do not transfer.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Admit and start", exact: true })).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: /^AWAITING APPROVAL$/ })).toBeVisible();
    await confirm("Approve plan", "Confirm plan approval");
    await ready("child_ready");
    await confirm("Admit and start", "Confirm admission and start");
  }
  await ready("finished", 90_000);
  await refresh();
  await expect(page.getByRole("status").filter({ hasText: /^EVIDENCE PENDING$/ })).toBeVisible();
  const cleanup = page.locator("dl.record-grid > div").filter({ has: page.locator("dt", { hasText: /^Cleanup$/ }) }).first();
  await expect(cleanup.locator("dd")).toHaveText("complete");
  const evidence = page.locator("dl.record-grid > div").filter({ has: page.locator("dt", { hasText: /^Evidence$/ }) }).first();
  await expect(evidence.locator("dd")).toHaveText("verified");
  await expect(page.getByText("The server verified the retained bundle. An authorized export owner is not configured.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Export evidence", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Admit and start", exact: true })).toHaveCount(0);
  const admissions = mutations.filter((item) => item.path.endsWith("/admission-start"));
  const approvals = mutations.filter((item) => item.path.endsWith("/plan-approval"));
  expect(admissions).toHaveLength(fixture.mode === "bounded_replan" ? 2 : 1);
  expect(approvals).toHaveLength(admissions.length);
  expect(admissions.every((item) => item.status >= 200 && item.status < 300)).toBe(true);
  if (admissions.length === 2) expect(admissions[0].body.approval_receipt_id).not.toBe(admissions[1].body.approval_receipt_id);
  expect(Object.keys(mutations[0].body).sort()).toEqual(["engagement_binding", "objective", "risk_profile", "target_binding"]);
});
