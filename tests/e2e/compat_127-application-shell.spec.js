import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";


test("typed shell navigates deep links back and forward without header feature links", async ({ page }) => {
  await installShellApi(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeFocused();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toHaveCount(1);
  await expect(page.getByRole("banner").locator('a[href="/engagements"]')).toHaveCount(0);
  await page.getByRole("link", { name: "Engagements", exact: true }).click();
  await expect(page).toHaveURL(/\/engagements$/);
  await expect(page.getByRole("heading", { level: 1, name: "Engagements" })).toBeFocused();
  await expect(page.getByRole("link", { name: "Engagements", exact: true })).toHaveAttribute("aria-current", "page");

  await page.goBack();
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeFocused();
  await page.goForward();
  await expect(page.getByRole("heading", { level: 1, name: "Engagements" })).toBeFocused();
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Engagements" })).toBeVisible();
});

test("unknown deep link renders explicit 404 inside the stable shell", async ({ page }) => {
  await installShellApi(page);
  await page.goto("/not-a-redagent-route");

  await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
  await expect(page.getByText(/not part of this operator console/i)).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
  await expect(page.getByText("Synthetic local")).toBeVisible();
});

test("320px modal drawer contains the single primary model and restores focus", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await installShellApi(page);
  await page.goto("/");

  const trigger = page.getByRole("button", { name: "Open navigation" });
  await expect(trigger).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toHaveCount(0);
  await trigger.click();
  const drawer = page.getByRole("dialog", { name: "Primary navigation" });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("navigation", { name: "Primary navigation" })).toHaveCount(1);
  await expect(drawer.getByRole("button", { name: "Close navigation" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect(trigger).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);

  const axe = await new AxeBuilder({ page }).analyze();
  expect(axe.violations.filter((item) => ["serious", "critical"].includes(item.impact))).toEqual([]);
});

test("permission-filtered command search and persistent safety control remain non-authorizing", async ({ page }) => {
  await installShellApi(page, ["campaign:read"]);
  await page.goto("/");

  const search = page.getByRole("combobox", { name: "Find destination" });
  await search.fill("campaign");
  const results = page.getByRole("listbox");
  await expect(results.getByRole("option")).toHaveCount(3);
  await search.press("ArrowDown");
  await expect(search).toBeFocused();
  await expect(search).toHaveAttribute("aria-activedescendant", "route-command-option-campaigns");
  await search.press("Escape");
  await expect(page.getByRole("listbox")).toHaveCount(0);

  await page.getByRole("button", { name: "Stop & revoke" }).click();
  const dialog = page.getByRole("dialog", { name: "Stop and revoke controls" });
  await expect(dialog.getByText(/does not dispatch or grant authority/i)).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
  await expect(dialog.getByRole("link", { name: "Open governed job controls" })).toHaveAttribute("href", "/jobs");
});

test("route-data outage does not erase authoritative shell safety context", async ({ page }) => {
  await installShellApi(page, ["*"] , true);
  await page.goto("/");

  await expect(page.getByText("tenant-r127")).toBeVisible();
  await expect(page.getByText("Synthetic local")).toBeVisible();
  await expect(page.getByRole("alert", { name: "Route data unavailable" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
});


async function installShellApi(page, permissions = ["*"], failEngagements = false) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/context") return json(route, { data: {
      subject: "operator-r127",
      tenant_id: "tenant-r127",
      permissions,
      roles: ["operator"],
      operator_shell: {
        schema_version: "1",
        environment: "local",
        safety_profile: "synthetic-local",
        status: "ready",
      },
    } });
    if (path === "/api/v1/engagements") {
      if (failEngagements) return route.abort("failed");
      return json(route, { data: [], page: { limit: 50, offset: 0, returned: 0 } });
    }
    return json(route, { error: { code: "resource_not_found", message: "Not found" } }, 404);
  });
}

async function json(route, body, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}
