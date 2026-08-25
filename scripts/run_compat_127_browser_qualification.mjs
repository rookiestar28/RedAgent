#!/usr/bin/env node
/** Loopback-only compat_127 shell smoke across the frozen compat_126 browser matrix. */

import AxeBuilder from "@axe-core/playwright";
import { chromium, firefox, webkit } from "playwright";


const BASE_URL = new URL(process.argv[2] ?? "http://127.0.0.1:4173/");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
if (
  BASE_URL.protocol !== "http:"
  || BASE_URL.hostname !== "127.0.0.1"
  || BASE_URL.username
  || BASE_URL.password
  || BASE_URL.search
  || BASE_URL.hash
  || BASE_URL.pathname !== "/"
) throw new Error("r127_qualification_loopback_url_required");

const browsers = [
  ["chromium", chromium, { expectedVersion: "149.0.7827.55" }],
  ["edge", chromium, { expectedVersion: "151.0.4129.101", launchOptions: { channel: "msedge" } }],
  ["firefox", firefox, { expectedVersion: "151.0" }],
  ["webkit", webkit, { expectedVersion: "26.5" }],
];
const viewports = [
  { label: "desktop", width: 1440, height: 900 },
  { label: "mobile", width: 320, height: 800 },
];
const results = [];

for (const [browserName, engine, options] of browsers) {
  const browser = await engine.launch({ headless: true, ...(options.launchOptions ?? {}) });
  assert(browser.version() === options.expectedVersion, "r127_browser_pin_mismatch", {
    browserName,
    expected: options.expectedVersion,
    actual: browser.version(),
  });
  try {
    for (const viewport of viewports) {
      results.push(await qualify(browser, browserName, viewport));
    }
    if (browserName === "chromium") {
      results.push(await qualify(browser, browserName, {
        label: "reduced-motion",
        width: 1440,
        height: 900,
      }, { reducedMotion: "reduce" }));
      results.push(await qualify(browser, browserName, {
        label: "forced-colors",
        width: 1440,
        height: 900,
      }, { forcedColors: "active" }));
    }
  } finally {
    await browser.close();
  }
}

process.stdout.write(`${JSON.stringify({ status: "PASS", rows: results }, null, 2)}\n`);

async function qualify(browser, browserName, viewport, media = {}) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    colorScheme: "dark",
    reducedMotion: media.reducedMotion ?? "no-preference",
    ...(media.forcedColors ? { forcedColors: media.forcedColors } : {}),
  });
  const page = await context.newPage();
  const consoleErrors = [];
  const resourceErrors = [];
  const hosts = new Set();
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("request", (request) => hosts.add(new URL(request.url()).host));
  page.on("response", (response) => {
    if (response.status() >= 400) resourceErrors.push(`${response.status()}:${response.url()}`);
  });
  await page.route("**/api/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/api/v1/context") return fulfill(route, { data: {
      subject: "qualifier-r127",
      tenant_id: "tenant-r127",
      roles: ["reviewer"],
      permissions: ["*"],
      operator_shell: {
        schema_version: "1",
        environment: "local",
        safety_profile: "local-conformance",
        status: "ready",
      },
    } });
    if (pathname === "/api/v1/engagements") {
      return fulfill(route, { data: [], page: { limit: 50, offset: 0, returned: 0 } });
    }
    return fulfill(route, { error: { code: "not_found", message: "Not found" } }, 404);
  });
  try {
    await page.goto(BASE_URL.href, { waitUntil: "networkidle" });
    await page.getByRole("heading", { level: 1, name: "Overview" }).waitFor();
    await page.getByText("Local conformance").waitFor();
    const skipLink = page.getByRole("link", { name: "Skip to main content" });
    await skipLink.focus();
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "main-content");

    if (viewport.label === "mobile") {
      assert(await page.getByRole("navigation", { name: "Primary navigation" }).count() === 0, "r127_mobile_hidden_navigation_exposed", { browserName });
      const trigger = page.getByRole("button", { name: "Open navigation" });
      await trigger.click();
      const drawer = page.getByRole("dialog", { name: "Primary navigation" });
      await drawer.waitFor();
      await page.waitForFunction(() => document.activeElement?.textContent?.includes("Close navigation"));
      await axe(page, `${browserName}-mobile-drawer`);
      await page.keyboard.press("Escape");
      await page.waitForFunction(() => document.activeElement?.textContent?.includes("Open navigation"));
    } else {
      assert(await page.getByRole("navigation", { name: "Primary navigation" }).count() === 1, "r127_primary_navigation_count", { browserName });
      assert(await page.getByRole("banner").locator('a[href="/engagements"]').count() === 0, "r127_header_module_link", { browserName });
    }

    const geometry = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    assert(geometry.scrollWidth <= geometry.clientWidth + 1, "r127_horizontal_overflow", { browserName, viewport, geometry });
    await axe(page, `${browserName}-${viewport.label}`);

    const mediaEvidence = await page.evaluate(() => {
      const focused = document.querySelector(':focus-visible');
      const current = document.querySelector('.primary-navigation a[aria-current="page"]');
      const stop = document.querySelector('.danger-action');
      const durations = [...document.querySelectorAll("*")].flatMap((element) => (
        getComputedStyle(element).transitionDuration.split(",").map((part) => (
          parseFloat(part) * (part.includes("ms") ? 1 : 1000)
        ))
      ));
      return {
        forcedColors: matchMedia("(forced-colors: active)").matches,
        reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
        maxTransitionMs: Math.max(0, ...durations),
        focusedOutline: focused ? getComputedStyle(focused).outlineStyle : "none",
        currentBorder: current ? getComputedStyle(current).borderLeftStyle : "none",
        stopBorder: stop ? getComputedStyle(stop).borderTopStyle : "none",
      };
    });
    if (media.reducedMotion === "reduce") {
      assert(
        mediaEvidence.reducedMotion && mediaEvidence.maxTransitionMs <= 1,
        "r127_reduced_motion_failure",
        { browserName, mediaEvidence },
      );
    }
    if (media.forcedColors === "active") {
      assert(
        mediaEvidence.forcedColors
          && mediaEvidence.focusedOutline !== "none"
          && mediaEvidence.currentBorder !== "none"
          && mediaEvidence.stopBorder !== "none",
        "r127_forced_colors_failure",
        { browserName, mediaEvidence },
      );
    }

    if (viewport.label === "mobile") {
      await page.getByRole("button", { name: "Open navigation" }).click();
      await page.getByRole("dialog", { name: "Primary navigation" }).getByRole("link", { name: "Engagements", exact: true }).click();
    } else {
      await page.getByRole("link", { name: "Engagements", exact: true }).click();
    }
    await page.getByRole("heading", { level: 1, name: "Engagements" }).waitFor();
    assert(
      await page.getByRole("heading", { level: 1, name: "Engagements" }).evaluate((element) => element === document.activeElement),
      "r127_route_heading_focus",
      { browserName, viewport: viewport.label },
    );

    await page.goto(new URL("/unknown-r127", BASE_URL).href, { waitUntil: "networkidle" });
    await page.getByRole("heading", { level: 1, name: "Page not found" }).waitFor();
    assert(consoleErrors.length === 0, "r127_console_errors", { browserName, viewport: viewport.label, consoleErrors });
    assert(resourceErrors.length === 0, "r127_resource_errors", { browserName, viewport: viewport.label, resourceErrors });
    const unexpectedHosts = [...hosts].filter((host) => host !== BASE_URL.host);
    assert(unexpectedHosts.length === 0, "r127_external_network", { browserName, viewport: viewport.label, unexpectedHosts });
    return { browserName, viewport: viewport.label, geometry, axe: "PASS", media: mediaEvidence };
  } finally {
    await context.close();
  }
}

async function axe(page, label) {
  const scan = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  assert(scan.violations.length === 0, "r127_axe_violation", {
    label,
    violations: scan.violations.map(({ id, impact, nodes }) => ({ id, impact, nodes: nodes.length })),
  });
}

async function fulfill(route, body, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function assert(condition, code, details = undefined) {
  if (!condition) throw new Error(`${code}${details === undefined ? "" : `:${JSON.stringify(details)}`}`);
}
