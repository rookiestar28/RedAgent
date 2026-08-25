#!/usr/bin/env node
/** Read-only, loopback-only compat_126 prototype browser qualification. */

import AxeBuilder from "@axe-core/playwright";
import { chromium, firefox, webkit } from "playwright";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "..");
const OUTPUT = path.join(ROOT, "output", "playwright", "compat_126");
const BASE_URL = new URL(process.argv[2] ?? "http://127.0.0.1:4174/");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

if (
  BASE_URL.protocol !== "http:"
  || BASE_URL.hostname !== "127.0.0.1"
  || BASE_URL.username
  || BASE_URL.password
  || BASE_URL.search
  || BASE_URL.hash
  || BASE_URL.pathname !== "/"
) {
  throw new Error("r126_qualification_loopback_url_required");
}
const packageLock = JSON.parse(
  await readFile(path.join(ROOT, "package-lock.json"), "utf8"),
);
const playwrightVersion = packageLock.packages?.["node_modules/@playwright/test"]?.version;
if (playwrightVersion !== "1.61.1") {
  throw new Error("r126_qualification_playwright_pin_mismatch");
}

await mkdir(OUTPUT, { recursive: true });
const results = [];

function assert(condition, code, details = undefined) {
  if (!condition) {
    throw new Error(`${code}${details === undefined ? "" : `:${JSON.stringify(details)}`}`);
  }
}

async function axe(page, label) {
  const scan = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  assert(
    scan.violations.length === 0,
    "r126_qualification_axe_violation",
    {
      label,
      violations: scan.violations.map(({ id, impact, nodes }) => ({
        id,
        impact,
        nodeCount: nodes.length,
        nodes: nodes.slice(0, 10).map(({ target, failureSummary }) => ({
          target,
          failureSummary,
        })),
      })),
    },
  );
}

async function qualifyViewport(
  name,
  engine,
  viewport,
  { launchOptions = {}, expectedVersion } = {},
) {
  const browser = await engine.launch({ headless: true, ...launchOptions });
  const browserVersion = browser.version();
  assert(
    browserVersion === expectedVersion,
    "r126_qualification_browser_pin_mismatch",
    { name, expectedVersion, browserVersion },
  );
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    colorScheme: "dark",
    reducedMotion: "no-preference",
  });
  const page = await context.newPage();
  const consoleErrors = [];
  const resourceErrors = [];
  const hosts = new Set();
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push({ text: message.text(), location: message.location() });
    }
  });
  page.on("request", (request) => hosts.add(new URL(request.url()).host));
  page.on("response", (response) => {
    if (response.status() >= 400) {
      resourceErrors.push({ status: response.status(), url: response.url() });
    }
  });
  try {
    await page.goto(BASE_URL.href, { waitUntil: "domcontentloaded" });
    await page.getByRole("list", { name: "Assessment readiness" }).waitFor();
    const skipLink = page.getByRole("link", { name: "Skip to main content" });
    await skipLink.focus();
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "main-content");
    assert(
      await page.locator("#main-content").evaluate(
        (element) => element === document.activeElement,
      ),
      "r126_qualification_skip_link_focus",
      { name, mode: viewport.label },
    );
    const geometry = await page.evaluate(() => ({
      innerWidth,
      documentScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
    }));
    assert(
      geometry.documentScrollWidth <= geometry.innerWidth
        && geometry.bodyScrollWidth <= geometry.innerWidth,
      "r126_qualification_horizontal_overflow",
      { name, mode: viewport.label, geometry },
    );
    await axe(page, `${name}-${viewport.label}`);
    if (viewport.label === "mobile") {
      const launcher = page.getByRole("button", { name: "Open navigation" });
      await launcher.click();
      const drawer = page.getByRole("dialog", { name: "Primary navigation" });
      await drawer.waitFor();
      await drawer.getByRole("button", { name: "Stop and revoke" }).waitFor();
      const focusEntry = await page.evaluate(
        () => document.activeElement?.getAttribute("aria-label"),
      );
      assert(focusEntry === "Close navigation", "r126_qualification_drawer_focus_entry", {
        name,
        focusEntry,
      });
      await axe(page, `${name}-drawer`);
      await page.keyboard.press("Escape");
      await page.waitForFunction(
        () => document.activeElement?.getAttribute("aria-label") === "Open navigation",
      );
      assert(
        await launcher.evaluate((element) => element === document.activeElement),
        "r126_qualification_drawer_focus_return",
        { name },
      );
    } else {
      await page.keyboard.press("Control+K");
      const combobox = page.getByRole("combobox", {
        name: "Permission-filtered search",
      });
      assert(
        await combobox.evaluate((element) => element === document.activeElement),
        "r126_qualification_combobox_shortcut",
        { name },
      );
      const searchFocus = await combobox.evaluate((element) => {
        const container = element.closest(".header-search");
        const style = container ? getComputedStyle(container) : undefined;
        return {
          outlineStyle: style?.outlineStyle,
          outlineWidth: style?.outlineWidth,
        };
      });
      assert(
        searchFocus.outlineStyle !== "none"
          && Number.parseFloat(searchFocus.outlineWidth ?? "0") >= 2,
        "r126_qualification_combobox_visible_focus",
        { name, searchFocus },
      );
      await combobox.fill("evidence");
      assert(
        await page.getByRole("option").count() === 1,
        "r126_qualification_search_filtered_results",
        { name },
      );
      await combobox.fill("runner");
      await page.getByRole("status")
        .getByText("Result unavailable for current permissions", { exact: true })
        .waitFor();
      await combobox.fill("no-such-permitted-result");
      await page.getByRole("status")
        .getByText("No permitted results", { exact: true })
        .waitFor();
      await page.keyboard.press("Escape");
    }
    await page.screenshot({
      path: path.join(OUTPUT, `${name}-${viewport.label}.png`),
      fullPage: true,
    });
    const routeChecks = [];
    for (const [destination, heading] of [
      ["Campaigns", "Campaign path review"],
      ["Evidence", "Cleanup and evidence reconciliation"],
      ["Findings", "Finding remediation and retest"],
    ]) {
      if (viewport.label === "mobile") {
        await page.getByRole("button", { name: "Open navigation" }).click();
        await page.getByRole("dialog", { name: "Primary navigation" })
          .getByRole("button", { name: destination, exact: true })
          .click();
      } else {
        await page.getByRole("button", { name: destination, exact: true }).click();
      }
      await page.getByRole("heading", { name: heading }).waitFor();
      const routeHeading = page.getByRole("heading", {
        name: destination,
        exact: true,
        level: 1,
      });
      await routeHeading.waitFor();
      await page.waitForFunction(
        (expectedHeading) => document.activeElement?.textContent?.trim() === expectedHeading,
        destination,
      );
      assert(
        await routeHeading.evaluate((element) => element === document.activeElement),
        "r126_qualification_route_heading_focus",
        { name, mode: viewport.label, destination },
      );
      await axe(page, `${name}-${viewport.label}-${destination.toLowerCase()}`);
      const routeGeometry = await page.evaluate(() => ({
        innerWidth,
        documentScrollWidth: document.documentElement.scrollWidth,
        bodyScrollWidth: document.body.scrollWidth,
      }));
      assert(
        routeGeometry.documentScrollWidth <= routeGeometry.innerWidth
          && routeGeometry.bodyScrollWidth <= routeGeometry.innerWidth,
        "r126_qualification_task_route_horizontal_overflow",
        { name, mode: viewport.label, destination, routeGeometry },
      );
      routeChecks.push({ destination, axeViolations: 0, geometry: routeGeometry });
      if (name === "chromium") {
        await page.screenshot({
          path: path.join(
            OUTPUT,
            `${name}-${viewport.label}-${destination.toLowerCase()}.png`,
          ),
          fullPage: true,
        });
      }

      if (destination === "Campaigns") {
        if (viewport.label === "mobile") {
          await page.getByRole("button", { name: "Open navigation" }).click();
          await page.getByRole("dialog", { name: "Primary navigation" })
            .getByRole("button", { name: "Stop and revoke" })
            .click();
        } else {
          await page.getByRole("button", { name: "Stop and revoke" }).click();
        }
        await page.getByRole("button", { name: "Simulate stop" }).click();
        await page.getByText("Containment pending", { exact: true }).waitFor();
        await page.getByText("Blocked — no further synthetic dispatch", { exact: true }).waitFor();
        await axe(page, `${name}-${viewport.label}-campaign-stopped`);
        if (name === "chromium") {
          await page.screenshot({
            path: path.join(OUTPUT, `${name}-${viewport.label}-campaign-stopped.png`),
            fullPage: true,
          });
        }
      }
    }
    const unexpectedHosts = [...hosts].filter(
      (host) => host !== `${BASE_URL.hostname}:${BASE_URL.port}`,
    );
    assert(unexpectedHosts.length === 0, "r126_qualification_external_network", {
      name,
      unexpectedHosts,
    });
    assert(consoleErrors.length === 0, "r126_qualification_console_error", {
      name,
      consoleErrors,
    });
    assert(resourceErrors.length === 0, "r126_qualification_resource_error", {
      name,
      resourceErrors,
    });
    results.push({
      browser: name,
      browserVersion,
      mode: viewport.label,
      geometry,
      axeViolations: 0,
      consoleErrors: 0,
      resourceErrors,
      hosts: [...hosts],
      routeChecks,
      campaignStopOutcome: "containment-pending-dispatch-blocked",
    });
  } finally {
    await context.close();
    await browser.close();
  }
}

const browserMatrix = [
  ["chromium", chromium, { expectedVersion: "149.0.7827.55" }],
  ["edge", chromium, {
    expectedVersion: "151.0.4129.101",
    launchOptions: { channel: "msedge" },
  }],
  ["firefox", firefox, { expectedVersion: "151.0" }],
  ["webkit", webkit, { expectedVersion: "26.5" }],
];
for (const [name, engine, options] of browserMatrix) {
  await qualifyViewport(
    name,
    engine,
    { width: 1440, height: 900, label: "desktop" },
    options,
  );
  await qualifyViewport(
    name,
    engine,
    { width: 320, height: 800, label: "mobile" },
    options,
  );
}

const browser = await chromium.launch({ headless: true });
try {
  const reducedContext = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    colorScheme: "dark",
    reducedMotion: "reduce",
  });
  const reducedPage = await reducedContext.newPage();
  await reducedPage.goto(BASE_URL.href, { waitUntil: "domcontentloaded" });
  const reducedEvidence = await reducedPage.evaluate(() => ({
    media: matchMedia("(prefers-reduced-motion: reduce)").matches,
    maxTransitionMs: Math.max(
      ...[...document.querySelectorAll("*")].map((element) => Math.max(
        0,
        ...getComputedStyle(element).transitionDuration.split(",").map((part) => (
          parseFloat(part) * (part.includes("ms") ? 1 : 1000)
        )),
      )),
    ),
  }));
  assert(
    reducedEvidence.media && reducedEvidence.maxTransitionMs <= 1,
    "r126_qualification_reduced_motion",
    reducedEvidence,
  );
  await reducedPage.screenshot({
    path: path.join(OUTPUT, "chromium-reduced-motion.png"),
    fullPage: true,
  });
  results.push({ browser: "chromium", mode: "reduced-motion", ...reducedEvidence });
  await reducedContext.close();

  const forcedContext = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    forcedColors: "active",
  });
  const forcedPage = await forcedContext.newPage();
  await forcedPage.goto(BASE_URL.href, { waitUntil: "domcontentloaded" });
  const forcedEvidence = await forcedPage.evaluate(() => {
    const stop = document.querySelector('[aria-label="Stop and revoke"]');
    const active = document.querySelector(".nav-link.active");
    return {
      media: matchMedia("(forced-colors: active)").matches,
      stopBorder: getComputedStyle(stop).borderTopStyle,
      activeOutline: getComputedStyle(active).outlineStyle,
    };
  });
  assert(
    forcedEvidence.media
      && forcedEvidence.stopBorder !== "none"
      && forcedEvidence.activeOutline !== "none",
    "r126_qualification_forced_colors",
    forcedEvidence,
  );
  await axe(forcedPage, "chromium-forced-colors");
  await forcedPage.screenshot({
    path: path.join(OUTPUT, "chromium-forced-colors.png"),
    fullPage: true,
  });
  results.push({
    browser: "chromium",
    mode: "forced-colors",
    ...forcedEvidence,
    axeViolations: 0,
  });
  await forcedContext.close();

  // IMPORTANT: WCAG 400% reflow from 1280 px is a 320 CSS px layout;
  // pinch scaling a 320 px layout would incorrectly test an 80 px viewport.
  const sourceViewportWidth = 1280;
  const zoomPercent = 400;
  const equivalentCssWidth = sourceViewportWidth / (zoomPercent / 100);
  const zoomContext = await browser.newContext({
    viewport: { width: equivalentCssWidth, height: 800 },
  });
  const zoomPage = await zoomContext.newPage();
  await zoomPage.goto(BASE_URL.href, { waitUntil: "domcontentloaded" });
  const zoomEvidence = await zoomPage.evaluate(() => ({
    innerWidth,
    documentScrollWidth: document.documentElement.scrollWidth,
    bodyScrollWidth: document.body.scrollWidth,
  }));
  assert(
    equivalentCssWidth === 320
      && zoomEvidence.innerWidth === equivalentCssWidth
      && zoomEvidence.documentScrollWidth <= zoomEvidence.innerWidth
      && zoomEvidence.bodyScrollWidth <= zoomEvidence.innerWidth,
    "r126_qualification_400_percent",
    zoomEvidence,
  );
  await zoomPage.screenshot({
    path: path.join(OUTPUT, "chromium-400-percent.png"),
  });
  results.push({
    browser: "chromium",
    mode: "400-percent-reflow-equivalent",
    sourceViewportWidth,
    zoomPercent,
    equivalentCssWidth,
    ...zoomEvidence,
  });
  await zoomContext.close();
} finally {
  await browser.close();
}

console.log(JSON.stringify({
  ok: true,
  schema: "redagent.r126.browser-qualification/v1",
  playwrightVersion,
  baseUrl: BASE_URL.href,
  results,
}, null, 2));
