#!/usr/bin/env node
/** Loopback-only compat_128 residual-route browser, reflow, and media qualification. */

import AxeBuilder from "@axe-core/playwright";
import { chromium, firefox, webkit } from "playwright";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "..");
const BASE_URL = new URL(process.argv.find((value) => value.startsWith("http://")) ?? "http://127.0.0.1:4173/");
const MEDIA_ONLY = process.argv.includes("--media-only");
const PERFORMANCE_ONLY = process.argv.includes("--performance-only");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const ROUTE_LOAD_BUDGET_MS = 5_000;
const ROUTES = [
  ["/", "Overview"], ["/engagements", "Engagements"], ["/jobs", "Jobs"],
  ["/access", "Access"], ["/policy", "Policy"], ["/evidence", "Evidence"],
  ["/finding-operations", "Findings and remediation"], ["/secrets", "Credential leases"],
  ["/activity", "Activity"], ["/runners", "Runners"], ["/observability", "Observability"],
  ["/lab", "Safe lab"], ["/zap", "ZAP runtime"], ["/nuclei", "Nuclei runtime"],
  ["/api-differential", "API authorization"], ["/network-assessment", "Network assessment"],
  ["/cloud-posture", "Cloud posture"], ["/identity-posture", "Identity posture"],
  ["/artifact-posture", "Artifact posture"], ["/purple-lab", "Purple lab"],
  ["/human-simulation", "Human simulation"], ["/agent", "Agent kernel"],
  ["/workbench", "Campaign workbench"], ["/states", "Page not found"],
];
const BROWSERS = [
  ["chromium", chromium, { expectedVersion: "149.0.7827.55" }],
  ["edge", chromium, { expectedVersion: "151.0.4129.101", launchOptions: { channel: "msedge" } }],
  ["firefox", firefox, { expectedVersion: "151.0" }],
  ["webkit", webkit, { expectedVersion: "26.5" }],
];
const VIEWPORTS = [
  { label: "desktop", width: 1440, height: 900 },
  { label: "mobile-portrait", width: 320, height: 800 },
];

assert(BASE_URL.protocol === "http:" && BASE_URL.hostname === "127.0.0.1"
  && BASE_URL.pathname === "/" && !BASE_URL.username && !BASE_URL.password
  && !BASE_URL.search && !BASE_URL.hash, "r128_loopback_url_required");
assert(ROUTES.length === 24, "r128_route_inventory_count", { count: ROUTES.length });
const packageLock = JSON.parse(await readFile(path.join(ROOT, "package-lock.json"), "utf8"));
assert(packageLock.packages?.["node_modules/@playwright/test"]?.version === "1.61.1",
  "r128_playwright_pin_mismatch");
const UI_BUDGETS = JSON.parse(await readFile(path.join(
  ROOT, "frontend", "src", "ui-foundation", "uiFoundationBudgetManifest.json",
), "utf8")).performance;

const results = [];
for (const [browserName, engine, options] of MEDIA_ONLY || PERFORMANCE_ONLY ? [] : BROWSERS) {
  const browser = await engine.launch({ headless: true, ...(options.launchOptions ?? {}) });
  assert(browser.version() === options.expectedVersion, "r128_browser_pin_mismatch", {
    browserName, expected: options.expectedVersion, actual: browser.version(),
  });
  try {
    for (const viewport of VIEWPORTS) {
      record(await qualifyRoutes(browser, browserName, viewport));
    }
  } finally {
    await browser.close();
  }
}

const chromiumBrowser = await chromium.launch({ headless: true });
try {
  if (!MEDIA_ONLY && !PERFORMANCE_ONLY) {
    record(await qualifyRoutes(chromiumBrowser, "chromium", {
      label: "mobile-landscape", width: 800, height: 320,
    }, { runAxe: false }));
    record(await qualifyRoutes(chromiumBrowser, "chromium", {
      label: "400-percent-reflow", width: 320, height: 800,
    }, { runAxe: false, assertionPrefix: "r128_400_percent_reflow" }));
    record(await qualifyRoutes(chromiumBrowser, "chromium", {
      label: "text-spacing", width: 320, height: 800,
    }, { runAxe: false, textSpacing: true, assertionPrefix: "r128_text_spacing_overflow" }));
  }
  if (!PERFORMANCE_ONLY) {
    record(await qualifyMedia(chromiumBrowser, "reduced-motion", { reducedMotion: "reduce" }));
    record(await qualifyMedia(chromiumBrowser, "forced-colors", { forcedColors: "active" }));
  }
  if (!MEDIA_ONLY) record(await qualifyPerformance(chromiumBrowser));
} finally {
  await chromiumBrowser.close();
}

process.stdout.write(`${JSON.stringify({
  status: "PASS",
  schema: "redagent.r128.browser-qualification/v1",
  playwrightVersion: "1.61.1",
  routeCount: ROUTES.length,
  results,
}, null, 2)}\n`);

async function qualifyRoutes(browser, browserName, viewport, options = {}) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    colorScheme: "dark",
    reducedMotion: "no-preference",
  });
  const page = await context.newPage();
  const consoleErrors = [];
  const resourceErrors = [];
  const hosts = new Set();
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  page.on("request", (request) => hosts.add(new URL(request.url()).host));
  page.on("response", (response) => {
    const pathname = new URL(response.url()).pathname;
    if (response.status() >= 400 && !pathname.startsWith("/api/v1/")) {
      resourceErrors.push(`${response.status()}:${response.url()}`);
    }
  });
  await installApiFixture(page);
  const loads = [];
  try {
    for (const [routePath, heading] of ROUTES) {
      const started = performance.now();
      await page.goto(new URL(routePath, BASE_URL).href, { waitUntil: "networkidle" });
      const routeHeading = page.getByRole("heading", { level: 1, name: heading, exact: true });
      await routeHeading.waitFor();
      const loadMs = performance.now() - started;
      assert(loadMs <= ROUTE_LOAD_BUDGET_MS, "r128_route_load_budget", {
        browserName, viewport: viewport.label, routePath, loadMs,
      });
      assert(await routeHeading.evaluate((element) => element === document.activeElement),
        "r128_route_heading_focus", { browserName, viewport: viewport.label, routePath });
      const mainText = await page.getByRole("main").innerText();
      assert(mainText.includes(heading) && mainText.trim().length > heading.length + 20,
        "r128_route_body_missing", { browserName, viewport: viewport.label, routePath, mainText });
      assert(await page.getByRole("alert", { name: "Route access denied" }).count() === 0,
        "r128_route_access_denied", { browserName, viewport: viewport.label, routePath });
      if (routePath === "/engagements") {
        await qualifyEngagementWorkflow(page, browserName, viewport.label);
      }
      if (options.textSpacing) {
        await page.addStyleTag({ content: "*{line-height:1.5!important;letter-spacing:.12em!important;word-spacing:.16em!important}p{margin-bottom:2em!important}" });
      }
      const geometry = await page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
      }));
      const assertionCode = options.assertionPrefix ?? "r128_horizontal_overflow";
      assert(geometry.documentWidth <= geometry.clientWidth + 1
        && geometry.bodyWidth <= geometry.clientWidth + 1, assertionCode,
      { browserName, viewport: viewport.label, routePath, geometry });
      const undersizedTargets = await page.evaluate(() => [...document.querySelectorAll("button,input,select,textarea")]
        .filter((element) => {
          const rectangle = element.getBoundingClientRect();
          const style = getComputedStyle(element);
          return style.display !== "none" && style.visibility !== "hidden"
            && rectangle.width > 0 && rectangle.height > 0
            && (rectangle.width < 24 || rectangle.height < 24);
        }).map((element) => ({ tag: element.tagName, label: element.getAttribute("aria-label") ?? element.textContent?.trim() ?? "" })));
      assert(undersizedTargets.length === 0, "r128_target_size", {
        browserName, viewport: viewport.label, routePath, undersizedTargets,
      });
      if (options.runAxe !== false) await axe(page, `${browserName}-${viewport.label}-${routePath}`);
      loads.push(loadMs);
    }
    const unexpectedHosts = [...hosts].filter((host) => host !== BASE_URL.host);
    assert(unexpectedHosts.length === 0, "r128_external_network", { browserName, viewport: viewport.label, unexpectedHosts });
    assert(consoleErrors.length === 0, "r128_console_errors", { browserName, viewport: viewport.label, consoleErrors });
    assert(resourceErrors.length === 0, "r128_resource_errors", { browserName, viewport: viewport.label, resourceErrors });
    return {
      browser: browserName, viewport: viewport.label, routes: ROUTES.length,
      axe: options.runAxe === false ? "covered-by-primary-matrix" : "PASS",
      maxLoadMs: Math.round(Math.max(...loads)), externalHosts: 0, consoleErrors: 0, resourceErrors: 0,
    };
  } finally {
    await context.close();
  }
}

async function qualifyMedia(browser, label, media) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ...media });
  const page = await context.newPage();
  await installApiFixture(page);
  try {
    await page.goto(BASE_URL.href, { waitUntil: "networkidle" });
    await page.getByRole("heading", { level: 1, name: "Overview" }).waitFor();
    const evidence = await page.evaluate(() => ({
      reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
      forcedColors: matchMedia("(forced-colors: active)").matches,
      maxTransitionMs: Math.max(0, ...[...document.querySelectorAll("*")].flatMap((element) =>
        getComputedStyle(element).transitionDuration.split(",").map((part) => parseFloat(part) * (part.includes("ms") ? 1 : 1000)))),
      currentBorder: getComputedStyle(document.querySelector('.primary-navigation a[aria-current="page"]')).borderLeftStyle,
      stopBorder: getComputedStyle(document.querySelector(".danger-action")).borderTopStyle,
    }));
    if (label === "reduced-motion") assert(evidence.reducedMotion && evidence.maxTransitionMs <= 1,
      "r128_reduced_motion", evidence);
    if (label === "forced-colors") assert(evidence.forcedColors
      && evidence.currentBorder !== "none" && evidence.stopBorder !== "none", "r128_forced_colors", evidence);
    await axe(page, `chromium-${label}`);
    return { browser: "chromium", viewport: label, routes: 1, axe: "PASS", ...evidence };
  } finally {
    await context.close();
  }
}

async function installApiFixture(page) {
  let engagement = null;
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (pathname === "/api/v1/context") return fulfill(route, { data: {
      subject: "qualifier-r128", tenant_id: "tenant-r128", roles: ["reviewer"], permissions: ["*"],
      operator_shell: { schema_version: "1", environment: "local", safety_profile: "local-conformance", status: "ready" },
    } });
    if (pathname === "/api/v1/engagements" && request.method() === "POST") {
      engagement = { ...request.postDataJSON(), tenant_id: "tenant-r128", version: 1 };
      return fulfill(route, { data: engagement, meta: {
        replayed: false, audit_id: "audit-r128-matrix", outbox_id: "outbox-r128-matrix",
      } }, 201);
    }
    if (pathname === "/api/v1/engagements") {
      return fulfill(route, { data: engagement ? [engagement] : [], page: {
        limit: 50, offset: 0, returned: engagement ? 1 : 0, next_offset: null,
      } });
    }
    if (pathname.endsWith("/targets") || pathname.endsWith("/roe-versions")) {
      return fulfill(route, { data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } });
    }
    if (pathname === "/api/v1/jobs"
      || pathname === "/api/v1/containment-controls") {
      return fulfill(route, { data: [], page: { limit: 50, offset: 0, returned: 0 } });
    }
    if (pathname === "/api/v1/quotas/status") return fulfill(route, { data: [] });
    // IMPORTANT: a body-less success response exercises fail-closed client parsing without
    // manufacturing browser-level 4xx console noise that could mask real console exceptions.
    return route.fulfill({ status: 204 });
  });
}

async function qualifyEngagementWorkflow(page, browserName, viewport) {
  await page.getByRole("heading", { level: 2, name: "Engagements", exact: true }).waitFor();
  const create = page.getByRole("button", { name: "Create engagement", exact: true });
  assert(await create.isEnabled(), "r128_engagement_wildcard_create_disabled", { browserName, viewport });
  assert(await page.getByLabel("Engagement ID").count() === 0,
    "r128_engagement_raw_id_input", { browserName, viewport });
  await page.getByLabel("Engagement name").fill("Matrix synthetic engagement");
  await create.click();
  await page.getByRole("heading", { name: "Matrix synthetic engagement", exact: true }).waitFor();
  assert(await page.getByText("No targets defined", { exact: true }).count() === 1,
    "r128_engagement_workflow_target_state_missing", { browserName, viewport });
}

async function qualifyPerformance(browser) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const totalRecords = UI_BUDGETS.largeData.totalRecords;
  const rows = Array.from({ length: totalRecords }, (_, index) => ({
    engagement_id: `engagement-r128-perf-${String(index).padStart(4, "0")}`,
    tenant_id: "tenant-r128-performance",
    name: `compat_128 performance engagement ${String(index).padStart(4, "0")}`,
    owner_user_id: "performance-operator-r128",
    version: 1,
  }));
  await page.addInitScript(() => {
    window.__r128LongTasks = [];
    new PerformanceObserver((list) => {
      window.__r128LongTasks.push(...list.getEntries().map(({ duration }) => duration));
    }).observe({ type: "longtask", buffered: true });
  });
  await installPerformanceFixture(page, rows);
  const shellReadyMilliseconds = [];
  const largeDataReadyMilliseconds = [];
  const feedbackMilliseconds = [];
  const commandSearchMilliseconds = [];
  const longTasksMilliseconds = [];
  let renderedRows = 0;
  let largeDataDomElements = 0;
  try {
    for (let sample = 0; sample < 20; sample += 1) {
      const started = performance.now();
      await page.goto(BASE_URL.href, { waitUntil: "domcontentloaded" });
      await page.getByRole("heading", { level: 1, name: "Overview", exact: true }).waitFor();
      await page.getByText("compat_128 performance engagement 0000", { exact: true }).waitFor();
      shellReadyMilliseconds.push(performance.now() - started);
      longTasksMilliseconds.push(...await consumeLongTasks(page));
    }
    await page.goto(new URL("/engagements", BASE_URL).href, { waitUntil: "domcontentloaded" });
    const engagementRows = page.locator("main .record-list");
    await engagementRows.getByText("compat_128 performance engagement 0000", { exact: true }).waitFor();
    for (let sample = 0; sample < 20; sample += 1) {
      const nextPage = sample % 2 === 0;
      const started = performance.now();
      await page.getByRole("button", {
        name: nextPage ? "Next engagements" : "Previous engagements", exact: true,
      }).click();
      await engagementRows.getByText(
        nextPage ? "compat_128 performance engagement 0050" : "compat_128 performance engagement 0000",
        { exact: true },
      ).waitFor();
      largeDataReadyMilliseconds.push(performance.now() - started);
      renderedRows = await page.locator("main .record-list > li").count();
      largeDataDomElements = await page.locator("main *").count();
      longTasksMilliseconds.push(...await consumeLongTasks(page));
    }
    const search = page.getByRole("combobox", { name: "Find destination" });
    for (let sample = 0; sample < 20; sample += 1) {
      const started = performance.now();
      await search.fill("workbench");
      await page.getByRole("option").getByText("Campaign workbench", { exact: true }).waitFor();
      commandSearchMilliseconds.push(performance.now() - started);
      await search.press("Escape");
    }
    const stop = page.getByRole("button", { name: "Stop & revoke", exact: true });
    for (let sample = 0; sample < 20; sample += 1) {
      const started = performance.now();
      await stop.click();
      await page.getByRole("dialog", { name: "Stop and revoke" }).waitFor();
      feedbackMilliseconds.push(performance.now() - started);
      await page.keyboard.press("Escape");
    }
    longTasksMilliseconds.push(...await consumeLongTasks(page));

    const evidence = {
      shellReadyMilliseconds,
      feedbackMilliseconds,
      commandSearchMilliseconds,
      largeDataReadyMilliseconds,
      longTasksMilliseconds,
      totalRecords,
      renderedRows,
      largeDataDomElements,
      p95: {
        shellReadyMilliseconds: percentile(shellReadyMilliseconds, 0.95),
        feedbackMilliseconds: percentile(feedbackMilliseconds, 0.95),
        commandSearchMilliseconds: percentile(commandSearchMilliseconds, 0.95),
        largeDataReadyMilliseconds: percentile(largeDataReadyMilliseconds, 0.95),
      },
      maximumLongTaskMilliseconds: Math.max(0, ...longTasksMilliseconds),
    };
    assert(evidence.p95.shellReadyMilliseconds <= UI_BUDGETS.localShellReadyP95Milliseconds,
      "r128_shell_ready_budget", evidence);
    assert(evidence.p95.feedbackMilliseconds <= UI_BUDGETS.localFeedbackP95Milliseconds,
      "r128_feedback_budget", evidence);
    assert(evidence.p95.commandSearchMilliseconds <= UI_BUDGETS.commandSearch.readyP95Milliseconds,
      "r128_command_search_budget", evidence);
    assert(evidence.p95.largeDataReadyMilliseconds <= UI_BUDGETS.largeData.readyP95Milliseconds,
      "r128_large_data_ready_budget", evidence);
    assert(renderedRows > 0 && renderedRows <= UI_BUDGETS.largeData.renderedPageSize,
      "r128_large_data_page_bound", evidence);
    assert(largeDataDomElements <= UI_BUDGETS.largeData.maximumWorkspaceDomElements,
      "r128_large_data_dom_budget", evidence);
    assert(longTasksMilliseconds.every((duration) => duration < UI_BUDGETS.longTaskMaximumMilliseconds),
      "r128_long_task_budget", evidence);
    return { browser: "chromium", viewport: "performance", routes: 2, axe: "covered-by-primary-matrix", ...evidence };
  } finally {
    await context.close();
  }
}

async function installPerformanceFixture(page, rows) {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/v1/context") return fulfill(route, { data: {
      subject: "performance-operator-r128", tenant_id: "tenant-r128-performance",
      roles: ["operator"], permissions: ["*"],
      operator_shell: { schema_version: "1", environment: "local", safety_profile: "local-conformance", status: "ready" },
    } });
    if (url.pathname === "/api/v1/engagements") {
      const limit = Math.min(50, Number(url.searchParams.get("limit") ?? "50"));
      const offset = Math.max(0, Number(url.searchParams.get("offset") ?? "0"));
      const data = rows.slice(offset, offset + limit);
      const nextOffset = offset + data.length < rows.length ? offset + data.length : null;
      return fulfill(route, { data, page: {
        limit, offset, returned: data.length, total: rows.length, next_offset: nextOffset,
      } });
    }
    return route.fulfill({ status: 204 });
  });
}

async function consumeLongTasks(page) {
  return page.evaluate(() => {
    const durations = [...(window.__r128LongTasks ?? [])];
    window.__r128LongTasks = [];
    return durations;
  });
}

function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * quantile) - 1)] ?? Number.NaN;
}

async function axe(page, label) {
  const scan = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  assert(scan.violations.length === 0, "r128_axe_violation", {
    label, violations: scan.violations.map(({ id, impact, nodes }) => ({
      id, impact, nodes: nodes.length,
      samples: nodes.slice(0, 8).map(({ target, failureSummary }) => ({ target, failureSummary })),
    })),
  });
}

async function fulfill(route, body, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function assert(condition, code, details = undefined) {
  if (!condition) throw new Error(`${code}${details === undefined ? "" : `:${JSON.stringify(details)}`}`);
}

function record(result) {
  results.push(result);
  process.stderr.write(`r128_matrix_row_pass browser=${result.browser} viewport=${result.viewport} routes=${result.routes}\n`);
}
