import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  APPLICATION_ROUTES,
  commandRoutesForPermissions,
  isSafeApplicationPath,
  orientationRoutesForPermissions,
  validateRouteRegistry,
} from "./routeRegistry";


const EXPECTED_PATHS = [
  "/", "/access", "/activity", "/agent", "/api-differential", "/artifact-posture",
  "/campaigns", "/campaigns/attention", "/campaigns/new", "/cloud-posture",
  "/engagements", "/evidence", "/finding-operations", "/human-simulation",
  "/identity-posture", "/jobs", "/lab", "/network-assessment", "/nuclei",
  "/observability", "/policy", "/purple-lab", "/runners", "/secrets",
  "/workbench", "/zap",
] as const;


describe("compat_127 typed route registry", () => {
  it("is the complete unique source for all 26 current routes", () => {
    expect(APPLICATION_ROUTES.map(({ path }) => path).sort()).toEqual([...EXPECTED_PATHS]);
    expect(APPLICATION_ROUTES).toHaveLength(26);
    expect(validateRouteRegistry(APPLICATION_ROUTES)).toEqual([]);
  });

  it("records complete routing, orientation, and lazy-adapter metadata", () => {
    for (const route of APPLICATION_ROUTES) {
      expect(route.id).toBeTruthy();
      expect(route.title).toBeTruthy();
      expect(route.breadcrumb.length).toBeGreaterThan(0);
      expect(route.featureState).toMatch(/^(enabled|conditional|development)$/);
      expect(route.visibility).toMatch(/^(production|development)$/);
      expect(route.load).toBeTypeOf("function");
      if (route.visibility === "production") expect(route.group).not.toBeNull();
    }
    expect(APPLICATION_ROUTES.filter(({ visibility }) => visibility === "production")).toHaveLength(26);
    expect(APPLICATION_ROUTES.every(({ visibility }) => visibility === "production")).toBe(true);
  });

  it("fails closed on duplicate or incomplete records", () => {
    const first = APPLICATION_ROUTES[0];
    expect(first).toBeDefined();
    if (!first) return;
    expect(validateRouteRegistry([...APPLICATION_ROUTES, first])).toContain(`duplicate route id: ${first.id}`);
    expect(validateRouteRegistry([{ ...first, title: "", breadcrumb: [] }])).toEqual(expect.arrayContaining([
      `${first.path} title is required`,
      `${first.path} breadcrumb is required`,
    ]));
  });

  it("filters bounded command results by authenticated permissions without granting authority", () => {
    const results = commandRoutesForPermissions(
      APPLICATION_ROUTES,
      ["campaign:read"],
      "campaign",
      10,
    );
    expect(results.map(({ path }) => path)).toEqual([
      "/campaigns",
      "/campaigns/attention",
      "/campaigns/new",
    ]);
    expect(commandRoutesForPermissions(APPLICATION_ROUTES, [], "campaign", 10)).toEqual([]);
    expect(commandRoutesForPermissions(APPLICATION_ROUTES, ["*"], "", 100)).toHaveLength(26);
    expect(commandRoutesForPermissions(APPLICATION_ROUTES, ["*"], "", 2)).toHaveLength(2);
    expect(orientationRoutesForPermissions(APPLICATION_ROUTES, ["campaign:read"], {
      campaignCreateEnabled: false,
    }).map(({ path }) => path)).toEqual(["/", "/campaigns", "/campaigns/attention"]);
  });

  it("rejects open-redirect, backslash, traversal, query, and unknown path candidates", () => {
    expect(isSafeApplicationPath("/engagements")).toBe(true);
    expect(isSafeApplicationPath("https://example.test/engagements")).toBe(false);
    expect(isSafeApplicationPath("//example.test/engagements")).toBe(false);
    expect(isSafeApplicationPath("/\\example.test")).toBe(false);
    expect(isSafeApplicationPath("/../engagements")).toBe(false);
    expect(isSafeApplicationPath("/engagements?authority=claimed")).toBe(false);
    expect(isSafeApplicationPath("/unknown")).toBe(false);
  });

  it("deletes the legacy header catalog, raw App pathname chain, and horizontal nowrap strip", () => {
    const appSource = readFileSync(resolve(process.cwd(), "frontend/src/App.tsx"), "utf8");
    const shellSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/OperationalShell.tsx"), "utf8");
    const styles = readFileSync(resolve(process.cwd(), "frontend/src/styles.css"), "utf8");

    expect(appSource).not.toContain("window.location.pathname");
    expect(appSource).not.toContain("Control plane</h1>");
    expect(shellSource).not.toContain('<nav className="primary-nav"');
    expect(readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8"))
      .not.toMatch(/if\s*\(path\s*===/);
    expect(styles).not.toMatch(/\.primary-nav\s*\{/);
    expect(styles).not.toMatch(/white-space:\s*nowrap/);
    expect(styles).not.toMatch(/overflow-x:\s*auto/);
  });
});
