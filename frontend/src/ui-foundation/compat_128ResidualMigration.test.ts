import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { APPLICATION_ROUTES } from "../shell/routeRegistry";
import { OPERATIONAL_SURFACE_INVENTORY } from "./operationalSurfaceInventory";


describe("compat_128 residual surface migration contract", () => {
  it("keeps exactly the three immutable compat_124 campaign routes", () => {
    expect(APPLICATION_ROUTES.filter(({ path }) => path.startsWith("/campaigns"))
      .map(({ id, path }) => ({ id, path }))).toEqual([
      { id: "campaigns", path: "/campaigns" },
      { id: "campaign-attention", path: "/campaigns/attention" },
      { id: "campaign-new", path: "/campaigns/new" },
    ]);
  });

  it("removes the development-only lifecycle route and inventory entry", () => {
    expect(APPLICATION_ROUTES.some(({ path }) => path === "/states")).toBe(false);
    expect(OPERATIONAL_SURFACE_INVENTORY.some(({ path }) => path === "/states")).toBe(false);
    expect(APPLICATION_ROUTES).toHaveLength(26);
    expect(OPERATIONAL_SURFACE_INVENTORY).toHaveLength(23);
  });

  it("deletes the page monolith and legacy route wrapper composition", () => {
    const monolith = resolve(process.cwd(), "frontend/src/OperationalPages.tsx");
    const routePort = readFileSync(
      resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"),
      "utf8",
    );

    expect(existsSync(monolith)).toBe(false);
    expect(routePort).not.toContain("../OperationalPages");
    expect(routePort).not.toContain("LegacyRawIdMutationGuard");
    expect(routePort).not.toMatch(/function Legacy\(/);
  });

  it("pins the complete residual browser and visual acceptance contracts", () => {
    const browserRunner = readFileSync(
      resolve(process.cwd(), "scripts/run_compat_128_browser_qualification.mjs"),
      "utf8",
    );
    const visualSpec = readFileSync(
      resolve(process.cwd(), "tests/e2e/compat_128-visual.spec.js"),
      "utf8",
    );

    for (const token of [
      '"/"', '"/engagements"', '"/jobs"', '"/access"', '"/policy"',
      '"/evidence"', '"/finding-operations"', '"/secrets"', '"/activity"',
      '"/runners"', '"/observability"', '"/lab"', '"/zap"', '"/nuclei"',
      '"/api-differential"', '"/network-assessment"', '"/cloud-posture"',
      '"/identity-posture"', '"/artifact-posture"', '"/purple-lab"',
      '"/human-simulation"', '"/agent"', '"/workbench"', '"/states"',
    ]) expect(browserRunner).toContain(token);
    for (const token of ["149.0.7827.55", "151.0.4129.101", "151.0", "26.5",
      "wcag22aa", "r128_external_network", "r128_route_load_budget",
      "r128_400_percent_reflow", "r128_text_spacing_overflow", "r128_target_size",
    ]) expect(browserRunner).toContain(token);
    expect(visualSpec).toContain("maxDiffPixelRatio: 0.001");
    expect(visualSpec).toContain("animations: \"disabled\"");
  });
});
