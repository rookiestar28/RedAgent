import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  UI_FOUNDATION_CONTRACT_VERSION,
  UI_FOUNDATION_QUALIFICATION,
  validateUiFoundationQualification,
} from "./uiFoundationQualification";

describe("compat_126 qualification contract", () => {
  it("versions the contract and freezes every canonical viewport", () => {
    expect(UI_FOUNDATION_CONTRACT_VERSION).toBe("2026-08-25.r126.2");
    expect(UI_FOUNDATION_QUALIFICATION.viewports).toEqual([
      { id: "desktop", width: 1440, height: 900 },
      { id: "tablet", width: 1024, height: 768 },
      { id: "mobile", width: 390, height: 844 },
      { id: "reflow", width: 320, height: 800 },
    ]);
  });

  it("pins the required browser engines without claiming Safari certification", () => {
    expect(UI_FOUNDATION_QUALIFICATION.browsers).toEqual([
      expect.objectContaining({ id: "chromium", packageRevision: "1228", browserVersion: "149.0.7827.55", scope: "critical" }),
      expect.objectContaining({ id: "edge-stable", channel: "msedge", observedVersion: "151.0.4129.101", scope: "critical" }),
      expect.objectContaining({ id: "firefox", packageRevision: "1532", browserVersion: "151.0", scope: "shell-smoke" }),
      expect.objectContaining({ id: "webkit", packageRevision: "2311", browserVersion: "26.5", scope: "shell-smoke", certification: "playwright-webkit-not-safari" }),
    ]);
  });

  it("keeps the executable browser runner aligned with the frozen Edge Stable pin", () => {
    const runner = readFileSync(
      resolve(process.cwd(), "scripts/run_compat_126_browser_qualification.mjs"),
      "utf8",
    );
    expect(runner).toContain('expectedVersion: "151.0.4129.101"');
    expect(runner).not.toContain('expectedVersion: "150.0.4078.65"');
    expect(runner).toContain('"wcag21a"');
    expect(runner).toContain('"wcag21aa"');
    expect(runner).toContain('resourceErrors.length === 0');
    expect(runner).toContain('"r126_qualification_resource_error"');
    expect(runner).toContain('"r126_qualification_skip_link_focus"');
    expect(runner).toContain('"r126_qualification_combobox_visible_focus"');
    expect(runner).toContain('"r126_qualification_search_filtered_results"');
    expect(runner).toContain('"r126_qualification_route_heading_focus"');
  });

  it("freezes visual, reflow, accessibility, state, and axe gates numerically", () => {
    expect(UI_FOUNDATION_QUALIFICATION.visual).toEqual({
      maxDiffPixelRatio: 0.001,
      animations: "disabled",
      volatileMasking: "narrow-reviewed-only",
      baselineChanges: "explicit-review-required",
    });
    expect(UI_FOUNDATION_QUALIFICATION.accessibility).toMatchObject({
      wcagVersion: "2.2",
      conformance: "AA",
      zoom: 4,
      rootTwoDimensionalScrollAllowed: false,
      normalTextContrast: 4.5,
      largeTextContrast: 3,
      meaningfulNonTextContrast: 3,
      focusContrast: 3,
      focusPerimeterCssPixels: 2,
      targetSizeCssPixels: 24,
      defaultControlHeightCssPixels: 40,
      mobilePrimaryControlHeightCssPixels: 44,
      maximumOwnedAxeViolations: 0,
    });
    expect(UI_FOUNDATION_QUALIFICATION.accessibility.axeTags).toEqual(expect.arrayContaining([
      "wcag2a",
      "wcag2aa",
      "wcag21a",
      "wcag21aa",
      "wcag22aa",
    ]));
    expect(UI_FOUNDATION_QUALIFICATION.requiredChecks).toEqual(expect.arrayContaining([
      "keyboard-only",
      "focus-visible-unobscured",
      "reduced-motion",
      "forced-colors",
      "route-not-found",
      "authorization-denial",
      "stop-cleanup-visibility",
    ]));
  });

  it("accepts the frozen contract", () => {
    expect(validateUiFoundationQualification(UI_FOUNDATION_QUALIFICATION)).toEqual([]);
  });

  it("rejects relaxed, incomplete, or misleading qualification contracts", () => {
    const invalid = structuredClone(UI_FOUNDATION_QUALIFICATION);
    invalid.viewports.pop();
    invalid.visual.maxDiffPixelRatio = 0.01;
    invalid.accessibility.targetSizeCssPixels = 20;
    invalid.accessibility.axeTags = [];
    invalid.browsers[3]!.certification = "Safari certified";
    invalid.requiredChecks = invalid.requiredChecks.filter((value) => value !== "authorization-denial");

    expect(validateUiFoundationQualification(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("viewports"),
      expect.stringContaining("visual"),
      expect.stringContaining("target"),
      expect.stringContaining("axe"),
      expect.stringContaining("Safari"),
      expect.stringContaining("authorization-denial"),
    ]));
  });

  it("rejects browser pin drift, downgraded scopes, non-finite numbers, and stronger-looking matrix drift", () => {
    const invalid = structuredClone(UI_FOUNDATION_QUALIFICATION);
    invalid.browsers[0]!.packageRevision = "latest";
    invalid.browsers[1]!.observedVersion = "151.0.0.0";
    invalid.browsers[2]!.scope = "critical";
    invalid.visual.maxDiffPixelRatio = Number.NaN;
    invalid.accessibility.zoom = Number.NaN;
    invalid.accessibility.normalTextContrast = 7;

    expect(validateUiFoundationQualification(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("browser matrix"),
      expect.stringContaining("finite"),
      expect.stringContaining("accessibility matrix"),
    ]));
  });
});
