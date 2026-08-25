export type QualificationViewport = {
  id: string;
  width: number;
  height: number;
};

export type QualificationBrowser = {
  id: string;
  scope: "critical" | "shell-smoke";
  packageRevision?: string;
  browserVersion?: string;
  channel?: string;
  observedVersion?: string;
  certification: string;
};

export type UiFoundationQualification = {
  version: string;
  viewports: QualificationViewport[];
  browsers: QualificationBrowser[];
  visual: {
    maxDiffPixelRatio: number;
    animations: string;
    volatileMasking: string;
    baselineChanges: string;
  };
  accessibility: {
    wcagVersion: string;
    conformance: string;
    zoom: number;
    rootTwoDimensionalScrollAllowed: boolean;
    normalTextContrast: number;
    largeTextContrast: number;
    meaningfulNonTextContrast: number;
    focusContrast: number;
    focusPerimeterCssPixels: number;
    targetSizeCssPixels: number;
    defaultControlHeightCssPixels: number;
    mobilePrimaryControlHeightCssPixels: number;
    maximumOwnedAxeViolations: number;
    axeTags: string[];
  };
  requiredChecks: string[];
};

export const UI_FOUNDATION_CONTRACT_VERSION = "2026-08-25.r126.2";

export const UI_FOUNDATION_QUALIFICATION: UiFoundationQualification = {
  version: UI_FOUNDATION_CONTRACT_VERSION,
  viewports: [
    { id: "desktop", width: 1440, height: 900 },
    { id: "tablet", width: 1024, height: 768 },
    { id: "mobile", width: 390, height: 844 },
    { id: "reflow", width: 320, height: 800 },
  ],
  browsers: [
    {
      id: "chromium",
      packageRevision: "1228",
      browserVersion: "149.0.7827.55",
      scope: "critical",
      certification: "playwright-chromium",
    },
    {
      id: "edge-stable",
      channel: "msedge",
      observedVersion: "151.0.4129.101",
      scope: "critical",
      certification: "edge-stable-channel",
    },
    {
      id: "firefox",
      packageRevision: "1532",
      browserVersion: "151.0",
      scope: "shell-smoke",
      certification: "playwright-firefox",
    },
    {
      id: "webkit",
      packageRevision: "2311",
      browserVersion: "26.5",
      scope: "shell-smoke",
      certification: "playwright-webkit-not-safari",
    },
  ],
  visual: {
    maxDiffPixelRatio: 0.001,
    animations: "disabled",
    volatileMasking: "narrow-reviewed-only",
    baselineChanges: "explicit-review-required",
  },
  accessibility: {
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
    axeTags: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"],
  },
  requiredChecks: [
    "keyboard-only",
    "focus-visible-unobscured",
    "reduced-motion",
    "forced-colors",
    "route-not-found",
    "authorization-denial",
    "stop-cleanup-visibility",
  ],
};

const EXPECTED_VIEWPORTS = UI_FOUNDATION_QUALIFICATION.viewports.map(
  ({ id, width, height }) => `${id}:${width}x${height}`,
);
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const EXPECTED_BROWSER_ROWS = UI_FOUNDATION_QUALIFICATION.browsers.map(canonicalJson);
const REQUIRED_AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const REQUIRED_CHECKS = [
  "keyboard-only",
  "focus-visible-unobscured",
  "reduced-motion",
  "forced-colors",
  "route-not-found",
  "authorization-denial",
  "stop-cleanup-visibility",
];

export function validateUiFoundationQualification(
  contract: UiFoundationQualification,
): string[] {
  const issues: string[] = [];

  if (contract.version !== UI_FOUNDATION_CONTRACT_VERSION) {
    issues.push(`version must be ${UI_FOUNDATION_CONTRACT_VERSION}`);
  }

  const actualViewports = contract.viewports.map(
    ({ id, width, height }) => `${id}:${width}x${height}`,
  );
  if (actualViewports.length !== EXPECTED_VIEWPORTS.length
    || actualViewports.some((value, index) => value !== EXPECTED_VIEWPORTS[index])) {
    issues.push(`viewports must remain ${EXPECTED_VIEWPORTS.join(", ")}`);
  }

  const browserRows = contract.browsers.map(canonicalJson);
  if (browserRows.length !== EXPECTED_BROWSER_ROWS.length
    || browserRows.some((row, index) => row !== EXPECTED_BROWSER_ROWS[index])) {
    issues.push("browser matrix must preserve the exact frozen engines, revisions, channels, versions, scopes, and certifications");
  }
  const webkit = contract.browsers.find(({ id }) => id === "webkit");
  if (webkit && webkit.certification !== "playwright-webkit-not-safari") {
    issues.push("WebKit smoke is Playwright-only and must not claim Safari certification");
  }

  if (contract.visual.maxDiffPixelRatio <= 0
    || contract.visual.maxDiffPixelRatio > 0.001
    || contract.visual.animations !== "disabled"
    || contract.visual.volatileMasking !== "narrow-reviewed-only"
    || contract.visual.baselineChanges !== "explicit-review-required") {
    issues.push("visual qualification exceeds the frozen deterministic threshold");
  }

  const accessibility = contract.accessibility;
  const numericQualificationValues = [
    ...contract.viewports.flatMap(({ width, height }) => [width, height]),
    contract.visual.maxDiffPixelRatio,
    accessibility.zoom,
    accessibility.normalTextContrast,
    accessibility.largeTextContrast,
    accessibility.meaningfulNonTextContrast,
    accessibility.focusContrast,
    accessibility.focusPerimeterCssPixels,
    accessibility.targetSizeCssPixels,
    accessibility.defaultControlHeightCssPixels,
    accessibility.mobilePrimaryControlHeightCssPixels,
    accessibility.maximumOwnedAxeViolations,
  ];
  if (numericQualificationValues.some((value) => !Number.isFinite(value))) {
    issues.push("qualification numeric values must be finite");
  }
  if (accessibility.wcagVersion !== "2.2" || accessibility.conformance !== "AA") {
    issues.push("accessibility target must remain WCAG 2.2 AA");
  }
  if (accessibility.zoom < 4 || accessibility.rootTwoDimensionalScrollAllowed) {
    issues.push("reflow must support 400% zoom without root two-dimensional scrolling");
  }
  if (accessibility.normalTextContrast < 4.5
    || accessibility.largeTextContrast < 3
    || accessibility.meaningfulNonTextContrast < 3
    || accessibility.focusContrast < 3) {
    issues.push("contrast thresholds are below the frozen WCAG bounds");
  }
  if (accessibility.focusPerimeterCssPixels < 2) {
    issues.push("focus perimeter must remain at least 2 CSS pixels");
  }
  if (accessibility.targetSizeCssPixels < 24
    || accessibility.defaultControlHeightCssPixels < 40
    || accessibility.mobilePrimaryControlHeightCssPixels < 44) {
    issues.push("target and control sizes are below the frozen bounds");
  }
  if (accessibility.maximumOwnedAxeViolations !== 0) {
    issues.push("owned axe violations must remain zero");
  }
  for (const tag of REQUIRED_AXE_TAGS) {
    if (!accessibility.axeTags.includes(tag)) issues.push(`axe tags are missing ${tag}`);
  }
  if (canonicalJson(accessibility) !== canonicalJson(UI_FOUNDATION_QUALIFICATION.accessibility)) {
    issues.push("accessibility matrix must exactly match the frozen compat_126 values");
  }

  for (const check of REQUIRED_CHECKS) {
    if (!contract.requiredChecks.includes(check)) issues.push(`required checks are missing ${check}`);
  }
  if (contract.requiredChecks.length !== REQUIRED_CHECKS.length) {
    issues.push("required checks must contain only the frozen compat_126 checks");
  }

  return issues;
}
