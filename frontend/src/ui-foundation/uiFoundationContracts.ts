import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";
import budgetManifest from "./uiFoundationBudgetManifest.json";

export const UI_FOUNDATION_CONTRACTS_VERSION = UI_FOUNDATION_CONTRACT_VERSION;
export const UI_FOUNDATION_BUDGET_MANIFEST_VERSION = budgetManifest.version;

export type ShellSpecification = {
  regions: Array<{
    id: string;
    landmark: string;
    purpose: string;
    optional: boolean;
  }>;
  primaryNavigation: {
    orientation: "vertical";
    desktop: string;
    tablet: string;
    mobile: string;
    groups: string[];
  };
  globalContextHeader: { allowedContents: string[] };
  prohibitedPatterns: string[];
};

export type InteractionContract = {
  id: string;
  semanticPattern: string;
  accessibleName: string;
  announcement: string;
  forcedColors: string;
  keyboard: string[];
  focus: { entry: string; exit: string; restore: string };
  states: string[];
  responsive: string[];
  reducedMotion: string;
};

export type ApiGap = {
  id: string;
  owner: string;
  schemaDisposition: string;
  authorization: string;
  rls: string;
  pagination: string;
  states: string[];
  auditEvents: string[];
  generatedClientImpact: string;
  acceptanceTests: string[];
};

export type RepresentativeRole = {
  participantSlot: string;
  role: "red-team-operator" | "approver-security-lead" | "evidence-finding-reviewer" | "platform-administrator" | "keyboard-accessibility-evaluator";
  requiredExperience: string;
};

export type RepresentativeTask = {
  id: string;
  objective: string;
  startingContext: string;
  success: string;
  safetyCritical: boolean;
};

export type RepresentativeTaskProtocol = {
  roles: RepresentativeRole[];
  tasks: RepresentativeTask[];
  thresholds: {
    safetyCriticalSuccessRate: number;
    overallUnassistedSuccessRate: number;
    nonSafetyUnassistedSuccessRate: number;
    unsafeInterpretations: number;
    medianTopLevelActivations: number;
    medianDestinationActivations: number;
  };
  privacy: string[];
};

export type PerformanceBudgets = {
  lcpP75Milliseconds: number;
  inpP75Milliseconds: number;
  clsP75: number;
  localShellReadyP95Milliseconds: number;
  localFeedbackP95Milliseconds: number;
  longTaskMaximumMilliseconds: number;
  initialJavaScriptGzipBytes: number;
  initialCssGzipBytes: number;
  initialCombinedGzipBytes: number;
  largeData: {
    totalRecords: number;
    renderedPageSize: number;
    readyP95Milliseconds: number;
    maximumWorkspaceDomElements: number;
  };
  commandSearch: {
    optionCount: number;
    resultLimit: number;
    readyP95Milliseconds: number;
  };
};

export const SHELL_SPECIFICATION: ShellSpecification = {
  regions: [
    { id: "primary-navigation", landmark: "nav", purpose: "Grouped production destinations", optional: false },
    { id: "global-context-header", landmark: "header", purpose: "Server-derived global context and global actions only", optional: false },
    { id: "primary-workspace", landmark: "main", purpose: "Route-specific operational task", optional: false },
    { id: "context-inspector", landmark: "aside", purpose: "On-demand provenance, policy rationale, and advanced detail", optional: true },
  ],
  primaryNavigation: {
    orientation: "vertical",
    desktop: "Grouped expanded sidebar from 1200px",
    tablet: "Grouped compact rail from 768px",
    mobile: "Labelled modal drawer through 767px using the same groups",
    groups: [
      "command-center",
      "campaigns",
      "assets-assessments",
      "findings-evidence",
      "approvals-governance",
      "platform",
    ],
  },
  globalContextHeader: {
    allowedContents: [
      "product-identity",
      "tenant-context",
      "engagement-context",
      "environment-safety-profile",
      "breadcrumbs",
      "global-search-command-entry",
      "notifications",
      "connection-health",
      "user-session",
    ],
  },
  prohibitedPatterns: [
    "horizontal-feature-strip",
    "wrapped-header-navigation",
    "scrolling-header-navigation",
    "compressed-header-navigation",
    "overflow-header-navigation",
    "hidden-legacy-header-fallback",
  ],
};

const BASE_STATES = ["loading", "empty", "error", "denied", "stale"];

function interaction(
  value: Omit<InteractionContract, "states"> & { states?: string[] },
): InteractionContract {
  return { ...value, states: [...BASE_STATES, ...(value.states ?? [])] };
}

export const INTERACTION_CONTRACTS: InteractionContract[] = [
  interaction({
    id: "primary-navigation",
    semanticPattern: "One labelled native nav containing grouped lists, links, and disclosure buttons; never menu, menubar, tabs, or treeview",
    accessibleName: "The nav is labelled Primary navigation; every icon-only compact-rail link retains its destination name",
    announcement: "aria-current=page exposes the selected route and disclosure expanded state is programmatic",
    forcedColors: "Current route, focus, disclosure, and group boundaries use system colors and remain distinguishable without authored fills",
    keyboard: ["Tab visits disclosure buttons and links in DOM order", "Enter or Space toggles a disclosure", "Enter activates a link", "aria-current=page identifies the current destination"],
    focus: { entry: "Skip link or first visible group control", exit: "Tab continues into utility header or main according to DOM order", restore: "Route transition focuses the route h1; browser back restores the active link when available" },
    states: ["group-collapsed", "group-expanded", "current-route-hidden-by-permission"],
    responsive: ["Expanded sidebar >=1200px", "Compact rail 768-1199px", "Moves into modal drawer <=767px"],
    reducedMotion: "No sliding or scaling is required; visibility changes are immediate when reduced motion is requested",
  }),
  interaction({
    id: "mobile-navigation-drawer",
    semanticPattern: "Labelled modal dialog containing the same primary navigation registry and an explicit close button",
    accessibleName: "The dialog is labelled Primary navigation and its open and close buttons have action-specific names",
    announcement: "Dialog name, modal state, current route, and navigation completion are exposed without a duplicate live announcement",
    forcedColors: "Drawer boundary, close control, current route, and focus use system colors and remain visible against Canvas",
    keyboard: ["Trigger opens with Enter or Space", "Tab and Shift+Tab remain inside", "Escape closes", "Route activation closes after navigation"],
    focus: { entry: "Explicit close button unless a more relevant selected link is visible", exit: "Escape, close button, or successful navigation", restore: "Returns to the drawer trigger except after navigation, which focuses the route h1" },
    states: ["closed", "open", "route-activating"],
    responsive: ["Available through 767px", "Background is inert while open", "Drawer never creates root horizontal overflow"],
    reducedMotion: "Open and close without translation when reduced motion is requested",
  }),
  interaction({
    id: "command-search",
    semanticPattern: "APG combobox over a bounded tenant- and permission-filtered destination/action list; arbitrary commands and URLs are impossible",
    accessibleName: "The input is labelled Search permitted destinations and actions; the popup and active option are programmatically related",
    announcement: "Bounded result count, no-results, unavailable result, selection, and denial are announced through the combobox/status contract",
    forcedColors: "Input boundary, popup boundary, active option, selected state, and focus remain distinct using system colors",
    keyboard: ["Typing filters", "Arrow keys move active option", "Enter selects", "Escape closes", "Home and End remain native text-editing keys when the popup is closed"],
    focus: { entry: "Search input", exit: "Selection, Escape, or explicit close", restore: "Returns to invocation trigger after cancel; route h1 after navigation" },
    states: ["query-empty", "results", "no-results", "result-unavailable"],
    responsive: ["Popover on wide layouts", "Modal command surface on narrow layouts", "Result list remains bounded to 50"],
    reducedMotion: "No scale animation; results update without layout transition",
  }),
  interaction({
    id: "context-inspector",
    semanticPattern: "Labelled complementary aside when docked and labelled dialog/disclosure when overlaid",
    accessibleName: "Every inspector trigger names the inspected subject and the region/dialog is labelled by its visible heading",
    announcement: "Open/closed state, unavailable provenance, stale detail, and denied detail are exposed without moving focus for docked updates",
    forcedColors: "Inspector boundary, trigger, close control, headings, and focus use system colors with no color-only provenance state",
    keyboard: ["Trigger toggles with Enter or Space", "Escape closes overlay", "Docked content follows main in landmark order"],
    focus: { entry: "Inspector heading or first actionable control", exit: "Close control, Escape for overlay, or normal Tab order when docked", restore: "Returns to the exact inspector trigger" },
    states: ["closed", "docked", "overlay", "provenance-unavailable"],
    responsive: ["Docked from 1440px when space permits", "Overlay below 1440px", "Never covers persistent stop/revoke controls"],
    reducedMotion: "No slide animation when reduced motion is requested",
  }),
  interaction({
    id: "persistent-stop-revoke",
    semanticPattern: "A persistent labelled button outside route content opens a governed confirmation; visibility never implies authorization and dispatch remains server-controlled",
    accessibleName: "The control is named Stop and revoke active work and includes the bound engagement or execution when one is active",
    announcement: "Unavailable, unauthorized, submitting, containment-pending, contained, cleanup-required, and failure states are exposed as persistent text status",
    forcedColors: "The persistent control, danger boundary, focus, confirmation consequence, and containment status remain distinguishable with system colors",
    keyboard: ["The control remains in the shell Tab order", "Enter or Space opens confirmation", "Escape cancels when safe", "Focus never moves to confirmation action by default"],
    focus: { entry: "Persistent shell control before route-specific destructive actions", exit: "Safe cancel, governed confirmation, or normal shell order", restore: "Returns to the shell control on cancel and focuses containment/recovery status after submission" },
    states: ["unavailable", "unauthorized", "submitting", "containment-pending", "contained", "cleanup-required"],
    responsive: ["Remains visible in expanded and compact shells", "Remains in the labelled mobile drawer", "Remains reachable during loading, error, denial, and every route transition"],
    reducedMotion: "No pulsing or motion-only urgency; persistent text, icon, and system-color boundary communicate the state",
  }),
  interaction({
    id: "destructive-confirmation",
    semanticPattern: "Labelled modal dialog with explicit consequence, scope, safe cancel, and action-specific confirmation",
    accessibleName: "The dialog is labelled by an action-specific consequence heading and every confirmation names the exact action",
    announcement: "Submitting, rejected, accepted, cleanup-required, and recovery states are announced without premature success",
    forcedColors: "Consequence, cancel, destructive action, focus, error, and completion use system colors and text labels",
    keyboard: ["Tab remains contained", "Escape cancels when cancellation is safe", "Enter never defaults to the destructive action unless that control owns focus"],
    focus: { entry: "Least destructive appropriate control", exit: "Cancel, safe Escape, or confirmed completion", restore: "Returns to trigger on cancel; focuses status/recovery guidance on completion" },
    states: ["confirming", "submitting", "rejected", "accepted", "cleanup-required"],
    responsive: ["Centered bounded dialog on wide layouts", "Inset full-width dialog on narrow layouts", "Critical consequence remains above the action row"],
    reducedMotion: "No zoom or bounce; focus and semantic change provide feedback",
  }),
  interaction({
    id: "read-only-data-table",
    semanticPattern: "Native table with caption, headers, and links/buttons only for real row actions; never ARIA grid for read-only data",
    accessibleName: "The table has a visible caption and every labelled local overflow region names the data it contains",
    announcement: "Filter, pagination, empty, stale, denied, and returned-count changes use a bounded status message",
    forcedColors: "Caption, header/body boundaries, links, buttons, local-scroll focus, and selected filters use system colors",
    keyboard: ["Tab visits only interactive descendants", "Native browser table reading order is preserved", "Local scroll region is keyboard reachable when horizontal overflow is unavoidable"],
    focus: { entry: "Caption-adjacent controls or labelled scroll region", exit: "Normal document order", restore: "Pagination/filter updates return focus to the changed table caption or status only when needed" },
    states: ["page-ready", "page-empty", "page-limit-reached", "local-overflow"],
    responsive: ["Columns reflow or hide only by field-priority contract", "Wide evidence data scrolls in a labelled local region", "Primary actions remain outside the scroll region"],
    reducedMotion: "Rows update without transition; status text announces the result count",
  }),
  interaction({
    id: "status-feedback",
    semanticPattern: "Native status for non-urgent updates and alert for actionable failure; text identifies state and recovery",
    accessibleName: "Every recovery control names its action and every persistent status is labelled by nearby visible context",
    announcement: "Non-urgent updates use status; urgent actionable failures use alert once; repeated unchanged content is not re-announced",
    forcedColors: "Success, warning, danger, info, focus, and recovery remain distinguishable through text, icons, boundaries, and system colors",
    keyboard: ["No focus move for passive status", "Actionable recovery controls remain in normal Tab order"],
    focus: { entry: "No automatic entry for passive updates", exit: "Normal document order", restore: "Submission failure focuses the first invalid field or error summary; destructive completion focuses recovery guidance" },
    states: ["success", "warning", "danger", "info", "evidence-outage", "cleanup-incomplete"],
    responsive: ["Inline near the decision point", "Never hidden solely in a toast", "Persistent safety failures do not overlap focused controls"],
    reducedMotion: "No auto-dismiss motion; urgent states remain until acknowledged or resolved",
  }),
  interaction({
    id: "route-transition",
    semanticPattern: "Declarative nested route transition that preserves the shell and server-derived safety context",
    accessibleName: "The route main region is labelled by one h1 while shell navigation and safety controls keep stable names",
    announcement: "Route title, not-found, context-unavailable, and denied outcomes are exposed once after user-initiated navigation",
    forcedColors: "Shell boundaries, current route, focus, route status, denial, and persistent safety controls use system colors",
    keyboard: ["Link activation follows native browser semantics", "Back and forward restore route and context", "Skip link remains first focusable item"],
    focus: { entry: "Route h1 after user-initiated navigation", exit: "Normal document order", restore: "History navigation restores a meaningful route position without forcing focus into stale content" },
    states: ["route-loading", "route-ready", "route-not-found", "context-unavailable"],
    responsive: ["Same route registry at every viewport", "Shell remains visible during lazy loading", "No full-page spinner replaces safety context"],
    reducedMotion: "No decorative view transition; route content changes immediately",
  }),
];

export const API_GAP_LEDGER: ApiGap[] = [
  {
    id: "operator-shell-context",
    owner: "compat_127",
    schemaDisposition: "Extend authenticated GET /api/v1/context with versioned OperatorShellContext for tenant/session/environment/safety identity",
    authorization: "Authenticated server-derived context; unavailable or unknown renders explicit unsafe state and cannot be supplied by client configuration",
    rls: "Tenant and session identity are resolved by the existing authenticated request boundary; no cross-tenant fields are returned",
    pagination: "Not applicable: one bounded shell context document",
    states: ["ready", "unauthenticated", "forbidden", "unknown-safety-profile", "unavailable", "stale-session"],
    auditEvents: ["session_context_denied", "shell_context_unavailable"],
    generatedClientImpact: "Regenerate OpenAPI types/client and remove hard-coded Local/safe copy",
    acceptanceTests: ["wrong-tenant denial", "unknown safety fails closed", "shell bootstrap independent of engagement list"],
  },
  {
    id: "routeable-resource-context",
    owner: "compat_127",
    schemaDisposition: "Typed path/search parameters resolved to authorized tenant resources before breadcrumbs or actions render",
    authorization: "URL state is an identifier request only and never grants tenant, engagement, resource, or action authority",
    rls: "Every resolver query remains tenant/RLS scoped and rejects wrong-tenant identifiers indistinguishably from unauthorized resources",
    pagination: "Resolver candidates are bounded; route identity resolves one resource revision",
    states: ["resolved", "missing", "deleted", "stale", "wrong-tenant", "forbidden"],
    auditEvents: ["route_context_denied", "route_context_stale"],
    generatedClientImpact: "Add typed resolver shapes and route binding IDs without client-only authority state",
    acceptanceTests: ["deep link", "refresh", "back-forward", "wrong tenant", "deleted resource", "stale revision", "denied resource"],
  },
  {
    id: "operator-attention-queue",
    owner: "compat_124",
    schemaDisposition: "Add bounded paginated OperatorAttentionQueue aggregate over approvals, denials, incidents, stale plans, cleanup/evidence failures, reconciliation, and finding/retest SLA",
    authorization: "Tenant/permission filters are applied before aggregation; the queue cannot expose or authorize hidden actions",
    rls: "All joined rows remain tenant and engagement scoped under PostgreSQL RLS and service authorization",
    pagination: "Authoritative limit/offset/returned/total or documented continuation with deterministic order",
    states: ["ready", "empty", "partial-source-outage", "stale", "forbidden"],
    auditEvents: ["attention_item_viewed", "attention_action_denied"],
    generatedClientImpact: "Add generated queue item union and page metadata",
    acceptanceTests: ["permission filtering", "pagination beyond first page", "source outage", "cross-tenant denial", "stable binding IDs"],
  },
  {
    id: "automation-resource-options",
    owner: "compat_124",
    schemaDisposition: "Add typed option/read models for R119-R123 graph, capability, path, approval, and execution resources",
    authorization: "Only currently authorized and policy-visible resources are returned; unavailable options include machine-readable reasons without secret values",
    rls: "Tenant/engagement/resource filters and RLS precede label projection",
    pagination: "Bounded searchable pages with stable IDs, label, revision, freshness, eligibility, and unavailable reason",
    states: ["eligible", "ineligible", "stale", "revoked", "unavailable", "empty"],
    auditEvents: ["automation_option_denied", "automation_option_selected"],
    generatedClientImpact: "Add exact generated option unions consumed by Campaign Cockpit",
    acceptanceTests: ["wrong-tenant omission", "stale option", "revoked option", "secret redaction", "pagination and search bounds"],
  },
  {
    id: "legacy-resource-resolvers",
    owner: "compat_128",
    schemaDisposition: "Add domain resolvers for ROE, policy, reservation, lease, plan, job, runner, target, evidence, and finding choices",
    authorization: "Resolvers expose only authorized stored resources and never accept free-text values as authority",
    rls: "Every domain query is tenant/engagement scoped with generated contract parity",
    pagination: "All resolver lists expose authoritative bounded page metadata and navigation",
    states: ["ready", "empty", "stale", "needs-review", "forbidden", "unavailable"],
    auditEvents: ["resolver_denied", "resolver_selection_stale"],
    generatedClientImpact: "Replace ID-first form bindings with typed resolver results; retain exact IDs/hashes on demand",
    acceptanceTests: ["no primary raw-ID entry", "wrong tenant", "stale revision", "missing item", "later page reachable"],
  },
  {
    id: "bounded-pagination",
    owner: "compat_128",
    schemaDisposition: "Standardize list responses as data plus limit/offset/returned/total or documented continuation",
    authorization: "Page cursors and offsets do not bypass scope or permission filters",
    rls: "Totals and page data are computed within the same tenant/RLS boundary",
    pagination: "No permanent limit=50/offset=0 trap; stable sort and next/previous behavior are explicit",
    states: ["first-page", "middle-page", "last-page", "empty", "stale-cursor", "forbidden"],
    auditEvents: ["bounded_list_denied"],
    generatedClientImpact: "Expose authoritative page metadata and typed continuation where used",
    acceptanceTests: ["more than 50 rows", "stable order", "stale cursor", "bounded limit", "cross-tenant total denial"],
  },
  {
    id: "canonical-target-taxonomy",
    owner: "compat_120",
    schemaDisposition: "Publish one canonical target enum/mapping with explicit legacy needs_review state",
    authorization: "Taxonomy does not grant target scope; engagement and policy authority remain separate",
    rls: "Tenant target records retain RLS; the global enum contains no tenant data",
    pagination: "Not applicable to the bounded enum; target records remain paginated",
    states: ["mapped", "needs-review", "unsupported", "forbidden"],
    auditEvents: ["target_mapping_needs_review", "target_mapping_rejected"],
    generatedClientImpact: "Generate exact hostname/IP/CIDR/URL/application and future qualified target types",
    acceptanceTests: ["legacy ambiguous value", "unknown value", "generated enum parity", "no silent coercion"],
  },
  {
    id: "direct-agent-path-execution",
    owner: "compat_123",
    schemaDisposition: "Keep the mutation surface absent until compat_123 defines exact policy/approval/dispatcher authority",
    authorization: "An unused client method or visible recommendation never creates execution entitlement",
    rls: "Not applicable while absent; any future contract must enforce tenant/engagement/target RLS and service authorization",
    pagination: "Not applicable to the absent mutation; governed plan/read models remain bounded",
    states: ["absent", "disabled", "denied", "approval-required", "policy-unavailable"],
    auditEvents: ["direct_execution_denied"],
    generatedClientImpact: "No UI consumer until compat_123 acceptance; generated methods alone remain non-entitlement",
    acceptanceTests: ["no arbitrary command", "no direct dispatch", "missing approval", "policy unavailable", "wrong tenant"],
  },
];

export const REPRESENTATIVE_TASK_PROTOCOL: RepresentativeTaskProtocol = {
  roles: [
    { participantSlot: "operator-a", role: "red-team-operator", requiredExperience: "Day-to-day authorized engagement operations" },
    { participantSlot: "operator-b", role: "red-team-operator", requiredExperience: "Day-to-day assessment and stop/cleanup operations" },
    { participantSlot: "approver", role: "approver-security-lead", requiredExperience: "Scope, policy, risk-tier, and separation-of-duties review" },
    { participantSlot: "reviewer", role: "evidence-finding-reviewer", requiredExperience: "Evidence, finding, remediation, and retest review" },
    { participantSlot: "administrator", role: "platform-administrator", requiredExperience: "Runner, incident, policy convergence, and platform health" },
    { participantSlot: "keyboard-evaluator", role: "keyboard-accessibility-evaluator", requiredExperience: "Keyboard-only and assistive-technology workflow evaluation" },
  ],
  tasks: [
    { id: "recognize-scope-authority", objective: "State the active tenant/engagement, approved scope, environment/safety state, and whether execution is currently authorized", startingContext: "Command Center with synthetic mixed readiness", success: "Correctly identifies every authority boundary and does not infer permission from visible navigation", safetyCritical: true },
    { id: "find-pending-approval", objective: "Locate the highest-priority pending approval and its exact risk/scope binding", startingContext: "Command Center attention queue", success: "Opens the governed approval without using an internal ID", safetyCritical: false },
    { id: "understand-rejected-tool-path", objective: "Explain why one capability/path is rejected and what must change", startingContext: "Campaign recommendation detail", success: "Names the machine-readable rejection and does not propose bypass", safetyCritical: true },
    { id: "compare-safe-alternatives", objective: "Compare two eligible alternatives by risk, cost, duration, evidence, and cleanup", startingContext: "Campaign path alternatives", success: "Selects or defers using displayed bounded criteria", safetyCritical: false },
    { id: "stop-active-work", objective: "Stop active work and verify dispatch is blocked", startingContext: "Active campaign execution", success: "Uses persistent stop/revoke control and recognizes pending containment", safetyCritical: true },
    { id: "verify-cleanup-evidence", objective: "Confirm cleanup, residual risk, and evidence acceptance after stop", startingContext: "Stopped execution with mixed receipts", success: "Distinguishes accepted cleanup/evidence from incomplete state", safetyCritical: true },
    { id: "find-remediation-retest", objective: "Locate finding ownership, remediation status, and retest outcome", startingContext: "Finding notification", success: "Reaches authoritative finding/retest state without transcribing IDs", safetyCritical: false },
  ],
  thresholds: {
    safetyCriticalSuccessRate: 1,
    overallUnassistedSuccessRate: 0.9,
    nonSafetyUnassistedSuccessRate: 0.9,
    unsafeInterpretations: 0,
    medianTopLevelActivations: 2,
    medianDestinationActivations: 3,
  },
  privacy: [
    "Use synthetic tenant, engagement, target, evidence, and participant identifiers",
    "Record role coverage, task outcomes, activations, failures, and design changes only",
    "Do not record names, credentials, private evidence, raw audio/video, or operational target data",
  ],
};

export const PERFORMANCE_BUDGETS: PerformanceBudgets = budgetManifest.performance;

export type UiFoundationContracts = {
  shell: ShellSpecification;
  interactions: InteractionContract[];
  apiGaps: ApiGap[];
  protocol: RepresentativeTaskProtocol;
  performance: PerformanceBudgets;
};

const REQUIRED_STATES = ["loading", "empty", "error", "denied", "stale"];
const REQUIRED_INTERACTION_IDS = [
  "primary-navigation",
  "mobile-navigation-drawer",
  "command-search",
  "context-inspector",
  "persistent-stop-revoke",
  "destructive-confirmation",
  "read-only-data-table",
  "status-feedback",
  "route-transition",
] as const;
const REQUIRED_SHELL_REGION_IDS = [
  "primary-navigation",
  "global-context-header",
  "primary-workspace",
  "context-inspector",
] as const;
const REQUIRED_NAVIGATION_GROUPS = [
  "command-center",
  "campaigns",
  "assets-assessments",
  "findings-evidence",
  "approvals-governance",
  "platform",
] as const;
const REQUIRED_API_GAP_IDS = [
  "operator-shell-context",
  "routeable-resource-context",
  "operator-attention-queue",
  "automation-resource-options",
  "legacy-resource-resolvers",
  "bounded-pagination",
  "canonical-target-taxonomy",
  "direct-agent-path-execution",
] as const;
const REQUIRED_ROLE_COUNTS: Readonly<Record<RepresentativeRole["role"], number>> = {
  "red-team-operator": 2,
  "approver-security-lead": 1,
  "evidence-finding-reviewer": 1,
  "platform-administrator": 1,
  "keyboard-accessibility-evaluator": 1,
};

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

export function validateUiFoundationContracts(contracts: UiFoundationContracts): string[] {
  const issues: string[] = [];

  if (contracts.shell.primaryNavigation.orientation !== "vertical") {
    issues.push("primary navigation must be vertical");
  }
  if (contracts.shell.globalContextHeader.allowedContents.includes("module-navigation")) {
    issues.push("header must not contain module navigation");
  }
  if (canonicalJson(contracts.shell) !== canonicalJson(SHELL_SPECIFICATION)) {
    issues.push("shell specification must exactly match the frozen compat_126 regions, landmarks, navigation, header, and prohibited patterns");
  }
  const regionIds = contracts.shell.regions.map(({ id }) => id);
  if (regionIds.length !== REQUIRED_SHELL_REGION_IDS.length
    || REQUIRED_SHELL_REGION_IDS.some((id) => !regionIds.includes(id))
    || new Set(regionIds).size !== regionIds.length) {
    issues.push("shell regions must contain the exact four frozen region families");
  }
  const navigationGroups = contracts.shell.primaryNavigation.groups;
  if (navigationGroups.length !== REQUIRED_NAVIGATION_GROUPS.length
    || REQUIRED_NAVIGATION_GROUPS.some((group) => !navigationGroups.includes(group))
    || new Set(navigationGroups).size !== navigationGroups.length) {
    issues.push("navigation groups must contain the exact six frozen domains");
  }
  if (JSON.stringify(contracts.shell) !== JSON.stringify(SHELL_SPECIFICATION)) {
    issues.push("shell specification must exactly match the frozen compat_126 region, landmark, responsive, header, and prohibited-pattern contract");
  }

  const interactionIds = contracts.interactions.map(({ id }) => id);
  for (const id of REQUIRED_INTERACTION_IDS) {
    if (!interactionIds.includes(id)) issues.push(`missing interaction ${id}`);
  }
  for (const id of new Set(interactionIds)) {
    if (interactionIds.filter((candidate) => candidate === id).length > 1) issues.push(`duplicate interaction ${id}`);
    if (!(REQUIRED_INTERACTION_IDS as readonly string[]).includes(id)) issues.push(`unexpected interaction ${id}`);
  }

  for (const contract of contracts.interactions) {
    if (!contract.semanticPattern) issues.push(`${contract.id} semanticPattern is required`);
    if (!contract.accessibleName) issues.push(`${contract.id} accessibleName is required`);
    if (!contract.announcement) issues.push(`${contract.id} announcement is required`);
    if (!contract.forcedColors) issues.push(`${contract.id} forcedColors is required`);
    if (contract.keyboard.length === 0) issues.push(`${contract.id} keyboard contract is required`);
    if (!contract.focus.entry || !contract.focus.exit || !contract.focus.restore) {
      issues.push(`${contract.id} complete focus contract is required`);
    }
    for (const state of REQUIRED_STATES) {
      if (!contract.states.includes(state)) issues.push(`${contract.id} states missing ${state}`);
    }
    if (contract.responsive.length === 0) issues.push(`${contract.id} responsive contract is required`);
    if (!contract.reducedMotion) issues.push(`${contract.id} reducedMotion contract is required`);
  }

  const apiGapIds = contracts.apiGaps.map(({ id }) => id);
  for (const id of REQUIRED_API_GAP_IDS) {
    if (!apiGapIds.includes(id)) issues.push(`missing API gap ${id}`);
  }
  for (const id of new Set(apiGapIds)) {
    if (apiGapIds.filter((candidate) => candidate === id).length > 1) issues.push(`duplicate API gap ${id}`);
    if (!(REQUIRED_API_GAP_IDS as readonly string[]).includes(id)) issues.push(`unexpected API gap ${id}`);
  }

  for (const gap of contracts.apiGaps) {
    if (!gap.owner) issues.push(`${gap.id} owner is required`);
    const requiredStrings: Array<[string, string]> = [
      ["schemaDisposition", gap.schemaDisposition],
      ["authorization", gap.authorization],
      ["rls", gap.rls],
      ["pagination", gap.pagination],
      ["generatedClientImpact", gap.generatedClientImpact],
    ];
    for (const [field, value] of requiredStrings) {
      if (!value) issues.push(`${gap.id} ${field} is required`);
    }
    if (gap.states.length === 0) issues.push(`${gap.id} states are required`);
    if (gap.auditEvents.length === 0) issues.push(`${gap.id} auditEvents are required`);
    if (gap.acceptanceTests.length === 0) issues.push(`${gap.id} acceptanceTests are required`);
  }
  // SECURITY: presence-only checks cannot qualify authorization, RLS, audit, or acceptance semantics.
  if (canonicalJson(contracts.apiGaps) !== canonicalJson(API_GAP_LEDGER)) {
    issues.push("API-gap ledger must exactly match the frozen compat_126 field contracts");
  }

  if (contracts.protocol.roles.length !== 6) issues.push("representative protocol requires six roles");
  for (const [role, count] of Object.entries(REQUIRED_ROLE_COUNTS)) {
    if (contracts.protocol.roles.filter((candidate) => candidate.role === role).length !== count) {
      issues.push(`representative protocol requires ${count} ${role}`);
    }
  }
  if (contracts.protocol.tasks.length === 0) issues.push("representative protocol requires tasks");
  if (contracts.protocol.privacy.length < 3
    || !contracts.protocol.privacy.some((requirement) => requirement.toLowerCase().includes("synthetic"))
    || !contracts.protocol.privacy.some((requirement) => requirement.toLowerCase().includes("do not record"))) {
    issues.push("representative protocol privacy requirements are incomplete");
  }
  if (contracts.protocol.thresholds.safetyCriticalSuccessRate !== 1
    || contracts.protocol.thresholds.overallUnassistedSuccessRate < 0.9
    || contracts.protocol.thresholds.nonSafetyUnassistedSuccessRate < 0.9
    || contracts.protocol.thresholds.unsafeInterpretations !== 0) {
    issues.push("representative safety thresholds must remain fail-closed");
  }
  if (canonicalJson(contracts.protocol) !== canonicalJson(REPRESENTATIVE_TASK_PROTOCOL)) {
    issues.push("representative protocol must exactly match the frozen compat_126 roles, seven tasks, privacy rules, and activation thresholds");
  }

  if (canonicalJson(contracts.performance) !== canonicalJson(PERFORMANCE_BUDGETS)) {
    issues.push("performance budgets must exactly match the frozen compat_126 manifest");
  }

  return issues;
}
