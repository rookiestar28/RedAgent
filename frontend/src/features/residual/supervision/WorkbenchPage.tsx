import { useEffect, useState } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["WorkbenchDashboardData"];
type Binding = components["schemas"]["WorkbenchDraftBindingData"];

export function WorkbenchPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "audit:read");
  const canMutateDraft = hasPermission(context, "job:create");
  const canFreeze = hasPermission(context, "job:stop");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void client.getWorkbenchDashboard()
      .then((value) => { if (active) setDashboard(value); })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading supervised Workbench state"><strong>Loading supervised Workbench state</strong><p>Verifying fixture binding, exact proposal, disclosure, review, and MCP inventory truth.</p></section>;

  const binding = dashboard.binding_options.find(bindingAvailable) ?? null;

  async function refresh() {
    setDashboard(await client.getWorkbenchDashboard());
  }

  async function act(key: string, operation: () => Promise<string>) {
    setBusy(key); setActionError(null); setNotice(null);
    try { setNotice(await operation()); await refresh(); }
    catch (cause) { setActionError(projectError(cause)); }
    finally { setBusy(null); }
  }

  function createDraft(selected: Binding) {
    void act("create", async () => {
      const result = await client.createWorkbenchDraft({
        draft_id: `draft-${crypto.randomUUID()}`, campaign_id: selected.campaign_id, plan_id: selected.plan_id,
        target_id: selected.target_id, tool_fqn: selected.tool_fqn,
        confirmation: "--confirm-r114-structured-draft",
      });
      return `Fixture-only draft ${result.draft_id} stored for independent review; no MCP tool was dispatched.`;
    });
  }

  function review(draft: Dashboard["drafts"][number]) {
    if (draft.created_by === context.subject || !window.confirm(`Approve only proposal ${draft.proposal_sha256}?`)) return;
    void act(draft.draft_id, async () => {
      const result = await client.reviewWorkbenchDraft(
        draft.draft_id, `review-${crypto.randomUUID()}`, draft.proposal_sha256, "approve_exact",
      );
      return `Exact proposal ${result.proposal_sha256} approved; no broad approval or dispatch occurred.`;
    });
  }

  function successor(draft: Dashboard["drafts"][number], selected: Binding) {
    if (!window.confirm(`Create a successor for ${draft.draft_id} and invalidate its approval?`)) return;
    void act(draft.draft_id, async () => {
      const result = await client.createWorkbenchSuccessor(
        draft.draft_id, `successor-${crypto.randomUUID()}`, selected.successor_plan_id,
      );
      return `Successor ${result.draft_id} stored; prior exact approval invalidated.`;
    });
  }

  function freeze(registration: Dashboard["registrations"][number]) {
    if (!window.confirm(`Freeze ${registration.server_id} and invalidate exact approvals?`)) return;
    void act(registration.registration_id, async () => {
      const result = await client.freezeMcpServer(registration.registration_id, registration.inventory_sha256);
      return `${registration.server_id} frozen; ${result.invalidated_approval_count} exact approval(s) invalidated.`;
    });
  }

  return <div className="operational-page workbench-page">
    <section className="work-panel" aria-labelledby="workbench-title"><div className="section-heading"><div><span className="eyebrow">R114 · exact supervised decision</span><h2 id="workbench-title">Supervised campaign workbench</h2></div><span className="environment-chip">Fixture only · no external I/O</span></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Remote HTTP, stdio, provider MCP, dynamic discovery, token passthrough, process launch, credentials, sensitive retention, and direct dispatch remain disabled.</p><p><strong>Operator:</strong> {context.subject} · exact approval remains separate from draft authorship.</p></section>
    <section className="work-panel" aria-labelledby="workbench-binding-title"><h2 id="workbench-binding-title">Server-owned fixture binding</h2>{binding ? <article><strong>{binding.campaign_label}</strong><p>{binding.plan_label} · {binding.target_label}</p><p>{binding.binding_state} · fixture only: {binding.fixture_only ? "yes" : "no"} · egress {binding.egress_class}</p><p>Tool: <code>{binding.tool_fqn}</code></p><button type="button" disabled={!canMutateDraft || busy === "create"} onClick={() => createDraft(binding)}>Create fixture-only structured draft</button></article> : <p className="empty-state">No server-owned fixture binding is available; draft creation remains blocked.</p>}</section>
    <section className="work-panel" aria-labelledby="workbench-mcp-title"><h2 id="workbench-mcp-title">Attested MCP boundary</h2>{dashboard.registrations.length === 0 ? <p className="empty-state">No attested fixture server is registered.</p> : dashboard.registrations.map((registration) => <article key={registration.registration_id}><strong>{registration.server_id}</strong><p>{registration.protocol_version} · {registration.transport_kind} · {registration.registration_state}</p><p>Inventory: <code>{registration.inventory_sha256}</code> · {registration.risk_class} / {registration.data_class}</p><button type="button" disabled={!canFreeze || busy === registration.registration_id || registration.registration_state === "frozen"} onClick={() => freeze(registration)}>Freeze server and invalidate approvals</button></article>)}{dashboard.attestations.map((item) => <p key={item.attestation_id}>{item.attestation_state} · transport enabled: {item.transport_enabled ? "yes" : "no"}</p>)}{dashboard.items.map((item) => <p key={item.item_id}>{item.item_name} · {item.tool_mode} · schema <code>{item.request_schema_sha256}</code> · <span className="state-label">{item.tool_mode === "proposal_only" ? "Pinned proposal only" : "Item ineligible"}</span></p>)}{dashboard.freezes.map((item) => <p key={item.freeze_id}><span className="state-label">Server frozen</span> · {item.reason_code} · {item.invalidated_approval_count} approval(s) invalidated</p>)}</section>
    <section className="work-panel" aria-labelledby="workbench-lanes-title"><h2 id="workbench-lanes-title">Provenance lanes</h2>{dashboard.trust_items.length === 0 ? <p className="empty-state">No minimized trust-lane items are stored.</p> : dashboard.trust_items.map((item) => <article key={item.item_id}><strong>{laneLabel(item.trust_lane)}</strong><p>{item.item_state} · provenance <code>{item.provenance_sha256}</code></p></article>)}</section>
    <section className="work-panel" aria-labelledby="workbench-proposals-title"><h2 id="workbench-proposals-title">Exact proposals and disclosure</h2>{dashboard.drafts.length === 0 ? <p className="empty-state">No stored drafts require review.</p> : dashboard.drafts.map((draft) => { const disclosure = dashboard.disclosures.find((item) => item.draft_id === draft.draft_id); return <article className="lifecycle-state lifecycle-state--approval" key={draft.draft_id}><strong>{draft.draft_id} · revision {draft.draft_revision} · {draft.draft_state}</strong><p>Proposal: <code>{draft.proposal_sha256}</code></p><p>Authority: <code>{draft.authority_sha256}</code></p><p>Created by {draft.created_by}</p>{disclosure && <p>{disclosure.access_class} · {disclosure.egress_class} · {disclosure.disclosure_state} · fields <code>{disclosure.sanitized_fields_sha256}</code> · target <code>{disclosure.target_scope_sha256}</code> · budget <code>{disclosure.budget_sha256}</code></p>}{draft.draft_state === "awaiting_review" && <button type="button" disabled={!canMutateDraft || busy === draft.draft_id || draft.created_by === context.subject} onClick={() => review(draft)}>Approve exact proposal</button>}<button type="button" disabled={!canMutateDraft || !binding || busy === draft.draft_id || !new Set(["awaiting_review", "approved"]).has(draft.draft_state)} onClick={() => { if (binding) successor(draft, binding); }}>Create successor and invalidate approval</button></article>; })}{dashboard.decisions.map((decision) => <p key={decision.decision_id}>{decision.decision_kind} · {decision.decision_state} · <code>{decision.proposal_sha256}</code></p>)}{dashboard.lifecycle.map((event) => <p key={event.event_id}>{event.event_kind} · {event.from_state} → {event.to_state}</p>)}</section>
  </div>;
}

function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Workbench unavailable"}><strong>{denied ? "Access denied" : "Workbench unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review supervised Workbench state." : "Fixture binding, proposal, disclosure, and MCP inventory truth could not be loaded; no draft or approval state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function bindingAvailable(binding: Binding): boolean { return binding.binding_state === "available" && binding.fixture_only && binding.egress_class === "none"; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("workbench_unavailable", "Workbench unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The supervised Workbench action could not be completed."; }
function laneLabel(value: string): string { return value.split("_").map((part) => part === "ai" ? "AI" : `${part.charAt(0).toUpperCase()}${part.slice(1)}`).join(" "); }
