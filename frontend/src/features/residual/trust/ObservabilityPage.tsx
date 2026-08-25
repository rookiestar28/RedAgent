import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["ObservabilityDashboardData"];
type Incident = components["schemas"]["IncidentData"];
type Timeline = components["schemas"]["IncidentTimelineData"];
type Runbook = components["schemas"]["IncidentRunbookData"];
type IncidentPage = Awaited<ReturnType<Client["listIncidentsPage"]>>;
type CorrelationPage = Awaited<ReturnType<Client["lookupCorrelationPage"]>>;

const PAGE_SIZE = 50;

export function ObservabilityPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [incidents, setIncidents] = useState<IncidentPage | null>(null);
  const [runbooks, setRunbooks] = useState<Runbook[]>([]);
  const [timeline, setTimeline] = useState<Record<string, Timeline[]>>({});
  const [correlation, setCorrelation] = useState<CorrelationPage | null>(null);
  const [correlationId, setCorrelationId] = useState<string | null>(null);
  const [incidentOffsets, setIncidentOffsets] = useState<readonly number[]>([0]);
  const [correlationOffsets, setCorrelationOffsets] = useState<readonly number[]>([0]);
  const [incidentIndex, setIncidentIndex] = useState(0);
  const [correlationIndex, setCorrelationIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "audit:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([
      client.getObservabilityDashboard(), client.listIncidentsPage(PAGE_SIZE, 0), client.listIncidentRunbooks(),
    ]).then(([nextDashboard, nextIncidents, nextRunbooks]) => {
      if (!active) return;
      setDashboard(nextDashboard); setIncidents(nextIncidents); setRunbooks(nextRunbooks);
      setIncidentOffsets([0]); setIncidentIndex(0);
    }).catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard || !incidents) return <section className="route-state" role="status" aria-label="Loading observability state">
    <strong>Loading observability state</strong><p>Resolving SLO, export, incident, and reviewed runbook truth.</p>
  </section>;

  async function refresh() {
    setActionError(null);
    try {
      const [nextDashboard, nextIncidents, nextRunbooks] = await Promise.all([
        client.getObservabilityDashboard(), client.listIncidentsPage(PAGE_SIZE, 0), client.listIncidentRunbooks(),
      ]);
      setDashboard(nextDashboard); setIncidents(nextIncidents); setRunbooks(nextRunbooks);
      setIncidentOffsets([0]); setIncidentIndex(0);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function lookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setActionError(null);
    const data = new FormData(event.currentTarget);
    const value = data.get("correlation_id");
    if (typeof value !== "string" || value.length === 0) return;
    try {
      setCorrelation(await client.lookupCorrelationPage(value, PAGE_SIZE, 0));
      setCorrelationId(value); setCorrelationOffsets([0]); setCorrelationIndex(0);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function loadIncidents(offset: number, index: number, offsets: readonly number[]) {
    setActionError(null);
    try { setIncidents(await client.listIncidentsPage(PAGE_SIZE, offset)); setIncidentOffsets(offsets); setIncidentIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  async function loadCorrelation(offset: number, index: number, offsets: readonly number[]) {
    if (!correlationId) return;
    setActionError(null);
    try { setCorrelation(await client.lookupCorrelationPage(correlationId, PAGE_SIZE, offset)); setCorrelationOffsets(offsets); setCorrelationIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  async function showTimeline(incident: Incident) {
    try {
      const rows = await client.getIncidentTimeline(incident.incident_id);
      setTimeline((current) => ({ ...current, [incident.incident_id]: rows }));
    }
    catch (cause) { setActionError(projectError(cause)); }
  }

  async function act(incident: Incident, action: components["schemas"]["IncidentActionRequest"]["action"]) {
    if (!window.confirm(`${action.replace("_", " ")} ${incident.incident_id}?`)) return;
    try {
      const updated = await client.applyIncidentAction(incident.incident_id, {
        action_id: crypto.randomUUID(), action, expected_version: incident.version,
        assignee_id: action === "assign" ? context.subject : null,
      });
      setIncidents((current) => current ? { ...current, data: current.data.map((item) => item.incident_id === updated.incident_id ? updated : item) } : current);
      await showTimeline(updated);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid observability-page">
    {actionError && <p className="inline-error" role="alert">{actionError}</p>}
    <section className="work-panel" aria-labelledby="observability-title">
      <div className="section-heading"><div><span className="eyebrow">Live operational truth</span><h2 id="observability-title">Observability and SLOs</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>
      <dl><dt>Open alerts</dt><dd>{dashboard.open_alerts}</dd><dt>Unreplayed dead letters</dt><dd>{dashboard.unreplayed_dead_letters}</dd>
        <dt>Export states</dt><dd>{formatCounts(dashboard.export_state_counts)}</dd><dt>SLO states</dt><dd>{formatCounts(dashboard.slo_state_counts)}</dd><dt>Incident states</dt><dd>{formatCounts(dashboard.incident_state_counts)}</dd></dl>
      <form onSubmit={(event) => { void lookup(event); }}><label>Correlation ID<input name="correlation_id" required maxLength={100} pattern="[A-Za-z0-9._:-]+" /></label><button type="submit">Look up correlation</button></form>
      {correlation && (correlation.data.length === 0 ? <p className="empty-state">No correlated operations</p> : <ul className="record-list">{correlation.data.map((row) => <li key={row.operation_id}><strong>{row.operation_id}</strong><span>{row.export_state} · {row.signal_kind}</span><small>{row.reason_code ?? "No delivery reason"}</small></li>)}</ul>)}
      {correlation && <PageControls label="correlation results" index={correlationIndex} page={correlation.page}
        previous={() => { const index = correlationIndex - 1; void loadCorrelation(correlationOffsets[index] ?? 0, index, correlationOffsets); }}
        next={() => { const offset = correlation.page.next_offset; if (offset === null || offset === undefined) return; const offsets = [...correlationOffsets.slice(0, correlationIndex + 1), offset]; void loadCorrelation(offset, offsets.length - 1, offsets); }} />}
    </section>
    <section className="work-panel" aria-labelledby="incident-title">
      <div className="section-heading"><div><span className="eyebrow">Canonical response</span><h2 id="incident-title">Security incidents</h2></div><span className="count-chip">{incidents.data.filter((item) => item.state !== "closed").length} open on page</span></div>
      {incidents.data.length === 0 ? <p className="empty-state">No incidents</p> : <ul className="record-list">{incidents.data.map((incident) => <li key={incident.incident_id}>
        <strong>{incident.incident_id}</strong><span>{incident.severity} · {incident.state}</span><small>{incident.reason_code} · Version {incident.version}</small>
        <button type="button" onClick={() => { void showTimeline(incident); }}>Timeline</button>
        {!incident.assigned_to_user_id && ["open", "acknowledged"].includes(incident.state) && <button type="button" onClick={() => { void act(incident, "assign"); }}>Assign to me</button>}
        {incident.state === "open" && <button type="button" onClick={() => { void act(incident, "acknowledge"); }}>Acknowledge</button>}
        {incident.state === "acknowledged" && !incident.evidence_preserved && <button type="button" onClick={() => { void act(incident, "preserve_evidence"); }}>Preserve evidence</button>}
        {incident.state === "acknowledged" && incident.evidence_preserved && !incident.containment_verified && <button type="button" onClick={() => { void act(incident, "verify_containment"); }}>Verify containment</button>}
        {incident.state === "acknowledged" && incident.evidence_preserved && incident.containment_verified && <button type="button" onClick={() => { void act(incident, "mark_contained"); }}>Mark contained</button>}
        {incident.state === "contained" && <button type="button" onClick={() => { void act(incident, "mark_recovered"); }}>Mark recovered</button>}
        {incident.state === "recovered" && <button type="button" onClick={() => { void act(incident, "complete_review"); }}>Complete review</button>}
        {incident.state === "reviewed" && <button type="button" onClick={() => { void act(incident, "close"); }}>Close incident</button>}
        {(timeline[incident.incident_id]?.length ?? 0) > 0 && <ol>{timeline[incident.incident_id]?.map((event) => <li key={event.event_id}>{event.event_type} · {event.actor_user_id}</li>)}</ol>}
      </li>)}</ul>}
      <PageControls label="incidents" index={incidentIndex} page={incidents.page}
        previous={() => { const index = incidentIndex - 1; void loadIncidents(incidentOffsets[index] ?? 0, index, incidentOffsets); }}
        next={() => { const offset = incidents.page.next_offset; if (offset === null || offset === undefined) return; const offsets = [...incidentOffsets.slice(0, incidentIndex + 1), offset]; void loadIncidents(offset, offsets.length - 1, offsets); }} />
      <h3>Reviewed runbooks</h3>{runbooks.length === 0 ? <p className="empty-state">No runbooks available</p> : <ul className="record-list">{runbooks.map((runbook) => <li key={runbook.runbook_id}><strong>{runbook.runbook_id}</strong><span>{runbook.owner}</span><small>{runbook.triage[0]} {runbook.containment[0]}</small></li>)}</ul>}
    </section>
  </div>;
}

function PageControls({ label, index, page, previous, next }: { readonly label: string; readonly index: number; readonly page: IncidentPage["page"]; readonly previous: () => void; readonly next: () => void }) {
  return <div className="pagination-controls" aria-label={`${label} pages`}><button type="button" disabled={index === 0} onClick={previous}>Previous {label}</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={next}>Next {label}</button></div>;
}

function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) {
  return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Observability unavailable"}><strong>{denied ? "Access denied" : "Observability unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review observability and incident truth." : "Observability data could not be loaded; no incident state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>;
}

function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The observability action could not be completed."; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("observability_unavailable", "Observability unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function formatCounts(values: Record<string, number>): string { const rows = Object.entries(values).sort(([left], [right]) => left.localeCompare(right)); return rows.length ? rows.map(([name, count]) => `${name}: ${count}`).join(" · ") : "No data"; }
