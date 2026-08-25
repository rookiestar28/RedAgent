import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["FindingOperationsDashboardData"];
type EvidencePage = Awaited<ReturnType<Client["listEvidencePage"]>>;

const PAGE_SIZE = 50;

export function FindingOperationsPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [evidence, setEvidence] = useState<EvidencePage | null>(null);
  const [evidenceOffsets, setEvidenceOffsets] = useState<readonly number[]>([0]);
  const [evidenceIndex, setEvidenceIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "finding:read");
  const canIngest = hasPermission(context, "finding:ingest");
  const canReadEvidence = hasPermission(context, "evidence:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    const evidencePage = canIngest && canReadEvidence
      ? client.listEvidencePage(PAGE_SIZE, 0)
      : Promise.resolve(null);
    void Promise.all([client.getFindingOperationsDashboard(), evidencePage])
      .then(([nextDashboard, nextEvidence]) => {
        if (!active) return;
        setDashboard(nextDashboard);
        setEvidence(nextEvidence);
        setEvidenceOffsets([0]);
        setEvidenceIndex(0);
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canIngest, canRead, canReadEvidence, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading finding operations">
    <strong>Loading finding operations</strong><p>Resolving reviewed issues, report snapshots, and fixture-only delivery truth.</p>
  </section>;

  async function refresh() {
    setActionError(null);
    try { setDashboard(await client.getFindingOperationsDashboard()); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  async function importFixture(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!evidence) return;
    const artifactId = new FormData(event.currentTarget).get("evidence_binding");
    const artifact = evidence.data.find((item) => item.artifact_id === artifactId
      && item.artifact_class === "report_safe" && item.quarantine_reason === null);
    if (!artifact) return;
    setBusy("import"); setActionError(null);
    try {
      const binding = crypto.randomUUID();
      await client.importFindingFixture({
        import_id: `fixture-import-${binding}`,
        run_id: `fixture-run-${binding}`,
        source_record_id: `fixture-source-${binding}`,
        resource_id: `fixture-resource-${binding}`,
        evidence_id: artifact.artifact_id,
        evidence_sha256: artifact.content_sha256,
        coverage_state: "complete",
        baseline_run_id: null,
        confirmation: "--confirm-r115-fixture-import",
      });
      setNotice("Accepted normalized fixture result imported from approved report-safe evidence.");
      await refresh();
    } catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function review(issueId: string, disposition: "confirmed" | "false_positive") {
    if (!window.confirm(`Record ${disposition} for ${issueId} without changing occurrence evidence?`)) return;
    setBusy(issueId); setActionError(null);
    try { await client.reviewFindingIssue(issueId, disposition, `reviewed-fixture-${disposition}`); setNotice("Reviewed disposition recorded."); await refresh(); }
    catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function report(issue: Dashboard["issues"][number]) {
    if (!dashboard) return;
    const occurrence = dashboard.occurrences.find((item) => item.issue_id === issue.issue_id);
    if (!occurrence) { setActionError("Approved occurrence evidence is required."); return; }
    setBusy(`report-${issue.issue_id}`); setActionError(null);
    try {
      await client.createFindingReport(`report-${crypto.randomUUID()}`, "technical", issue.issue_fingerprint,
        occurrence.evidence_sha256, occurrence.coverage_state === "complete" ? "complete" : "partial");
      setNotice("Deterministic technical report created."); await refresh();
    } catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function deliver(item: Dashboard["reports"][number]) {
    if (!window.confirm(`Queue zero-network fixture delivery for exact report ${item.report_sha256}?`)) return;
    setBusy(`delivery-${item.report_id}`); setActionError(null);
    try { await client.queueFindingDelivery(`delivery-${crypto.randomUUID()}`, item, "SEC"); setNotice("Fixture ticket delivery queued; no network contact was authorized."); await refresh(); }
    catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function publish(item: Dashboard["reports"][number]) {
    if (!window.confirm(`Independently publish exact report ${item.report_sha256}?`)) return;
    setBusy(`publish-${item.report_id}`); setActionError(null);
    try { await client.publishFindingReport(item); setNotice("Exact reviewed report published."); await refresh(); }
    catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function loadEvidence(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setEvidence(await client.listEvidencePage(PAGE_SIZE, offset)); setEvidenceOffsets(history); setEvidenceIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  const issues = dashboard.issues;
  const reports = dashboard.reports;
  const deliveries = dashboard.deliveries;
  const normalizedQuery = query.trim().toLowerCase();
  const visibleIssues = normalizedQuery ? issues.filter((item) =>
    `${item.issue_id} ${item.title} ${item.severity} ${item.disposition} ${item.issue_fingerprint}`.toLowerCase().includes(normalizedQuery)) : issues;
  const visibleIssueIds = new Set(visibleIssues.map((item) => item.issue_id));
  const approvedEvidence = evidence?.data.filter((item) => item.artifact_class === "report_safe" && item.quarantine_reason === null) ?? [];

  return <div className="operational-page finding-operations-page">
    <section className="work-panel" aria-labelledby="finding-operations-title"><div className="section-heading"><div><span className="eyebrow">Reviewed remediation truth</span><h2 id="finding-operations-title">Finding and remediation operations</h2></div><span className="environment-chip">Fixture connectors · zero network</span></div><p>Operator {context.subject} works from normalized stored records and report-safe evidence. AI cannot approve or publish.</p>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}</section>
    <section className="work-panel" aria-labelledby="finding-queues-title"><div className="section-heading"><h2 id="finding-queues-title">Action queues</h2><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div><label>Search findings<input type="search" value={query} onChange={(event) => setQuery(event.target.value)} /></label><div className="metric-grid"><article><strong>{issues.filter((item) => item.disposition === "needs_review").length}</strong><span>Needs review</span></article><article><strong>{issues.filter((item) => item.sla_due_at && new Date(item.sla_due_at) < new Date()).length}</strong><span>SLA breaches</span></article><article><strong>{issues.filter((item) => item.disposition === "risk_accepted").length}</strong><span>Exception expiry</span></article><article><strong>{reports.filter((item) => item.report_state === "blocked").length}</strong><span>Publication blocked</span></article><article><strong>{deliveries.filter((item) => item.delivery_state === "dead_letter").length}</strong><span>Connector dead-letter</span></article></div></section>
    <section className="work-panel"><h2>Import accepted normalized fixture result</h2>{!canIngest ? <p className="empty-state">Requires finding:ingest.</p> : !canReadEvidence ? <p className="empty-state">Requires evidence:read for approved evidence selection.</p> : approvedEvidence.length === 0 ? <p className="empty-state">No approved report-safe evidence is available on this page.</p> : <form onSubmit={(event) => { void importFixture(event); }}><label>Approved report-safe evidence<select name="evidence_binding" required><option value="">Select evidence</option>{approvedEvidence.map((item) => <option key={item.artifact_id} value={item.artifact_id}>{item.artifact_id} · retained until {new Date(item.retain_until).toLocaleDateString()}</option>)}</select></label><small>Import, run, source, and resource bindings are generated. The fixed normalized fixture creates no execution or network action.</small><button type="submit" disabled={busy === "import"}>Import fixture result</button></form>}{evidence && <div className="pagination-controls" aria-label="Approved evidence pages"><button type="button" disabled={evidenceIndex === 0} onClick={() => { const index = evidenceIndex - 1; void loadEvidence(evidenceOffsets[index] ?? 0, index, evidenceOffsets); }}>Previous evidence choices</button><span>Page {evidenceIndex + 1}</span><button type="button" disabled={evidence.page.next_offset === null || evidence.page.next_offset === undefined} onClick={() => { const offset = evidence.page.next_offset; if (offset === null || offset === undefined) return; const history = [...evidenceOffsets.slice(0, evidenceIndex + 1), offset]; void loadEvidence(offset, history.length - 1, history); }}>Next evidence choices</button></div>}</section>
    <section className="work-panel"><h2>Canonical issues and reviewed disposition</h2>{visibleIssues.length === 0 && <p className="empty-state">No canonical issues match the current search.</p>}{visibleIssues.map((issue) => <article key={issue.issue_id} className="lifecycle-state"><strong>{issue.title} · {issue.severity}</strong><p>{issue.disposition} · revision {issue.disposition_revision}</p><p>Fingerprint <code>{issue.issue_fingerprint}</code> · state {issue.issue_state}</p><p>Owner {issue.owner_id ?? "Unassigned"} · SLA {issue.sla_due_at ?? "Not assigned"}</p><button type="button" disabled={busy === issue.issue_id || !hasPermission(context, "finding:review")} onClick={() => { void review(issue.issue_id, "confirmed"); }}>Confirm reviewed issue</button><button type="button" disabled={busy === issue.issue_id || !hasPermission(context, "finding:review")} onClick={() => { void review(issue.issue_id, "false_positive"); }}>Mark reviewed false positive</button><button type="button" disabled={busy === `report-${issue.issue_id}` || issue.disposition === "needs_review" || !hasPermission(context, "report:create")} onClick={() => { void report(issue); }}>Create deterministic technical report</button></article>)}</section>
    <section className="work-panel"><h2>Immutable occurrences and evidence lineage</h2>{dashboard.occurrences.filter((item) => visibleIssueIds.has(item.issue_id)).map((item) => <article key={item.occurrence_id}><strong>{item.occurrence_id}</strong><p>{item.rule_id} · {item.coverage_state} · {item.occurrence_state}</p><p>{item.tool_id} {item.tool_version} · rule {item.rule_version} · database {item.database_version}</p><p>Evidence {item.evidence_id} · {item.redaction_state} · <code>{item.evidence_sha256}</code></p></article>)}</section>
    <section className="work-panel"><h2>Deterministic publication</h2>{reports.map((item) => { const publication = dashboard.publications.find((value) => value.report_id === item.report_id); return <article key={item.report_id}><strong>{item.report_id} · {item.audience}</strong><p>{item.report_state} · {item.generation_profile} · generated by {item.generated_by}</p><p>Snapshot <code>{item.report_sha256}</code></p>{!publication && <button type="button" disabled={item.report_state !== "publishable" || busy === `publish-${item.report_id}` || item.generated_by === context.subject || !hasPermission(context, "report:publish")} onClick={() => { void publish(item); }}>Independently publish exact report</button>}{publication && <p>{publication.publication_state} · reviewer {publication.reviewer_id} · publisher {publication.publisher_id}</p>}<button type="button" disabled={!publication || busy === `delivery-${item.report_id}` || !hasPermission(context, "connector:deliver")} onClick={() => { void deliver(item); }}>Queue fixture ticket delivery</button></article>; })}</section>
    <section className="work-panel"><h2>Connector delivery and reconciliation</h2>{deliveries.length === 0 ? <p className="empty-state">No connector deliveries</p> : deliveries.map((item) => <article key={item.delivery_id}><strong>{item.delivery_id} · {item.profile_id}</strong><p>{item.delivery_state} · {item.attempt_count} attempts · {item.network_contact_count} network contacts</p><p>Exact report <code>{item.snapshot_sha256}</code></p></article>)}</section>
  </div>;
}

function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) {
  return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Finding operations unavailable"}><strong>{denied ? "Access denied" : "Finding operations unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review finding operations." : "Finding, report, and delivery truth could not be loaded; no state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>;
}

function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The finding operation could not be completed."; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("finding_operations_unavailable", "Finding operations unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
