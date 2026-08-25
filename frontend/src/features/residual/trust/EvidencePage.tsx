import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Evidence = components["schemas"]["EvidenceArtifactData"];
type EvidenceDetail = components["schemas"]["EvidenceArtifactDetailData"];
type EvidencePageData = Awaited<ReturnType<Client["listEvidencePage"]>>;
type JobPageData = Awaited<ReturnType<Client["listJobsPage"]>>;

const PAGE_SIZE = 50;

export function EvidencePage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [page, setPage] = useState<EvidencePageData | null>(null);
  const [jobs, setJobs] = useState<JobPageData | null>(null);
  const [selected, setSelected] = useState<EvidenceDetail | null>(null);
  const [offsets, setOffsets] = useState<readonly number[]>([0]);
  const [jobOffsets, setJobOffsets] = useState<readonly number[]>([0]);
  const [pageIndex, setPageIndex] = useState(0);
  const [jobPageIndex, setJobPageIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "evidence:read");
  const canRegister = hasPermission(context, "evidence:write");
  const canReadJobs = hasPermission(context, "job:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    const jobPage = canRegister && canReadJobs
      ? client.listJobsPage(PAGE_SIZE, 0)
      : Promise.resolve(null);
    void Promise.all([client.listEvidencePage(PAGE_SIZE, 0), jobPage])
      .then(([nextPage, nextJobs]) => {
        if (!active) return;
        setPage(nextPage);
        setJobs(nextJobs);
        setOffsets([0]);
        setPageIndex(0);
        setJobOffsets([0]);
        setJobPageIndex(0);
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, canReadJobs, canRegister, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError
    denied={isAccessDenied(routeError)}
    correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }}
  />;
  if (!page) return <section className="route-state" role="status" aria-label="Loading evidence state">
    <strong>Loading evidence state</strong><p>Resolving immutable custody metadata and authorized resource choices.</p>
  </section>;

  async function inspect(artifactId: string) {
    setActionError(null);
    try { setSelected(await client.getEvidence(artifactId)); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  async function verify() {
    if (!selected) return;
    setActionError(null);
    try {
      const result = await client.verifyEvidence(selected.artifact_id);
      setNotice(result.verified
        ? `Exact version ${result.object_version_id} verified.`
        : `Verification failed: ${result.reason}`);
      await inspect(selected.artifact_id);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function placeHold() {
    if (!selected || !window.confirm(`Place an irreversible application-level legal hold on ${selected.artifact_id}?`)) return;
    setActionError(null);
    try {
      const held = await client.placeEvidenceLegalHold(selected.artifact_id, selected.version);
      replaceEvidence(held);
      setNotice(`Legal hold placed on exact object version ${held.object_version_id}.`);
      await inspect(held.artifact_id);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function derive(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const artifactClass = new FormData(event.currentTarget).get("artifact_class");
    if (artifactClass !== "report_safe" && artifactClass !== "export_safe") return;
    setActionError(null);
    try {
      const created = await client.deriveEvidence(selected.artifact_id, {
        artifact_id: `evidence-${crypto.randomUUID()}`,
        artifact_class: artifactClass,
        transform_name: "central-redaction",
        transform_version: "1",
        quality_approved: true,
      });
      prependEvidence(created);
      setNotice(`Immutable ${created.artifact_class} derivative created.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function registerSynthetic(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!jobs) return;
    const data = new FormData(event.currentTarget);
    const jobId = data.get("job_binding");
    const fixtureKind = data.get("fixture_kind");
    const job = jobs.data.find((item) => item.job_id === jobId);
    if (!job || (fixtureKind !== "sanitized-log" && fixtureKind !== "sanitized-json")) return;
    setActionError(null);
    try {
      const created = await client.registerSyntheticEvidence({
        artifact_id: `evidence-${crypto.randomUUID()}`,
        engagement_id: job.engagement_id,
        job_id: job.job_id,
        fixture_kind: fixtureKind,
        retention_days: 30,
      });
      prependEvidence(created);
      setNotice(`Synthetic evidence ${created.artifact_id} registered.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function selectForPurpose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const purpose = new FormData(event.currentTarget).get("selection_purpose");
    if (purpose !== "review" && purpose !== "report" && purpose !== "export") return;
    setActionError(null);
    try {
      const chosen = await client.selectEvidence(selected.artifact_id, purpose);
      await inspect(chosen.artifact_id);
      setNotice(`Approved ${purpose} evidence selected.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function loadPage(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try {
      setPage(await client.listEvidencePage(PAGE_SIZE, offset));
      setOffsets(history);
      setPageIndex(index);
      setSelected(null);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function loadJobs(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try {
      setJobs(await client.listJobsPage(PAGE_SIZE, offset));
      setJobOffsets(history);
      setJobPageIndex(index);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  function replaceEvidence(artifact: Evidence) {
    setPage((current) => current
      ? { ...current, data: current.data.map((item) => item.artifact_id === artifact.artifact_id ? artifact : item) }
      : current);
  }

  function prependEvidence(artifact: Evidence) {
    setPage((current) => current ? { ...current, data: [artifact, ...current.data] } : current);
  }

  return <div className="operational-grid evidence-page">
    <section className="work-panel" aria-labelledby="evidence-title">
      <div className="section-heading"><div><span className="eyebrow">Immutable custody</span><h2 id="evidence-title">Evidence</h2></div><span className="count-chip">{page.data.length} on page</span></div>
      <p>Only metadata and integrity state are displayed. Raw evidence bytes, object-store credentials, and provider controls are never rendered.</p>
      {actionError && <p className="inline-error" role="alert">{actionError}</p>}
      {notice && <p className="operation-notice" role="status">{notice}</p>}
      {page.data.length === 0 ? <p className="empty-state">No persistent evidence yet</p> : <ul className="record-list">{page.data.map((row) => <li key={row.artifact_id}>
        <button className="record-select" type="button" onClick={() => { void inspect(row.artifact_id); }}><strong>{row.artifact_id}</strong><span>{row.artifact_class} · {row.classification}</span><small>Version {row.version} · {row.legal_hold ? "legal hold" : row.quarantine_reason ?? "verification available"}</small></button>
      </li>)}</ul>}
      <PageControls index={pageIndex} page={page}
        previous={() => { const index = pageIndex - 1; void loadPage(offsets[index] ?? 0, index, offsets); }}
        next={() => { const offset = page.page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, pageIndex + 1), offset]; void loadPage(offset, history.length - 1, history); }} />
    </section>
    <section className="form-panel" aria-labelledby="synthetic-evidence-title">
      <span className="eyebrow">Local fixture only</span><h2 id="synthetic-evidence-title">Register synthetic evidence</h2>
      {!canRegister ? <p className="empty-state">Requires evidence:write.</p>
        : !canReadJobs ? <p className="empty-state">Requires job:read to choose an authorized job.</p>
          : !jobs || jobs.data.length === 0 ? <p className="empty-state">No authorized job is available.</p>
            : <form onSubmit={(event) => { void registerSynthetic(event); }}>
              <label>Authorized job<select name="job_binding" required><option value="">Select job</option>{jobs.data.map((job) => <option key={job.job_id} value={job.job_id}>{job.status} · {job.current_gate} · {job.job_id}</option>)}</select></label>
              <label>Fixture<select name="fixture_kind"><option value="sanitized-log">Sanitized log</option><option value="sanitized-json">Sanitized JSON</option></select></label>
              <small>The server chooses fixed bytes, object key, retention, encryption, and provider settings. Artifact and engagement bindings are generated or derived.</small>
              <button type="submit">Register fixture</button>
            </form>}
      {jobs && <div className="pagination-controls" aria-label="Authorized job pages"><button type="button" disabled={jobPageIndex === 0} onClick={() => { const index = jobPageIndex - 1; void loadJobs(jobOffsets[index] ?? 0, index, jobOffsets); }}>Previous jobs</button><span>Page {jobPageIndex + 1}</span><button type="button" disabled={jobs.page.next_offset === null || jobs.page.next_offset === undefined} onClick={() => { const offset = jobs.page.next_offset; if (offset === null || offset === undefined) return; const history = [...jobOffsets.slice(0, jobPageIndex + 1), offset]; void loadJobs(offset, history.length - 1, history); }}>Next jobs</button></div>}
    </section>
    {selected && <section className="workspace-panel" aria-labelledby="evidence-detail-title">
      <div className="section-heading"><div><span className="eyebrow">Exact object version</span><h2 id="evidence-detail-title">{selected.artifact_id}</h2></div><span className="state-label">{selected.quarantine_reason ?? "Available"}</span></div>
      <dl><dt>SHA-256</dt><dd>{selected.content_sha256}</dd><dt>Object version</dt><dd>{selected.object_version_id}</dd><dt>Class</dt><dd>{selected.artifact_class} · {selected.classification}</dd><dt>Retention</dt><dd>{selected.retention_mode} until {new Date(selected.retain_until).toLocaleString()}</dd><dt>Legal hold</dt><dd>{selected.legal_hold ? "ON" : "OFF"}</dd><dt>Lineage</dt><dd>{selected.source_artifact_id ?? "Original"} · {selected.transform_config_hash ?? "No transform"}</dd><dt>Custody / verification</dt><dd>{selected.custody_event_count} events · {selected.verification_count} checks · {selected.last_verified === false ? "Failed" : "Passing"}</dd></dl>
      <div className="job-actions"><button type="button" disabled={!hasPermission(context, "evidence:verify")} onClick={() => { void verify(); }}>Verify exact version</button><button type="button" disabled={selected.legal_hold || !hasPermission(context, "evidence:retention-admin")} onClick={() => { void placeHold(); }}>Place legal hold</button></div>
      <form onSubmit={(event) => { void selectForPurpose(event); }}><h3>Select approved evidence</h3><label>Selection purpose<select name="selection_purpose"><option value="review">Review</option><option value="report">Report</option><option value="export">Export</option></select></label><button type="submit">Select approved evidence</button></form>
      <form onSubmit={(event) => { void derive(event); }}><h3>Create approved derivative</h3><label>Purpose-safe class<select name="artifact_class"><option value="report_safe">Report safe</option><option value="export_safe">Export safe</option></select></label><small>Uses central-redaction v1 and immutable source lineage; raw bytes are not shown and the derivative binding is generated.</small><button type="submit" disabled={!hasPermission(context, "evidence:derive") || selected.artifact_class === "export_safe"}>Create derivative</button></form>
    </section>}
  </div>;
}

function PageControls({ index, page, previous, next }: {
  readonly index: number;
  readonly page: EvidencePageData;
  readonly previous: () => void;
  readonly next: () => void;
}) {
  return <div className="pagination-controls" aria-label="Evidence pages"><button type="button" disabled={index === 0} onClick={previous}>Previous evidence</button><span>Page {index + 1}</span><button type="button" disabled={page.page.next_offset === null || page.page.next_offset === undefined} onClick={next}>Next evidence</button></div>;
}

function RouteError({ denied, correlationId, retry }: {
  readonly denied: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Evidence unavailable"}><strong>{denied ? "Access denied" : "Evidence unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review evidence custody metadata." : "Evidence metadata could not be loaded; no custody or verification state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The evidence action could not be completed.";
}

function asConsoleError(cause: unknown): ConsoleApiError {
  return cause instanceof ConsoleApiError
    ? cause
    : new ConsoleApiError("evidence_unavailable", "Evidence unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}
