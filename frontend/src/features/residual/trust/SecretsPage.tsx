import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Lease = components["schemas"]["SecretLeaseData"];
type Page = Awaited<ReturnType<Client["listSecretLeasesPage"]>>;
type ReferencePage = Awaited<ReturnType<Client["listSecretReferencesPage"]>>;
type JobPage = Awaited<ReturnType<Client["listJobsPage"]>>;
type PageMeta = Page["page"];

const PAGE_SIZE = 50;

export function SecretsPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [leases, setLeases] = useState<Page | null>(null);
  const [references, setReferences] = useState<ReferencePage | null>(null);
  const [jobs, setJobs] = useState<JobPage | null>(null);
  const [leaseOffsets, setLeaseOffsets] = useState<readonly number[]>([0]);
  const [referenceOffsets, setReferenceOffsets] = useState<readonly number[]>([0]);
  const [jobOffsets, setJobOffsets] = useState<readonly number[]>([0]);
  const [leaseIndex, setLeaseIndex] = useState(0);
  const [referenceIndex, setReferenceIndex] = useState(0);
  const [jobIndex, setJobIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "secret:read");
  const canIssue = hasPermission(context, "secret:issue");
  const canReadJobs = hasPermission(context, "job:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    const jobPage = canIssue && canReadJobs ? client.listJobsPage(PAGE_SIZE, 0) : Promise.resolve(null);
    void Promise.all([
      client.listSecretReferencesPage(PAGE_SIZE, 0), client.listSecretLeasesPage(PAGE_SIZE, 0), jobPage,
    ]).then(([nextReferences, nextLeases, nextJobs]) => {
      if (!active) return;
      setReferences(nextReferences); setLeases(nextLeases); setJobs(nextJobs);
      setLeaseOffsets([0]); setReferenceOffsets([0]); setJobOffsets([0]);
      setLeaseIndex(0); setReferenceIndex(0); setJobIndex(0);
    }).catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canIssue, canRead, canReadJobs, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!leases || !references) return <section className="route-state" role="status" aria-label="Loading credential lease state"><strong>Loading credential lease state</strong><p>Resolving opaque references, leases, and authorized synthetic workload bindings.</p></section>;

  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!jobs) return;
    const data = new FormData(event.currentTarget);
    const job = jobs.data.find((item) => item.job_id === data.get("job_binding"));
    const ttl = Number(data.get("ttl_seconds"));
    if (!job || !Number.isInteger(ttl) || ttl < 1 || ttl > 900) return;
    setActionError(null); setNotice(null);
    try {
      const binding = crypto.randomUUID();
      const lease = await client.issueSyntheticSecretLease({
        reference_id: `synthetic-reference-${binding}`,
        lease_id: `synthetic-lease-${binding}`,
        engagement_id: job.engagement_id,
        job_id: job.job_id,
        workload_client_id: `synthetic-workload-${binding}`,
        ttl_seconds: ttl,
      }, job.roe_version_id);
      setLeases((current) => current ? { ...current, data: [lease, ...current.data.filter((item) => item.lease_id !== lease.lease_id)] } : current);
      setReferences(await client.listSecretReferencesPage(PAGE_SIZE, referenceOffsets[referenceIndex] ?? 0));
      setNotice(`Lease ${lease.lease_id} delivered once to the attested synthetic workload.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function revoke(lease: Lease) {
    if (!window.confirm(`Revoke exact lease ${lease.lease_id}?`)) return;
    setActionError(null);
    try {
      const updated = await client.revokeSecretLease(lease.lease_id, lease.version);
      setLeases((current) => current ? { ...current, data: current.data.map((item) => item.lease_id === updated.lease_id ? updated : item) } : current);
      setNotice(`Exact lease ${updated.lease_id} is ${updated.lease_state}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageLeases(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setLeases(await client.listSecretLeasesPage(PAGE_SIZE, offset)); setLeaseOffsets(history); setLeaseIndex(index); } catch (cause) { setActionError(projectError(cause)); } }
  async function pageReferences(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setReferences(await client.listSecretReferencesPage(PAGE_SIZE, offset)); setReferenceOffsets(history); setReferenceIndex(index); } catch (cause) { setActionError(projectError(cause)); } }
  async function pageJobs(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setJobs(await client.listJobsPage(PAGE_SIZE, offset)); setJobOffsets(history); setJobIndex(index); } catch (cause) { setActionError(projectError(cause)); } }

  return <div className="operational-grid secrets-page">
    <section className="work-panel" aria-labelledby="secrets-title"><div className="section-heading"><div><span className="eyebrow">External lease truth</span><h2 id="secrets-title">Credential leases</h2></div><span className="count-chip">{leases.data.length} on page</span></div><p>Only opaque reference and lease metadata is rendered. Credential material, provider payloads, tokens, and role paths never enter the console.</p>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}{leases.data.length === 0 ? <p className="empty-state">No credential leases</p> : <ul className="job-list">{leases.data.map((lease) => <li key={lease.lease_id} className="job-record"><div className="job-record__heading"><div><strong>{lease.lease_id}</strong><span>{lease.capability}</span></div><span className="state-label">{lease.lease_state}</span></div><dl><dt>Reference / workload</dt><dd>{lease.reference_id} / {lease.workload_client_id}</dd><dt>Job / ROE</dt><dd>{lease.job_id} / {lease.roe_version_id}</dd><dt>Expires</dt><dd>{new Date(lease.expires_at).toLocaleString()}</dd><dt>Renewal</dt><dd>{lease.renewable ? "Eligible after full boundary revalidation" : "Not renewable"} · {lease.renewal_count}</dd><dt>Failure</dt><dd>{lease.failure_code ?? "None"}</dd></dl><button className="danger-action" type="button" disabled={!hasPermission(context, "secret:revoke") || new Set(["revoked", "expired"]).has(lease.lease_state)} onClick={() => { void revoke(lease); }}>Revoke exact lease</button></li>)}</ul>}<Pager label="leases" index={leaseIndex} page={leases.page} offsets={leaseOffsets} load={pageLeases} /></section>
    <section className="work-panel"><h3>Opaque references</h3>{references.data.length === 0 ? <p className="empty-state">No configured references</p> : <ul className="record-list">{references.data.map((item) => <li key={item.reference_id}><strong>{item.redaction_label}</strong><span>{item.reference_kind} · {item.reference_status}</span><small>{item.allowed_capabilities.join(", ")} · rotation {new Date(item.rotation_due_at).toLocaleString()}</small></li>)}</ul>}<Pager label="references" index={referenceIndex} page={references.page} offsets={referenceOffsets} load={pageReferences} /></section>
    <section className="form-panel" aria-labelledby="synthetic-secret-title"><span className="eyebrow">Local conformance only</span><h2 id="synthetic-secret-title">Issue synthetic lease</h2>{!canIssue ? <p className="empty-state">Requires secret:issue.</p> : !canReadJobs ? <p className="empty-state">Requires job:read to choose an authorized job.</p> : !jobs || jobs.data.length === 0 ? <p className="empty-state">No authorized job is available.</p> : <form onSubmit={(event) => { void issue(event); }}><label>Authorized job<select name="job_binding" required><option value="">Select job</option>{jobs.data.map((job) => <option key={job.job_id} value={job.job_id}>{job.status} · {job.current_gate} · {job.job_id}</option>)}</select></label><label>TTL seconds<input name="ttl_seconds" type="number" min={1} max={900} defaultValue={300} required /></label><small>Reference, lease, workload, engagement, job, and ROE bindings are generated or derived. Capability and permission remain fixed to synthetic-noop/read; no credential value is accepted.</small><button type="submit">Issue to synthetic workload</button></form>}{jobs && <Pager label="jobs" index={jobIndex} page={jobs.page} offsets={jobOffsets} load={pageJobs} />}</section>
  </div>;
}

function Pager({ label, index, page, offsets, load }: { readonly label: string; readonly index: number; readonly page: PageMeta; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) {
  return <div className="pagination-controls" aria-label={`${label} pages`}><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous {label}</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next {label}</button></div>;
}

function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Credential service unavailable"}><strong>{denied ? "Access denied" : "Credential service unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review credential lease metadata." : "Opaque reference and lease metadata could not be loaded; no credential state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The credential lease action could not be completed."; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("secret_unavailable", "Credential service unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
