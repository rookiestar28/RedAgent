import { useEffect, useState } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type RunnerStatus = components["schemas"]["RunnerStatusData"];
type RegistrationPage = Awaited<ReturnType<Client["listRunnerRegistrationsPage"]>>;
type ManifestPage = Awaited<ReturnType<Client["listRunnerManifestsPage"]>>;
type ExecutionPage = Awaited<ReturnType<Client["listRunnerExecutionsPage"]>>;

const PAGE_SIZE = 50;

export function RunnersPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [status, setStatus] = useState<RunnerStatus | null>(null);
  const [registrations, setRegistrations] = useState<RegistrationPage | null>(null);
  const [manifests, setManifests] = useState<ManifestPage | null>(null);
  const [executions, setExecutions] = useState<ExecutionPage | null>(null);
  const [registrationOffsets, setRegistrationOffsets] = useState<readonly number[]>([0]);
  const [manifestOffsets, setManifestOffsets] = useState<readonly number[]>([0]);
  const [executionOffsets, setExecutionOffsets] = useState<readonly number[]>([0]);
  const [registrationIndex, setRegistrationIndex] = useState(0);
  const [manifestIndex, setManifestIndex] = useState(0);
  const [executionIndex, setExecutionIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "runner:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([
      client.getRunnerStatus(),
      client.listRunnerRegistrationsPage(PAGE_SIZE, 0),
      client.listRunnerManifestsPage(PAGE_SIZE, 0),
      client.listRunnerExecutionsPage(PAGE_SIZE, 0),
    ]).then(([nextStatus, nextRegistrations, nextManifests, nextExecutions]) => {
      if (!active) return;
      setStatus(nextStatus);
      setRegistrations(nextRegistrations);
      setManifests(nextManifests);
      setExecutions(nextExecutions);
      setRegistrationOffsets([0]); setRegistrationIndex(0);
      setManifestOffsets([0]); setManifestIndex(0);
      setExecutionOffsets([0]); setExecutionIndex(0);
    }).catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (status === null || registrations === null || manifests === null || executions === null) {
    return <section className="route-state" role="status" aria-label="Loading runner inventory">
      <strong>Loading runner inventory</strong><p>Resolving metadata-only readiness and lineage.</p>
    </section>;
  }

  const ready = status.active_registration_count > 0
    && status.certified_capability_count > 0
    && status.failed_execution_count === 0;

  async function loadRegistrations(offset: number, nextIndex: number, offsets: readonly number[]) {
    setPageError(null);
    try {
      setRegistrations(await client.listRunnerRegistrationsPage(PAGE_SIZE, offset));
      setRegistrationOffsets(offsets); setRegistrationIndex(nextIndex);
    } catch (cause) { setPageError(projectError(cause)); }
  }
  async function loadManifests(offset: number, nextIndex: number, offsets: readonly number[]) {
    setPageError(null);
    try {
      setManifests(await client.listRunnerManifestsPage(PAGE_SIZE, offset));
      setManifestOffsets(offsets); setManifestIndex(nextIndex);
    } catch (cause) { setPageError(projectError(cause)); }
  }
  async function loadExecutions(offset: number, nextIndex: number, offsets: readonly number[]) {
    setPageError(null);
    try {
      setExecutions(await client.listRunnerExecutionsPage(PAGE_SIZE, offset));
      setExecutionOffsets(offsets); setExecutionIndex(nextIndex);
    } catch (cause) { setPageError(projectError(cause)); }
  }

  return <div className="operational-grid">
    {pageError && <p className="inline-error" role="alert">{pageError}</p>}
    <section className="work-panel workspace-panel" aria-labelledby="runner-fleet-title">
      <div className="section-heading"><div><span className="eyebrow">Ephemeral execution plane</span><h2 id="runner-fleet-title">Runner fleet</h2></div><span className="state-label">{ready ? "Ready" : "Unhealthy"}</span></div>
      <p>Read-only operational metadata. Identity material, manifest bodies, signatures, lease tokens, and executable inputs are never exposed.</p>
      <dl>
        <dt>Registrations</dt><dd>{status.active_registration_count} active / {status.registration_count} total</dd>
        <dt>Capabilities</dt><dd>{status.capability_revisions.join(", ") || "None certified"}</dd>
        <dt>Policy</dt><dd>{status.policy_revisions.join(", ") || "No active revision"}</dd>
        <dt>Work</dt><dd>{status.open_manifest_count} open manifests · {status.active_lease_count} active leases</dd>
        <dt>Outcomes</dt><dd>{status.succeeded_execution_count} succeeded · {status.failed_execution_count} failed</dd>
        <dt>Heartbeat</dt><dd>{status.last_heartbeat_at ?? "No heartbeat"}</dd>
      </dl>
      <h3>Registrations</h3>
      {registrations.data.length === 0 ? <p className="empty-state">No runner registrations</p> : <ul className="record-list">{registrations.data.map((row) => <li key={`${row.runner_id}:${row.generation}`}><div className="access-record"><div><strong>{row.runner_id}</strong><span>{row.runner_class_id} · {row.environment}</span><small>Generation {row.generation} · {row.required_policy_revision}</small></div><span className="state-label">{row.registration_state}</span></div></li>)}</ul>}
      <PageControls label="registrations" index={registrationIndex} page={registrations.page}
        previous={() => { const index = registrationIndex - 1; void loadRegistrations(registrationOffsets[index] ?? 0, index, registrationOffsets); }}
        next={() => { const offset = registrations.page.next_offset; if (offset === null || offset === undefined) return; const offsets = [...registrationOffsets.slice(0, registrationIndex + 1), offset]; void loadRegistrations(offset, offsets.length - 1, offsets); }} />
    </section>
    <section className="work-panel" aria-labelledby="runner-executions-title">
      <span className="eyebrow">Evidence-linked outcomes</span><h2 id="runner-executions-title">Runner executions</h2>
      {executions.data.length === 0 ? <p className="empty-state">No runner executions</p> : <ul className="record-list">{executions.data.map((row) => <li key={row.execution_id}><div className="access-record"><div><strong>{row.execution_id}</strong><span>{row.job_id} · {row.evidence_artifact_id ?? "No evidence accepted"}</span><small>{row.manifest_sha256} · {row.cleanup_completed ? "Cleanup verified" : "Cleanup incomplete"}</small></div><span className="state-label">{row.outcome}</span></div>{row.residual_risk && <p className="inline-error">Action required: {row.residual_risk}</p>}</li>)}</ul>}
      <PageControls label="executions" index={executionIndex} page={executions.page}
        previous={() => { const index = executionIndex - 1; void loadExecutions(executionOffsets[index] ?? 0, index, executionOffsets); }}
        next={() => { const offset = executions.page.next_offset; if (offset === null || offset === undefined) return; const offsets = [...executionOffsets.slice(0, executionIndex + 1), offset]; void loadExecutions(offset, offsets.length - 1, offsets); }} />
    </section>
    <section className="work-panel" aria-labelledby="runner-manifests-title">
      <span className="eyebrow">Signed lineage metadata</span><h2 id="runner-manifests-title">Runner manifests</h2>
      {manifests.data.length === 0 ? <p className="empty-state">No active manifests</p> : <ul className="compact-list">{manifests.data.map((row) => <li key={row.manifest_id}>{row.manifest_id} · {row.capability_id}:{row.capability_revision} · {row.manifest_state}</li>)}</ul>}
      <PageControls label="manifests" index={manifestIndex} page={manifests.page}
        previous={() => { const index = manifestIndex - 1; void loadManifests(manifestOffsets[index] ?? 0, index, manifestOffsets); }}
        next={() => { const offset = manifests.page.next_offset; if (offset === null || offset === undefined) return; const offsets = [...manifestOffsets.slice(0, manifestIndex + 1), offset]; void loadManifests(offset, offsets.length - 1, offsets); }} />
    </section>
  </div>;
}

function PageControls({ label, index, page, previous, next }: {
  readonly label: "registrations" | "executions" | "manifests";
  readonly index: number;
  readonly page: RegistrationPage["page"];
  readonly previous: () => void;
  readonly next: () => void;
}) {
  const title = `${label[0]?.toUpperCase() ?? ""}${label.slice(1, -1)} page ${index + 1}`;
  return <div className="pagination-controls" aria-label={`${label} pages`}>
    <button type="button" disabled={index === 0} onClick={previous}>Previous {label}</button>
    <span>{title}</span>
    <button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={next}>Next {label}</button>
  </div>;
}

function RouteError({ denied, correlationId, retry }: {
  readonly denied: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  return <section className="route-state route-state--error" role="alert"
    aria-label={denied ? "Route access denied" : "Runner inventory unavailable"}>
    <strong>{denied ? "Access denied" : "Runner inventory unavailable"}</strong>
    <p>{denied
      ? "The authenticated session is not permitted to review runner metadata."
      : "Runner readiness and lineage could not be loaded; no execution state was inferred."}</p>
    {correlationId && <p className="correlation">Correlation: {correlationId}</p>}
    {retry && <button type="button" onClick={retry}>Retry route data</button>}
  </section>;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The runner page could not be loaded.";
}

function asConsoleError(cause: unknown): ConsoleApiError {
  return cause instanceof ConsoleApiError
    ? cause
    : new ConsoleApiError("runner_inventory_unavailable", "Runner inventory unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}
