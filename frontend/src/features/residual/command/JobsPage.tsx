import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Engagement = components["schemas"]["EngagementData"];
type Roe = components["schemas"]["RoeVersionData"];
type Job = components["schemas"]["JobData"];
type JobContainment = components["schemas"]["JobContainmentData"];
type ContainmentControl = components["schemas"]["ContainmentControlData"];
type QuotaStatus = components["schemas"]["QuotaStatusData"];
type JobPage = Awaited<ReturnType<Client["listJobsPage"]>>;
type JobAction = "approve" | "pause" | "resume" | "retry" | "cancel";
type ScopeKind = "job" | "campaign" | "capability" | "tenant" | "global";

const PAGE_SIZE = 50;

export function JobsPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementId, setEngagementId] = useState("");
  const [roes, setRoes] = useState<Roe[]>([]);
  const [page, setPage] = useState<JobPage["page"] | null>(null);
  const [offsetHistory, setOffsetHistory] = useState<readonly number[]>([0]);
  const [pageIndex, setPageIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [containments, setContainments] = useState<Record<string, JobContainment>>({});
  const [controls, setControls] = useState<ContainmentControl[]>([]);
  const [quotas, setQuotas] = useState<QuotaStatus[]>([]);
  const [scopeKind, setScopeKind] = useState<ScopeKind>("job");
  const canRead = hasPermission(context, "job:read");
  const canReadRoe = hasPermission(context, "roe:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([
      client.listJobsPage(PAGE_SIZE, 0),
      client.listContainmentControls(),
      client.getQuotaStatus(),
      client.listEngagementsPage(PAGE_SIZE, 0),
    ]).then(([jobPage, nextControls, nextQuotas, engagementPage]) => {
      if (!active) return;
      setJobs([...jobPage.data]);
      setPage(jobPage.page);
      setControls(nextControls);
      setQuotas(nextQuotas);
      const nextEngagements = [...engagementPage.data];
      setEngagements(nextEngagements);
      setEngagementId(nextEngagements[0]?.engagement_id ?? "");
    }).catch((cause: unknown) => {
      if (active) setRouteError(cause instanceof ConsoleApiError
        ? cause
        : new ConsoleApiError("api_unavailable", "Route data unavailable", 0, null));
    });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  useEffect(() => {
    let active = true;
    if (engagementId && canReadRoe) {
      void client.listRoeVersions(engagementId).then((next) => {
        if (active) setRoes(next);
      }).catch((cause: unknown) => {
        if (active) setError(projectError(cause));
      });
    }
    return () => { active = false; };
  }, [canReadRoe, client, engagementId]);

  const loadPage = useCallback(async (offset: number) => {
    setError(null);
    try {
      const next = await client.listJobsPage(PAGE_SIZE, offset);
      setJobs([...next.data]);
      setPage(next.page);
    } catch (cause) {
      setError(projectError(cause));
    }
  }, [client]);

  const scopeOptions = useMemo(
    () => containmentScopeOptions(scopeKind, jobs, context.tenant_id),
    [context.tenant_id, jobs, scopeKind],
  );
  const approvedRoes = roes.filter((roe) => roe.status === "approved");
  const availableQuotas = quotas.filter((quota) => quota.remaining > 0);

  if (routeError) {
    const denied = isAccessDenied(routeError);
    return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Route data unavailable"}>
      <strong>{denied ? "Access denied" : "Route data unavailable"}</strong>
      <p>{denied
        ? "The authenticated session is not permitted to load this route."
        : "The job control projection could not be loaded. Global safety context remains authoritative."}</p>
      {routeError.correlationId && <p className="correlation">Correlation: {routeError.correlationId}</p>}
      <button type="button" onClick={() => { setRouteError(null); setReloadToken((value) => value + 1); }}>Retry route data</button>
    </section>;
  }

  async function createJob(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(null);
    setNotice(null);
    try {
      const created = await client.createJob({
        job_id: createOpaqueId("job"),
        engagement_id: required(data, "engagement_id"),
        roe_version_id: required(data, "roe_version_id"),
        request: {
          capability: required(data, "capability") as "synthetic-noop" | "synthetic-conformance",
          approval_timeout_seconds: 3600,
          max_activity_attempts: 3,
          budget_reference: required(data, "budget_reference"),
        },
      });
      setJobs((current) => [created, ...current]);
      setNotice(`Job ${created.job_id} accepted by durable orchestration.`);
      form.reset();
      setEngagementId(engagements[0]?.engagement_id ?? "");
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function command(job: Job, action: JobAction) {
    setError(null);
    setNotice(null);
    try {
      const updated = await client.commandJob(job.job_id, job.roe_version_id, {
        command_id: createOpaqueId("command"),
        action,
        expected_revision: job.orchestration_revision,
        reason: `Console ${action} request for durable workflow`,
      });
      setJobs((current) => current.map((item) => item.job_id === updated.job_id ? updated : item));
      setNotice(`${title(action)} accepted for ${job.job_id}.`);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function stop(job: Job) {
    setError(null);
    setNotice(null);
    try {
      const accepted = await client.emergencyStopJob(job.job_id, job.roe_version_id, "Console emergency stop request for durable workflow");
      const containment = await client.getJobContainment(job.job_id);
      setContainments((current) => ({ ...current, [job.job_id]: containment }));
      setNotice(`Stop ${accepted.stop_id} accepted; phase receipts now determine containment for ${job.job_id}.`);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function refreshContainment(job: Job) {
    setError(null);
    try {
      const containment = await client.getJobContainment(job.job_id);
      setContainments((current) => ({ ...current, [job.job_id]: containment }));
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function requestControl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(null);
    setNotice(null);
    try {
      const created = await client.requestContainmentControl({
        stop_id: createOpaqueId("stop"),
        scope_kind: scopeKind,
        scope_id: scopeKind === "global" ? null : required(data, "scope_binding"),
        expected_version: 1,
        reason: required(data, "reason"),
      });
      setControls((current) => [created, ...current.filter((item) => item.control_id !== created.control_id)]);
      setNotice(`Containment control ${created.control_id} is ${created.control_state}.`);
      form.reset();
      setScopeKind("job");
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function approveControl(control: ContainmentControl) {
    setError(null);
    setNotice(null);
    try {
      const updated = await client.approveContainmentControl(control.control_id, control.request_hash, control.version);
      setControls((current) => current.map((item) => item.control_id === updated.control_id ? updated : item));
      setNotice(`Containment control ${updated.control_id} activated by independent approval.`);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function recoverControl(control: ContainmentControl) {
    setError(null);
    setNotice(null);
    try {
      const updated = await client.recoverContainmentControl(control.control_id, control.version);
      setControls((current) => current.map((item) => item.control_id === updated.control_id ? updated : item));
      setNotice(`Containment control ${updated.control_id} recovered after independent review.`);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function goToNextPage() {
    const nextOffset = page?.next_offset;
    if (nextOffset === null || nextOffset === undefined) return;
    setOffsetHistory([...offsetHistory.slice(0, pageIndex + 1), nextOffset]);
    setPageIndex(pageIndex + 1);
    await loadPage(nextOffset);
  }

  async function goToPreviousPage() {
    if (pageIndex === 0) return;
    const previousIndex = pageIndex - 1;
    setPageIndex(previousIndex);
    await loadPage(offsetHistory[previousIndex] ?? 0);
  }

  return <div className="operational-grid">
    <section className="work-panel workspace-panel" aria-labelledby="jobs-title">
      <div className="section-heading"><div><span className="eyebrow">Durable workflow truth</span><h2 id="jobs-title">Jobs</h2></div><span className="count-chip">{jobs.length} on this page</span></div>
      <p>Lifecycle commands are durable and audited. compat_100 owns real execution; compat_101 owns containment completion.</p>
      {error && <InlineError message={error} />}
      {notice && <p className="operation-notice" role="status">{notice}</p>}
      {!canRead ? <Empty text="Requires job:read." /> : jobs.length === 0 ? <Empty text="No durable jobs yet" /> : <ul className="job-list">
        {jobs.map((job) => {
          const containment = containments[job.job_id];
          return <li key={job.job_id} className="job-record">
            <div className="job-record__heading"><div><strong>{job.job_id}</strong><span>{job.orchestration_state}</span></div><span className="state-label">{job.current_gate}</span></div>
            <dl><dt>Workflow</dt><dd>{job.workflow_id}</dd><dt>Run</dt><dd>{job.workflow_run_id ?? "Pending dispatch"}</dd><dt>Revision</dt><dd>Revision {job.orchestration_revision} · Record version {job.version}</dd><dt>Retry / failure</dt><dd>{job.retry_count} / {job.failure_code ?? "None"}</dd><dt>ROE</dt><dd>{job.roe_version_id}</dd></dl>
            <div className="job-actions" aria-label={`Lifecycle commands for ${job.job_id}`}>
              {acceptedActions(job).map((action) => <button key={action} type="button" aria-label={`${title(action)} ${job.job_id}`} disabled={!canCommand(context, job, action)} onClick={() => { void command(job, action); }}>{title(action)}</button>)}
              {!terminal(job.orchestration_state) && <button className="danger-action" type="button" aria-label={`Emergency stop ${job.job_id}`} disabled={!hasPermission(context, "job:stop")} onClick={() => { void stop(job); }}>Emergency stop</button>}
              {(job.stop_requested || containment) && <button type="button" aria-label={`Refresh containment ${job.job_id}`} onClick={() => { void refreshContainment(job); }}>Refresh containment</button>}
            </div>
            {containment && <ContainmentSummary value={containment} />}
          </li>;
        })}
      </ul>}
      <div className="pagination-controls" aria-label="Job pages"><button type="button" disabled={pageIndex === 0} onClick={() => { void goToPreviousPage(); }}>Previous jobs</button><span>Page {pageIndex + 1}</span><button type="button" disabled={page?.next_offset === null || page?.next_offset === undefined} onClick={() => { void goToNextPage(); }}>Next jobs</button></div>
    </section>
    <section className="form-panel" aria-labelledby="create-job-title">
      <span className="eyebrow">Closed synthetic admission</span><h2 id="create-job-title">Start durable job</h2>
      <form onSubmit={(event) => { void createJob(event); }}>
        <label>Engagement<select name="engagement_id" required value={engagementId} onChange={(event) => { setEngagementId(event.currentTarget.value); }}><option value="">Select engagement</option>{engagements.map((row) => <option key={row.engagement_id} value={row.engagement_id}>{row.name}</option>)}</select></label>
        <label>Approved ROE<select name="roe_version_id" required><option value="">Select approved ROE</option>{approvedRoes.map((roe) => <option key={roe.roe_version_id} value={roe.roe_version_id}>Revision {roe.revision} · {roe.status}</option>)}</select></label>
        <label>Capability<select name="capability" defaultValue="synthetic-noop"><option value="synthetic-noop">Synthetic no-op</option><option value="synthetic-conformance">Ephemeral runner conformance</option></select></label>
        <label>Budget authority<select name="budget_reference" required><option value="">Select available quota</option>{availableQuotas.map((quota) => <option key={quota.policy_record_id} value={quota.policy_record_id}>{quota.dimension} · {quota.remaining} remaining</option>)}</select></label>
        <small>Only repository-certified synthetic capabilities and server-projected authority are accepted.</small>
        <button type="submit" disabled={!hasPermission(context, "job:create") || approvedRoes.length === 0 || availableQuotas.length === 0}>Start job</button>
      </form>
    </section>
    <section className="work-panel workspace-panel containment-control-panel" aria-labelledby="containment-controls-title">
      <div className="section-heading"><div><span className="eyebrow">Fail-closed safety plane</span><h2 id="containment-controls-title">Containment controls and quotas</h2></div><span className="count-chip">{controls.filter((item) => item.control_state === "active").length} active</span></div>
      <p>Job controls activate immediately. Broader controls require a distinct approver; recovery requires a third-person review and clean terminal evidence.</p>
      {controls.length === 0 ? <Empty text="No containment controls recorded" /> : <ul className="job-list">{controls.map((control) => <li key={control.control_id} className="job-record">
        <div className="job-record__heading"><div><strong>{control.scope_kind}:{control.scope_id ?? "*"}</strong><span>{control.control_state}</span></div><span className="state-label">v{control.version}</span></div>
        <dl><dt>Control / stop</dt><dd>{control.control_id} / {control.stop_id}</dd><dt>Mode</dt><dd>{control.control_mode}</dd><dt>Ack deadline</dt><dd>{new Date(control.ack_deadline).toLocaleString()}</dd><dt>Request hash</dt><dd>{control.request_hash}</dd><dt>Approval</dt><dd>{control.approved_by_user_id ?? "Pending distinct approver"}</dd></dl>
        <div className="job-actions">{control.control_state === "pending_approval" && hasPermission(context, "job:approve") && <button type="button" onClick={() => { void approveControl(control); }}>Approve control</button>}{control.control_state === "active" && hasPermission(context, "audit:read") && <button type="button" onClick={() => { void recoverControl(control); }}>Review recovery</button>}</div>
      </li>)}</ul>}
      <h3>Hard quota status</h3>
      {quotas.length === 0 ? <Empty text="No active quota policy" /> : <ul className="record-list">{quotas.map((quota) => <li key={quota.policy_record_id}><strong>{quota.dimension}</strong><span>{quota.scope_kind}:{quota.scope_id ?? "*"}</span><span>{quota.remaining} remaining of {quota.hard_limit} · {quota.reserved} reserved · {quota.consumed} consumed</span></li>)}</ul>}
    </section>
    <section className="form-panel" aria-labelledby="request-containment-title">
      <span className="eyebrow">Adapter-independent</span><h2 id="request-containment-title">Request containment</h2>
      <form onSubmit={(event) => { void requestControl(event); }}>
        <label>Scope<select name="scope_kind" value={scopeKind} onChange={(event) => { setScopeKind(event.currentTarget.value as ScopeKind); }}><option value="job">Job</option><option value="campaign">Campaign</option><option value="capability">Capability</option><option value="tenant">Tenant</option><option value="global">Global</option></select></label>
        {scopeKind !== "global" && <label>Containment target<select name="scope_binding" required><option value="">Select authorized target</option>{scopeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>}
        <label>Reason<textarea name="reason" required minLength={10} maxLength={500} /></label>
        <small>Targets are derived from the current authorized job page and authenticated tenant context.</small>
        <button className="danger-action" type="submit" disabled={!hasPermission(context, "job:stop") || (scopeKind !== "global" && scopeOptions.length === 0)}>Request containment</button>
      </form>
    </section>
  </div>;
}

function ContainmentSummary({ value }: { readonly value: JobContainment }) {
  return <section className="containment-summary" aria-label={`Containment status ${value.job_id}`}><strong>{value.containment_complete ? "Containment verified" : "Containment unresolved"}</strong><dl><dt>Control / action</dt><dd>{value.control_state} / {value.action_state}</dd><dt>Outcome</dt><dd>{value.outcome ?? "Pending phase receipts"}</dd><dt>Acknowledgement deadline</dt><dd>{new Date(value.ack_deadline).toLocaleString()}</dd><dt>Residual risk</dt><dd>{value.residual_risk_codes.join(", ") || "None recorded"}</dd><dt>Open incidents</dt><dd>{value.open_incident_ids.join(", ") || "None"}</dd></dl><ol className="containment-phases">{value.phases.map((phase) => <li key={phase.phase}><span>{phase.phase}</span><strong>{phase.state}</strong><small>{phase.reason_code} · {phase.duration_ms} ms</small></li>)}</ol></section>;
}

function containmentScopeOptions(kind: ScopeKind, jobs: readonly Job[], tenantId: string): readonly { value: string; label: string }[] {
  const values = kind === "job" ? jobs.map((job) => job.job_id)
    : kind === "campaign" ? jobs.flatMap((job) => job.campaign_id ? [job.campaign_id] : [])
      : kind === "capability" ? jobs.map((job) => job.request.capability)
        : kind === "tenant" ? [tenantId] : [];
  return [...new Set(values)].map((value) => ({ value, label: value }));
}

function acceptedActions(job: Job): JobAction[] {
  if (job.orchestration_state === "awaiting_approval") return ["approve", "cancel"];
  if (job.orchestration_state === "running") return ["pause", "cancel"];
  if (job.orchestration_state === "paused") return ["resume", "cancel"];
  if (job.orchestration_state === "failed") return ["retry", "cancel"];
  return terminal(job.orchestration_state) ? [] : ["cancel"];
}

function canCommand(context: Context, job: Job, action: JobAction): boolean {
  return action === "approve"
    ? hasPermission(context, "job:approve") && job.created_by_user_id !== context.subject
    : hasPermission(context, "job:update");
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function terminal(state: string): boolean {
  return new Set(["succeeded", "cancelled", "timed_out"]).has(state);
}

function createOpaqueId(prefix: string): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}-${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function required(data: FormData, name: string): string {
  const entry = data.get(name);
  if (typeof entry !== "string" || !entry.trim()) throw new Error(`${name} is required`);
  return entry.trim();
}

function title(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The operation could not be completed.";
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}

function Empty({ text }: { readonly text: string }) { return <p className="empty-inline">{text}</p>; }
function InlineError({ message }: { readonly message: string }) { return <p className="inline-error" role="alert">{message}</p>; }
