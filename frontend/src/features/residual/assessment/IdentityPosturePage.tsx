import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["IdentitySaasDashboardData"];
type Profile = components["schemas"]["IdentitySaasProfileData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled"]);

export function IdentityPosturePage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [decisions, setDecisions] = useState<DecisionPage | null>(null);
  const [decisionOffsets, setDecisionOffsets] = useState<readonly number[]>([0]);
  const [decisionIndex, setDecisionIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [observedAt, setObservedAt] = useState(0);
  const canRead = hasPermission(context, "job:read") && hasPermission(context, "audit:read");
  const canCreate = hasPermission(context, "job:create");
  const canReadPolicy = hasPermission(context, "policy:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    const decisionPage = canCreate && canReadPolicy ? client.listPolicyDecisionsPage(PAGE_SIZE, 0) : Promise.resolve(null);
    void Promise.all([client.listIdentitySaasProfiles(), client.getIdentitySaasDashboard(), decisionPage])
      .then(([nextProfiles, nextDashboard, nextDecisions]) => {
        if (!active) return;
        setProfiles(nextProfiles); setDashboard(nextDashboard); setDecisions(nextDecisions);
        setDecisionOffsets([0]); setDecisionIndex(0); setObservedAt(Date.now());
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canCreate, canRead, canReadPolicy, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading identity posture runtime"><strong>Loading identity posture runtime</strong><p>Verifying emulator tenant and server-owned execution bindings.</p></section>;

  const currentDashboard = dashboard;
  const bindingOptions = dashboard.binding_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const reservationOptions = dashboard.reservation_options ?? [];
  const leaseOptions = dashboard.lease_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "identity.plan.compile" && decision.resource_type === "identity_profile") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextProfiles, nextDashboard] = await Promise.all([client.listIdentitySaasProfiles(), client.getIdentitySaasDashboard()]);
      setProfiles(nextProfiles); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("Identity posture runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const profile = profiles.find((item) => item.profile_id === data.get("profile_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const binding = bindingOptions.find((item) => item.binding_id === data.get("tenant_binding"));
    const reservation = reservationOptions.find((item) => item.reservation_id === data.get("reservation_binding"));
    const lease = leaseOptions.find((item) => item.lease_id === data.get("lease_binding"));
    if (!profile || !job || !decision || !binding || !reservation || !lease
      || binding.profile_id !== profile.profile_id || !bindingEligible(binding)
      || !reservationEligible(reservation, observedAt) || !leaseEligible(lease, observedAt)
      || lease.job_id !== job.job_id || lease.roe_version_id !== job.roe_version_id
      || lease.permission_digest !== binding.permission_digest) return;
    setActionError(null); setNotice(null);
    try {
      const plan = await client.compileIdentitySaasPlan({
        plan_id: `identity-plan-${crypto.randomUUID()}`, profile_id: profile.profile_id,
        tenant_binding_id: binding.binding_id,
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id, reservation_id: reservation.reservation_id,
        credential_lease_id: lease.lease_id, confirmation: "--confirm-r109-local-lab",
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled protected emulator collection for ${binding.provider_tenant_id}.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function queue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const plan = currentDashboard.plans.find((item) => item.plan_id === data.get("plan_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const runner = runnerOptions.find((item) => item.runner_id === data.get("runner_binding"));
    if (!plan || !job || !runner || !runnerEligible(runner, observedAt)
      || new Date(plan.expires_at).getTime() <= observedAt) return;
    setActionError(null); setNotice(null);
    try {
      const run = await client.createIdentitySaasRun({
        run_id: `identity-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id, confirmation: "--confirm-r109-local-lab",
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through the selected identity posture job and certified emulator runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block directory requests and revoke the lease before stopping ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelIdentitySaasRun(run.run_id, run.version, "Operator requested controlled identity posture cancellation");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Lease-first cancellation requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid identity-posture-page">
    <section className="work-panel" aria-labelledby="identity-posture-title"><div className="section-heading"><div><span className="eyebrow">Exact tenant and permission truth</span><h2 id="identity-posture-title">Identity and SaaS posture</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only repo-owned loopback Microsoft 365, Google Workspace, and Okta emulators are qualified. Real tenants, arbitrary endpoints, credentials, user content, writes, authentication tests, cross-tenant discovery, graph export, and model access are disabled.</p>{profiles.length === 0 ? <p className="empty-state">No certified identity profile available</p> : <ul className="record-list">{profiles.map((profile) => <li key={profile.profile_id}><strong>{profile.profile_id}</strong><span>{profile.provider_tenant_id} · {profile.audience} · {profile.consent_mode}</span><small>{profile.operations.map((item) => `${item.permission_scope} / ${item.effective_role_permission}`).join(", ")}</small><small>{profile.operations.flatMap((item) => item.selected_fields).join(", ")} · {profile.retention_days} day retention</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="identity-plan-title"><span className="eyebrow">Closed protected compiler</span><h2 id="identity-plan-title">Compile protected collection</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Certified profile<select name="profile_binding" required><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.provider} · {profile.profile_id}</option>)}</select></label><label>Authorized identity job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt || decision.resource_id === "needs_review"}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Emulator tenant binding<select name="tenant_binding" required><option value="">Select tenant binding</option>{bindingOptions.map((binding) => <option key={binding.binding_id} value={binding.binding_id} disabled={!bindingEligible(binding)}>{binding.provider_tenant_id} · {binding.audience} · {binding.profile_id}</option>)}</select></label><label>Active quota reservation<select name="reservation_binding" required><option value="">Select reservation</option>{reservationOptions.map((reservation) => <option key={reservation.reservation_id} value={reservation.reservation_id} disabled={!reservationEligible(reservation, observedAt)}>{reservation.remaining_amount} remaining · {reservation.reservation_state} · expires {new Date(reservation.expires_at).toLocaleString()}</option>)}</select></label><label>Read-only credential lease<select name="lease_binding" required><option value="">Select lease</option>{leaseOptions.map((lease) => <option key={lease.lease_id} value={lease.lease_id} disabled={!leaseEligible(lease, observedAt)}>{lease.job_id} · {lease.lease_state} · expires {new Date(lease.expires_at).toLocaleString()}</option>)}</select></label><small>Plan identity is generated. Endpoint, tenant, audience, scopes, roles, fields, queries, baselines, graph settings, policy revision, approved ROE, quota, and credentials remain server-owned.</small><button type="submit">Compile approved collection</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="identity-run-title"><span className="eyebrow">Durable emulator runner</span><h2 id="identity-run-title">Queue identity posture run</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.profile_id} · {plan.plan_state} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>Authorized identity job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Certified emulator runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.registration_state}</option>)}</select></label><small>Run identity is generated; compile revalidates tenant binding, policy, ROE, quota, and lease. Queueing uses the active stored plan and guarded mutation without inferring additional backend revalidation.</small><button type="submit">Queue local run</button></form>}</section>
    <section className="work-panel" aria-labelledby="identity-runs-title"><div className="section-heading"><div><span className="eyebrow">Coverage, exception, graph, and cleanup truth</span><h2 id="identity-runs-title">Identity runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No identity posture runs recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.complete ? "Complete" : "Partial or pending"}</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Partial reasons</dt><dd>{run.partial_reasons.join(", ") || "None"}</dd><dt>Snapshot</dt><dd className="mono-value">{run.snapshot_sha256 ?? "Pending"}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void cancel(run); }}>Revoke lease and cancel</button>}</li>)}</ul>}<p role="status">{dashboard.exceptions.length} exception annotations · {dashboard.graphs.length} separately approved restricted graphs · {dashboard.cleanups.length} cleanup receipts</p></section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Identity posture runtime unavailable"}><strong>{denied ? "Access denied" : "Identity posture runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review identity posture runtime state." : "Emulator tenant and server-owned bindings could not be loaded; no execution or identity posture state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function bindingEligible(binding: Dashboard["binding_options"][number]): boolean { return binding.binding_state === "active-local-emulator"; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function reservationEligible(reservation: Dashboard["reservation_options"][number], now: number): boolean { return new Set(["reserved", "partially_consumed"]).has(reservation.reservation_state) && reservation.remaining_amount > 0 && new Date(reservation.expires_at).getTime() > now; }
function leaseEligible(lease: Dashboard["lease_options"][number], now: number): boolean { return lease.lease_state === "active" && new Date(lease.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("identity_posture_unavailable", "Identity posture runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The identity posture runtime action could not be completed."; }
