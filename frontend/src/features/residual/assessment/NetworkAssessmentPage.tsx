import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["NetworkDashboardData"];
type Profile = components["schemas"]["NetworkProfileData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled", "cleanup_failed"]);

export function NetworkAssessmentPage({ client, context }: { readonly client: Client; readonly context: Context }) {
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
    void Promise.all([client.listNetworkProfiles(), client.getNetworkDashboard(), decisionPage])
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
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading network assessment runtime"><strong>Loading network assessment runtime</strong><p>Verifying isolated topology and server-owned execution bindings.</p></section>;

  const currentDashboard = dashboard;
  const targetOptions = dashboard.target_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const reservationOptions = dashboard.reservation_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "network.plan.compile" && decision.resource_type === "network_profile") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextProfiles, nextDashboard] = await Promise.all([client.listNetworkProfiles(), client.getNetworkDashboard()]);
      setProfiles(nextProfiles); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("Network assessment runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const profile = profiles.find((item) => item.profile_id === data.get("profile_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const target = targetOptions.find((item) => item.target_set_id === data.get("target_binding"));
    const reservation = reservationOptions.find((item) => item.reservation_id === data.get("reservation_binding"));
    if (!profile || !job || !decision || !target || !reservation
      || !targetEligible(target, observedAt) || !reservationEligible(reservation, observedAt)) return;
    setActionError(null); setNotice(null);
    try {
      const plan = await client.compileNetworkPlan({
        plan_id: `network-plan-${crypto.randomUUID()}`, profile_id: profile.profile_id,
        target_set_id: target.target_set_id as "r107-local-fixture",
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id, reservation_id: reservation.reservation_id,
        confirmation: "--confirm-r107-local-lab",
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled isolated literal-tuple plan for ${plan.target_set_id}.`);
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
      || runner.required_policy_revision !== plan.policy_revision
      || new Date(plan.expires_at).getTime() <= observedAt) return;
    setActionError(null); setNotice(null);
    try {
      const run = await client.createNetworkRun({
        run_id: `network-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id, confirmation: "--confirm-r107-local-lab",
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through the selected authorized job and isolated runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block the network gateway before stopping ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelNetworkRun(run.run_id, run.version, "Operator requested controlled network cancellation");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Gateway-first cancellation requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid network-assessment-page">
    <section className="work-panel" aria-labelledby="network-assessment-title"><div className="section-heading"><div><span className="eyebrow">Exact scope and traffic truth</span><h2 id="network-assessment-title">Network assessment</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only literal IP/port tuples from the attested local fixture can run through the independent gateway. Hostnames, CIDRs, port ranges, raw sockets, UDP, scripts, scanner flags, proxies, resolvers, and public routes are disabled.</p>{profiles.length === 0 ? <p className="empty-state">No certified network profiles available</p> : <ul className="record-list">{profiles.map((profile) => <li key={profile.profile_id}><strong>{profile.profile_id}</strong><span>{profile.profile_state}</span><small>{profile.max_targets} targets · {profile.max_ports_per_target} ports/target · {profile.max_attempts} attempts · {profile.rate_per_second}/s · concurrency {profile.concurrency_limit}</small><small>TCP CONNECT · no retries · {profile.connect_timeout_seconds}s connect timeout · {profile.banner_bytes} bounded bytes</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="network-plan-title"><span className="eyebrow">Closed compiler</span><h2 id="network-plan-title">Compile local scope</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Certified profile<select name="profile_binding" required><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id} · {profile.category}</option>)}</select></label><label>Authorized network job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt || decision.resource_id === "needs_review"}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Isolated target set<select name="target_binding" required><option value="">Select target set</option>{targetOptions.map((target) => <option key={target.target_set_id} value={target.target_set_id} disabled={!targetEligible(target, observedAt)}>{target.target_set_id} · {target.target_set_state} · expires {new Date(target.expires_at).toLocaleString()}{targetEligible(target, observedAt) ? "" : " · unavailable"}</option>)}</select></label><label>Active quota reservation<select name="reservation_binding" required><option value="">Select reservation</option>{reservationOptions.map((reservation) => <option key={reservation.reservation_id} value={reservation.reservation_id} disabled={!reservationEligible(reservation, observedAt)}>{reservation.remaining_amount} remaining · {reservation.reservation_state} · expires {new Date(reservation.expires_at).toLocaleString()}{reservationEligible(reservation, observedAt) ? "" : " · unavailable"}</option>)}</select></label><small>Plan identity is generated. Literal tuples, ports, protocol, topology, route, policy revision, approved ROE, and quota remain server-owned.</small><button type="submit">Compile approved scope</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="network-run-title"><span className="eyebrow">Durable local runner</span><h2 id="network-run-title">Queue isolated discovery</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.profile_id} · {plan.target_set_id} · {plan.tuple_count} tuples · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>Authorized network job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Compatible isolated runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.required_policy_revision} · {runner.registration_state}{runnerEligible(runner, observedAt) ? "" : " · unavailable"}</option>)}</select></label><small>Run identity is generated; the server revalidates topology, plan, policy, ROE, quota, job capability, and image-bound runner.</small><button type="submit">Queue local run</button></form>}</section>
    <section className="work-panel" aria-labelledby="network-runs-title"><div className="section-heading"><div><span className="eyebrow">Coverage, uncertainty, and cleanup</span><h2 id="network-runs-title">Network runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No network runs recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.completed_tuples} of {run.total_tuples} tuples</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Coverage</dt><dd>{run.partial ? "Partial coverage" : "Complete coverage"}</dd><dt>Reason</dt><dd>{run.reason_code}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void cancel(run); }}>Block gateway and cancel</button>}</li>)}</ul>}<h3>Normalized observations</h3>{dashboard.observations.length === 0 ? <p className="empty-state">No network observations recorded</p> : <ul className="record-list">{dashboard.observations.map((observation) => <li key={observation.observation_id}><strong>{observation.service_class}</strong><span>{observation.connection_state} · {observation.uncertainty} uncertainty</span><small>{observation.latency_bucket} · {observation.redaction_state}</small></li>)}</ul>}{dashboard.cleanups.map((cleanup) => <p key={cleanup.receipt_id} role="status">Cleanup verified: {cleanup.residual_resource_count} residual resources.</p>)}</section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Network assessment runtime unavailable"}><strong>{denied ? "Access denied" : "Network assessment runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review network assessment runtime state." : "Isolated topology and server-owned bindings could not be loaded; no execution or observation state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function targetEligible(target: Dashboard["target_options"][number], now: number): boolean { return target.target_set_state === "active-local-lab" && target.non_production && target.no_public_route && target.no_direct_target_route && new Date(target.expires_at).getTime() > now; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function reservationEligible(reservation: Dashboard["reservation_options"][number], now: number): boolean { return new Set(["reserved", "partially_consumed"]).has(reservation.reservation_state) && reservation.remaining_amount > 0 && new Date(reservation.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("network_assessment_unavailable", "Network assessment runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The network assessment runtime action could not be completed."; }
