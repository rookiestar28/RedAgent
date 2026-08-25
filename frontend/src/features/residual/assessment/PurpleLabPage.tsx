import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["PurpleDashboardData"];
type Ability = components["schemas"]["PurpleAbilityData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled"]);

export function PurpleLabPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [abilities, setAbilities] = useState<Ability[]>([]);
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
    void Promise.all([client.listPurpleAbilities(), client.getPurpleDashboard(), decisionPage])
      .then(([nextAbilities, nextDashboard, nextDecisions]) => {
        if (!active) return;
        setAbilities(nextAbilities); setDashboard(nextDashboard); setDecisions(nextDecisions);
        setDecisionOffsets([0]); setDecisionIndex(0); setObservedAt(Date.now());
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canCreate, canRead, canReadPolicy, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading purple lab runtime"><strong>Loading purple lab runtime</strong><p>Verifying owned disposable lab and exact approval choices.</p></section>;

  const currentDashboard = dashboard;
  const labOptions = dashboard.lab_options ?? [];
  const approvalOptions = dashboard.approval_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const reservationOptions = dashboard.reservation_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "purple.plan.compile" && decision.resource_type === "purple_ability") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextAbilities, nextDashboard] = await Promise.all([client.listPurpleAbilities(), client.getPurpleDashboard()]);
      setAbilities(nextAbilities); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("Purple lab runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const ability = abilities.find((item) => item.ability_id === data.get("ability_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const lab = labOptions.find((item) => item.binding_id === data.get("lab_binding"));
    const approval = approvalOptions.find((item) => item.approval_id === data.get("approval_binding"));
    const reservation = reservationOptions.find((item) => item.reservation_id === data.get("reservation_binding"));
    const labRunner = runnerOptions.find((item) => item.runner_id === lab?.runner_id);
    if (!ability || !job || !decision || !lab || !approval || !reservation || !labRunner
      || decision.resource_id !== ability.ability_id || new Date(decision.valid_until).getTime() <= observedAt
      || approval.ability_id !== ability.ability_id || approval.lab_binding_id !== lab.binding_id
      || !labEligible(lab, observedAt) || !approvalEligible(approval, observedAt)
      || !runnerEligible(labRunner, observedAt) || !jobEligible(job)
      || !reservationEligible(reservation, observedAt)) return;
    setActionError(null); setNotice(null);
    const identifier = crypto.randomUUID();
    try {
      const plan = await client.compilePurplePlan({
        plan_id: `purple-plan-${identifier}`, ability_id: ability.ability_id,
        lab_binding_id: lab.binding_id, approval_id: approval.approval_id,
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id, reservation_id: reservation.reservation_id,
        lease_id: `purple-lease-${identifier}`, kill_switch_id: `purple-kill-${identifier}`,
        quota_id: `purple-quota-${identifier}`, confirmation: "--confirm-r111-owned-disposable-lab",
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled ${ability.attack_technique_id} for the exact owned disposable lab and approval.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function queue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const plan = currentDashboard.plans.find((item) => item.plan_id === data.get("plan_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const runner = runnerOptions.find((item) => item.runner_id === data.get("runner_binding"));
    const lab = labOptions.find((item) => item.binding_id === plan?.lab_binding_id);
    if (!plan || !job || !runner || !lab || plan.roe_revision !== job.roe_version_id
      || lab.runner_id !== runner.runner_id || !labEligible(lab, observedAt)
      || !runnerEligible(runner, observedAt) || !jobEligible(job)
      || new Date(plan.expires_at).getTime() <= observedAt) return;
    setActionError(null); setNotice(null);
    try {
      const run = await client.createPurpleRun({
        run_id: `purple-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id,
        confirmation: "--confirm-r111-owned-disposable-lab",
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through its ROE-matched purple lab job and exact disposable-lab runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function kill(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block dispatch and revoke the execution lease before killing ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.killPurpleRun(run.run_id, run.version, "Operator requested immediate owned-lab ability stop");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Dispatch-blocking kill requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid purple-lab-page">
    <section className="work-panel" aria-labelledby="purple-lab-title"><div className="section-heading"><div><span className="eyebrow">ATT&amp;CK-mapped detection and cleanup truth</span><h2 id="purple-lab-title">Lab-only purple-team runtime</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only one signed RedAgent-owned benign marker ability may run in an owned disposable filesystem lab. External frameworks and content, commands, payloads, agents, C2, credentials, privilege, network, persistence, evasion, lateral movement, production, and third-party targets are disabled.</p>{abilities.length === 0 ? <p className="empty-state">No signed owned ability available</p> : <ul className="record-list">{abilities.map((ability) => <li key={ability.ability_id}><strong>{ability.ability_id}</strong><span>{ability.attack_technique_id} · lab only</span><small>{ability.phases.join(" → ")}</small><small>Expected detection: {ability.detection_strategy_id} / {ability.analytic_id} / {ability.event_schema}</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="purple-plan-title"><span className="eyebrow">Exact owned resources and independent approval</span><h2 id="purple-plan-title">Compile approved ability plan</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Signed ability<select name="ability_binding" required><option value="">Select ability</option>{abilities.map((ability) => <option key={ability.ability_id} value={ability.ability_id}>{ability.attack_technique_id} · {ability.ability_id}</option>)}</select></label><label>Authorized purple lab job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={!jobEligible(job)}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Owned disposable lab<select name="lab_binding" required><option value="">Select lab</option>{labOptions.map((lab) => <option key={lab.binding_id} value={lab.binding_id} disabled={!labEligible(lab, observedAt)}>{lab.runner_id} · {lab.binding_state} · expires {new Date(lab.expires_at).toLocaleString()}</option>)}</select></label><label>Exact independent approval<select name="approval_binding" required><option value="">Select approval</option>{approvalOptions.map((approval) => <option key={approval.approval_id} value={approval.approval_id} disabled={!approvalEligible(approval, observedAt)}>{approval.ability_id} · {approval.lab_binding_id} · expires {new Date(approval.expires_at).toLocaleString()}</option>)}</select></label><label>Active quota reservation<select name="reservation_binding" required><option value="">Select reservation</option>{reservationOptions.map((reservation) => <option key={reservation.reservation_id} value={reservation.reservation_id} disabled={!reservationEligible(reservation, observedAt)}>{reservation.remaining_amount} remaining · {reservation.reservation_state}</option>)}</select></label><small>Plan, execution lease, kill-switch, and quota correlation identities are generated. Technique, adapter, marker path/content, operations, expected telemetry, timeout, cleanup, teardown, policy revision, and ROE remain server-owned.</small><button type="submit">Compile lab-only plan</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="purple-run-title"><span className="eyebrow">Exact disposable runner only</span><h2 id="purple-run-title">Queue approved rehearsal</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.ability_id} · {plan.plan_state} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>ROE-matched purple lab job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={!jobEligible(job)}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Lab-bound compatible runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.registration_state} · {runner.runner_id}</option>)}</select></label><small>Run identity is generated. Queueing requires plan/job ROE equality and the exact runner bound to the selected plan's owned disposable lab.</small><button type="submit">Queue owned-lab rehearsal</button></form>}</section>
    <section className="work-panel" aria-labelledby="purple-runs-title"><div className="section-heading"><div><span className="eyebrow">Action alone is never success</span><h2 id="purple-runs-title">Purple-team runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No purple-team run recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.detection_observed && run.cleanup_complete && run.teardown_verified ? "Verified" : "Incomplete or pending"}</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Expected telemetry observed</dt><dd>{run.detection_observed ? "Yes" : "No"}</dd><dt>Cleanup / teardown</dt><dd>{run.cleanup_complete ? "Cleanup complete" : "Cleanup pending"} · {run.teardown_verified ? "Teardown verified" : "Teardown pending"}</dd><dt>Dispatch</dt><dd>{run.dispatch_blocked ? "Blocked" : "Eligible while authorization remains current"}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void kill(run); }}>Revoke lease and kill now</button>}</li>)}</ul>}<p role="status">{dashboard.telemetry.length} correlated telemetry events · {dashboard.cleanups.length} cleanup receipts · {dashboard.teardowns.length} teardown receipts · {dashboard.rehearsals.length} signed rehearsals</p></section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Purple lab runtime unavailable"}><strong>{denied ? "Access denied" : "Purple lab runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review purple lab runtime state." : "Owned-lab choices and runtime truth could not be loaded; no authorization or execution state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function labEligible(lab: Dashboard["lab_options"][number], now: number): boolean { return lab.binding_state === "active-disposable-owned" && lab.disposable && !lab.production && !lab.egress_allowed && new Date(lab.expires_at).getTime() > now; }
function approvalEligible(approval: Dashboard["approval_options"][number], now: number): boolean { return approval.approval_state === "approved-exact" && new Date(approval.expires_at).getTime() > now; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function jobEligible(job: Dashboard["job_options"][number]): boolean { return !job.dispatch_blocked && !job.stop_requested; }
function reservationEligible(reservation: Dashboard["reservation_options"][number], now: number): boolean { return new Set(["reserved", "partially_consumed"]).has(reservation.reservation_state) && reservation.remaining_amount > 0 && new Date(reservation.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("purple_lab_unavailable", "Purple lab runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The purple lab runtime action could not be completed."; }
