import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["HumanSimulationDashboardData"];
type Campaign = components["schemas"]["HumanSimulationCampaignData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;

export function HumanSimulationPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
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
    void Promise.all([client.listHumanSimulationCampaigns(), client.getHumanSimulationDashboard(), decisionPage])
      .then(([nextCampaigns, nextDashboard, nextDecisions]) => {
        if (!active) return;
        setCampaigns(nextCampaigns); setDashboard(nextDashboard); setDecisions(nextDecisions);
        setDecisionOffsets([0]); setDecisionIndex(0); setObservedAt(Date.now());
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canCreate, canRead, canReadPolicy, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading human simulation sink"><strong>Loading human simulation sink</strong><p>Verifying synthetic-only campaign, approval, and deletion authority.</p></section>;

  const currentDashboard = dashboard;
  const approvalOptions = dashboard.approval_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const reservationOptions = dashboard.reservation_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "human_simulation.plan.compile" && decision.resource_type === "human_campaign") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextCampaigns, nextDashboard] = await Promise.all([client.listHumanSimulationCampaigns(), client.getHumanSimulationDashboard()]);
      setCampaigns(nextCampaigns); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("Human simulation sink truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const campaign = campaigns.find((item) => item.campaign_id === data.get("campaign_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const approval = approvalOptions.find((item) => item.approval_id === data.get("approval_binding"));
    const reservation = reservationOptions.find((item) => item.reservation_id === data.get("reservation_binding"));
    if (!campaign || !job || !decision || !approval || !reservation
      || !campaignEligible(campaign) || approval.campaign_id !== campaign.campaign_id
      || !approvalEligible(approval, observedAt) || decision.resource_id !== campaign.campaign_id
      || new Date(decision.valid_until).getTime() <= observedAt || !jobEligible(job)
      || !reservationEligible(reservation, observedAt)) return;
    setActionError(null); setNotice(null);
    const identifier = crypto.randomUUID();
    try {
      const plan = await client.compileHumanSimulationPlan({
        plan_id: `human-plan-${identifier}`, campaign_id: campaign.campaign_id,
        approval_id: approval.approval_id, policy_decision_id: decision.decision_id,
        policy_revision: decision.bundle_revision, roe_version_id: job.roe_version_id,
        reservation_id: reservation.reservation_id, delivery_lease_id: `human-lease-${identifier}`,
        stop_switch_id: `human-stop-${identifier}`, quota_id: `human-quota-${identifier}`,
        confirmation: "--confirm-r112-synthetic-sink-only",
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled ${campaign.campaign_id} for its exact synthetic-sink approval.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function queue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const plan = currentDashboard.plans.find((item) => item.plan_id === data.get("plan_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const runner = runnerOptions.find((item) => item.runner_id === data.get("runner_binding"));
    if (!plan || !job || !runner || plan.roe_revision !== job.roe_version_id
      || !jobEligible(job) || !runnerEligible(runner, observedAt)
      || new Date(plan.expires_at).getTime() <= observedAt) return;
    setActionError(null); setNotice(null);
    try {
      const run = await client.createHumanSimulationRun({
        run_id: `human-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id,
        confirmation: "--confirm-r112-synthetic-sink-only",
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through its ROE-matched synthetic-sink job and certified in-process runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function stop(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block new delivery and revoke the lease before stopping ${run.run_id}? Captured messages are not recalled and still require deletion.`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.stopHumanSimulationRun(run.run_id, run.version, "Operator requested immediate sink campaign stop and deletion");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`New delivery blocked and stop requested for ${updated.run_id}; deletion remains required.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid human-simulation-page">
    <section className="work-panel" aria-labelledby="human-simulation-title"><div className="section-heading"><div><span className="eyebrow">Consent, minimization, and deletion truth</span><h2 id="human-simulation-title">Controlled human simulation sink</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">This promotion has no human or external delivery. It accepts one owned synthetic .invalid recipient in an in-process sink. Real recipients, SMTP/provider APIs, credentials, submitted values, tracking, external links, attachments, relay, forward, release, stealth, and third-party branding are disabled.</p>{campaigns.length === 0 ? <p className="empty-state">No signed sink campaign available</p> : <ul className="record-list">{campaigns.map((campaign) => <li key={campaign.campaign_id}><strong>{campaign.campaign_id}</strong><span>{campaign.recipient_class} · {campaign.sink_id}</span><small>Consent + suppression + privacy review required · deletion required after {campaign.retention_seconds}s</small><small>Human delivery: no · external delivery: no · raw submission retention: no</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="human-plan-title"><span className="eyebrow">Exact synthetic campaign and three-party approval</span><h2 id="human-plan-title">Compile sink-only plan</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Signed sink campaign<select name="campaign_binding" required><option value="">Select campaign</option>{campaigns.map((campaign) => <option key={campaign.campaign_id} value={campaign.campaign_id} disabled={!campaignEligible(campaign)}>{campaign.campaign_id} · {campaign.recipient_class}</option>)}</select></label><label>Authorized simulation job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={!jobEligible(job)}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Exact three-party approval<select name="approval_binding" required><option value="">Select approval</option>{approvalOptions.map((approval) => <option key={approval.approval_id} value={approval.approval_id} disabled={!approvalEligible(approval, observedAt)}>{approval.campaign_id} · {approval.approval_state} · expires {new Date(approval.expires_at).toLocaleString()}</option>)}</select></label><label>Active quota reservation<select name="reservation_binding" required><option value="">Select reservation</option>{reservationOptions.map((reservation) => <option key={reservation.reservation_id} value={reservation.reservation_id} disabled={!reservationEligible(reservation, observedAt)}>{reservation.remaining_amount} remaining · {reservation.reservation_state}</option>)}</select></label><small>Plan, delivery-lease, stop-switch, and quota correlation identities are generated. Roster, suppression, recipient, sender, template, content, canary, schedule, rate, collection categories, retention, deletion, policy revision, and ROE remain server-owned.</small><button type="submit">Compile synthetic sink plan</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="human-run-title"><span className="eyebrow">No provider or mailbox</span><h2 id="human-run-title">Queue sink rehearsal</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled sink plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.campaign_id} · {plan.plan_state} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>ROE-matched simulation job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={!jobEligible(job)}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Certified in-process sink runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.registration_state} · {runner.runner_id}</option>)}</select></label><small>Run identity is generated. Queueing requires plan/job ROE equality and a certified compatible sink runner; the current backend handler remains authoritative for active-plan acceptance.</small><button type="submit">Queue synthetic sink rehearsal</button></form>}</section>
    <section className="work-panel" aria-labelledby="human-runs-title"><div className="section-heading"><div><span className="eyebrow">Captured is not delivered to a person</span><h2 id="human-runs-title">Simulation runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No human-simulation sink run recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.deletion_verified ? "Deleted" : "Deletion pending"}</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Human / external deliveries</dt><dd>{run.human_delivery_count} / {run.external_delivery_count}</dd><dt>New delivery</dt><dd>{run.new_delivery_blocked ? "Blocked" : "Eligible only inside owned sink"}</dd><dt>Deletion</dt><dd>{run.deletion_verified ? "Verified zero residual" : "Required before close"}</dd></dl>{run.run_state !== "deleted" && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void stop(run); }}>Block delivery, revoke lease, and stop</button>}</li>)}</ul>}<p role="status">{dashboard.approvals.length} exact approvals · {dashboard.deliveries.length} sink captures · {dashboard.events.length} minimized events · {dashboard.canaries.length} canary correlations · {dashboard.deletions.length} deletion receipts</p></section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Human simulation sink unavailable"}><strong>{denied ? "Access denied" : "Human simulation sink unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review human simulation state." : "Synthetic-sink choices and deletion truth could not be loaded; no delivery or deletion state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function campaignEligible(campaign: Campaign): boolean { return campaign.recipient_class === "synthetic-invalid-owned" && !campaign.human_delivery && !campaign.external_delivery && !campaign.production_qualified && campaign.raw_submission_retention === false; }
function approvalEligible(approval: Dashboard["approval_options"][number], now: number): boolean { return approval.approval_state === "send-approved-exact" && new Date(approval.expires_at).getTime() > now; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function jobEligible(job: Dashboard["job_options"][number]): boolean { return !job.dispatch_blocked && !job.stop_requested; }
function reservationEligible(reservation: Dashboard["reservation_options"][number], now: number): boolean { return new Set(["reserved", "partially_consumed"]).has(reservation.reservation_state) && reservation.remaining_amount > 0 && new Date(reservation.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("human_simulation_unavailable", "Human simulation sink unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The human simulation action could not be completed."; }
