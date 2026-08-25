import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["ApiDifferentialDashboardData"];
type Profile = components["schemas"]["ApiDifferentialProfileData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled", "cleaned", "quota_denied", "containment_denied"]);

export function ApiDifferentialPage({ client, context }: { readonly client: Client; readonly context: Context }) {
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
    void Promise.all([client.listApiDifferentialProfiles(), client.getApiDifferentialDashboard(), decisionPage])
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
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading API differential runtime"><strong>Loading API differential runtime</strong><p>Verifying the signed specification and server-owned execution bindings.</p></section>;

  const currentDashboard = dashboard;
  const targetOptions = dashboard.target_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "api_diff.plan.compile" && decision.resource_type === "api_diff_profile") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextProfiles, nextDashboard] = await Promise.all([
        client.listApiDifferentialProfiles(), client.getApiDifferentialDashboard(),
      ]);
      setProfiles(nextProfiles); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("API differential runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const profile = profiles.find((item) => item.profile_id === data.get("profile_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const target = targetOptions.find((item) => item.attestation_sha256 === data.get("target_binding"));
    const seed = Number(data.get("seed"));
    if (!profile || !job || !decision || !target || !targetEligible(target, observedAt)
      || !Number.isSafeInteger(seed) || seed < 0) return;
    setActionError(null); setNotice(null);
    try {
      const plan = await client.compileApiDifferentialPlan({
        plan_id: `api-diff-plan-${crypto.randomUUID()}`, profile_id: profile.profile_id,
        target_id: target.target_id as "r106-owned-api-fixture",
        target_attestation_sha256: target.attestation_sha256,
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id, seed,
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled signed API authorization matrix for ${plan.target_id}.`);
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
      const run = await client.createApiDifferentialRun({
        run_id: `api-diff-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id,
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through the selected authorized job and compatible runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block the gateway, request native stop, and compensate ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelApiDifferentialRun(
        run.run_id, run.version, "Operator requested controlled API differential cancellation",
      );
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Cancellation and containment requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid api-differential-page">
    <section className="work-panel" aria-labelledby="api-differential-title"><div className="section-heading"><div><span className="eyebrow">Authorization decision workspace</span><h2 id="api-differential-title">API authorization differential</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only the signed compat_106 specification, reviewed operation inventory, synthetic identity matrix, and owned fixture are accepted. URLs, specifications, requests, headers, cookies, credentials, bodies, callbacks, plugins, and engine flags cannot be supplied here.</p>{profiles.length === 0 ? <p className="empty-state">No certified API differential profiles available</p> : <ul className="record-list">{profiles.map((profile) => <li key={profile.profile_id}><strong>{profile.profile_id}</strong><span>{profile.profile_state} · Schemathesis {profile.engine_version}</span><small>{profile.operation_ids.length} operations · {profile.identity_states.join(", ")}</small><small>{profile.max_requests} requests · {profile.request_rate_per_second}/s · concurrency {profile.concurrency_limit}</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="api-differential-plan-title"><span className="eyebrow">Closed compiler</span><h2 id="api-differential-plan-title">Compile approved matrix</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Certified profile<select name="profile_binding" required><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id} · {profile.bundle_id}</option>)}</select></label><label>Authorized API differential job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt || decision.resource_id === "needs_review"}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Owned target attestation<select name="target_binding" required><option value="">Select target</option>{targetOptions.map((target) => <option key={target.attestation_sha256} value={target.attestation_sha256} disabled={!targetEligible(target, observedAt)}>{target.target_id} · {target.attestation_state} · expires {new Date(target.expires_at).toLocaleString()}{targetEligible(target, observedAt) ? "" : " · unavailable"}</option>)}</select></label><label>Deterministic public seed<input name="seed" type="number" required min={0} max={Number.MAX_SAFE_INTEGER} defaultValue={10620260711} /></label><small>Plan identity is generated. Profile/specification, target attestation, policy revision, and approved ROE are selected or derived from authoritative rows.</small><button type="submit">Compile plan</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="api-differential-run-title"><span className="eyebrow">Durable runner binding</span><h2 id="api-differential-run-title">Queue isolated run</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.profile_id} · {plan.target_id} · seed {plan.seed} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>Authorized API differential job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Compatible runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.required_policy_revision} · {runner.registration_state}{runnerEligible(runner, observedAt) ? "" : " · unavailable"}</option>)}</select></label><small>Run identity is generated; the server revalidates signed promotion, plan, job capability, image-bound runner, quota, and containment.</small><button type="submit">Queue run</button></form>}</section>
    <section className="work-panel" aria-labelledby="api-differential-runs-title"><div className="section-heading"><div><span className="eyebrow">Progress and business-security truth</span><h2 id="api-differential-runs-title">Differential runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No API differential runs recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.progress_percent}%</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Requests / bytes</dt><dd>{run.request_count} / {run.response_bytes}</dd><dt>Findings</dt><dd>{run.finding_count}</dd><dt>Reason</dt><dd>{run.reason_code}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void cancel(run); }}>Cancel and contain</button>}</li>)}</ul>}<h3>Authorization observations</h3>{dashboard.observations.length === 0 ? <p className="empty-state">No normalized authorization observations</p> : <ul className="record-list">{dashboard.observations.map((observation) => <li key={observation.observation_id}><strong>{observation.finding_type ?? "valid negative"}</strong><span>{observation.violated ? "violated" : "expected"}</span><small>{observation.reason_code} · case {observation.case_id}</small></li>)}</ul>}<h3>Minimized semantic replay</h3>{dashboard.replays.length === 0 ? <p className="empty-state">No minimized replay recorded</p> : <ul className="record-list">{dashboard.replays.map((replay) => <li key={replay.replay_id}><strong>{replay.semantic_predicate}</strong><span>{replay.replay_state}</span><small className="mono-value">{replay.minimized_replay_sha256}</small></li>)}</ul>}{dashboard.cleanups.map((cleanup) => <p key={cleanup.receipt_id} role="status">Cleanup {cleanup.compensation_complete && cleanup.lease_revoked ? "verified" : "incomplete"}: {cleanup.residual_resource_count} residual resources; lease {cleanup.lease_revoked ? "revoked" : "active"}.</p>)}</section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "API differential runtime unavailable"}><strong>{denied ? "Access denied" : "API differential runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review API differential runtime state." : "Signed specification and server-owned bindings could not be loaded; no execution or finding state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function targetEligible(target: Dashboard["target_options"][number], now: number): boolean { return target.non_production && target.attestation_state === "active" && new Date(target.expires_at).getTime() > now; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("api_differential_unavailable", "API differential runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The API differential runtime action could not be completed."; }
