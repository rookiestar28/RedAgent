import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["ZapDashboardData"];
type Profile = components["schemas"]["ZapProfileData"];
type JobPage = Awaited<ReturnType<Client["listJobsPage"]>>;
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;
type ReferencePage = Awaited<ReturnType<Client["listSecretReferencesPage"]>>;
type PageMeta = JobPage["page"];

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled", "cleaned", "quota_denied", "containment_denied"]);

export function ZapPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [jobs, setJobs] = useState<JobPage | null>(null);
  const [decisions, setDecisions] = useState<DecisionPage | null>(null);
  const [references, setReferences] = useState<ReferencePage | null>(null);
  const [jobOffsets, setJobOffsets] = useState<readonly number[]>([0]);
  const [decisionOffsets, setDecisionOffsets] = useState<readonly number[]>([0]);
  const [referenceOffsets, setReferenceOffsets] = useState<readonly number[]>([0]);
  const [jobIndex, setJobIndex] = useState(0);
  const [decisionIndex, setDecisionIndex] = useState(0);
  const [referenceIndex, setReferenceIndex] = useState(0);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [observedAt, setObservedAt] = useState(0);
  const canRead = hasPermission(context, "job:read") && hasPermission(context, "audit:read");
  const canCreate = hasPermission(context, "job:create");
  const canReadPolicy = hasPermission(context, "policy:read");
  const canReadSecrets = hasPermission(context, "secret:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    const jobPage = canCreate ? client.listJobsPage(PAGE_SIZE, 0) : Promise.resolve(null);
    const decisionPage = canCreate && canReadPolicy ? client.listPolicyDecisionsPage(PAGE_SIZE, 0) : Promise.resolve(null);
    const referencePage = canCreate && canReadSecrets ? client.listSecretReferencesPage(PAGE_SIZE, 0) : Promise.resolve(null);
    void Promise.all([client.listZapProfiles(), client.getZapDashboard(), jobPage, decisionPage, referencePage])
      .then(([nextProfiles, nextDashboard, nextJobs, nextDecisions, nextReferences]) => {
        if (!active) return;
        setProfiles(nextProfiles); setDashboard(nextDashboard); setJobs(nextJobs);
        setDecisions(nextDecisions); setReferences(nextReferences);
        setObservedAt(Date.now());
        setJobOffsets([0]); setDecisionOffsets([0]); setReferenceOffsets([0]);
        setJobIndex(0); setDecisionIndex(0); setReferenceIndex(0);
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canCreate, canRead, canReadPolicy, canReadSecrets, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading ZAP runtime"><strong>Loading ZAP runtime</strong><p>Resolving certified profiles and server-owned execution bindings.</p></section>;

  const currentDashboard = dashboard;
  const now = observedAt;
  const targetOptions = dashboard.target_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const zapJobs = jobs?.data.filter((job) => job.request.capability === "zap-controlled-runtime") ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "zap.plan.compile" && decision.resource_type === "zap_profile") ?? [];
  const credentialOptions = references?.data.filter((reference) => reference.reference_status === "active"
    && reference.allowed_capabilities.includes("zap-controlled-runtime")) ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextProfiles, nextDashboard] = await Promise.all([client.listZapProfiles(), client.getZapDashboard()]);
      setProfiles(nextProfiles); setDashboard(nextDashboard); setObservedAt(Date.now()); setNotice("ZAP runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!jobs || !decisions) return;
    const data = new FormData(event.currentTarget);
    const profile = profiles.find((item) => item.profile_id === data.get("profile_binding"));
    const job = zapJobs.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const target = targetOptions.find((item) => item.attestation_sha256 === data.get("target_binding"));
    const credential = credentialOptions.find((item) => item.reference_id === data.get("credential_binding"));
    if (!profile || !job || !decision || !target || !isTargetEligible(target, now)) return;
    setActionError(null); setNotice(null);
    try {
      const plan = await client.compileZapPlan({
        plan_id: `zap-plan-${crypto.randomUUID()}`, profile_id: profile.profile_id,
        target_id: target.target_id as "r104-owned-web-fixture",
        target_attestation_sha256: target.attestation_sha256,
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id,
        credential_reference_ids: credential ? [credential.reference_id] : [],
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled ${plan.profile_id} plan for the authorized owned fixture.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function queue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!jobs) return;
    const data = new FormData(event.currentTarget);
    const plan = currentDashboard.plans.find((item) => item.plan_id === data.get("plan_binding"));
    const job = zapJobs.find((item) => item.job_id === data.get("job_binding"));
    const runner = runnerOptions.find((item) => item.runner_id === data.get("runner_binding"));
    if (!plan || !job || !runner || !isRunnerEligible(runner, now) || new Date(plan.expires_at).getTime() <= now) return;
    setActionError(null); setNotice(null);
    try {
      const run = await client.createZapRun({
        run_id: `zap-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id,
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through the selected authorized job and compatible runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Request native stop and containment for ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelZapRun(run.run_id, run.version, "Operator requested controlled ZAP cancellation");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Cancellation and containment requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageJobs(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setJobs(await client.listJobsPage(PAGE_SIZE, offset)); setJobOffsets(history); setJobIndex(index); } catch (cause) { setActionError(projectError(cause)); } }
  async function pageDecisions(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); } catch (cause) { setActionError(projectError(cause)); } }
  async function pageReferences(offset: number, index: number, history: readonly number[]) { setActionError(null); try { setReferences(await client.listSecretReferencesPage(PAGE_SIZE, offset)); setReferenceOffsets(history); setReferenceIndex(index); } catch (cause) { setActionError(projectError(cause)); } }

  return <div className="operational-grid zap-page">
    <section className="work-panel" aria-labelledby="zap-title"><div className="section-heading"><div><span className="eyebrow">Pinned service adapter</span><h2 id="zap-title">Controlled ZAP runtime</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only the owned compat_104 fixture and four certified profiles are accepted. URLs, YAML, scripts, add-ons, flags, and native API calls are not accepted.</p>{profiles.length === 0 ? <p className="empty-state">No certified ZAP profiles available</p> : <ul className="record-list">{profiles.map((profile) => <li key={profile.profile_id}><strong>{profile.profile_id}</strong><span>{profile.risk_class} · {profile.profile_state}</span><small>{profile.request_limit} requests · {profile.request_rate_per_second}/s · concurrency {profile.concurrency_limit} · {profile.timeout_seconds}s</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="zap-plan-title"><span className="eyebrow">Closed compiler</span><h2 id="zap-plan-title">Compile approved plan</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !jobs || !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Certified profile<select name="profile_binding" required><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id} · {profile.risk_class}</option>)}</select></label><label>Authorized ZAP job<select name="job_binding" required><option value="">Select job</option>{zapJobs.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable: dispatch blocked" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= now || decision.resource_id === "needs_review"}>{decision.resource_id} · {decision.reason_code} · valid to {new Date(decision.valid_until).toLocaleString()}</option>)}</select></label><label>Owned target attestation<select name="target_binding" required><option value="">Select target</option>{targetOptions.map((target) => <option key={target.attestation_sha256} value={target.attestation_sha256} disabled={!isTargetEligible(target, now)}>{target.target_id} · {target.attestation_state} · expires {new Date(target.expires_at).toLocaleString()}{isTargetEligible(target, now) ? "" : " · unavailable"}</option>)}</select></label>{canReadSecrets && <label>Approved credential profile (optional)<select name="credential_binding"><option value="">Unauthenticated profile</option>{credentialOptions.map((reference) => <option key={reference.reference_id} value={reference.reference_id}>{reference.redaction_label} · {reference.reference_kind}</option>)}</select></label>}<small>Plan identity is generated. Target attestation, policy revision, ROE, and any credential reference are selected or derived from authoritative server rows.</small><button type="submit">Compile plan</button></form>}{jobs && <Pager label="ZAP jobs" index={jobIndex} page={jobs.page} offsets={jobOffsets} load={pageJobs} />}{decisions && <Pager label="policy decisions" index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}{references && <Pager label="credential profiles" index={referenceIndex} page={references.page} offsets={referenceOffsets} load={pageReferences} />}</section>
    <section className="form-panel" aria-labelledby="zap-run-title"><span className="eyebrow">Durable runner binding</span><h2 id="zap-run-title">Queue certified run</h2>{!canCreate || !jobs ? <p className="empty-state">Requires job:create and authorized job choices.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= now}>{plan.profile_id} · {plan.target_id} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>Authorized ZAP job<select name="job_binding" required><option value="">Select job</option>{zapJobs.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Compatible runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!isRunnerEligible(runner, now)}>{runner.environment} · {runner.network_plane} · {runner.registration_state}{isRunnerEligible(runner, now) ? "" : " · unavailable"}</option>)}</select></label><small>Run identity is generated; the server revalidates the selected plan, job capability, runner registration, quota, and containment state.</small><button type="submit">Queue run</button></form>}</section>
    <section className="work-panel" aria-labelledby="zap-runs-title"><div className="section-heading"><div><span className="eyebrow">Progress and cleanup truth</span><h2 id="zap-runs-title">ZAP runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No ZAP runs recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.progress_percent}%</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Runner</dt><dd>{run.runner_id}</dd><dt>Passive queue</dt><dd>{run.passive_queue_size}</dd><dt>Reason</dt><dd>{run.reason_code}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void cancel(run); }}>Cancel and contain</button>}</li>)}</ul>}{dashboard.cleanups.map((cleanup) => <p key={cleanup.receipt_id} role="status">Cleanup {cleanup.cleanup_complete ? "verified" : "incomplete"}: {cleanup.residual_resource_count} residual resources.</p>)}</section>
  </div>;
}

function Pager({ label, index, page, offsets, load }: { readonly label: string; readonly index: number; readonly page: PageMeta; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label={`${label} pages`}><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous {label}</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next {label}</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "ZAP runtime unavailable"}><strong>{denied ? "Access denied" : "ZAP runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review ZAP runtime state." : "Certified ZAP profiles and server-owned bindings could not be loaded; no execution state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function isTargetEligible(target: Dashboard["target_options"][number], now: number): boolean { return target.non_production && target.attestation_state === "active" && new Date(target.expires_at).getTime() > now; }
function isRunnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("zap_unavailable", "ZAP runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The ZAP runtime action could not be completed."; }
