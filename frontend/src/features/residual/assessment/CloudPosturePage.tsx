import { useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["CloudDashboardData"];
type Profile = components["schemas"]["CloudProfileData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;

const PAGE_SIZE = 50;
const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled"]);

export function CloudPosturePage({ client, context }: { readonly client: Client; readonly context: Context }) {
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
    void Promise.all([client.listCloudProfiles(), client.getCloudDashboard(), decisionPage])
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
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading cloud posture runtime"><strong>Loading cloud posture runtime</strong><p>Verifying emulator-only identities and server-owned execution bindings.</p></section>;

  const currentDashboard = dashboard;
  const identityOptions = dashboard.identity_options ?? [];
  const runnerOptions = dashboard.runner_options ?? [];
  const jobOptions = dashboard.job_options ?? [];
  const reservationOptions = dashboard.reservation_options ?? [];
  const leaseOptions = dashboard.lease_options ?? [];
  const policyOptions = decisions?.data.filter((decision) => decision.allowed
    && decision.action === "cloud.plan.compile" && decision.resource_type === "cloud_profile") ?? [];

  async function refresh() {
    setActionError(null);
    try {
      const [nextProfiles, nextDashboard] = await Promise.all([client.listCloudProfiles(), client.getCloudDashboard()]);
      setProfiles(nextProfiles); setDashboard(nextDashboard); setObservedAt(Date.now());
      setNotice("Cloud posture runtime truth refreshed.");
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function compile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!decisions) return;
    const data = new FormData(event.currentTarget);
    const profile = profiles.find((item) => item.profile_id === data.get("profile_binding"));
    const job = jobOptions.find((item) => item.job_id === data.get("job_binding"));
    const decision = policyOptions.find((item) => item.decision_id === data.get("policy_binding"));
    const identity = identityOptions.find((item) => item.binding_id === data.get("identity_binding"));
    const reservation = reservationOptions.find((item) => item.reservation_id === data.get("reservation_binding"));
    const lease = leaseOptions.find((item) => item.lease_id === data.get("lease_binding"));
    if (!profile || !job || !decision || !identity || !reservation || !lease
      || identity.profile_id !== profile.profile_id || !identityEligible(identity)
      || !reservationEligible(reservation, observedAt) || !leaseEligible(lease, observedAt)
      || lease.job_id !== job.job_id || lease.roe_version_id !== job.roe_version_id
      || lease.permission_digest !== identity.permission_digest) return;
    setActionError(null); setNotice(null);
    try {
      const plan = await client.compileCloudPlan({
        plan_id: `cloud-plan-${crypto.randomUUID()}`, profile_id: profile.profile_id,
        identity_binding_id: identity.binding_id,
        policy_decision_id: decision.decision_id, policy_revision: decision.bundle_revision,
        roe_version_id: job.roe_version_id, reservation_id: reservation.reservation_id,
        credential_lease_id: lease.lease_id, confirmation: "--confirm-r108-local-lab",
      });
      setDashboard((current) => current ? { ...current, plans: [plan, ...current.plans.filter((item) => item.plan_id !== plan.plan_id)] } : current);
      setNotice(`Compiled read-only emulator collection for ${identity.expected_identity}.`);
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
      const run = await client.createCloudRun({
        run_id: `cloud-run-${crypto.randomUUID()}`, plan_id: plan.plan_id,
        job_id: job.job_id, runner_id: runner.runner_id, confirmation: "--confirm-r108-local-lab",
      });
      setDashboard((current) => current ? { ...current, runs: [run, ...current.runs.filter((item) => item.run_id !== run.run_id)] } : current);
      setNotice(`Queued ${run.plan_id} through the selected cloud posture job and isolated runner.`);
      event.currentTarget.reset();
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!window.confirm(`Block new provider requests and revoke the lease before stopping ${run.run_id}?`)) return;
    setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelCloudRun(run.run_id, run.version, "Operator requested controlled cloud posture cancellation");
      setDashboard((current) => current ? { ...current, runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item) } : current);
      setNotice(`Lease-first cancellation requested for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); }
  }

  async function pageDecisions(offset: number, index: number, history: readonly number[]) {
    setActionError(null);
    try { setDecisions(await client.listPolicyDecisionsPage(PAGE_SIZE, offset)); setDecisionOffsets(history); setDecisionIndex(index); }
    catch (cause) { setActionError(projectError(cause)); }
  }

  return <div className="operational-grid cloud-posture-page">
    <section className="work-panel" aria-labelledby="cloud-posture-title"><div className="section-heading"><div><span className="eyebrow">Exact identity and permission truth</span><h2 id="cloud-posture-title">Cloud and Kubernetes posture</h2></div><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">Only repo-owned loopback provider emulators and pinned offline fixtures are qualified. Production tenants, arbitrary endpoints, ambient credentials, wildcard or write permissions, secret/data-plane reads, host access, scanner flags, module downloads, and remediation are disabled.</p>{profiles.length === 0 ? <p className="empty-state">No certified cloud profile available</p> : <ul className="record-list">{profiles.map((profile) => <li key={profile.profile_id}><strong>{profile.profile_id}</strong><span>{profile.expected_identity} · {profile.profile_state}</span><small>{profile.operations.map((item) => `${item.action} (${item.data_class})`).join(", ")}</small><small>{profile.max_api_calls} calls · {profile.max_pages} pages · {profile.max_resources} resources · {profile.max_response_bytes} bytes</small></li>)}</ul>}</section>
    <section className="form-panel" aria-labelledby="cloud-plan-title"><span className="eyebrow">Closed read-only compiler</span><h2 id="cloud-plan-title">Compile read-only collection</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : !canReadPolicy ? <p className="empty-state">Requires policy:read to choose a current decision.</p> : !decisions ? <p className="empty-state">Authoritative compile choices are unavailable.</p> : <form onSubmit={(event) => { void compile(event); }}><label>Certified profile<select name="profile_binding" required><option value="">Select profile</option>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.provider} · {profile.profile_id}</option>)}</select></label><label>Authorized cloud job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}{job.dispatch_blocked ? " · unavailable" : ""}</option>)}</select></label><label>Current policy decision<select name="policy_binding" required><option value="">Select decision</option>{policyOptions.map((decision) => <option key={decision.decision_id} value={decision.decision_id} disabled={new Date(decision.valid_until).getTime() <= observedAt || decision.resource_id === "needs_review"}>{decision.resource_id} · {decision.reason_code} · {decision.bundle_revision}</option>)}</select></label><label>Emulator identity binding<select name="identity_binding" required><option value="">Select identity</option>{identityOptions.map((identity) => <option key={identity.binding_id} value={identity.binding_id} disabled={!identityEligible(identity)}>{identity.expected_identity} · {identity.profile_id} · {identity.binding_state}</option>)}</select></label><label>Active quota reservation<select name="reservation_binding" required><option value="">Select reservation</option>{reservationOptions.map((reservation) => <option key={reservation.reservation_id} value={reservation.reservation_id} disabled={!reservationEligible(reservation, observedAt)}>{reservation.remaining_amount} remaining · {reservation.reservation_state} · expires {new Date(reservation.expires_at).toLocaleString()}</option>)}</select></label><label>Read-only credential lease<select name="lease_binding" required><option value="">Select lease</option>{leaseOptions.map((lease) => <option key={lease.lease_id} value={lease.lease_id} disabled={!leaseEligible(lease, observedAt)}>{lease.job_id} · {lease.lease_state} · expires {new Date(lease.expires_at).toLocaleString()}</option>)}</select></label><small>Plan identity is generated. Provider endpoints, credential material, operations, data classes, pagination, policy revision, approved ROE, and quota remain server-owned.</small><button type="submit">Compile approved collection</button></form>}{decisions && <Pager index={decisionIndex} page={decisions.page} offsets={decisionOffsets} load={pageDecisions} />}</section>
    <section className="form-panel" aria-labelledby="cloud-run-title"><span className="eyebrow">Durable isolated runner</span><h2 id="cloud-run-title">Queue posture run</h2>{!canCreate ? <p className="empty-state">Requires job:create.</p> : <form onSubmit={(event) => { void queue(event); }}><label>Compiled plan<select name="plan_binding" required><option value="">Select plan</option>{dashboard.plans.map((plan) => <option key={plan.plan_id} value={plan.plan_id} disabled={new Date(plan.expires_at).getTime() <= observedAt}>{plan.profile_id} · {plan.plan_state} · expires {new Date(plan.expires_at).toLocaleString()}</option>)}</select></label><label>Authorized cloud job<select name="job_binding" required><option value="">Select job</option>{jobOptions.map((job) => <option key={job.job_id} value={job.job_id} disabled={job.dispatch_blocked || job.stop_requested}>{job.current_gate} · {job.status} · {job.job_id}</option>)}</select></label><label>Compatible isolated runner<select name="runner_binding" required><option value="">Select runner</option>{runnerOptions.map((runner) => <option key={runner.runner_id} value={runner.runner_id} disabled={!runnerEligible(runner, observedAt)}>{runner.environment} · {runner.network_plane} · {runner.required_policy_revision} · {runner.registration_state}</option>)}</select></label><small>Run identity is generated; the compile endpoint revalidates emulator identity, policy, ROE, quota, and lease, while queueing uses the active stored plan and guarded mutation.</small><button type="submit">Queue local run</button></form>}</section>
    <section className="work-panel" aria-labelledby="cloud-runs-title"><div className="section-heading"><div><span className="eyebrow">Coverage, partial state, evidence, and cleanup</span><h2 id="cloud-runs-title">Posture runs</h2></div><span className="count-chip">{dashboard.runs.length} runs</span></div>{dashboard.runs.length === 0 ? <p className="empty-state">No cloud posture runs recorded</p> : <ul className="job-list">{dashboard.runs.map((run) => <li key={run.run_id} className="job-record"><div className="job-record__heading"><div><strong>{run.run_id}</strong><span>{run.run_state}</span></div><span className="state-label">{run.complete ? "Complete" : "Partial or pending"}</span></div><dl><dt>Plan / job</dt><dd>{run.plan_id} / {run.job_id}</dd><dt>Partial reasons</dt><dd>{run.partial_reasons.join(", ") || "None"}</dd><dt>Snapshot</dt><dd className="mono-value">{run.snapshot_sha256 ?? "Pending"}</dd></dl>{!TERMINAL_STATES.has(run.run_state) && <button className="danger-action" type="button" disabled={!hasPermission(context, "job:stop")} onClick={() => { void cancel(run); }}>Revoke lease and cancel</button>}</li>)}</ul>}<h3>Per-resource control results</h3>{dashboard.results.length === 0 ? <p className="empty-state">No normalized posture results</p> : <ul className="record-list">{dashboard.results.map((result) => <li key={result.result_id}><strong>{result.check_id}</strong><span>{result.resource_id} · {result.passed ? "pass" : result.severity}</span><small>{result.control_pack_id} · {result.evidence_instance_id ?? "Evidence pending"}</small></li>)}</ul>}{dashboard.cleanups.map((cleanup) => <p key={cleanup.receipt_id} role="status">Cleanup {cleanup.lease_revoked && cleanup.new_requests_blocked && cleanup.residual_resource_count === 0 ? "verified" : "incomplete"}: lease {cleanup.lease_revoked ? "revoked" : "active"}; {cleanup.residual_resource_count} residual resources.</p>)}</section>
  </div>;
}

function Pager({ index, page, offsets, load }: { readonly index: number; readonly page: DecisionPage["page"]; readonly offsets: readonly number[]; readonly load: (offset: number, index: number, history: readonly number[]) => Promise<void> }) { return <div className="pagination-controls" aria-label="policy decision pages"><button type="button" disabled={index === 0} onClick={() => { const nextIndex = index - 1; void load(offsets[nextIndex] ?? 0, nextIndex, offsets); }}>Previous policy decisions</button><span>Page {index + 1}</span><button type="button" disabled={page.next_offset === null || page.next_offset === undefined} onClick={() => { const offset = page.next_offset; if (offset === null || offset === undefined) return; const history = [...offsets.slice(0, index + 1), offset]; void load(offset, history.length - 1, history); }}>Next policy decisions</button></div>; }
function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Cloud posture runtime unavailable"}><strong>{denied ? "Access denied" : "Cloud posture runtime unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review cloud posture runtime state." : "Emulator identity and server-owned bindings could not be loaded; no execution or posture state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function identityEligible(identity: Dashboard["identity_options"][number]): boolean { return identity.binding_state === "active-local-emulator"; }
function runnerEligible(runner: Dashboard["runner_options"][number], now: number): boolean { return runner.registration_state === "active" && new Date(runner.expires_at).getTime() > now; }
function reservationEligible(reservation: Dashboard["reservation_options"][number], now: number): boolean { return new Set(["reserved", "partially_consumed"]).has(reservation.reservation_state) && reservation.remaining_amount > 0 && new Date(reservation.expires_at).getTime() > now; }
function leaseEligible(lease: Dashboard["lease_options"][number], now: number): boolean { return lease.lease_state === "active" && new Date(lease.expires_at).getTime() > now; }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("cloud_posture_unavailable", "Cloud posture runtime unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The cloud posture runtime action could not be completed."; }
