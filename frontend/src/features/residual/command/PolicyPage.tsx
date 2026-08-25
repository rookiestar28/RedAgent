import { useCallback, useEffect, useState, type FormEvent } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type PolicyStatus = components["schemas"]["PolicyStatusData"];
type PolicyDecision = components["schemas"]["PolicyDecisionData"];
type PolicyBundle = components["schemas"]["PolicyBundleData"];
type DecisionPage = Awaited<ReturnType<Client["listPolicyDecisionsPage"]>>;
type BundlePage = Awaited<ReturnType<Client["listPolicyBundlesPage"]>>;
type TransitionKind = "promote" | "rollback";

const PAGE_SIZE = 50;

export function PolicyPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [status, setStatus] = useState<PolicyStatus | null>(null);
  const [decisions, setDecisions] = useState<PolicyDecision[]>([]);
  const [bundles, setBundles] = useState<PolicyBundle[]>([]);
  const [decisionPage, setDecisionPage] = useState<DecisionPage["page"] | null>(null);
  const [bundlePage, setBundlePage] = useState<BundlePage["page"] | null>(null);
  const [decisionHistory, setDecisionHistory] = useState<readonly number[]>([0]);
  const [bundleHistory, setBundleHistory] = useState<readonly number[]>([0]);
  const [decisionIndex, setDecisionIndex] = useState(0);
  const [bundleIndex, setBundleIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [operationState, setOperationState] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canRead = hasPermission(context, "policy:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([
      client.getPolicyStatus(),
      client.listPolicyDecisionsPage(PAGE_SIZE, 0),
      client.listPolicyBundlesPage(PAGE_SIZE, 0),
    ]).then(([nextStatus, nextDecisions, nextBundles]) => {
      if (!active) return;
      setStatus(nextStatus);
      setDecisions([...nextDecisions.data]);
      setBundles([...nextBundles.data]);
      setDecisionPage(nextDecisions.page);
      setBundlePage(nextBundles.page);
      setDecisionHistory([0]);
      setBundleHistory([0]);
      setDecisionIndex(0);
      setBundleIndex(0);
      setLoading(false);
    }).catch((cause: unknown) => {
      if (active) {
        setRouteError(asConsoleError(cause));
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  const refreshCurrent = useCallback(async () => {
    const [nextStatus, nextDecisions, nextBundles] = await Promise.all([
      client.getPolicyStatus(),
      client.listPolicyDecisionsPage(PAGE_SIZE, decisionPage?.offset ?? 0),
      client.listPolicyBundlesPage(PAGE_SIZE, bundlePage?.offset ?? 0),
    ]);
    setStatus(nextStatus);
    setDecisions([...nextDecisions.data]);
    setBundles([...nextBundles.data]);
    setDecisionPage(nextDecisions.page);
    setBundlePage(nextBundles.page);
  }, [bundlePage?.offset, client, decisionPage?.offset]);

  const loadDecisionPage = useCallback(async (offset: number) => {
    setError(null);
    try {
      const next = await client.listPolicyDecisionsPage(PAGE_SIZE, offset);
      setDecisions([...next.data]);
      setDecisionPage(next.page);
    } catch (cause) {
      setError(projectError(cause));
    }
  }, [client]);

  const loadBundlePage = useCallback(async (offset: number) => {
    setError(null);
    try {
      const next = await client.listPolicyBundlesPage(PAGE_SIZE, offset);
      setBundles([...next.data]);
      setBundlePage(next.page);
    } catch (cause) {
      setError(projectError(cause));
    }
  }, [client]);

  if (!canRead) return <RouteError denied />;
  if (routeError) {
    return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
      unavailable={routeError.status === 503 || routeError.code.includes("unavailable")}
      retry={() => { setLoading(true); setRouteError(null); setReloadToken((value) => value + 1); }} />;
  }
  if (loading) {
    return <section className="route-state" role="status" aria-label="Loading policy governance">
      <strong>Loading policy governance</strong><p>Resolving convergence, decisions, and accepted bundles.</p>
    </section>;
  }

  async function simulate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setOperationState(null);
    try {
      const fixture = required(new FormData(event.currentTarget), "fixture") as
        "api-job-create" | "workflow-job-command" | "evidence-write" | "secret-lease";
      const result = await client.simulatePolicy({ fixture });
      setNotice(`Fixture ${result.fixture} authorized by ${result.bundle_revision}; receipt ${result.receipt_id}.`);
      await refreshCurrent();
    } catch (cause) {
      setOperationState(isPolicyDenied(cause) ? "Simulation denied" : "Policy unavailable");
      setError(projectError(cause));
    }
  }

  async function transition(event: FormEvent<HTMLFormElement>, kind: TransitionKind) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setOperationState(null);
    const data = new FormData(event.currentTarget);
    try {
      const revision = required(data, "revision");
      const selected = bundles.find((bundle) => bundle.revision === revision);
      if (!selected || !eligibleBundle(selected, context)) throw new Error("Selected bundle is unavailable for this actor.");
      const payload = { revision: selected.revision, expected_version: selected.version, reason: required(data, "reason") };
      const result = kind === "rollback" ? await client.rollbackPolicy(payload) : await client.promotePolicy(payload);
      setNotice(`${stateLabel(result.state)}: ${result.revision}; ${result.acknowledged_agents.length} agents acknowledged.`);
      setOperationState(kind === "rollback" ? "Rollback promoted" : "Promoted");
      await refreshCurrent();
    } catch (cause) {
      setOperationState(kind === "rollback" ? "Rollback required" : "Promotion pending");
      setError(projectError(cause));
    }
  }

  async function nextDecisions() {
    const offset = decisionPage?.next_offset;
    if (offset === null || offset === undefined) return;
    const history = [...decisionHistory.slice(0, decisionIndex + 1), offset];
    await loadDecisionPage(offset);
    setDecisionHistory(history);
    setDecisionIndex(history.length - 1);
  }

  async function previousDecisions() {
    if (decisionIndex === 0) return;
    const nextIndex = decisionIndex - 1;
    await loadDecisionPage(decisionHistory[nextIndex] ?? 0);
    setDecisionIndex(nextIndex);
  }

  async function nextBundles() {
    const offset = bundlePage?.next_offset;
    if (offset === null || offset === undefined) return;
    const history = [...bundleHistory.slice(0, bundleIndex + 1), offset];
    await loadBundlePage(offset);
    setBundleHistory(history);
    setBundleIndex(history.length - 1);
  }

  async function previousBundles() {
    if (bundleIndex === 0) return;
    const nextIndex = bundleIndex - 1;
    await loadBundlePage(bundleHistory[nextIndex] ?? 0);
    setBundleIndex(nextIndex);
  }

  const statusState = policyStatusState(status);
  return <div className="operational-grid">
    <section className="work-panel" aria-labelledby="policy-title">
      <div className="section-heading"><div><span className="eyebrow">Distributed authorization</span><h2 id="policy-title">Policy decisions</h2></div><span className="state-label">{statusState}</span></div>
      {error && <p className="inline-error" role="alert">{error}</p>}
      {notice && <p className="operation-notice" role="status">{notice}</p>}
      {operationState && <p className="operation-state" role="status">{operationState}</p>}
      <dl><dt>Required revision</dt><dd>{status?.required_revision ?? "Unavailable"}</dd><dt>Promotion</dt><dd>{status?.promotion_state ?? "Policy unavailable"}</dd><dt>Convergence</dt><dd>{status?.converged ? "Converged" : "Not converged"}</dd><dt>Agent acknowledgement</dt><dd>{status?.acknowledged_agents.length ?? 0} / {status?.required_agents.length ?? 0}</dd></dl>
      {decisions.length === 0 ? <Empty text="No policy decisions recorded" /> : <ul className="job-list">{decisions.map((decision) => <li className="job-record" key={decision.decision_id}>
        <div className="job-record__heading"><div><strong>{decision.action}</strong><span>{decision.boundary} · {decision.resource_type}/{decision.resource_id}</span></div><span className="state-label">{decision.allowed ? "Allowed" : "Denied"}</span></div>
        <dl><dt>Revision</dt><dd>{decision.bundle_revision}</dd><dt>Reason</dt><dd>{decision.reason_code}</dd><dt>Input hash</dt><dd>{decision.input_hash}</dd><dt>Correlation</dt><dd>{decision.correlation_id}</dd></dl>
      </li>)}</ul>}
      <Pagination label="Policy decision pages" index={decisionIndex} previous={() => { void previousDecisions(); }}
        next={() => { void nextDecisions(); }} hasNext={decisionPage?.next_offset !== null && decisionPage?.next_offset !== undefined}
        previousLabel="Previous decisions" nextLabel="Next decisions" />
    </section>
    <section className="form-panel" aria-labelledby="policy-actions-title">
      <span className="eyebrow">Closed operations</span><h2 id="policy-actions-title">Policy lifecycle</h2>
      <form onSubmit={(event) => { void simulate(event); }}><h3>Fixed simulation</h3><label>Fixture<select name="fixture"><option value="api-job-create">API job create</option><option value="workflow-job-command">Workflow command</option><option value="evidence-write">Evidence write</option><option value="secret-lease">Secret lease</option></select></label><button type="submit" disabled={!hasPermission(context, "policy:simulate")}>Run fixed fixture</button></form>
      <PolicyTransitionForm kind="promote" bundles={bundles} context={context} onSubmit={transition} />
      <PolicyTransitionForm kind="rollback" bundles={bundles} context={context} onSubmit={transition} />
      <small>No Rego, data document, bundle, URL, key, arbitrary decision input, or caller-supplied version can be submitted here.</small>
      <h3>Reviewed bundle inventory</h3>
      {bundles.length === 0 ? <Empty text="No policy bundles recorded" /> : <ul className="record-list">{bundles.map((bundle) => <li key={bundle.revision}>
        <strong>{bundle.revision}</strong><span>{bundle.status} · version {bundle.version} · reviewer {bundle.reviewer_user_id}</span>
        {!eligibleBundle(bundle, context) && <small>{bundle.author_user_id === context.subject
          ? "Unavailable: author cannot promote the same bundle."
          : "Unavailable: bundle has not reached accepted status."}</small>}
      </li>)}</ul>}
      <Pagination label="Policy bundle pages" index={bundleIndex} previous={() => { void previousBundles(); }}
        next={() => { void nextBundles(); }} hasNext={bundlePage?.next_offset !== null && bundlePage?.next_offset !== undefined}
        previousLabel="Previous bundles" nextLabel="Next bundles" />
    </section>
  </div>;
}

function PolicyTransitionForm({ kind, bundles, context, onSubmit }: {
  readonly kind: TransitionKind;
  readonly bundles: readonly PolicyBundle[];
  readonly context: Context;
  readonly onSubmit: (event: FormEvent<HTMLFormElement>, kind: TransitionKind) => Promise<void>;
}) {
  const promote = kind === "promote";
  const permitted = hasPermission(context, promote ? "policy:promote" : "policy:rollback");
  const available = bundles.some((bundle) => eligibleBundle(bundle, context));
  return <form aria-label={promote ? "Promote policy revision" : "Rollback policy revision"}
    onSubmit={(event) => { void onSubmit(event, kind); }}>
    <h3>{promote ? "Promote reviewed revision" : "Rollback to accepted revision"}</h3>
    <label>Accepted revision<select name="revision" required><option value="">Select revision</option>{bundles.map((bundle) => <option
      key={bundle.revision} value={bundle.revision} disabled={!eligibleBundle(bundle, context)}>
      {bundle.revision} · v{bundle.version}{eligibleBundle(bundle, context) ? "" : " · unavailable"}
    </option>)}</select></label>
    <label>Reason<textarea name="reason" minLength={10} maxLength={500} required /></label>
    <button className={promote ? undefined : "danger-action"} type="submit" disabled={!permitted || !available}>
      {promote ? "Promote after convergence" : "Rollback after convergence"}
    </button>
  </form>;
}

function Pagination({ label, index, previous, next, hasNext, previousLabel, nextLabel }: {
  readonly label: string;
  readonly index: number;
  readonly previous: () => void;
  readonly next: () => void;
  readonly hasNext: boolean;
  readonly previousLabel: string;
  readonly nextLabel: string;
}) {
  return <div className="pagination-controls" aria-label={label}>
    <button type="button" disabled={index === 0} onClick={previous}>{previousLabel}</button>
    <span>Page {index + 1}</span>
    <button type="button" disabled={!hasNext} onClick={next}>{nextLabel}</button>
  </div>;
}

function RouteError({ denied, unavailable = false, correlationId, retry }: {
  readonly denied: boolean;
  readonly unavailable?: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  const label = denied ? "Route access denied" : unavailable ? "Policy unavailable" : "Route data unavailable";
  return <section className="route-state route-state--error" role="alert" aria-label={label}>
    <strong>{denied ? "Access denied" : unavailable ? "Policy unavailable" : "Route data unavailable"}</strong>
    <p>{denied
      ? "The authenticated session is not permitted to load policy governance."
      : "Policy status, decisions, and bundle authority could not be loaded; enforcement remains fail-closed."}</p>
    {correlationId && <p className="correlation">Correlation: {correlationId}</p>}
    {retry && <button type="button" onClick={retry}>Retry route data</button>}
  </section>;
}

function Empty({ text }: { readonly text: string }) {
  return <p className="empty-state">{text}</p>;
}

function eligibleBundle(bundle: PolicyBundle, context: Context): boolean {
  return bundle.status === "accepted" && bundle.author_user_id !== context.subject;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function policyStatusState(status: PolicyStatus | null): string {
  if (!status) return "Policy unavailable";
  if (status.promotion_state === "rollback_required") return "Rollback required";
  if (!status.converged) return "Promotion pending";
  return status.promotion_state === "promoted" || status.promotion_state === "rollback_promoted"
    ? "Promoted"
    : "Converged";
}

function stateLabel(value: string): string {
  return value.split("_").map((part) => part ? part[0]!.toUpperCase() + part.slice(1) : "").join(" ");
}

function required(data: FormData, name: string): string {
  const entry = data.get(name);
  if (typeof entry !== "string" || !entry.trim()) throw new Error(`${name} is required`);
  return entry.trim();
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The operation could not be completed.";
}

function asConsoleError(cause: unknown): ConsoleApiError {
  return cause instanceof ConsoleApiError
    ? cause
    : new ConsoleApiError("api_unavailable", "Policy projection unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}

function isPolicyDenied(cause: unknown): boolean {
  return cause instanceof ConsoleApiError
    && (cause.status === 403 || cause.code.includes("denied") || cause.code.includes("policy"));
}
