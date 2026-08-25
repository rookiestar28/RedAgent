import { useEffect, useState } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type LabDashboard = components["schemas"]["LabDashboardData"];

export function LabPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [dashboard, setDashboard] = useState<LabDashboard | null>(null);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "audit:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void client.getLabDashboard()
      .then((value) => { if (active) setDashboard(value); })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  async function refresh() {
    setRefreshError(null);
    try { setDashboard(await client.getLabDashboard()); }
    catch (cause) { setRefreshError(projectError(cause)); }
  }

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading safe lab state">
    <strong>Loading safe lab state</strong><p>Resolving the attested non-production qualification fixture.</p>
  </section>;

  const qualificationReady = dashboard.bundle?.bundle_state === "active"
    && dashboard.scenarios.length > 0
    && dashboard.scenarios.every(({ scenario_state }) => scenario_state === "succeeded")
    && dashboard.measurements.length > 0
    && dashboard.measurements.every(({ result_state }) => result_state === "passed")
    && dashboard.latest_teardown?.teardown_complete === true
    && dashboard.latest_teardown.residual_resource_count === 0;

  return <div className="operational-grid lab-page">
    <section className="work-panel" aria-labelledby="lab-title">
      <div className="section-heading"><div><span className="eyebrow">Disposable qualification only</span><h2 id="lab-title">Safe local lab</h2></div>
        <div><span className="state-label">{qualificationReady ? "Qualification ready" : "Qualification incomplete"}</span><button type="button" onClick={() => { void refresh(); }}>Refresh</button></div></div>
      {refreshError && <p className="inline-error" role="alert">{refreshError}</p>}
      <p className="safety-boundary">Arbitrary target input is disabled. Only the attested non-production fixture can be qualified.</p>
      {!dashboard.bundle ? <p className="empty-state">No lab bundle is registered</p> : <dl>
        <dt>Bundle</dt><dd>{dashboard.bundle.bundle_id} · revision {dashboard.bundle.bundle_revision}</dd>
        <dt>State</dt><dd>{dashboard.bundle.bundle_state}</dd>
        <dt>Network</dt><dd>{dashboard.bundle.network_id}</dd>
        <dt>Fixture digest</dt><dd className="mono-value">{dashboard.bundle.fixture_digest}</dd>
      </dl>}
      <a className="danger-link" href="/jobs">Emergency stop controls</a>
    </section>
    <section className="work-panel" aria-labelledby="matrix-title">
      <div className="section-heading"><div><span className="eyebrow">Durable receipts</span><h2 id="matrix-title">Golden scenario matrix</h2></div><span className="count-chip">{dashboard.scenarios.length} scenarios</span></div>
      {dashboard.scenarios.length === 0 ? <p className="empty-state">No qualification scenarios recorded</p> : <ul className="record-list">{dashboard.scenarios.map((scenario) => <li key={`${scenario.run_id}:${scenario.scenario_id}`}>
        <strong>{scenario.scenario_id}</strong><span>{scenario.scenario_state}</span><small>{scenario.reason_code} · version {scenario.version}</small>
      </li>)}</ul>}
      <h3>Measurements</h3>
      {dashboard.measurements.length === 0 ? <p className="empty-state">No measurements recorded</p> : <ul className="record-list">{dashboard.measurements.map((measurement) => <li key={measurement.measurement_id}>
        <strong>{measurement.metric_id}</strong><span>{measurement.result_state}</span><small>{measurement.observed_millionths} {measurement.comparison} {measurement.threshold_millionths} millionths · {measurement.unit}</small>
      </li>)}</ul>}
      {dashboard.latest_teardown
        ? <p role="status">Teardown {dashboard.latest_teardown.teardown_complete ? "verified" : "incomplete"}: {dashboard.latest_teardown.residual_resource_count} residual resources.</p>
        : <p className="empty-state">No teardown receipt recorded</p>}
    </section>
  </div>;
}

function RouteError({ denied, correlationId, retry }: {
  readonly denied: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  return <section className="route-state route-state--error" role="alert"
    aria-label={denied ? "Route access denied" : "Safe lab unavailable"}>
    <strong>{denied ? "Access denied" : "Safe lab unavailable"}</strong>
    <p>{denied
      ? "The authenticated session is not permitted to review safe-lab qualification evidence."
      : "The safe-lab dashboard could not be loaded; qualification was not inferred."}</p>
    {correlationId && <p className="correlation">Correlation: {correlationId}</p>}
    {retry && <button type="button" onClick={retry}>Retry route data</button>}
  </section>;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The safe-lab dashboard could not be loaded.";
}

function asConsoleError(cause: unknown): ConsoleApiError {
  return cause instanceof ConsoleApiError
    ? cause
    : new ConsoleApiError("safe_lab_unavailable", "Safe lab unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}
