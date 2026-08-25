import { useCallback, useEffect, useState } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Activity = components["schemas"]["ActivityData"];
type ActivityPageResult = Awaited<ReturnType<Client["listActivityPage"]>>;

const PAGE_SIZE = 50;

export function ActivityPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [rows, setRows] = useState<Activity[]>([]);
  const [page, setPage] = useState<ActivityPageResult["page"] | null>(null);
  const [history, setHistory] = useState<readonly number[]>([0]);
  const [pageIndex, setPageIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const canRead = hasPermission(context, "audit:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void client.listActivityPage(PAGE_SIZE, 0).then((next) => {
      if (!active) return;
      setRows([...next.data]);
      setPage(next.page);
      setHistory([0]);
      setPageIndex(0);
      setLoading(false);
    }).catch((cause: unknown) => {
      if (active) {
        setRouteError(asConsoleError(cause));
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  const loadPage = useCallback(async (offset: number) => {
    setError(null);
    try {
      const next = await client.listActivityPage(PAGE_SIZE, offset);
      setRows([...next.data]);
      setPage(next.page);
      return true;
    } catch (cause) {
      setError(projectError(cause));
      return false;
    }
  }, [client]);

  if (!canRead) return <RouteError denied />;
  if (routeError) {
    return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
      retry={() => { setLoading(true); setRouteError(null); setReloadToken((value) => value + 1); }} />;
  }
  if (loading) {
    return <section className="route-state" role="status" aria-label="Loading audit activity">
      <strong>Loading audit activity</strong><p>Resolving the immutable metadata projection.</p>
    </section>;
  }

  async function nextPage() {
    const offset = page?.next_offset;
    if (offset === null || offset === undefined) return;
    const nextHistory = [...history.slice(0, pageIndex + 1), offset];
    if (!await loadPage(offset)) return;
    setHistory(nextHistory);
    setPageIndex(nextHistory.length - 1);
  }

  async function previousPage() {
    if (pageIndex === 0) return;
    const nextIndex = pageIndex - 1;
    if (!await loadPage(history[nextIndex] ?? 0)) return;
    setPageIndex(nextIndex);
  }

  return <section className="work-panel" aria-labelledby="activity-title">
    <span className="eyebrow">Immutable operator trail</span><h2 id="activity-title">Activity</h2>
    <p className="operation-notice" role="status">Redacted metadata-only audit projection</p>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {rows.length === 0 ? <p className="empty-state">No visible activity</p> : <div className="table-scroll" tabIndex={0} aria-label="Audit activity table">
      <table><thead><tr><th>Action</th><th>Subject</th><th>Actor</th><th>Correlation</th><th>Occurred</th></tr></thead><tbody>{rows.map((row) => <tr key={row.event_id}>
        <td>{row.action}</td><td>{row.subject_type}: {row.subject_id}</td><td>{row.actor_user_id}</td>
        <td>{row.correlation_id}</td><td>{new Date(row.occurred_at).toLocaleString()}</td>
      </tr>)}</tbody></table>
    </div>}
    <div className="pagination-controls" aria-label="Activity pages">
      <button type="button" disabled={pageIndex === 0} onClick={() => { void previousPage(); }}>Previous activity</button>
      <span>Page {pageIndex + 1}</span>
      <button type="button" disabled={page?.next_offset === null || page?.next_offset === undefined}
        onClick={() => { void nextPage(); }}>Next activity</button>
    </div>
  </section>;
}

function RouteError({ denied, correlationId, retry }: {
  readonly denied: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  return <section className="route-state route-state--error" role="alert"
    aria-label={denied ? "Route access denied" : "Audit unavailable"}>
    <strong>{denied ? "Access denied" : "Audit unavailable"}</strong>
    <p>{denied
      ? "The authenticated session is not permitted to review audit activity."
      : "The immutable audit metadata projection could not be loaded; no event detail was inferred."}</p>
    {correlationId && <p className="correlation">Correlation: {correlationId}</p>}
    {retry && <button type="button" onClick={retry}>Retry route data</button>}
  </section>;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  return cause instanceof Error ? cause.message : "The audit page could not be loaded.";
}

function asConsoleError(cause: unknown): ConsoleApiError {
  return cause instanceof ConsoleApiError
    ? cause
    : new ConsoleApiError("audit_unavailable", "Audit projection unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}
