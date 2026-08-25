import { useCallback, useEffect, useState, type Dispatch, type FormEvent, type SetStateAction } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Engagement = components["schemas"]["EngagementData"];
type JitGrant = components["schemas"]["JitGrantData"];
type GrantPage = Awaited<ReturnType<Client["listJitGrantsPage"]>>;

const PAGE_SIZE = 50;

export function AccessPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [grants, setGrants] = useState<JitGrant[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [page, setPage] = useState<GrantPage["page"] | null>(null);
  const [offsetHistory, setOffsetHistory] = useState<readonly number[]>([0]);
  const [pageIndex, setPageIndex] = useState(0);
  const [reviewed, setReviewed] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const canRead = hasPermission(context, "jit:read");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([
      client.listJitGrantsPage(PAGE_SIZE, 0),
      client.listEngagementsPage(PAGE_SIZE, 0),
    ]).then(([grantPage, engagementPage]) => {
      if (!active) return;
      setGrants([...grantPage.data]);
      setPage(grantPage.page);
      setEngagements([...engagementPage.data]);
      setOffsetHistory([0]);
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
      const next = await client.listJitGrantsPage(PAGE_SIZE, offset);
      setGrants([...next.data]);
      setPage(next.page);
    } catch (cause) {
      setError(projectError(cause));
    }
  }, [client]);

  if (!canRead) {
    return <RouteError denied />;
  }
  if (routeError) {
    return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
      retry={() => { setLoading(true); setRouteError(null); setReloadToken((value) => value + 1); }} />;
  }
  if (loading) {
    return <section className="route-state" role="status" aria-label="Loading access governance">
      <strong>Loading access governance</strong>
      <p>Resolving authoritative grants and engagement choices.</p>
    </section>;
  }

  async function requestGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(null);
    setNotice(null);
    try {
      const created = await client.requestJitGrant({
        grant_id: createOpaqueId("grant"),
        role: "operator",
        permission: required(data, "permission"),
        scope_type: "engagement",
        scope_id: required(data, "scope_id"),
        reason: required(data, "reason"),
        expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
        break_glass: false,
      });
      setGrants((current) => [created, ...current]);
      setNotice(`JIT request ${created.grant_id} submitted for independent approval.`);
      form.reset();
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function approve(grant: JitGrant) {
    setError(null);
    try {
      const updated = await client.approveJitGrant(grant.grant_id, grant.version);
      replaceGrant(setGrants, updated);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function revoke(grant: JitGrant) {
    if (!window.confirm(`Revoke ${grant.grant_id}? This takes effect immediately.`)) return;
    setError(null);
    try {
      const updated = await client.revokeJitGrant(
        grant.grant_id,
        grant.version,
        "Revoked from the operational console",
      );
      replaceGrant(setGrants, updated);
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function review(grant: JitGrant) {
    if (!window.confirm(`Record independent review for ${grant.grant_id}?`)) return;
    setError(null);
    try {
      const updated = await client.reviewJitGrant(grant.grant_id, grant.version);
      replaceGrant(setGrants, updated);
      setReviewed((current) => new Set(current).add(grant.grant_id));
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function nextPage() {
    const nextOffset = page?.next_offset;
    if (nextOffset === null || nextOffset === undefined) return;
    const nextHistory = [...offsetHistory.slice(0, pageIndex + 1), nextOffset];
    await loadPage(nextOffset);
    setOffsetHistory(nextHistory);
    setPageIndex(nextHistory.length - 1);
  }

  async function previousPage() {
    if (pageIndex === 0) return;
    const nextIndex = pageIndex - 1;
    await loadPage(offsetHistory[nextIndex] ?? 0);
    setPageIndex(nextIndex);
  }

  return <div className="operational-grid">
    <section className="work-panel"><span className="eyebrow">Time-bound authority</span><h2>Access requests</h2>
      {error && <p className="inline-error" role="alert">{error}</p>}
      {notice && <p className="operation-notice" role="status">{notice}</p>}
      {grants.length === 0 ? <Empty text="No JIT grants" /> : <ul className="record-list">{grants.map((grant) => {
        const state = grantState(grant);
        const separationDenied = state === "pending" && grant.requester_user_id === context.subject;
        return <li key={grant.grant_id} className="access-record">
          <div><strong>{grant.grant_id}</strong><span>{grant.permission} · {engagementLabel(engagements, grant.scope_id)}</span><small>Version {grant.version}</small></div>
          <span className="state-label">{stateLabel(state)}</span>
          {state === "pending" && <button type="button" aria-label={`Approve ${grant.grant_id}`}
            disabled={!hasPermission(context, "jit:approve") || separationDenied}
            onClick={() => { void approve(grant); }}>Approve</button>}
          {separationDenied && <small>Separation of duties: requester cannot approve.</small>}
          {state === "active" && hasPermission(context, "jit:revoke") && <button type="button"
            aria-label={`Revoke ${grant.grant_id}`} onClick={() => { void revoke(grant); }}>Revoke</button>}
          {grant.break_glass && grant.approved_at && hasPermission(context, "jit:review") && <button type="button"
            aria-label={`Review ${grant.grant_id}`} disabled={reviewed.has(grant.grant_id)}
            onClick={() => { void review(grant); }}>{reviewed.has(grant.grant_id) ? "Reviewed" : "Review"}</button>}
        </li>;
      })}</ul>}
      <div className="pagination-controls" aria-label="Access request pages">
        <button type="button" disabled={pageIndex === 0} onClick={() => { void previousPage(); }}>Previous access requests</button>
        <span>Page {pageIndex + 1}</span>
        <button type="button" disabled={page?.next_offset === null || page?.next_offset === undefined}
          onClick={() => { void nextPage(); }}>Next access requests</button>
      </div>
    </section>
    <section className="form-panel"><span className="eyebrow">Least privilege</span><h2>Request access</h2>
      <form onSubmit={(event) => { void requestGrant(event); }}>
        <label>Engagement<select name="scope_id" required><option value="">Select engagement</option>{engagements.map((item) => <option key={item.engagement_id} value={item.engagement_id}>{item.name}</option>)}</select></label>
        <label>Permission<select name="permission"><option value="engagement:update">Update engagement</option><option value="target:create">Create target</option><option value="roe:create">Draft ROE</option></select></label>
        <label>Business reason<textarea name="reason" required minLength={10} maxLength={500} /></label>
        <small>Expires in 15 minutes. Independent approval is mandatory.</small>
        <button type="submit" disabled={!hasPermission(context, "jit:request") || engagements.length === 0}>Request JIT access</button>
      </form>
    </section>
  </div>;
}

function RouteError({ denied, correlationId, retry }: {
  readonly denied: boolean;
  readonly correlationId?: string | null;
  readonly retry?: () => void;
}) {
  return <section className="route-state route-state--error" role="alert"
    aria-label={denied ? "Route access denied" : "Route data unavailable"}>
    <strong>{denied ? "Access denied" : "Route data unavailable"}</strong>
    <p>{denied
      ? "The authenticated session is not permitted to load access governance."
      : "The access-governance projection could not be loaded; server policy remains authoritative."}</p>
    {correlationId && <p className="correlation">Correlation: {correlationId}</p>}
    {retry && <button type="button" onClick={retry}>Retry route data</button>}
  </section>;
}

function Empty({ text }: { readonly text: string }) {
  return <p className="empty-state">{text}</p>;
}

function replaceGrant(setGrants: Dispatch<SetStateAction<JitGrant[]>>, updated: JitGrant) {
  setGrants((current) => current.map((item) => item.grant_id === updated.grant_id ? updated : item));
}

function grantState(grant: JitGrant): "pending" | "active" | "expired" | "revoked" {
  if (grant.revoked_at) return "revoked";
  if (Date.parse(grant.expires_at) <= Date.now()) return "expired";
  return grant.approved_at ? "active" : "pending";
}

function stateLabel(state: ReturnType<typeof grantState>): string {
  return state === "pending" ? "Pending approval" : state[0]!.toUpperCase() + state.slice(1);
}

function engagementLabel(engagements: readonly Engagement[], engagementId: string): string {
  const engagement = engagements.find((item) => item.engagement_id === engagementId);
  return engagement ? `${engagement.name} (${engagement.engagement_id})` : engagementId;
}

function hasPermission(context: Context, permission: string): boolean {
  return context.permissions.includes("*") || context.permissions.includes(permission);
}

function createOpaqueId(prefix: string): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}-${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
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
    : new ConsoleApiError("api_unavailable", "Route data unavailable", 0, null);
}

function isAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401 || error.status === 403
    || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf");
}
