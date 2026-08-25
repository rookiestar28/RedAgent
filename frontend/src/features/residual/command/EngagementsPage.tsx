import { useCallback, useEffect, useState, type FormEvent } from "react";

import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = Awaited<ReturnType<Client["getContext"]>>;
type Engagement = Awaited<ReturnType<Client["listEngagements"]>>[number];
type Target = Awaited<ReturnType<Client["listTargets"]>>[number];
type Roe = Awaited<ReturnType<Client["listRoeVersions"]>>[number];
type EngagementPage = Awaited<ReturnType<Client["listEngagementsPage"]>>;

const ENGAGEMENT_PAGE_SIZE = 50;
const CANONICAL_TARGET_TYPES = ["hostname", "ip", "cidr", "url", "application"] as const;

export function EngagementsPage({ client, context }: {
  readonly client: Client;
  readonly context: Context;
}) {
  const [rows, setRows] = useState<Engagement[]>([]);
  const [selected, setSelected] = useState<Engagement | null>(null);
  const [page, setPage] = useState<EngagementPage["page"] | null>(null);
  const [offsetHistory, setOffsetHistory] = useState<readonly number[]>([0]);
  const [pageIndex, setPageIndex] = useState(0);
  const [loading, setLoading] = useState(hasPermission(context.permissions, "engagement:read"));
  const [error, setError] = useState<string | null>(null);
  const canRead = hasPermission(context.permissions, "engagement:read");
  const canCreate = hasPermission(context.permissions, "engagement:create");

  const loadPage = useCallback(async (offset: number) => {
    setLoading(true);
    setError(null);
    try {
      const next = await client.listEngagementsPage(ENGAGEMENT_PAGE_SIZE, offset);
      const nextRows = [...next.data];
      setRows(nextRows);
      setPage(next.page);
      setSelected(nextRows[0] ?? null);
    } catch (cause) {
      setError(projectError(cause));
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    let active = true;
    if (canRead) {
      void client.listEngagementsPage(ENGAGEMENT_PAGE_SIZE, 0).then((next) => {
        if (!active) return;
        const nextRows = [...next.data];
        setRows(nextRows);
        setPage(next.page);
        setSelected(nextRows[0] ?? null);
      }).catch((cause: unknown) => {
        if (active) setError(projectError(cause));
      }).finally(() => {
        if (active) setLoading(false);
      });
    }
    return () => { active = false; };
  }, [canRead, client]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(null);
    try {
      const created = await client.createEngagement({
        engagement_id: createOpaqueId("engagement"),
        name: required(data, "name"),
        owner_user_id: context.subject,
      });
      setRows((current) => [created, ...current]);
      setSelected(created);
      form.reset();
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function goToNextPage() {
    const nextOffset = page?.next_offset;
    if (nextOffset === null || nextOffset === undefined) return;
    const nextHistory = [...offsetHistory.slice(0, pageIndex + 1), nextOffset];
    setOffsetHistory(nextHistory);
    setPageIndex(pageIndex + 1);
    await loadPage(nextOffset);
  }

  async function goToPreviousPage() {
    if (pageIndex === 0) return;
    const previousIndex = pageIndex - 1;
    setPageIndex(previousIndex);
    await loadPage(offsetHistory[previousIndex] ?? 0);
  }

  if (!canRead) {
    return <section className="route-state route-state--error" role="alert" aria-label="Route access denied">
      <strong>Access denied</strong>
      <p>The authenticated session is not permitted to list engagements.</p>
    </section>;
  }

  return (
    <div className="operational-grid">
      <section className="work-panel" aria-labelledby="engagement-list-title" aria-busy={loading}>
        <div className="section-heading">
          <div><span className="eyebrow">Bounded workspaces</span><h2 id="engagement-list-title">Engagements</h2></div>
          <span className="count-chip">{rows.length} on this page</span>
        </div>
        {loading ? <p role="status">Loading engagements</p> : rows.length === 0 ? <Empty text="No engagements yet" /> : (
          <ul className="record-list">
            {rows.map((row) => (
              <li key={row.engagement_id}>
                <button type="button" className="record-select" aria-pressed={selected?.engagement_id === row.engagement_id} onClick={() => { setSelected(row); }}>
                  <strong>{row.name}</strong><span>{row.engagement_id}</span><small>Version {row.version}</small>
                </button>
              </li>
            ))}
          </ul>
        )}
        <div className="pagination-controls" aria-label="Engagement pages">
          <button type="button" disabled={loading || pageIndex === 0} onClick={() => { void goToPreviousPage(); }}>Previous engagements</button>
          <span>Page {pageIndex + 1}</span>
          <button type="button" disabled={loading || page?.next_offset === null || page?.next_offset === undefined} onClick={() => { void goToNextPage(); }}>Next engagements</button>
        </div>
      </section>
      <section className="form-panel" aria-labelledby="create-engagement-title">
        <span className="eyebrow">Onboarding</span><h2 id="create-engagement-title">Create engagement</h2>
        <p>The authenticated subject becomes the immutable initial owner. The binding ID is generated automatically.</p>
        {error && <InlineError message={error} />}
        <form onSubmit={(event) => { void submit(event); }}>
          <label>Engagement name<input name="name" required maxLength={200} /></label>
          <label>Owner<input value={context.subject} readOnly /></label>
          <button type="submit" disabled={!canCreate}>Create engagement</button>
          {!canCreate && <small>Requires engagement:create.</small>}
        </form>
      </section>
      {selected && <EngagementWorkspace key={selected.engagement_id} client={client} context={context} engagement={selected} />}
    </div>
  );
}

function EngagementWorkspace({ client, context, engagement }: {
  readonly client: Client;
  readonly context: Context;
  readonly engagement: Engagement;
}) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [roes, setRoes] = useState<Roe[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([
      hasPermission(context.permissions, "target:read") ? client.listTargets(engagement.engagement_id) : [],
      hasPermission(context.permissions, "roe:read") ? client.listRoeVersions(engagement.engagement_id) : [],
    ]).then(([nextTargets, nextRoes]) => {
      if (active) {
        setTargets(nextTargets);
        setRoes(nextRoes);
      }
    }).catch((cause: unknown) => {
      if (active) setError(projectError(cause));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [client, context.permissions, engagement.engagement_id]);

  async function addTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(null);
    try {
      const created = await client.createTarget(engagement.engagement_id, {
        target_id: createOpaqueId("target"),
        target_type: required(data, "target_type") as typeof CANONICAL_TARGET_TYPES[number],
        normalized_value: required(data, "normalized_value"),
      });
      setTargets((current) => [...current, created]);
      form.reset();
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function addRoe(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const revision = Math.max(0, ...roes.map((roe) => roe.revision)) + 1;
    setError(null);
    try {
      const created = await client.createRoeVersion(engagement.engagement_id, {
        roe_version_id: createOpaqueId("roe"),
        revision,
        document: {
          objective: required(data, "objective"),
          request_budget: Number(required(data, "request_budget")),
          execution_enabled: false,
        },
        policy_reference_id: "console-baseline",
        policy_name: "RedAgent console baseline",
        policy_version: "1",
      });
      setRoes((current) => [...current, created]);
      form.reset();
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function approve(roe: Roe) {
    setError(null);
    try {
      const updated = await client.approveRoeVersion(roe.roe_version_id, roe.version);
      setRoes((current) => current.map((item) => item.roe_version_id === updated.roe_version_id ? updated : item));
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  return (
    <section className="workspace-panel" aria-labelledby="scope-title" aria-busy={loading}>
      <div className="section-heading">
        <div><span className="eyebrow">Selected engagement</span><h2 id="scope-title">{engagement.name}</h2></div>
        <span>{engagement.engagement_id}</span>
      </div>
      {loading && <p role="status">Loading scope controls</p>}
      {error && <InlineError message={error} />}
      <div className="workspace-columns">
        <div>
          <h3>Targets</h3>
          {targets.length === 0 ? <Empty text="No targets defined" /> : <ul className="compact-list">{targets.map((target) => (
            <li key={target.target_id}>
              <strong>{target.normalized_value}</strong>
              {target.target_type === "needs_review"
                ? <span className="state-label">Needs review · unavailable</span>
                : <span>{target.target_type}</span>}
            </li>
          ))}</ul>}
          <form onSubmit={(event) => { void addTarget(event); }}>
            <label>Target type<select name="target_type">{CANONICAL_TARGET_TYPES.map((type) => <option key={type} value={type}>{targetTypeLabel(type)}</option>)}</select></label>
            <label>Normalized target<input name="normalized_value" required maxLength={500} /></label>
            <button type="submit" disabled={!hasPermission(context.permissions, "target:create")}>Add target</button>
          </form>
        </div>
        <div>
          <h3>Rules of engagement</h3>
          {roes.length === 0 ? <Empty text="No ROE versions" /> : <ul className="compact-list">{roes.map((roe) => (
            <li key={roe.roe_version_id}><strong>Revision {roe.revision}</strong><span>{roe.status} · Version {roe.version}</span></li>
          ))}</ul>}
          <form onSubmit={(event) => { void addRoe(event); }}>
            <label>Objective<input name="objective" required maxLength={300} /></label>
            <label>Request budget<input name="request_budget" required type="number" min="1" max="100000" /></label>
            <button type="submit" disabled={!hasPermission(context.permissions, "roe:create")}>Draft ROE</button>
          </form>
          {roes.filter((roe) => roe.status !== "approved").map((roe) => (
            <button key={roe.roe_version_id} type="button" disabled={!hasPermission(context.permissions, "roe:approve")} onClick={() => { void approve(roe); }}>Approve revision {roe.revision}</button>
          ))}
        </div>
      </div>
    </section>
  );
}

function hasPermission(permissions: readonly string[], permission: string): boolean {
  // SECURITY: the authenticated wildcard is server-issued authority and must match every focused route guard.
  return permissions.includes("*") || permissions.includes(permission);
}

function createOpaqueId(prefix: string): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}-${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function required(data: FormData, name: string): string {
  const entry = data.get(name);
  if (typeof entry !== "string") throw new Error(`${name} is required`);
  const value = entry.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function targetTypeLabel(value: typeof CANONICAL_TARGET_TYPES[number]): string {
  return value === "ip" ? "IP address" : value === "cidr" ? "CIDR" : value[0]!.toUpperCase() + value.slice(1);
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) {
    return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message;
  }
  return cause instanceof Error ? cause.message : "The operation could not be completed.";
}

function Empty({ text }: { readonly text: string }) {
  return <p className="empty-inline">{text}</p>;
}

function InlineError({ message }: { readonly message: string }) {
  return <p className="inline-error" role="alert">{message}</p>;
}
