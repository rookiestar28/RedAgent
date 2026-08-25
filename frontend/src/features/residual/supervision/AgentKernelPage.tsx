import { useEffect, useState } from "react";

import type { components } from "../../../generated/api";
import { ConsoleApiError, createConsoleClient } from "../../../lib/apiClient";

type Client = ReturnType<typeof createConsoleClient>;
type Context = components["schemas"]["ContextData"];
type Dashboard = components["schemas"]["AgentDashboardData"];
type Tool = components["schemas"]["AgentToolData"];

export function AgentKernelPage({ client, context }: { readonly client: Client; readonly context: Context }) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [routeError, setRouteError] = useState<ConsoleApiError | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [observedAt, setObservedAt] = useState(0);
  const canRead = hasPermission(context, "job:read") && hasPermission(context, "audit:read");
  const canApprove = hasPermission(context, "job:create");
  const canCancel = hasPermission(context, "job:stop");

  useEffect(() => {
    let active = true;
    if (!canRead) return () => { active = false; };
    void Promise.all([client.listAgentTools(), client.getAgentDashboard()])
      .then(([nextTools, nextDashboard]) => {
        if (!active) return;
        setTools(nextTools); setDashboard(nextDashboard); setObservedAt(Date.now());
      })
      .catch((cause: unknown) => { if (active) setRouteError(asConsoleError(cause)); });
    return () => { active = false; };
  }, [canRead, client, reloadToken]);

  if (!canRead) return <RouteError denied />;
  if (routeError) return <RouteError denied={isAccessDenied(routeError)} correlationId={routeError.correlationId}
    retry={() => { setRouteError(null); setReloadToken((value) => value + 1); }} />;
  if (!dashboard) return <section className="route-state" role="status" aria-label="Loading supervised agent state"><strong>Loading supervised agent state</strong><p>Verifying stored proposal, budget, approval, and cancellation truth.</p></section>;

  async function approve(proposal: Dashboard["proposals"][number]) {
    if (!canApprove || proposal.proposal_state !== "awaiting_approval"
      || new Date(proposal.expires_at).getTime() <= observedAt
      || !window.confirm(`Approve only proposal ${proposal.proposal_sha256}?`)) return;
    setBusy(proposal.proposal_id); setActionError(null); setNotice(null);
    try {
      const updated = await client.approveAgentProposal(
        proposal.proposal_id, `approval-${crypto.randomUUID()}`, proposal.proposal_sha256,
      );
      setDashboard((current) => current ? { ...current,
        proposals: current.proposals.map((item) => item.proposal_id === updated.proposal_id ? updated : item),
      } : current);
      setNotice(`Exact proposal hash approved for ${updated.proposal_id}; no tool was dispatched.`);
    } catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  async function cancel(run: Dashboard["runs"][number]) {
    if (!canCancel || run.cancel_requested
      || !window.confirm(`Cancel run ${run.run_id} and block further progression?`)) return;
    setBusy(run.run_id); setActionError(null); setNotice(null);
    try {
      const updated = await client.cancelAgentRun(run.run_id, run.version, "operator_cancelled_from_agent_console");
      setDashboard((current) => current ? { ...current,
        runs: current.runs.map((item) => item.run_id === updated.run_id ? updated : item),
      } : current);
      setNotice(`Further progression blocked for ${updated.run_id}.`);
    } catch (cause) { setActionError(projectError(cause)); } finally { setBusy(null); }
  }

  return <div className="operational-page agent-kernel-page">
    <section className="work-panel" aria-labelledby="agent-kernel-title"><div className="section-heading"><div><span className="eyebrow">R113 · supervised control plane</span><h2 id="agent-kernel-title">Supervised agent proposal kernel</h2></div><span className="environment-chip">Deterministic fake only</span></div>{actionError && <p className="inline-error" role="alert">{actionError}</p>}{notice && <p className="operation-notice" role="status">{notice}</p>}<p className="safety-boundary">External provider contact, hosted tools, direct dispatch, raw reasoning, and sensitive retention remain disabled.</p><p><strong>Reviewer:</strong> {context.subject} · proposals are bound to stored plans, policy, ROE, target digest, and exact hash.</p></section>
    <section className="work-panel" aria-labelledby="agent-runs-title"><h2 id="agent-runs-title">Runs and stop control</h2>{dashboard.runs.length === 0 ? <p className="empty-state">No agent runs have been proposed.</p> : dashboard.runs.map((run) => <article className="lifecycle-state" key={run.run_id}><strong>{run.run_id}</strong><p>{run.provider_id} · {run.run_state}</p><p>Registry digest: <code>{run.registry_sha256}</code></p><span className="state-label">{run.cancel_requested ? "Cancel requested · progression blocked" : run.failure_code ? `Failed · ${run.failure_code}` : "Supervised progression only"}</span><button type="button" disabled={!canCancel || busy === run.run_id || run.cancel_requested} onClick={() => { void cancel(run); }}>Cancel and block progression</button></article>)}</section>
    <section className="work-panel" aria-labelledby="agent-proposals-title"><h2 id="agent-proposals-title">Exact proposals awaiting independent review</h2>{dashboard.proposals.length === 0 ? <p className="empty-state">No stored proposals require review.</p> : dashboard.proposals.map((proposal) => <article className="lifecycle-state lifecycle-state--approval" key={proposal.proposal_id}><strong>{proposal.tool_fqn}</strong><p>{proposal.side_effect_classes.join(", ")} · {proposal.proposal_state}</p><p>Proposal digest: <code>{proposal.proposal_sha256}</code></p><p>Argument digest: <code>{proposal.argument_sha256}</code> · Target digest: <code>{proposal.target_sha256}</code></p><p>ROE {proposal.roe_version_id} · policy {proposal.policy_revision} / {proposal.policy_decision_id}</p><span className="state-label">{proposal.proposal_state === "approved" ? "Exact proposal approved" : proposal.proposal_state === "awaiting_approval" ? "Awaiting independent approval" : proposal.proposal_state}</span>{proposal.proposal_state === "awaiting_approval" && <button type="button" disabled={!canApprove || busy === proposal.proposal_id || new Date(proposal.expires_at).getTime() <= observedAt} onClick={() => { void approve(proposal); }}>Approve exact proposal hash</button>}</article>)}</section>
    <section className="work-panel"><h2 id="agent-budget-title">Aggregate budget truth</h2>{dashboard.budgets.length === 0 ? <p className="empty-state">No budget ledger recorded.</p> : dashboard.budgets.map((budget) => <p key={budget.ledger_id}><span className="state-label">{budget.ledger_state === "exceeded" ? "Budget denied" : budget.ledger_state}</span> · {budget.turn_count} turns · {budget.tool_call_count} tool calls · {budget.cost_microunits} µunits · {budget.result_bytes} bytes</p>)}</section>
    <section className="work-panel" aria-labelledby="agent-tools-title"><h2 id="agent-tools-title">Projected tool provenance</h2>{tools.length === 0 ? <p className="empty-state">No certified proposal-only tool is eligible.</p> : tools.map((tool) => <article key={tool.tool_fqn}><strong>{tool.tool_fqn}</strong><p>{tool.capability_id} rev {tool.capability_revision} · approval {tool.approval_tier} · network {tool.network_class}</p><p>Capability digest: <code>{tool.capability_sha256}</code></p><p>Unsupported: {tool.unsupported_features.join(", ")}</p><span className="state-label">{toolEligible(tool) ? "Certified proposal-only tool" : "Tool ineligible"}</span></article>)}</section>
    <section className="work-panel" aria-labelledby="agent-traces-title"><h2 id="agent-traces-title">Digest-only trace evidence</h2>{dashboard.traces.length === 0 ? <p className="empty-state">No trace envelope recorded.</p> : dashboard.traces.map((trace) => <p key={`${trace.trace_id}:${trace.span_id}`}><strong>{trace.event_type}</strong> · {trace.trace_state} · input <code>{trace.input_sha256}</code> · output <code>{trace.output_sha256}</code></p>)}</section>
  </div>;
}

function RouteError({ denied, correlationId, retry }: { readonly denied: boolean; readonly correlationId?: string | null; readonly retry?: () => void }) { return <section className="route-state route-state--error" role="alert" aria-label={denied ? "Route access denied" : "Agent kernel unavailable"}><strong>{denied ? "Access denied" : "Agent kernel unavailable"}</strong><p>{denied ? "The authenticated session is not permitted to review supervised agent state." : "Stored proposal, budget, and tool provenance could not be loaded; no approval or execution state was inferred."}</p>{correlationId && <p className="correlation">Correlation: {correlationId}</p>}{retry && <button type="button" onClick={retry}>Retry route data</button>}</section>; }
function hasPermission(context: Context, permission: string): boolean { return context.permissions.includes("*") || context.permissions.includes(permission); }
function toolEligible(tool: Tool): boolean { return tool.network_class === "none" && tool.access_class === "none" && tool.max_tool_calls <= 1 && tool.unsupported_features.includes("arbitrary_command"); }
function asConsoleError(cause: unknown): ConsoleApiError { return cause instanceof ConsoleApiError ? cause : new ConsoleApiError("agent_kernel_unavailable", "Agent kernel unavailable", 0, null); }
function isAccessDenied(error: ConsoleApiError): boolean { return error.status === 401 || error.status === 403 || error.code.includes("permission") || error.code.includes("tenant") || error.code.includes("csrf"); }
function projectError(cause: unknown): string { if (cause instanceof ConsoleApiError) return cause.correlationId ? `${cause.message} · Correlation ${cause.correlationId}` : cause.message; return cause instanceof Error ? cause.message : "The supervised agent action could not be completed."; }
