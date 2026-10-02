import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  ConsoleApiError,
  createConsoleClient,
  type CampaignOperations,
  type R124CampaignMutation,
  type R124CampaignOption,
  type R124CampaignOptionPage,
  type R124CampaignSummaryPage,
  type R124AttentionPage,
  type R124CampaignStart,
} from "../../lib/apiClient";


export type CampaignCoreClient = Pick<ReturnType<typeof createConsoleClient>,
  | "listCampaignCoreEngagementOptions"
  | "listCampaignCoreTargetOptions"
  | "listCampaignCoreRiskOptions"
  | "startCampaignCore"
  | "getCampaignCoreCampaign"
  | "recoverCampaignCore"
>;

export type CampaignReadClient = Pick<ReturnType<typeof createConsoleClient>,
  | "listCampaignCoreCampaigns"
  | "getCampaignCoreCampaign"
  | "getCampaignOperations"
  | "listCampaignCoreAttention"
  | "recoverCampaignCore"
>;

type Props = {
  client?: CampaignCoreClient;
  onActivation?: (event: "engagement" | "target" | "objective" | "risk" | "start") => void;
  createEnabled?: boolean;
};

const OBJECTIVES = [
  "Assess HTTP security posture",
  "Verify X-Content-Type-Options",
  "Assess repository snapshot posture",
] as const;

// IMPORTANT: keep the default client stable across renders or effects refetch forever.
const defaultCampaignClient = createConsoleClient();

export function CampaignCoreFeature({
  client = defaultCampaignClient,
  onActivation,
  createEnabled = true,
}: Props) {
  const [engagements, setEngagements] = useState<R124CampaignOptionPage | null>(null);
  const [targets, setTargets] = useState<R124CampaignOptionPage | null>(null);
  const [risks, setRisks] = useState<R124CampaignOptionPage | null>(null);
  const [engagement, setEngagement] = useState("");
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("");
  const [risk, setRisk] = useState("");
  const [campaign, setCampaign] = useState<Record<string, unknown> | null>(null);
  const [mutation, setMutation] = useState<R124CampaignMutation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const startIdempotencyKey = useRef<string | null>(null);

  useEffect(() => {
    if (!createEnabled) return;
    let active = true;
    client.listCampaignCoreEngagementOptions()
      .then((page) => { if (active) setEngagements(page); })
      .catch((cause: unknown) => { if (active) setError(projectError(cause)); });
    return () => { active = false; };
  }, [client, createEnabled]);

  const denied = useMemo(
    () => engagements?.data.filter(({ eligible }) => !eligible) ?? [],
    [engagements],
  );
  const ready = Boolean(engagement && target && objective && risk && !busy);

  if (!createEnabled) {
    return <section className="work-panel campaign-core" aria-labelledby="campaign-core-disabled-title">
      <span className="eyebrow">Safe rollback state</span>
      <h2 id="campaign-core-disabled-title">Campaign creation is disabled</h2>
      <p>Normal campaign entry is hidden. Status, attention, emergency stop, revoke, evidence, and audit recovery remain available.</p>
    </section>;
  }

  async function selectEngagement(binding: string) {
    onActivation?.("engagement");
    setEngagement(binding);
    setTarget("");
    setRisk("");
    setTargets(null);
    setRisks(null);
    setError(null);
    startIdempotencyKey.current = null;
    if (!binding) return;
    try {
      setTargets(await client.listCampaignCoreTargetOptions(binding));
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function selectTarget(binding: string) {
    onActivation?.("target");
    setTarget(binding);
    setRisk("");
    setRisks(null);
    setError(null);
    startIdempotencyKey.current = null;
    if (!binding || !engagement) return;
    try {
      setRisks(await client.listCampaignCoreRiskOptions(engagement, binding));
    } catch (cause) {
      setError(projectError(cause));
    }
  }

  async function start(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    onActivation?.("start");
    setBusy(true);
    setError(null);
    try {
      const payload: R124CampaignStart = {
        engagement_binding: engagement,
        target_binding: target,
        objective,
        risk_profile: risk,
      };
      startIdempotencyKey.current ??= campaignStartKey();
      const started = await client.startCampaignCore(payload, startIdempotencyKey.current);
      setMutation(started);
      setCampaign(await client.getCampaignCoreCampaign(started.campaign_id));
    } catch (cause) {
      setError(projectError(cause));
    } finally {
      setBusy(false);
    }
  }

  async function recover(action: "stop" | "revoke") {
    if (!mutation) return;
    const etag = typeof campaign?.etag === "string" ? campaign.etag : mutation.etag;
    setBusy(true);
    setError(null);
    try {
      const updated = await client.recoverCampaignCore(
        action,
        mutation.campaign_id,
        etag,
        action === "stop"
          ? "Operator requested campaign containment from the compat_124 core."
          : "Operator revoked campaign authority from the compat_124 core.",
      );
      setMutation(updated);
      setCampaign(await client.getCampaignCoreCampaign(updated.campaign_id));
    } catch (cause) {
      setError(projectError(cause));
    } finally {
      setBusy(false);
    }
  }

  if (campaign || mutation) {
    const recovery = record(campaign?.recovery);
    const authority = record(campaign?.authority);
    const effects = Array.isArray(campaign?.effects) ? campaign.effects : [];
    const findings = Array.isArray(campaign?.findings) ? campaign.findings : [];
    return <section className="work-panel campaign-core" aria-labelledby="campaign-core-status-title">
      <span className="eyebrow">Unified objective-to-retest core</span>
      <h2 id="campaign-core-status-title">{text(campaign?.label) ?? "Campaign start was accepted"}</h2>
      <p role="status">{text(campaign?.status) ?? mutation?.status}</p>
      <dl className="record-grid">
        <div><dt>Authority</dt><dd>{human(text(authority.state) ?? "unavailable")}</dd></div>
        <div><dt>Execution effects</dt><dd>{effects.length}</dd></div>
        <div><dt>Findings / retests</dt><dd>{findings.length}</dd></div>
        <div><dt>Cleanup</dt><dd>{campaign ? (recovery.cleanup_required === true ? "Required" : "No missing receipt observed") : "Refresh pending"}</dd></div>
      </dl>
      <p>{text(recovery.guidance) ?? "Review current evidence and recovery state."}</p>
      {error && <p className="inline-error" role="alert">{error}</p>}
      <div className="button-row">
        {(!campaign || recovery.stop_visible !== false) && <button className="danger-action" disabled={busy} onClick={() => void recover("stop")}>Request containment</button>}
        {(!campaign || recovery.revoke_visible !== false) && <button disabled={busy} onClick={() => void recover("revoke")}>Revoke future authority</button>}
      </div>
    </section>;
  }

  return <section className="work-panel campaign-core" aria-labelledby="campaign-core-title">
    <span className="eyebrow">Unified objective-to-retest core</span>
    <h2 id="campaign-core-title">Start an authorized campaign</h2>
    <p>Selections are resolved against current authority. Internal identifiers and transport idempotency are never operator input.</p>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {!engagements && !error && <p role="status">Loading authorized engagements…</p>}
    <form onSubmit={(event) => void start(event)}>
      <label>Authorized engagement
        <select value={engagement} onChange={(event) => void selectEngagement(event.target.value)} disabled={!engagements || busy}>
          <option value="">Select engagement</option>
          {eligible(engagements?.data).map((option) => <option key={option.binding} value={option.binding}>{option.label}</option>)}
        </select>
      </label>
      <label>Authorized target
        <select value={target} onChange={(event) => void selectTarget(event.target.value)} disabled={!engagement || !targets || busy}>
          <option value="">Select target</option>
          {eligible(targets?.data).map((option) => <option key={option.binding} value={option.binding}>{option.label}</option>)}
        </select>
      </label>
      <label>Objective
        <select value={objective} onChange={(event) => { onActivation?.("objective"); startIdempotencyKey.current = null; setObjective(event.target.value); }} disabled={!target || busy}>
          <option value="">Select objective</option>
          {OBJECTIVES.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      <label>Risk profile
        <select value={risk} onChange={(event) => { onActivation?.("risk"); startIdempotencyKey.current = null; setRisk(event.target.value); }} disabled={!objective || !risks || busy}>
          <option value="">Select risk profile</option>
          {eligible(risks?.data).map((option) => <option key={option.binding} value={option.binding}>{option.label}</option>)}
        </select>
      </label>
      <button type="submit" disabled={!ready}>{busy ? "Starting…" : "Start authorized campaign"}</button>
    </form>
    {denied.length > 0 && <aside aria-label="Unavailable authorized resources">
      <h3>Unavailable</h3>
      <ul>{denied.map((option) => <li key={option.binding}>{option.label}: {human(option.unavailable_reason ?? "unavailable")}</li>)}</ul>
      <p>Refresh current authority or ask the engagement owner to resolve the displayed reason.</p>
    </aside>}
  </section>;
}

export function CampaignStatusFeature({
  client = defaultCampaignClient,
}: { client?: CampaignReadClient }) {
  const [page, setPage] = useState<R124CampaignSummaryPage | null>(null);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [operations, setOperations] = useState<CampaignOperations | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingAction, setPendingAction] = useState<"stop" | "revoke" | null>(null);
  const selectedCampaignBinding = useRef<string | null>(null);
  const recoveryTrigger = useRef<HTMLButtonElement | null>(null);
  const confirmationButton = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    let active = true;
    client.listCampaignCoreCampaigns()
      .then((value) => { if (active) setPage(value); })
      .catch((cause: unknown) => { if (active) setError(projectError(cause)); });
    return () => { active = false; };
  }, [client]);

  useEffect(() => {
    if (pendingAction) confirmationButton.current?.focus();
  }, [pendingAction]);

  function recover(action: "stop" | "revoke") {
    const campaignId = text(selected?.campaign_id);
    const etag = text(selected?.etag);
    if (!campaignId || !etag) {
      setError("Current campaign recovery metadata is unavailable.");
      return;
    }
    setBusy(true);
    setError(null);
    void client.recoverCampaignCore(
      action,
      campaignId,
      etag,
      action === "stop"
        ? "Operator requested campaign containment from persistent status."
        : "Operator revoked campaign authority from persistent status.",
    ).then((updated) => Promise.all([
      client.getCampaignCoreCampaign(updated.campaign_id),
      client.getCampaignOperations(updated.campaign_id),
    ]))
      .then(([value, currentOperations]) => {
        if (selectedCampaignBinding.current !== campaignId) return;
        setSelected(value);
        setOperations((prior) => prior && prior.aggregate_version > currentOperations.aggregate_version
          ? prior : currentOperations);
      })
      .catch((cause: unknown) => {
        if (selectedCampaignBinding.current === campaignId) setError(projectError(cause));
      })
      .finally(() => {
        setBusy(false);
        // IMPORTANT: defer focus until React commits busy=false; disabled controls cannot receive focus.
        if (selectedCampaignBinding.current === campaignId) {
          globalThis.setTimeout(() => recoveryTrigger.current?.focus(), 0);
        }
      });
  }

  return <section className="work-panel campaign-core" aria-labelledby="campaign-status-list-title">
    <span className="eyebrow">Unified objective-to-retest core</span>
    <h2 id="campaign-status-list-title">Campaign status</h2>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {!page && !error && <p role="status">Loading campaign status…</p>}
    {page?.data.length === 0 && <p>No campaigns are available in the current authorized tenant.</p>}
    {page && page.data.length > 0 && <ul className="record-list">{page.data.map((campaign) =>
      <li key={campaign.campaign_id}>
        <strong>{campaign.label}</strong>
        <span>{human(campaign.status)} · {human(campaign.authority_state)}</span>
        {campaign.attention_reason && <span>{human(campaign.attention_reason)}</span>}
        <button type="button" onClick={() => {
          selectedCampaignBinding.current = campaign.campaign_id;
          setSelected(null);
          setOperations(null);
          setError(null);
          void Promise.all([
            client.getCampaignCoreCampaign(campaign.campaign_id),
            client.getCampaignOperations(campaign.campaign_id),
          ])
            .then(([value, currentOperations]) => {
              // CRITICAL: aggregate versions are campaign-local; never retain or apply a response
              // after the operator selected a different campaign or cross-campaign truth is mixed.
              if (selectedCampaignBinding.current !== campaign.campaign_id) return;
              setSelected(value);
              setOperations(currentOperations);
            })
            .catch((cause: unknown) => {
              if (selectedCampaignBinding.current === campaign.campaign_id) setError(projectError(cause));
            });
        }}>View current status</button>
      </li>)}</ul>}
    {selected && <CampaignTruthSummary
      campaign={selected}
      busy={busy}
      futureAuthorityRevoked={operations?.authority.state === "revoked"}
      onRecover={(action, trigger) => {
        recoveryTrigger.current = trigger;
        setPendingAction(action);
      }}
    />}
    {pendingAction && <div className="campaign-recovery-dialog" role="dialog" aria-labelledby="campaign-recovery-dialog-title">
      <h3 id="campaign-recovery-dialog-title">
        {pendingAction === "stop" ? "Confirm containment request" : "Confirm future-authority revocation"}
      </h3>
      <p>{pendingAction === "stop"
        ? "This requests server-owned containment. It does not claim that active effects are already contained."
        : "This revokes future campaign authority. Existing effects still require server-owned reconciliation and cleanup."}</p>
      <div className="button-row">
        <button ref={confirmationButton} className="danger-action" onClick={() => {
          const action = pendingAction;
          setPendingAction(null);
          recover(action);
        }}>{pendingAction === "stop" ? "Confirm containment request" : "Confirm future-authority revocation"}</button>
        <button onClick={() => {
          setPendingAction(null);
          globalThis.setTimeout(() => recoveryTrigger.current?.focus(), 0);
        }}>Cancel</button>
      </div>
    </div>}
    {selected && operations && <CampaignOperationsWorkspace operations={operations} />}
  </section>;
}

export function CampaignAttentionFeature({
  client = defaultCampaignClient,
}: { client?: CampaignReadClient }) {
  const [page, setPage] = useState<R124AttentionPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    client.listCampaignCoreAttention()
      .then((value) => { if (active) setPage(value); })
      .catch((cause: unknown) => { if (active) setError(projectError(cause)); });
    return () => { active = false; };
  }, [client]);

  return <section className="work-panel campaign-core" aria-labelledby="campaign-attention-title">
    <span className="eyebrow">Tenant-filtered operator attention</span>
    <h2 id="campaign-attention-title">Campaign attention queue</h2>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {!page && !error && <p role="status">Loading attention items…</p>}
    {page?.data.length === 0 && <p>No campaign exceptions currently require operator attention.</p>}
    {page && page.data.length > 0 && <ul className="record-list">{page.data.map((item) =>
      <li key={item.binding}>
        <strong>{item.campaign_label}</strong>
        <span>{human(item.category)}: {human(item.reason)}</span>
        <p>{item.next_safe_action}</p>
      </li>)}</ul>}
  </section>;
}

function CampaignTruthSummary({
  campaign,
  busy,
  futureAuthorityRevoked,
  onRecover,
}: {
  campaign: Record<string, unknown>;
  busy: boolean;
  futureAuthorityRevoked: boolean;
  onRecover: (action: "stop" | "revoke", trigger: HTMLButtonElement) => void;
}) {
  const authority = record(campaign.authority);
  const context = record(campaign.context);
  const decision = record(campaign.decision);
  const plan = record(campaign.plan);
  const recovery = record(campaign.recovery);
  const effects = Array.isArray(campaign.effects) ? campaign.effects : [];
  const findings = Array.isArray(campaign.findings) ? campaign.findings : [];
  return <aside aria-label="Selected campaign truth">
    <h3>{text(campaign.label) ?? "Selected campaign"}</h3>
    <p role="status">{human(text(campaign.status) ?? "unavailable")}</p>
    <dl className="record-grid">
      <div><dt>Authority</dt><dd>{human(text(authority.state) ?? "unavailable")}</dd></div>
      <div><dt>Snapshot</dt><dd>{text(context.freshness) ?? "Unavailable"}</dd></div>
      <div><dt>Decision</dt><dd>{human(text(decision.outcome) ?? "unavailable")}</dd></div>
      <div><dt>Primary plan</dt><dd>{text(plan.primary) ?? "Unavailable"}</dd></div>
      <div><dt>Execution effects</dt><dd>{effects.length}</dd></div>
      <div><dt>Findings / retests</dt><dd>{findings.length}</dd></div>
      <div><dt>Cleanup</dt><dd>{recovery.cleanup_required === true ? "Required" : "No missing receipt observed"}</dd></div>
    </dl>
    <p>{text(recovery.guidance) ?? "Review current evidence and governed recovery state."}</p>
    <div className="button-row">
      {recovery.stop_visible !== false && <button className="danger-action" disabled={busy} onClick={(event) => onRecover("stop", event.currentTarget)}>Request containment</button>}
      {recovery.revoke_visible !== false && !futureAuthorityRevoked && <button disabled={busy} onClick={(event) => onRecover("revoke", event.currentTarget)}>Revoke future authority</button>}
    </div>
  </aside>;
}


function CampaignOperationsWorkspace({ operations }: { operations: CampaignOperations }) {
  const budgetDimensions = Object.entries(operations.budget.dimensions);
  return <section className="campaign-operations" aria-labelledby="campaign-operations-title">
    <header className="campaign-operations__header">
      <div>
        <span className="eyebrow">Server-owned operational truth</span>
        <h3 id="campaign-operations-title">Autonomous campaign operations</h3>
      </div>
      <span className={`status-chip status-chip--${statusTone(operations.preparation_state)}`}>
        {human(operations.preparation_state)}
      </span>
    </header>

    <div className="campaign-operations__summary" aria-label="Authority validation and admission status">
      <article>
        <span>Approval binding</span>
        <strong>{title(operations.authority.state)}</strong>
        <small>{operations.authority.expires_at ? `Expires ${formatTime(operations.authority.expires_at)}` : "No retained expiry is available"}</small>
      </article>
      <article>
        <span>Independent validation</span>
        <strong>{title(operations.validation.result)}</strong>
        <small>{operations.validation.reason ? human(operations.validation.reason) : "No validator exception reported"}</small>
      </article>
      <article>
        <span>Admission</span>
        <strong>{title(operations.admission.outcome)}</strong>
        <small>{operations.admission.reason ? human(operations.admission.reason) : "No admission receipt is available"}</small>
      </article>
      <article>
        <span>Execution</span>
        <strong>{title(operations.execution.state)}</strong>
        {/* IMPORTANT: state alone hides whether recovery must reconcile the start, cleanup, or evidence. */}
        {operations.execution.terminal_reason && <small>{human(operations.execution.terminal_reason)}</small>}
        <small>{operations.execution.transition_count} of {operations.execution.max_transitions} bounded transitions</small>
      </article>
    </div>

    <details className="campaign-operations__binding">
      <summary>Exact authority binding</summary>
      <dl className="record-grid">
        <div><dt>Signed authority SHA-256</dt><dd><code>{operations.authority.signed_authority_sha256 ?? "Unavailable"}</code></dd></div>
        <div><dt>Authority SHA-256</dt><dd><code>{operations.authority.authority_sha256 ?? "Unavailable"}</code></dd></div>
        <div><dt>Admission receipt SHA-256</dt><dd><code>{operations.admission.receipt_sha256 ?? "Unavailable"}</code></dd></div>
        <div><dt>Lifecycle epoch</dt><dd>{operations.authority.lifecycle_epoch ?? "Unavailable"}</dd></div>
        <div><dt>Policy revocation epoch</dt><dd>{operations.authority.policy_revocation_epoch ?? "Unavailable"}</dd></div>
        <div><dt>Rules-of-engagement epoch</dt><dd>{operations.authority.roe_revocation_epoch ?? "Unavailable"}</dd></div>
        <div><dt>Kill-switch epoch</dt><dd>{operations.authority.kill_switch_epoch ?? "Unavailable"}</dd></div>
      </dl>
    </details>

    {operations.validation.counterexample_codes.length > 0 && <aside className="campaign-operations__denial" aria-label="Validator counterexamples">
      <strong>Preparation was denied by bounded validation</strong>
      <ul>{operations.validation.counterexample_codes.map((code) => <li key={code}>{title(code.replaceAll("-", "_"))}</li>)}</ul>
    </aside>}

    <div className="campaign-operations__grid">
      <article className="campaign-operations__panel campaign-operations__plan">
        <div className="campaign-operations__panel-heading">
          <div><span className="eyebrow">Plan and live frontier</span><h4>{operations.plan.revision_label}</h4></div>
          <span>{operations.plan.nodes.length} steps</span>
        </div>
        {operations.plan.nodes.length === 0
          ? <p>No accepted planner revision is available for this campaign.</p>
          : <ol className="campaign-plan-list" aria-label="Plan ordered steps">
            {operations.plan.nodes.map((node) => <li key={`${node.order}-${node.label}`}>
              <span className="campaign-plan-list__index" aria-hidden="true">{node.order + 1}</span>
              <div><strong>{node.label}</strong><span>{node.capability}</span></div>
              <span className={`status-chip status-chip--${statusTone(node.state)}`}>{human(node.state)}</span>
            </li>)}
          </ol>}
        {operations.plan.edges.length > 0 && <ul className="campaign-plan-edges" aria-label="Plan relationships">
          {operations.plan.edges.map((edge) => <li key={`${edge.source}-${edge.target}`}>{edge.source} → {edge.target}</li>)}
        </ul>}
        {Object.keys(operations.execution.frontier).length > 0 && <p className="campaign-operations__note">
          Frontier: {Object.entries(operations.execution.frontier).map(([state, count]) => `${count} ${human(state)}`).join(" · ")}
        </p>}
      </article>

      <article className="campaign-operations__panel">
        <div className="campaign-operations__panel-heading"><div><span className="eyebrow">Residual authority</span><h4>Budget</h4></div></div>
        {budgetDimensions.length === 0 || operations.budget.state === "unavailable"
          ? <p>No admitted campaign budget is available.</p>
          : <ul className="campaign-budget-list">{budgetDimensions.map(([name, dimension]) => <li key={name}>
            <strong>{human(name)}</strong>
            <span>{dimension.residual ?? 0} of {dimension.authorized ?? 0} {dimension.unit} remaining</span>
          </li>)}</ul>}
      </article>

      <article className="campaign-operations__panel">
        <div className="campaign-operations__panel-heading"><div><span className="eyebrow">Trusted only</span><h4>Observations</h4></div></div>
        {operations.observations.length === 0 ? <p>No trusted observation has been promoted.</p> : <ul className="campaign-detail-list">
          {operations.observations.map((observation, index) => <li key={`${observation.observation_sha256 ?? "observation"}-${index}`}>
            <strong>{observation.fact}</strong><span>{human(observation.producer_kind)} · {title(observation.freshness)}</span>
            <details><summary>Evidence provenance</summary>
              <dl><dt>Observation SHA-256</dt><dd>{observation.observation_sha256 ?? "Unavailable"}</dd>
                <dt>Provenance SHA-256</dt><dd>{observation.provenance_sha256 ?? "Unavailable"}</dd></dl>
            </details>
          </li>)}
        </ul>}
      </article>

      <article className="campaign-operations__panel">
        <div className="campaign-operations__panel-heading"><div><span className="eyebrow">Bounded lineage</span><h4>Revision differences</h4></div></div>
        {operations.revisions.length > 0 && <p className="campaign-operations__note">
          Each child proposal needs a new exact approval and admission before execution.
        </p>}
        {operations.revisions.length === 0 ? <p>No bounded replan proposal is available.</p> : <ul className="campaign-detail-list">
          {operations.revisions.map((revision) => <li key={`${revision.label}-${revision.proposal_sha256 ?? "unavailable"}`}>
            <strong>{revision.label} · {human(revision.state)}</strong>
            <span>{revision.invalidated_count} invalidated · {revision.retained_count} retained · {revision.substitution_count} substitution</span>
          </li>)}
        </ul>}
      </article>

      <article className="campaign-operations__panel">
        <div className="campaign-operations__panel-heading"><div><span className="eyebrow">Allowlisted lineage</span><h4>Audit</h4></div></div>
        {operations.audit.length === 0 ? <p>No campaign operations audit event is available.</p> : <ol className="campaign-detail-list">
          {operations.audit.map((event, index) => <li key={`${event.details_sha256}-${index}`}>
            <strong>{human(event.action)}</strong><span>{event.occurred_at ? formatTime(event.occurred_at) : "Time unavailable"}</span>
          </li>)}
        </ol>}
      </article>

      <article className="campaign-operations__panel">
        <div className="campaign-operations__panel-heading"><div><span className="eyebrow">Evidence boundary</span><h4>Cleanup and export</h4></div></div>
        <dl className="record-grid">
          <div><dt>Effect receipts</dt><dd>{operations.evidence.effect_count}</dd></div>
          <div><dt>Evidence records</dt><dd>{operations.evidence.evidence_count}</dd></div>
          <div><dt>Cleanup</dt><dd>{human(operations.evidence.cleanup_state)}</dd></div>
          <div><dt>Terminal receipt</dt><dd>{operations.evidence.terminal_receipt_present ? "Present" : "Not present"}</dd></div>
        </dl>
        <p className="campaign-operations__note">A verified retained bundle is not available. Export remains disabled until the server verifies the bundle and independent trust anchor.</p>
      </article>
    </div>
  </section>;
}

function campaignStartKey(): string {
  return globalThis.crypto.randomUUID();
}

function eligible(options: R124CampaignOption[] | undefined): R124CampaignOption[] {
  return options?.filter(({ eligible: available }) => available) ?? [];
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function human(value: string): string {
  return value.replaceAll("_", " ");
}


function title(value: string): string {
  const normalized = human(value);
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}


function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}


function statusTone(value: string): "good" | "warn" | "bad" | "neutral" {
  if (["admitted", "valid", "running", "confirmed", "complete", "terminal"].includes(value)) return "good";
  if (["denied", "failed", "expired", "revoked"].includes(value)) return "bad";
  if (["unavailable", "not_prepared", "manual_review_required", "reconciliation_required", "stopping"].includes(value)) return "warn";
  return "neutral";
}

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) {
    return `${cause.message}${cause.correlationId ? ` Correlation: ${cause.correlationId}` : ""}`;
  }
  return "The campaign operation could not be completed. Refresh current authority and retry safely.";
}
