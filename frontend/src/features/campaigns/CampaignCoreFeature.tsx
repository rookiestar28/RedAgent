import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  ConsoleApiError,
  createConsoleClient,
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
        {(!campaign || recovery.stop_visible !== false) && <button className="danger-action" disabled={busy} onClick={() => void recover("stop")}>Stop &amp; revoke</button>}
        {(!campaign || recovery.revoke_visible !== false) && <button disabled={busy} onClick={() => void recover("revoke")}>Revoke authority</button>}
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
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    client.listCampaignCoreCampaigns()
      .then((value) => { if (active) setPage(value); })
      .catch((cause: unknown) => { if (active) setError(projectError(cause)); });
    return () => { active = false; };
  }, [client]);

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
          setError(null);
          void client.getCampaignCoreCampaign(campaign.campaign_id)
            .then((value) => setSelected(value))
            .catch((cause: unknown) => setError(projectError(cause)));
        }}>View current status</button>
      </li>)}</ul>}
    {selected && <CampaignTruthSummary
      campaign={selected}
      busy={busy}
      onRecover={(action) => {
        const campaignId = text(selected.campaign_id);
        const etag = text(selected.etag);
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
        ).then((updated) => client.getCampaignCoreCampaign(updated.campaign_id))
          .then((value) => setSelected(value))
          .catch((cause: unknown) => setError(projectError(cause)))
          .finally(() => setBusy(false));
      }}
    />}
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
  onRecover,
}: {
  campaign: Record<string, unknown>;
  busy: boolean;
  onRecover: (action: "stop" | "revoke") => void;
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
      {recovery.stop_visible !== false && <button className="danger-action" disabled={busy} onClick={() => onRecover("stop")}>Stop &amp; revoke</button>}
      {recovery.revoke_visible !== false && <button disabled={busy} onClick={() => onRecover("revoke")}>Revoke authority</button>}
    </div>
  </aside>;
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

function projectError(cause: unknown): string {
  if (cause instanceof ConsoleApiError) {
    return `${cause.message}${cause.correlationId ? ` Correlation: ${cause.correlationId}` : ""}`;
  }
  return "The campaign operation could not be completed. Refresh current authority and retry safely.";
}
