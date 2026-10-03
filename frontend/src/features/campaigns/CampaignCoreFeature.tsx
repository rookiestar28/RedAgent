import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent, type RefObject } from "react";
import { createPortal } from "react-dom";

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
  type AutonomousCampaignAvailability,
  type AutonomousCampaignIntent,
  type AutonomousCampaignStatus,
  type AutonomousCampaignPreview,
} from "../../lib/apiClient";


export type CampaignCoreClient = Pick<ReturnType<typeof createConsoleClient>,
  | "listCampaignCoreEngagementOptions"
  | "listCampaignCoreTargetOptions"
  | "listCampaignCoreRiskOptions"
  | "startCampaignCore"
  | "getCampaignCoreCampaign"
  | "recoverCampaignCore"
  | "getAutonomousCampaignAvailability"
  | "createAutonomousCampaignIntent"
  | "getAutonomousCampaignStatus"
  | "prepareAutonomousCampaignPlan"
  | "decideAutonomousCampaignPlan"
  | "admitAutonomousCampaign"
  | "prepareAutonomousCampaignChild"
  | "recoverAutonomousCampaign"
>;

type NativeCampaignClient = Pick<ReturnType<typeof createConsoleClient>,
  | "getAutonomousCampaignStatus" | "prepareAutonomousCampaignPlan" | "decideAutonomousCampaignPlan"
  | "admitAutonomousCampaign" | "prepareAutonomousCampaignChild" | "recoverAutonomousCampaign"
>;

export type CampaignReadClient = NativeCampaignClient & Pick<ReturnType<typeof createConsoleClient>,
  | "listCampaignCoreCampaigns"
  | "getCampaignCoreCampaign"
  | "getCampaignOperations"
  | "listCampaignCoreAttention"
  | "recoverCampaignCore"
  | "getAutonomousCampaignAvailability"
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
  const [availability, setAvailability] = useState<AutonomousCampaignAvailability | null>(null);
  const [nativeIntent, setNativeIntent] = useState<AutonomousCampaignIntent | null>(null);
  const [nativeStatus, setNativeStatus] = useState<AutonomousCampaignStatus | null>(null);
  const preparationKeys = useRef(new Map<string, string>());
  const canonical = availability?.canonical_configured === true;

  useEffect(() => {
    if (!createEnabled) return;
    let active = true;
    client.getAutonomousCampaignAvailability()
      .then(async (value) => {
        if (!active) return;
        setAvailability(value);
        if (value.canonical_configured ? value.create_available && value.preparation_available : value.legacy_available) {
          const page = await client.listCampaignCoreEngagementOptions();
          if (active) setEngagements(page);
        }
      })
      .catch((cause: unknown) => { if (active) setError(`Campaign entry is unavailable. ${projectError(cause)}`); });
    return () => { active = false; };
  }, [client, createEnabled]);

  const denied = useMemo(
    () => engagements?.data.filter(({ eligible }) => !eligible) ?? [],
    [engagements],
  );
  const entryAvailable = Boolean(availability && (canonical
    ? availability.create_available && availability.preparation_available : availability.legacy_available));
  const ready = Boolean(entryAvailable && engagement && target && objective && risk && !busy);

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
      if (canonical) {
        const intent = await client.createAutonomousCampaignIntent(payload, startIdempotencyKey.current);
        setNativeIntent(intent);
        const current = await client.getAutonomousCampaignStatus(intent.campaign_id);
        setNativeStatus(current);
        if (current.lifecycle_state === "INTENT_CREATED") {
          const fingerprint = nativeStageFingerprint("prepare", current);
          if (!preparationKeys.current.has(fingerprint)) preparationKeys.current.set(fingerprint, campaignStartKey());
          await client.prepareAutonomousCampaignPlan(current.campaign_id, current.aggregate_revision,
            current.etag, preparationKeys.current.get(fingerprint)!);
          setNativeStatus(await client.getAutonomousCampaignStatus(intent.campaign_id));
        }
        return;
      }
      const started = await client.startCampaignCore(payload, startIdempotencyKey.current);
      setMutation(started);
      setCampaign(await client.getCampaignCoreCampaign(started.campaign_id));
    } catch (cause) {
      setError(projectError(cause));
    } finally {
      setBusy(false);
    }
  }

  if (nativeIntent && availability) {
    return <AutonomousCampaignJourney client={client} availability={availability} intent={nativeIntent}
      status={nativeStatus} onStatus={(value) => { setNativeStatus(value); setError(null); }} initialError={error} initialBusy={busy}
      mutationKeysRef={preparationKeys}
      targetLabel={targets?.data.find((item) => item.binding === target)?.label ?? "Authorized target"} />;
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
    <h2 id="campaign-core-title">{canonical ? "Prepare an authorized campaign" : "Start an authorized campaign"}</h2>
    <p>Selections are resolved against current authority. Internal identifiers and transport idempotency are never operator input.</p>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {!availability && !error && <p role="status">Checking current operator availability…</p>}
    {availability && !entryAvailable && <p role="status">Campaign preparation is unavailable: {human(availability.reason)}. Status and recovery remain available.</p>}
    {entryAvailable && !engagements && !error && <p role="status">Loading authorized engagements…</p>}
    {entryAvailable && <form onSubmit={(event) => void start(event)}>
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
          {OBJECTIVES.filter((item) => !canonical || item !== "Assess repository snapshot posture")
            .map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      <label>Risk profile
        <select value={risk} onChange={(event) => { onActivation?.("risk"); startIdempotencyKey.current = null; setRisk(event.target.value); }} disabled={!objective || !risks || busy}>
          <option value="">Select risk profile</option>
          {eligible(risks?.data).map((option) => <option key={option.binding} value={option.binding}>{option.label}</option>)}
        </select>
      </label>
      <button type="submit" disabled={!ready}>{busy ? (canonical ? "Preparing…" : "Starting…")
        : canonical ? "Prepare plan" : "Start authorized campaign"}</button>
    </form>}
    {denied.length > 0 && <aside aria-label="Unavailable authorized resources">
      <h3>Unavailable</h3>
      <ul>{denied.map((option) => <li key={option.binding}>{option.label}: {human(option.unavailable_reason ?? "unavailable")}</li>)}</ul>
      <p>Refresh current authority or ask the engagement owner to resolve the displayed reason.</p>
    </aside>}
  </section>;
}

type NativeAction = "approve" | "deny" | "admit" | "stop" | "revoke" | "child";
const NATIVE_ACTION_LABELS: Record<NativeAction, string> = {
  approve: "Confirm plan approval", deny: "Confirm plan denial", admit: "Confirm admission and start",
  stop: "Confirm containment request", revoke: "Confirm authority revocation", child: "Confirm child plan preparation",
};

function nativeStageFingerprint(action: string, snapshot: AutonomousCampaignStatus) {
  return `${action}:${snapshot.campaign_id}:${snapshot.aggregate_revision}:${snapshot.preview?.preview_sha256 ?? "intent"}`;
}

function AutonomousCampaignJourney({ client, availability, intent, status, onStatus, targetLabel: fallbackTargetLabel, mutationKeysRef,
  initialError = null, initialBusy = false }: {
  client: NativeCampaignClient; availability: AutonomousCampaignAvailability; intent: AutonomousCampaignIntent;
  status: AutonomousCampaignStatus | null; onStatus: (value: AutonomousCampaignStatus) => void;
  targetLabel: string; initialError?: string | null; initialBusy?: boolean;
  mutationKeysRef?: RefObject<Map<string, string>>;
}) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<{ action: NativeAction; snapshot: AutonomousCampaignStatus } | null>(null);
  const keys = useRef(new Map<string, string>());
  const trigger = useRef<HTMLButtonElement | null>(null);
  const cancelButton = useRef<HTMLButtonElement | null>(null);
  const refreshButton = useRef<HTMLButtonElement | null>(null);
  const dialogRoot = useRef<HTMLDivElement | null>(null);
  const busy = working || initialBusy;
  const preview = status?.preview;
  const targetLabel = status?.target_label ?? fallbackTargetLabel;

  useEffect(() => {
    if (!confirmation || !dialogRoot.current) return;
    // IMPORTANT: aria-modal describes a dialog but does not isolate background controls.
    // The body portal lets us make each sibling inert, then restore its prior state on close.
    const siblings = [...document.body.children].filter((element) => element !== dialogRoot.current);
    const previous = siblings.map((element) => element.getAttribute("inert"));
    siblings.forEach((element) => element.setAttribute("inert", ""));
    cancelButton.current?.focus();
    return () => siblings.forEach((element, index) => {
      if (previous[index] === null) element.removeAttribute("inert");
      else element.setAttribute("inert", previous[index]!);
    });
  }, [confirmation]);

  function stageKey(action: string, snapshot: AutonomousCampaignStatus) {
    // IMPORTANT: root preparation and persisted-intent recovery share the key for the same
    // semantic stage. Replacing it after a lost response prevents exact native receipt replay.
    const owner = mutationKeysRef?.current ?? keys.current;
    const fingerprint = nativeStageFingerprint(action, snapshot);
    if (!owner.has(fingerprint)) owner.set(fingerprint, campaignStartKey());
    return owner.get(fingerprint)!;
  }

  function closeConfirmation() {
    setConfirmation(null);
    // IMPORTANT: restore focus after React commits the enabled trigger; a completed stage may
    // remove that trigger, in which case current status refresh is the stable recovery control.
    globalThis.setTimeout(() => {
      if (trigger.current?.isConnected && !trigger.current.disabled) trigger.current.focus();
      else refreshButton.current?.focus();
    }, 0);
  }

  async function refresh() {
    setWorking(true);
    setError(null);
    setConfirmation(null);
    try { onStatus(await client.getAutonomousCampaignStatus(intent.campaign_id)); }
    catch (cause) { setError(projectError(cause)); }
    finally { setWorking(false); }
  }

  async function prepare() {
    if (!status || status.lifecycle_state !== "INTENT_CREATED") return;
    setWorking(true);
    setError(null);
    try {
      await client.prepareAutonomousCampaignPlan(status.campaign_id, status.aggregate_revision, status.etag, stageKey("prepare", status));
      onStatus(await client.getAutonomousCampaignStatus(status.campaign_id));
    } catch (cause) { setError(projectError(cause)); }
    finally { setWorking(false); }
  }

  function ask(action: NativeAction, button: HTMLButtonElement) {
    if (!status || busy) return;
    trigger.current = button;
    setConfirmation({ action, snapshot: status });
  }

  async function confirm() {
    if (!confirmation || busy) return;
    const { action, snapshot } = confirmation;
    setWorking(true);
    setError(null);
    setNotice(null);
    try {
      const key = stageKey(action, snapshot);
      if (action === "approve" || action === "deny") {
        if (!snapshot.preview || !snapshot.preview_etag) throw new Error("preview unavailable");
        await client.decideAutonomousCampaignPlan(action, snapshot.campaign_id, {
          preview_id: snapshot.preview.preview_id, preview_sha256: snapshot.preview.preview_sha256,
        }, snapshot.preview_etag, key);
      } else if (action === "admit") {
        if (!snapshot.approval || !snapshot.approval_etag) throw new Error("approval unavailable");
        await client.admitAutonomousCampaign(snapshot.campaign_id, {
          approval_receipt_id: snapshot.approval.receipt_id, approval_receipt_sha256: snapshot.approval.receipt_sha256,
        }, snapshot.approval_etag, key);
      } else if (action === "child") {
        await client.prepareAutonomousCampaignChild(snapshot.campaign_id, snapshot.aggregate_revision, snapshot.roe_version_id, key);
      } else {
        await client.recoverAutonomousCampaign(action, snapshot.campaign_id, snapshot.aggregate_revision, snapshot.etag,
          action === "stop" ? "Operator requests safe containment of the current campaign." : "Operator revokes future campaign authority.", key);
        if (action === "stop") setNotice("A stop request does not prove containment or cleanup. Refresh the native execution and result owners.");
      }
      onStatus(await client.getAutonomousCampaignStatus(snapshot.campaign_id));
    } catch (cause) {
      // CRITICAL: stale or uncertain mutations only refetch. Reusing a new revision automatically
      // would apply an old human confirmation to a different plan or authority boundary.
      try { onStatus(await client.getAutonomousCampaignStatus(snapshot.campaign_id)); }
      catch { /* Keep the last snapshot visible; the failed read grants no new state. */ }
      setError(`${projectError(cause)} Review the refreshed state and confirm again.`);
    } finally {
      setWorking(false);
      closeConfirmation();
    }
  }

  function dialogKeys(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape" && !busy) { event.preventDefault(); closeConfirmation(); return; }
    if (event.key !== "Tab") return;
    const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not([disabled])")];
    const first = buttons[0], last = buttons.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }

  const scopeCurrent = !status?.attention.includes("operator_native_source_changed");
  const gatesClear = Boolean(status && status.attention.length === 0
    && !["denied", "revoked", "expired", "unavailable"].includes(status.operations.authority.state));
  const childGatesClear = Boolean(status && status.attention.every((reason) => reason === "evidence_pending")
    // CRITICAL: an expired parent admission cannot transfer authority, but must not hide child
    // preparation. The server rechecks current campaign scope; the child needs fresh human gates.
    && !["denied", "revoked", "unavailable"].includes(status.operations.authority.state));
  const mayDecide = Boolean(gatesClear && scopeCurrent && status && preview && status.preview_etag && !status.preview_expired
    && status.lifecycle_state === "AWAITING_APPROVAL" && availability.preparation_available);
  const mayAdmit = Boolean(gatesClear && scopeCurrent && status && status.mode !== "plan_only" && status.lifecycle_state === "APPROVED"
    && status.approval?.decision === "approved" && !status.approval.expired && !status.preview_expired
    && status.approval_etag && availability.create_available);
  const mayStop = Boolean(status && availability.stop_available
    && ["start_pending", "running", "stopping", "reconciliation_required"].includes(status.operations.execution.state));
  const mayRevoke = Boolean(status && availability.revoke_available
    && ["INTENT_CREATED", "PLAN_VALIDATED", "AWAITING_APPROVAL", "APPROVED", "ADMITTED", "EXECUTION_QUEUED",
      "RUNNING", "MANUAL_REVIEW_REQUIRED"].includes(status.lifecycle_state));
  const mayChild = Boolean(childGatesClear && scopeCurrent && status && availability.preparation_available && status.mode === "bounded_replan" && !status.child
    && ["EVIDENCE_PENDING", "FAILED_CONTAINED"].includes(status.lifecycle_state));

  return <section className="work-panel campaign-core" aria-labelledby="native-campaign-title" aria-busy={busy}>
    <span className="eyebrow">Authorized staged campaign</span>
    <h2 id="native-campaign-title">{targetLabel}</h2>
    <p role="status">{status ? human(status.lifecycle_state) : "Intent persisted; current status refresh required"}</p>
    <dl className="record-grid">
      <div><dt>Server mode</dt><dd>{human(status?.mode ?? intent.mode)}</dd></div>
      <div><dt>Application revision</dt><dd>{status?.aggregate_revision ?? intent.aggregate_revision}</dd></div>
      <div><dt>Cleanup</dt><dd>{human(status?.result.cleanup_state ?? "unavailable")}</dd></div>
      <div><dt>Evidence</dt><dd>{human(status?.result.evidence_state ?? "unavailable")}</dd></div>
    </dl>
    {(error ?? initialError) && <p className="inline-error" role="alert">{error ?? initialError}</p>}
    {notice && <p role="status">{notice}</p>}
    {status?.attention.length ? <aside aria-label="Campaign attention"><h3>Attention required</h3>
      <ul>{status.attention.map((reason) => <li key={reason}>{human(reason)}</li>)}</ul></aside> : null}
    {!scopeCurrent && <p role="status">The authorized scope changed after intent creation. New approval and execution are blocked. Review current scope and create a new intent; containment and revocation remain available.</p>}
    {status?.preview_expired && <p role="status">The preview has expired. Refresh current authority; approval and admission remain unavailable.</p>}
    {status?.approval?.expired && <p role="status">Approval has expired. It cannot authorize another execution.</p>}
    {status?.mode === "plan_only" && <p>PLAN_ONLY prepares and records human decisions with zero execution I/O.</p>}
    {preview && <ImmutablePlanSummary preview={preview} targetLabel={targetLabel} objectiveLabel={status?.objective_label} />}
    {status?.child && <p>Child revision {status.child.replan_sequence} requires its own exact approval and admission. Parent receipts do not transfer.</p>}
    <div className="button-row">
      <button ref={refreshButton} disabled={busy} onClick={() => void refresh()}>Refresh current status</button>
      {scopeCurrent && status?.lifecycle_state === "INTENT_CREATED" && availability.preparation_available
        && <button disabled={busy} onClick={() => void prepare()}>Prepare plan</button>}
      {mayDecide && <><button disabled={busy} onClick={(event) => ask("approve", event.currentTarget)}>Approve plan</button>
        <button disabled={busy} onClick={(event) => ask("deny", event.currentTarget)}>Deny plan</button></>}
      {mayAdmit && <button disabled={busy} onClick={(event) => ask("admit", event.currentTarget)}>Admit and start</button>}
      {mayStop && <button className="danger-action" disabled={busy} onClick={(event) => ask("stop", event.currentTarget)}>Request containment</button>}
      {mayRevoke && <button disabled={busy} onClick={(event) => ask("revoke", event.currentTarget)}>Revoke future authority</button>}
      {mayChild && <button disabled={busy} onClick={(event) => ask("child", event.currentTarget)}>Prepare child plan</button>}
      <button disabled aria-describedby="native-export-reason">Export evidence</button>
    </div>
    <p id="native-export-reason">{status?.result.export_state === "unavailable_export_not_configured"
      ? "The server verified the retained bundle. An authorized export owner is not configured."
      : "Export is unavailable until the server verifies a retained bundle against an independent trust anchor."}</p>
    {mayChild && <p>Child preparation rechecks trusted observations, cooldown and all bounds on the server. A denial requires refresh and a new confirmation.</p>}
    {status && <CampaignOperationsWorkspace operations={status.operations} />}
    {confirmation && createPortal(<div ref={dialogRoot} className="navigation-drawer-backdrop">
      <section className="safety-dialog campaign-plan-dialog" role="dialog" aria-modal="true"
        aria-label={NATIVE_ACTION_LABELS[confirmation.action]} onKeyDown={dialogKeys}>
        <h2>{NATIVE_ACTION_LABELS[confirmation.action]}</h2>
        <p>Confirm this exact application revision {confirmation.snapshot.aggregate_revision} for {confirmation.snapshot.target_label}.</p>
        {confirmation.action === "approve" && confirmation.snapshot.preview
          && <ImmutablePlanSummary preview={confirmation.snapshot.preview} targetLabel={confirmation.snapshot.target_label}
            objectiveLabel={confirmation.snapshot.objective_label} />}
        {confirmation.action === "admit" && <p>This separately requests current policy admission and bounded execution. Approval alone has not started a runner.</p>}
        {confirmation.action === "stop" && <p>A stop request does not prove containment or cleanup. Native owners must report both.</p>}
        {confirmation.action === "revoke" && <p>Revoke future authority. This does not prove that an active effect has stopped or cleaned up.</p>}
        {confirmation.action === "child" && <p>Prepare one bounded child from the terminal parent. Review its new plan, then provide fresh approval and admission.</p>}
        <div className="dialog-actions">
          <button ref={cancelButton} disabled={busy} onClick={closeConfirmation}>Cancel</button>
          <button disabled={busy} onClick={() => void confirm()}>{NATIVE_ACTION_LABELS[confirmation.action]}</button>
        </div>
      </section>
    </div>, document.body)}
  </section>;
}

function ImmutablePlanSummary({ preview, targetLabel, objectiveLabel }: {
  preview: AutonomousCampaignPreview; targetLabel: string; objectiveLabel?: string | null | undefined;
}) {
  return <article className="campaign-operations__panel campaign-plan-summary">
    <h3>Immutable plan</h3>
    <dl className="record-grid">
      <div><dt>Target</dt><dd>{targetLabel}</dd></div>
      <div><dt>Objective</dt><dd>{objectiveLabel ?? "Server-defined objective"}</dd></div>
      <div><dt>Plan revision</dt><dd>{preview.application_revision}</dd></div>
      <div><dt>Independent validation</dt><dd>{preview.validation_result}</dd></div>
      <div><dt>Validator</dt><dd>{preview.validator_version}</dd></div>
      <div><dt>Expires</dt><dd>{formatTime(preview.expires_at)}</dd></div>
      <div><dt>Approver roles</dt><dd>{preview.required_approvers.map((item) => item.role_id).join(", ")}</dd></div>
    </dl>
    <ol className="campaign-plan-actions">{preview.actions.map((action) => <li key={action.node_id}>
      <strong>{human(action.capability_id)} · revision {action.capability_revision}</strong>
      <p>{human(action.effect_class)} · {action.executable ? "Bounded execution" : "No executable effect"}</p>
      <p>Maximum {action.max_duration_seconds} seconds, {action.max_requests} requests, {action.max_rate_per_minute} requests/minute,
        concurrency {action.concurrency_weight}, retries {action.max_retries}.</p>
      <p>Cleanup: {human(action.cleanup_mode)}. Evidence: at most {action.max_evidence_bytes} bytes; data: {action.max_data_bytes} bytes.</p>
      <p>Risk maximum: {action.max_risk_micropoints} micropoints; cost maximum: {action.max_cost_microunits} microunits.</p>
    </li>)}</ol>
    <h4>Plan total bounds</h4>
    <dl className="record-grid" aria-label="Plan total bounds">{Object.entries(preview.plan_budget).filter(([key]) => key !== "schema_version")
      .map(([key, value]) => <div key={key}><dt>{human(key)}</dt><dd>{value}</dd></div>)}</dl>
    <h4>Authorized campaign bounds</h4>
    <dl className="record-grid" aria-label="Authorized campaign bounds">{Object.entries(preview.authorized_budget).filter(([key]) => key !== "schema_version")
      .map(([key, value]) => <div key={key}><dt>{human(key)}</dt><dd>{value}</dd></div>)}</dl>
    <p>Evidence requires retained native receipts, complete cleanup and independent bundle verification.</p>
    <details><summary>Exact plan binding</summary>
      <p className="campaign-plan-digest">Preview digest: <code>{preview.preview_sha256}</code></p>
    </details>
  </article>;
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
  const [nativeSelected, setNativeSelected] = useState<{ status: AutonomousCampaignStatus;
    availability: AutonomousCampaignAvailability; label: string } | null>(null);
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
          setNativeSelected(null);
          setOperations(null);
          setPendingAction(null);
          setError(null);
          if (campaign.operator_kind === "canonical") {
            // CRITICAL: the server catalog selects the owner. A failed native read cannot fall
            // through to legacy strategy/effect rows and silently show a different campaign truth.
            void Promise.all([client.getAutonomousCampaignStatus(campaign.campaign_id), client.getAutonomousCampaignAvailability()])
              .then(([status, availability]) => {
                if (selectedCampaignBinding.current !== campaign.campaign_id) return;
                setNativeSelected({ status, availability, label: campaign.label });
              }).catch((cause: unknown) => {
                if (selectedCampaignBinding.current === campaign.campaign_id) setError(projectError(cause));
              });
            return;
          }
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
    {nativeSelected && <AutonomousCampaignJourney key={nativeSelected.status.campaign_id} client={client}
      availability={nativeSelected.availability} targetLabel={nativeSelected.label} status={nativeSelected.status}
      intent={{ campaign_id: nativeSelected.status.campaign_id, mode: nativeSelected.status.mode,
        lifecycle_state: nativeSelected.status.lifecycle_state, aggregate_revision: nativeSelected.status.aggregate_revision,
        etag: nativeSelected.status.etag, replayed: false }}
      onStatus={(status) => {
        if (selectedCampaignBinding.current !== status.campaign_id) return;
        setNativeSelected((prior) => prior ? { ...prior, status } : null);
      }} />}
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
