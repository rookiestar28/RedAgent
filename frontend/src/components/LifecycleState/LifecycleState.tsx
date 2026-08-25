import { lifecycleFixtures, type LifecycleStatus } from "./fixtures";

export type { LifecycleStatus } from "./fixtures";

export function LifecycleState({ state }: { state: LifecycleStatus }) {
  const fixture = lifecycleFixtures.find((item) => item.state === state);
  if (!fixture) return null;
  return (
    <article className={`lifecycle-state lifecycle-state--${state}`} role="status">
      <div className="lifecycle-state__header">
        <span className="status-glyph" aria-hidden="true">{glyph(state)}</span>
        <strong>{fixture.label}</strong>
        <span className="preview-label">Deterministic preview</span>
      </div>
      <p>{fixture.detail}</p>
      <span className="lifecycle-state__next">{fixture.nextAction}</span>
    </article>
  );
}

function glyph(state: LifecycleStatus): string {
  if (state === "denied" || state === "failed") return "!";
  if (state === "approval") return "?";
  if (state === "queued" || state === "cleanup") return "…";
  return "•";
}
