import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LifecycleState } from "./LifecycleState";
import { lifecycleFixtures } from "./fixtures";

describe("LifecycleState", () => {
  it("renders every roadmap lifecycle fixture with text and an explicit non-live boundary", () => {
    for (const fixture of lifecycleFixtures) {
      const { unmount } = render(<LifecycleState state={fixture.state} />);
      expect(screen.getByRole("status")).toHaveTextContent(fixture.label);
      expect(screen.getByRole("status")).toHaveTextContent(fixture.nextAction);
      expect(screen.getByText("Deterministic preview")).toBeVisible();
      unmount();
    }
  });

  it("does not rely on color alone for denied and failed states", () => {
    render(<LifecycleState state="denied" />);
    expect(screen.getByText("Denied")).toBeVisible();
    expect(screen.getByText(/authorization or scope/i)).toBeVisible();
  });
});
