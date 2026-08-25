import { describe, expect, it } from "vitest";

import {
  REQUIRED_CONTRAST_PAIRS,
  UI_FOUNDATION_TOKENS_VERSION,
  UI_FOUNDATION_TOKENS,
  resolveToken,
  validateUiFoundationTokens,
} from "./uiFoundationTokens";
import type { Token, UiFoundationTokenDocument } from "./uiFoundationTokens";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

function mutableToken(document: UiFoundationTokenDocument, path: string): Token {
  let current: unknown = document;
  for (const segment of path.split(".")) {
    current = (current as Record<string, unknown>)[segment];
  }
  return current as Token;
}

describe("compat_126 design tokens", () => {
  it("uses the shared versioned UI foundation contract", () => {
    expect(UI_FOUNDATION_TOKENS_VERSION).toBe(UI_FOUNDATION_CONTRACT_VERSION);
  });

  it("uses the stable DTCG 2025.10 schema and validates without issues", () => {
    expect(UI_FOUNDATION_TOKENS.$schema).toBe(
      "https://www.designtokens.org/schemas/2025.10/format.json",
    );
    expect(validateUiFoundationTokens(UI_FOUNDATION_TOKENS)).toEqual([]);
  });

  it("resolves the frozen semantic palette through primitive aliases", () => {
    expect(resolveToken(UI_FOUNDATION_TOKENS, "color.semantic.canvas").$value).toMatchObject({ hex: "#0A0A0A" });
    expect(resolveToken(UI_FOUNDATION_TOKENS, "color.semantic.action").$value).toMatchObject({ hex: "#8CC8FF" });
    expect(resolveToken(UI_FOUNDATION_TOKENS, "color.semantic.danger").$value).toMatchObject({ hex: "#FF918A" });
    expect(resolveToken(UI_FOUNDATION_TOKENS, "color.semantic.meaningfulBorder").$value).toMatchObject({ hex: "#66717B" });
  });

  it("passes every frozen text, status, focus, and meaningful-boundary contrast pair", () => {
    for (const pair of REQUIRED_CONTRAST_PAIRS) {
      expect(pair.ratio, pair.id).toBeGreaterThanOrEqual(pair.minimum);
    }
  });

  it("freezes the operational type, spacing, control, and shell geometry scales", () => {
    expect(["caption", "body", "default", "heading3", "heading2", "heading1", "display"].map(
      (name) => resolveToken(UI_FOUNDATION_TOKENS, `font.size.${name}`).$value,
    )).toEqual([12, 14, 16, 18, 20, 24, 32].map((value) => ({ value, unit: "px" })));
    expect(["zero", "hairline", "micro", "xs", "sm", "md", "lg", "xl", "2xl", "3xl", "4xl"].map(
      (name) => resolveToken(UI_FOUNDATION_TOKENS, `space.${name}`).$value,
    )).toEqual([0, 2, 4, 8, 12, 16, 20, 24, 32, 48, 64].map((value) => ({ value, unit: "px" })));
    expect(resolveToken(UI_FOUNDATION_TOKENS, "control.height.default").$value).toMatchObject({ value: 40, unit: "px" });
    expect(resolveToken(UI_FOUNDATION_TOKENS, "control.height.touch").$value).toMatchObject({ value: 44, unit: "px" });
    expect(resolveToken(UI_FOUNDATION_TOKENS, "shell.navigation.expandedWidth").$value).toMatchObject({ value: 272, unit: "px" });
  });

  it("rejects circular aliases instead of guessing a value", () => {
    const invalid = structuredClone(UI_FOUNDATION_TOKENS);
    invalid.color.semantic.canvas.$value = "{color.semantic.surface}";
    invalid.color.semantic.surface.$value = "{color.semantic.canvas}";

    expect(validateUiFoundationTokens(invalid)).toEqual(
      expect.arrayContaining([expect.stringContaining("circular alias")]),
    );
  });

  it("rejects unsupported types, missing critical paths, and unsafe numeric values", () => {
    const invalid = structuredClone(UI_FOUNDATION_TOKENS);
    mutableToken(invalid, "font.weight.regular").$type = "unsupported";
    mutableToken(invalid, "shell.navigation.expandedWidth").$value = { value: -272, unit: "px" };
    mutableToken(invalid, "motion.fast").$value = { value: Number.NaN, unit: "ms" };
    delete invalid.color.semantic.focus;

    expect(validateUiFoundationTokens(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("unsupported $type"),
      expect.stringContaining("non-negative finite"),
      expect.stringContaining("missing required token color.semantic.focus"),
    ]));
  });

  it("validates required contrast against the supplied document", () => {
    const invalid = structuredClone(UI_FOUNDATION_TOKENS);
    mutableToken(invalid, "color.semantic.textPrimary").$value = "{color.semantic.canvas}";

    expect(validateUiFoundationTokens(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("contrast"),
      expect.stringContaining("color.semantic.textPrimary on color.semantic.canvas"),
    ]));
  });

  it("rejects incomplete token-shaped nodes and transparent or non-finite colors", () => {
    const invalid = structuredClone(UI_FOUNDATION_TOKENS) as UiFoundationTokenDocument & {
      experimental?: Record<string, unknown>;
    };
    invalid.experimental = { ghost: { $type: "color" } };
    const transparent = mutableToken(invalid, "color.primitive.neutral050").$value as { alpha: number };
    transparent.alpha = 0;
    const nonFinite = mutableToken(invalid, "color.primitive.neutral250").$value as { alpha: number };
    nonFinite.alpha = Number.NaN;

    expect(validateUiFoundationTokens(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("experimental.ghost is missing $value"),
      expect.stringContaining("neutral050 has invalid color value"),
      expect.stringContaining("neutral250 has invalid color value"),
    ]));
  });

  it("rejects color components that disagree with the qualified hex fallback", () => {
    const invalid = structuredClone(UI_FOUNDATION_TOKENS);
    const value = mutableToken(invalid, "color.primitive.neutral1000").$value as {
      components: [number, number, number];
      hex: string;
    };
    value.components = [1, 1, 1];
    value.hex = "#0A0A0A";

    expect(validateUiFoundationTokens(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("neutral1000 color components do not match hex"),
    ]));
  });
});
