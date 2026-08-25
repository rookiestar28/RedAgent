import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

export const UI_FOUNDATION_TOKENS_VERSION = UI_FOUNDATION_CONTRACT_VERSION;

export type ColorValue = {
  colorSpace: "srgb";
  components: [number, number, number];
  alpha: number;
  hex: string;
};

export type DimensionValue = { value: number; unit: "px" | "rem" };
export type DurationValue = { value: number; unit: "ms" };
export type TokenValue =
  | ColorValue
  | DimensionValue
  | DurationValue
  | number
  | string
  | string[];

export type Token = {
  $type: string;
  $value: TokenValue;
};

const SUPPORTED_TOKEN_TYPES = new Set(["color", "dimension", "duration", "number", "fontFamily"]);

export type TokenGroup = {
  [key: string]: Token | TokenGroup | string;
};

type SemanticColorGroup = TokenGroup & {
  canvas: Token;
  surface: Token;
  action: Token;
  danger: Token;
  meaningfulBorder: Token;
};

export type UiFoundationTokenDocument = TokenGroup & {
  $schema: string;
  color: TokenGroup & {
    primitive: TokenGroup;
    semantic: SemanticColorGroup;
  };
};

export type ContrastPair = {
  readonly id: string;
  readonly ratio: number;
  readonly minimum: number;
};

const DTCG_SCHEMA = "https://www.designtokens.org/schemas/2025.10/format.json";

function srgb(hex: string): ColorValue {
  const normalized = hex.toUpperCase();
  const components = [1, 3, 5].map(
    (index) => Number.parseInt(normalized.slice(index, index + 2), 16) / 255,
  ) as [number, number, number];
  return { colorSpace: "srgb", components, alpha: 1, hex: normalized };
}

function color(value: string | ColorValue): Token {
  return { $type: "color", $value: typeof value === "string" && value.startsWith("{") ? value : typeof value === "string" ? srgb(value) : value };
}

function dimension(value: number): Token {
  return { $type: "dimension", $value: { value, unit: "px" } };
}

function numberToken(value: number): Token {
  return { $type: "number", $value: value };
}

function duration(value: number): Token {
  return { $type: "duration", $value: { value, unit: "ms" } };
}

export const UI_FOUNDATION_TOKENS: UiFoundationTokenDocument = {
  $schema: DTCG_SCHEMA,
  color: {
    primitive: {
      neutral1000: color("#0A0A0A"),
      neutral950: color("#121416"),
      neutral900: color("#191C1F"),
      neutral850: color("#21252A"),
      neutral700: color("#30363D"),
      neutral600: color("#66717B"),
      neutral400: color("#9AA4AB"),
      neutral250: color("#C6CDD2"),
      neutral050: color("#F4F7F8"),
      blue400: color("#8CC8FF"),
      blue200: color("#B9DCFF"),
      green400: color("#75D6A5"),
      amber400: color("#F1C36A"),
      red400: color("#FF918A"),
      ink1000: color("#071019"),
    },
    semantic: {
      canvas: color("{color.primitive.neutral1000}"),
      surface: color("{color.primitive.neutral950}"),
      elevated: color("{color.primitive.neutral900}"),
      overlay: color("{color.primitive.neutral850}"),
      decorativeHairline: color("{color.primitive.neutral700}"),
      meaningfulBorder: color("{color.primitive.neutral600}"),
      textMuted: color("{color.primitive.neutral400}"),
      textSecondary: color("{color.primitive.neutral250}"),
      textPrimary: color("{color.primitive.neutral050}"),
      action: color("{color.primitive.blue400}"),
      info: color("{color.primitive.blue400}"),
      success: color("{color.primitive.green400}"),
      warning: color("{color.primitive.amber400}"),
      danger: color("{color.primitive.red400}"),
      focus: color("{color.primitive.blue200}"),
      onAccent: color("{color.primitive.ink1000}"),
    },
  },
  font: {
    family: {
      sans: { $type: "fontFamily", $value: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"] },
      mono: { $type: "fontFamily", $value: ["ui-monospace", "SFMono-Regular", "Consolas", "monospace"] },
    },
    size: {
      caption: dimension(12),
      body: dimension(14),
      default: dimension(16),
      heading3: dimension(18),
      heading2: dimension(20),
      heading1: dimension(24),
      display: dimension(32),
    },
    weight: {
      regular: numberToken(400),
      medium: numberToken(500),
      semibold: numberToken(600),
    },
    lineHeight: {
      compact: numberToken(1.25),
      default: numberToken(1.5),
      relaxed: numberToken(1.65),
    },
  },
  space: {
    zero: dimension(0),
    hairline: dimension(2),
    micro: dimension(4),
    xs: dimension(8),
    sm: dimension(12),
    md: dimension(16),
    lg: dimension(20),
    xl: dimension(24),
    "2xl": dimension(32),
    "3xl": dimension(48),
    "4xl": dimension(64),
  },
  radius: {
    none: dimension(0),
    compact: dimension(4),
    control: dimension(6),
    content: dimension(8),
    overlay: dimension(12),
  },
  control: {
    height: {
      absoluteFloor: dimension(24),
      default: dimension(40),
      touch: dimension(44),
    },
    focus: {
      width: dimension(2),
      offset: dimension(2),
      color: color("{color.semantic.focus}"),
    },
  },
  shell: {
    utilityHeader: { height: dimension(56) },
    navigation: {
      compactWidth: dimension(72),
      expandedWidth: dimension(272),
    },
    inspector: { dockedWidth: dimension(360) },
    workspace: { gap: dimension(16) },
    breakpoint: {
      drawerMaximum: dimension(767),
      railMinimum: dimension(768),
      expandedMinimum: dimension(1200),
      inspectorDockedMinimum: dimension(1440),
    },
  },
  motion: {
    reduced: duration(0),
    fast: duration(120),
    deliberate: duration(180),
  },
  component: {
    button: {
      background: color("{color.semantic.action}"),
      text: color("{color.semantic.onAccent}"),
      border: color("{color.semantic.meaningfulBorder}"),
      radius: { $type: "dimension", $value: "{radius.control}" },
    },
    panel: {
      background: color("{color.semantic.surface}"),
      border: color("{color.semantic.decorativeHairline}"),
      radius: { $type: "dimension", $value: "{radius.content}" },
    },
    status: {
      success: color("{color.semantic.success}"),
      warning: color("{color.semantic.warning}"),
      danger: color("{color.semantic.danger}"),
      info: color("{color.semantic.info}"),
    },
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function isToken(value: unknown): value is Token {
  return isRecord(value) && "$value" in value;
}

function tokenAt(document: UiFoundationTokenDocument, path: string): Token {
  let node: unknown = document;
  for (const segment of path.split(".")) {
    if (!isRecord(node) || !(segment in node)) throw new Error(`unknown token: ${path}`);
    node = node[segment];
  }
  if (!isToken(node)) throw new Error(`not a token: ${path}`);
  return node;
}

const ALIAS = /^\{([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\}$/;

export function resolveToken(
  document: UiFoundationTokenDocument,
  path: string,
  stack: readonly string[] = [],
): Token {
  if (stack.includes(path)) throw new Error(`circular alias: ${[...stack, path].join(" -> ")}`);
  const token = tokenAt(document, path);
  if (typeof token.$value !== "string") return token;
  const alias = token.$value.match(ALIAS)?.[1];
  if (!alias) return token;
  const resolved = resolveToken(document, alias, [...stack, path]);
  return { $type: token.$type, $value: resolved.$value };
}

function walkTokens(value: unknown, path: string[] = []): Array<[string, Token]> {
  if (isToken(value)) return [[path.join("."), value]];
  if (!isRecord(value)) return [];
  return Object.entries(value).flatMap(([key, child]) => {
    if (key.startsWith("$")) return [];
    return walkTokens(child, [...path, key]);
  });
}

function findIncompleteTokenNodes(value: unknown, path: string[] = []): string[] {
  if (!isRecord(value)) return [];
  const hasType = "$type" in value;
  const hasValue = "$value" in value;
  if (hasType || hasValue) {
    const currentPath = path.join(".") || "<root>";
    if (!hasType) return [`${currentPath} is missing $type`];
    if (!hasValue) return [`${currentPath} is missing $value`];
    return [];
  }
  return Object.entries(value).flatMap(([key, child]) => key.startsWith("$")
    ? []
    : findIncompleteTokenNodes(child, [...path, key]));
}

function validateResolvedType(path: string, token: Token, value: TokenValue): string[] {
  const record = asRecord(value);
  if (token.$type === "color") {
    const components = record?.["components"];
    const alpha = record?.["alpha"];
    const hex = record?.["hex"];
    // SECURITY: contrast qualification is valid only for fully opaque token colors.
    if (!record || record["colorSpace"] !== "srgb" || !Array.isArray(components)
      || components.length !== 3 || !components.every((component: unknown) => typeof component === "number" && component >= 0 && component <= 1)
      || typeof alpha !== "number" || !Number.isFinite(alpha) || alpha !== 1
      || typeof hex !== "string" || !/^#[0-9A-F]{6}$/.test(hex)) {
      return [`${path} has invalid color value`];
    }
    // SECURITY: contrast evidence uses hex, so its fallback must encode the same sRGB components.
    const componentHex = `#${(components as number[]).map((component) => Math.round(component * 255)
      .toString(16)
      .padStart(2, "0"))
      .join("")}`.toUpperCase();
    if (componentHex !== hex) return [`${path} color components do not match hex`];
  } else if (token.$type === "dimension") {
    if (!record || typeof record["value"] !== "number" || !Number.isFinite(record["value"]) || record["value"] < 0
      || !new Set(["px", "rem"]).has(String(record["unit"]))) {
      return [`${path} dimension must be a non-negative finite value in px or rem`];
    }
  } else if (token.$type === "duration") {
    if (!record || typeof record["value"] !== "number" || !Number.isFinite(record["value"]) || record["value"] < 0
      || record["unit"] !== "ms") {
      return [`${path} duration must be a non-negative finite value in ms`];
    }
  } else if (token.$type === "number" && (typeof value !== "number" || !Number.isFinite(value) || value < 0)) {
    return [`${path} number must be a non-negative finite value`];
  } else if (token.$type === "fontFamily"
    && !(typeof value === "string" || (Array.isArray(value) && value.every((item) => typeof item === "string")))) {
    return [`${path} has invalid fontFamily value`];
  }
  return [];
}

const REQUIRED_TOKEN_PATHS = [
  "color.semantic.canvas",
  "color.semantic.surface",
  "color.semantic.elevated",
  "color.semantic.overlay",
  "color.semantic.meaningfulBorder",
  "color.semantic.textPrimary",
  "color.semantic.textSecondary",
  "color.semantic.textMuted",
  "color.semantic.action",
  "color.semantic.success",
  "color.semantic.warning",
  "color.semantic.danger",
  "color.semantic.focus",
  "color.semantic.onAccent",
  "font.family.sans",
  "font.family.mono",
  "control.height.absoluteFloor",
  "control.height.default",
  "control.height.touch",
  "control.focus.width",
  "control.focus.offset",
  "shell.utilityHeader.height",
  "shell.navigation.compactWidth",
  "shell.navigation.expandedWidth",
  "shell.inspector.dockedWidth",
  "shell.breakpoint.drawerMaximum",
  "shell.breakpoint.railMinimum",
  "shell.breakpoint.expandedMinimum",
  "shell.breakpoint.inspectorDockedMinimum",
  "motion.reduced",
  "motion.fast",
  "motion.deliberate",
] as const;

export function validateUiFoundationTokens(
  document: UiFoundationTokenDocument,
): string[] {
  const issues: string[] = [];
  if (document.$schema !== DTCG_SCHEMA) issues.push(`unexpected schema: ${document.$schema}`);
  issues.push(...findIncompleteTokenNodes(document));

  for (const path of REQUIRED_TOKEN_PATHS) {
    try {
      tokenAt(document, path);
    } catch {
      issues.push(`missing required token ${path}`);
    }
  }

  for (const [path, token] of walkTokens(document)) {
    if (!token.$type) issues.push(`${path} is missing $type`);
    if (!SUPPORTED_TOKEN_TYPES.has(token.$type)) {
      issues.push(`${path} has unsupported $type ${token.$type}`);
      continue;
    }
    try {
      const resolved = resolveToken(document, path);
      issues.push(...validateResolvedType(path, token, resolved.$value));
    } catch (error) {
      issues.push(error instanceof Error ? error.message : `${path} could not be resolved`);
    }
  }
  try {
    for (const pair of contrastPairsForDocument(document)) {
      if (pair.ratio < pair.minimum) {
        issues.push(`contrast ${pair.id} is ${pair.ratio.toFixed(2)} below ${pair.minimum}`);
      }
    }
  } catch (error) {
    issues.push(`contrast validation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  return [...new Set(issues)];
}

function colorHex(document: UiFoundationTokenDocument, path: string): string {
  const value = resolveToken(document, path).$value;
  const hex = asRecord(value)?.["hex"];
  if (typeof hex !== "string") throw new Error(`${path} is not a resolved color`);
  return hex;
}

function relativeLuminance(hex: string): number {
  const channels = [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16) / 255);
  const linear = channels.map((channel) => channel <= 0.04045
    ? channel / 12.92
    : ((channel + 0.055) / 1.055) ** 2.4);
  return 0.2126 * (linear[0] ?? 0) + 0.7152 * (linear[1] ?? 0) + 0.0722 * (linear[2] ?? 0);
}

function contrastRatio(foreground: string, background: string): number {
  const first = relativeLuminance(foreground);
  const second = relativeLuminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

function contrastPair(document: UiFoundationTokenDocument, foreground: string, background: string, minimum: number): ContrastPair {
  return {
    id: `${foreground} on ${background}`,
    ratio: contrastRatio(colorHex(document, foreground), colorHex(document, background)),
    minimum,
  };
}

const BACKGROUNDS = ["color.semantic.canvas", "color.semantic.surface", "color.semantic.elevated", "color.semantic.overlay"] as const;
const TEXT_COLORS = ["color.semantic.textPrimary", "color.semantic.textSecondary", "color.semantic.textMuted"] as const;
const STATUS_COLORS = ["color.semantic.action", "color.semantic.success", "color.semantic.warning", "color.semantic.danger", "color.semantic.focus"] as const;

export function contrastPairsForDocument(document: UiFoundationTokenDocument): readonly ContrastPair[] {
  return [
    ...BACKGROUNDS.flatMap((background) => TEXT_COLORS.map((foreground) => contrastPair(document, foreground, background, 4.5))),
    ...BACKGROUNDS.flatMap((background) => STATUS_COLORS.map((foreground) => contrastPair(document, foreground, background, 3))),
    contrastPair(document, "color.semantic.meaningfulBorder", "color.semantic.overlay", 3),
    contrastPair(document, "color.semantic.onAccent", "color.semantic.action", 4.5),
  ];
}

export const REQUIRED_CONTRAST_PAIRS: readonly ContrastPair[] = contrastPairsForDocument(UI_FOUNDATION_TOKENS);
