import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { gzipSync } from "node:zlib";
import ts from "typescript";

function argumentValue(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function requireBudget(value, name) {
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive finite number`);
  }
  return value;
}

function attributeValue(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\\x60]+))`, "i"));
  return (match?.[1] ?? match?.[2] ?? match?.[3])?.trim();
}

function initialAssetReferences(html) {
  const references = [];
  for (const match of html.matchAll(/<script\b[^>]*>/gi)) {
    const source = attributeValue(match[0], "src");
    if (source !== undefined) references.push(source);
  }
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const relation = attributeValue(match[0], "rel")?.toLowerCase().split(/\s+/) ?? [];
    if (!relation.some((value) => value === "stylesheet" || value === "modulepreload")) continue;
    const target = attributeValue(match[0], "href");
    if (target !== undefined) references.push(target);
  }
  return references;
}

function inlineAssetContents(html) {
  const javascript = [];
  const css = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (attributeValue(`<script ${match[1] ?? ""}>`, "src") !== undefined) continue;
    const type = attributeValue(`<script ${match[1] ?? ""}>`, "type")?.toLowerCase();
    if (!type || type === "module" || type === "text/javascript" || type === "application/javascript") {
      javascript.push(match[2] ?? "");
    }
  }
  for (const match of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) css.push(match[1] ?? "");
  return { javascript, css };
}

function inlineJavascriptReferences(source) {
  const references = [];
  // IMPORTANT: parser resolution keeps unresolved inline imports from bypassing bundle budgets.
  const file = ts.createSourceFile("inline.js", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  if (file.parseDiagnostics.length > 0) throw new Error("invalid inline JavaScript syntax");
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (!ts.isStringLiteralLike(node.moduleSpecifier)) {
        throw new Error("non-literal module reference in inline JavaScript");
      }
      references.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const [target] = node.arguments;
      if (!target || !ts.isStringLiteralLike(target)) {
        throw new Error("non-literal dynamic import in inline JavaScript");
      }
      references.push(target.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return references;
}

function inlineCssReferences(source) {
  const references = [];
  for (const match of source.matchAll(/@import\s+(?:url\(\s*)?(["'])([^"']+)\1\s*\)?/gi)) {
    references.push(match[2]);
  }
  for (const match of source.matchAll(/@import\s+(?:url\(\s*)?([^"'\s);]+)/gi)) {
    references.push(match[1]);
  }
  return references;
}

function inlineAssetReferences(inlineAssets) {
  return [
    ...inlineAssets.javascript.flatMap(inlineJavascriptReferences),
    ...inlineAssets.css.flatMap(inlineCssReferences),
  ];
}

function resolveInitialAsset(dist, reference, importer) {
  // SECURITY: build output must not load or measure assets outside its own dist boundary.
  if (!reference || /^[a-z][a-z\d+.-]*:/i.test(reference) || reference.startsWith("//") || reference.includes("\\")) {
    throw new Error(`unsafe initial asset reference: ${reference || "<empty>"}`);
  }
  const withoutSuffix = reference.split(/[?#]/, 1)[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutSuffix);
  } catch {
    throw new Error(`invalid encoded initial asset reference: ${reference}`);
  }
  const rootRelative = decoded.startsWith("/");
  const relative = decoded.replace(/^\/+/, "").split("/").filter((segment) => segment && segment !== ".").join(path.sep);
  const base = rootRelative || !importer ? dist : path.dirname(importer);
  const resolved = path.resolve(base, relative);
  const boundary = path.relative(dist, resolved);
  if (!relative || boundary.startsWith("..") || path.isAbsolute(boundary)) {
    throw new Error(`initial asset escapes dist: ${reference}`);
  }
  const extension = path.extname(resolved).toLowerCase();
  if (extension !== ".js" && extension !== ".css") {
    throw new Error(`unsupported initial asset type: ${reference}`);
  }
  return resolved;
}

async function expandStylesheetGraph(dist, realDist, initialAssets) {
  const assets = new Set(initialAssets);
  const pending = initialAssets.filter((asset) => path.extname(asset).toLowerCase() === ".css");
  const visited = new Set();
  while (pending.length > 0) {
    const stylesheet = pending.pop();
    if (!stylesheet || visited.has(stylesheet)) continue;
    visited.add(stylesheet);
    const source = (await readWithinDist(realDist, stylesheet, "initial stylesheet")).toString("utf8");
    for (const reference of new Set(inlineCssReferences(source))) {
      const imported = resolveInitialAsset(dist, reference, stylesheet);
      if (path.extname(imported).toLowerCase() !== ".css") {
        throw new Error(`unsupported stylesheet import type: ${reference}`);
      }
      if (!assets.has(imported)) {
        assets.add(imported);
        pending.push(imported);
      }
    }
  }
  return [...assets];
}

async function readWithinDist(realDist, candidate, label) {
  // SECURITY: resolve linked build output before reading so assets cannot escape dist.
  let realCandidate;
  try {
    realCandidate = await realpath(candidate);
  } catch {
    throw new Error(`${label} is missing or unreadable: ${path.relative(realDist, candidate)}`);
  }
  const boundary = path.relative(realDist, realCandidate);
  if (boundary.startsWith("..") || path.isAbsolute(boundary)) {
    throw new Error(`${label} real path escapes dist: ${path.relative(realDist, candidate)}`);
  }
  try {
    return await readFile(realCandidate);
  } catch {
    throw new Error(`${label} is missing or unreadable: ${path.relative(realDist, candidate)}`);
  }
}

async function initialAssetGraph(dist, realDist, directAssets) {
  const manifestPath = path.join(dist, ".vite", "manifest.json");
  let manifest;
  try {
    manifest = JSON.parse((await readWithinDist(realDist, manifestPath, "Vite manifest")).toString("utf8"));
  } catch {
    throw new Error("Vite manifest is missing, unreadable, or invalid");
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Vite manifest must be an object");
  }

  const assets = new Set(directAssets);
  const entries = Object.entries(manifest);
  const byFile = new Map(entries.flatMap(([key, value]) => value && typeof value === "object" && typeof value.file === "string"
    ? [[value.file.replaceAll("\\", "/").replace(/^\//, ""), key]]
    : []));
  const visited = new Set();
  const visit = (key) => {
    if (visited.has(key)) return;
    visited.add(key);
    const entry = manifest[key];
    if (!entry || typeof entry !== "object" || typeof entry.file !== "string") {
      throw new Error(`Vite manifest import is missing or invalid: ${key}`);
    }
    if (entry.css !== undefined && (!Array.isArray(entry.css) || !entry.css.every((value) => typeof value === "string"))) {
      throw new Error(`Vite manifest css list is invalid: ${key}`);
    }
    if (entry.imports !== undefined && (!Array.isArray(entry.imports) || !entry.imports.every((value) => typeof value === "string"))) {
      throw new Error(`Vite manifest import list is invalid: ${key}`);
    }
    assets.add(resolveInitialAsset(dist, entry.file));
    const cssReferences = entry.css ?? [];
    const imports = entry.imports ?? [];
    if (!Array.isArray(cssReferences) || !cssReferences.every((value) => typeof value === "string")
      || !Array.isArray(imports) || !imports.every((value) => typeof value === "string")) {
      throw new Error(`Vite manifest entry has invalid eager references: ${key}`);
    }
    for (const css of cssReferences) assets.add(resolveInitialAsset(dist, css));
    for (const imported of imports) visit(imported);
  };

  for (const asset of directAssets) {
    if (path.extname(asset).toLowerCase() !== ".js") continue;
    const relative = path.relative(dist, asset).split(path.sep).join("/");
    const key = byFile.get(relative);
    if (!key) throw new Error(`initial JavaScript is absent from Vite manifest: ${relative}`);
    visit(key);
  }
  return [...assets];
}

async function main() {
  const root = process.cwd();
  const dist = path.resolve(root, argumentValue("--dist", path.join("frontend", "dist")));
  const manifestPath = path.resolve(
    root,
    argumentValue("--manifest", path.join("frontend", "src", "ui-foundation", "uiFoundationBudgetManifest.json")),
  );
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const budgets = manifest.performance ?? {};
  const maximums = {
    javascriptGzipBytes: requireBudget(budgets.initialJavaScriptGzipBytes, "initialJavaScriptGzipBytes"),
    cssGzipBytes: requireBudget(budgets.initialCssGzipBytes, "initialCssGzipBytes"),
    combinedGzipBytes: requireBudget(budgets.initialCombinedGzipBytes, "initialCombinedGzipBytes"),
  };

  const realDist = await realpath(dist);
  const indexPath = path.join(dist, "index.html");
  const html = (await readWithinDist(realDist, indexPath, "index.html")).toString("utf8");
  const inlineAssets = inlineAssetContents(html);
  const directAssets = [...new Set([
    ...initialAssetReferences(html),
    ...inlineAssetReferences(inlineAssets),
  ].map((reference) => resolveInitialAsset(dist, reference)))];
  const manifestAssets = await initialAssetGraph(dist, realDist, directAssets);
  const initialAssets = await expandStylesheetGraph(dist, realDist, manifestAssets);
  const measurements = { javascriptGzipBytes: 0, cssGzipBytes: 0, combinedGzipBytes: 0 };
  const counts = { html: 1, javascript: 0, css: 0 };
  measurements.combinedGzipBytes += gzipSync(Buffer.from(html), { level: 9 }).length;
  for (const file of initialAssets) {
    const extension = path.extname(file).toLowerCase();
    const contents = await readWithinDist(realDist, file, "initial asset");
    const gzipBytes = gzipSync(contents, { level: 9 }).length;
    measurements.combinedGzipBytes += gzipBytes;
    if (extension === ".js") {
      counts.javascript += 1;
      measurements.javascriptGzipBytes += gzipBytes;
    } else {
      counts.css += 1;
      measurements.cssGzipBytes += gzipBytes;
    }
  }

  for (const contents of inlineAssets.javascript) {
    counts.javascript += 1;
    measurements.javascriptGzipBytes += gzipSync(Buffer.from(contents), { level: 9 }).length;
  }
  for (const contents of inlineAssets.css) {
    counts.css += 1;
    measurements.cssGzipBytes += gzipSync(Buffer.from(contents), { level: 9 }).length;
  }

  if (counts.html === 0 || counts.javascript === 0 || counts.css === 0) {
    throw new Error("dist must contain at least one HTML, JavaScript, and CSS asset");
  }

  const exceeded = Object.entries(measurements)
    .filter(([name, value]) => value > maximums[name])
    .map(([name, value]) => ({ name, value, maximum: maximums[name] }));
  const result = {
    version: manifest.version,
    status: exceeded.length === 0 ? "PASS" : "FAIL",
    dist,
    files: counts,
    measurements,
    maximums,
    exceeded,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (exceeded.length > 0) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`ui_foundation_bundle_check_error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
