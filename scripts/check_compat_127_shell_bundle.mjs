import { readFileSync } from "node:fs";
import path from "node:path";


const root = process.cwd();
const source = (relative) => readFileSync(path.join(root, relative), "utf8");
const failures = [];
const app = source("frontend/src/App.tsx");
const shell = source("frontend/src/shell/OperationalShell.tsx");
const pageAdapters = source("frontend/src/shell/RoutePage.tsx");
const styles = source("frontend/src/styles.css");
const manifest = JSON.parse(source("frontend/dist/.vite/manifest.json"));
const entry = manifest["index.html"];
const routeChunk = manifest["src/shell/RoutePage.tsx"];

reject(app.includes("window.location.pathname"), "app_raw_pathname_forbidden");
reject(app.includes("Control plane</h1>"), "static_control_plane_heading_forbidden");
reject(shell.includes('className="primary-nav"'), "legacy_header_navigation_forbidden");
reject(/if\s*\(path\s*===/.test(pageAdapters), "route_adapter_path_branch_forbidden");
reject(/\.primary-nav\s*\{/.test(styles), "legacy_primary_nav_css_forbidden");
reject(/white-space:\s*nowrap/.test(styles), "global_route_nowrap_forbidden");
reject(/overflow-x:\s*auto/.test(styles), "global_route_overflow_forbidden");
reject(!entry?.isEntry, "vite_entry_missing");
reject(!entry?.dynamicImports?.includes("src/shell/RoutePage.tsx"), "route_adapter_not_lazy");
reject(!routeChunk?.isDynamicEntry, "route_adapter_dynamic_chunk_missing");

if (entry?.file) {
  const initialJavaScript = source(path.posix.join("frontend/dist", entry.file));
  reject(initialJavaScript.includes("Controlled ZAP runtime"), "route_page_content_in_initial_bundle");
  reject(initialJavaScript.includes("No engagements yet"), "overview_content_in_initial_bundle");
  reject(initialJavaScript.includes('"primary-nav"'), "legacy_navigation_in_initial_bundle");
}
if (entry?.css) {
  const initialCss = entry.css.map((file) => source(path.posix.join("frontend/dist", file))).join("\n");
  reject(/\.primary-nav\{/.test(initialCss), "legacy_navigation_in_css_bundle");
  reject(/white-space:nowrap/.test(initialCss), "nowrap_in_css_bundle");
  reject(/overflow-x:auto/.test(initialCss), "horizontal_route_overflow_in_css_bundle");
}

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  process.exit(1);
}
process.stdout.write(`r127_shell_bundle_passed entry=${entry.file} route=${routeChunk.file}\n`);

function reject(condition, message) {
  if (condition) failures.push(message);
}
