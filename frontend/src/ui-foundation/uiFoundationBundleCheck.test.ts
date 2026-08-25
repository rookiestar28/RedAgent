import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const ROOT = process.cwd();
const FIXTURE_ROOT = path.join(ROOT, ".tmp", "r126-bundle-check-test");
const SCRIPT = path.join(ROOT, "scripts", "check_ui_foundation_bundle.mjs");

async function createFixture(maximumBytes: number) {
  await rm(FIXTURE_ROOT, { recursive: true, force: true });
  const dist = path.join(FIXTURE_ROOT, "dist");
  await mkdir(path.join(dist, "assets"), { recursive: true });
  await writeFile(
    path.join(dist, "index.html"),
    [
      '<link rel="stylesheet" href="/assets/app.css">',
      "<main>RedAgent</main>",
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"),
    "utf8",
  );
  await writeFile(path.join(dist, "assets", "app.js"), "export const ready = true;", "utf8");
  await writeFile(path.join(dist, "assets", "app.css"), "body{color:white}", "utf8");
  await mkdir(path.join(dist, ".vite"), { recursive: true });
  await writeFile(path.join(dist, ".vite", "manifest.json"), JSON.stringify({
    "index.html": {
      file: "assets/app.js",
      css: ["assets/app.css"],
      isEntry: true,
      imports: [],
    },
  }), "utf8");
  const lazyBytes = Buffer.alloc(4096);
  let state = 0x12345678;
  for (let index = 0; index < lazyBytes.length; index += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    lazyBytes[index] = state & 0xff;
  }
  await writeFile(path.join(dist, "assets", "lazy-route.js"), lazyBytes);
  const manifest = path.join(FIXTURE_ROOT, "budgets.json");
  await writeFile(manifest, JSON.stringify({
    version: "test",
    performance: {
      initialJavaScriptGzipBytes: maximumBytes,
      initialCssGzipBytes: maximumBytes,
      initialCombinedGzipBytes: maximumBytes,
    },
  }), "utf8");
  return { dist, manifest };
}

afterEach(async () => {
  await rm(FIXTURE_ROOT, { recursive: true, force: true });
});

describe("compat_126 initial bundle checker", () => {
  it("reports deterministic gzip totals and passes within the shared manifest", async () => {
    const fixture = await createFixture(1024);
    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT,
      encoding: "utf8",
      shell: false,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      version: "test",
      status: "PASS",
      files: { html: 1, javascript: 1, css: 1 },
    });
  });

  it("fails closed when any gzip budget is exceeded", async () => {
    const fixture = await createFixture(1);
    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT,
      encoding: "utf8",
      shell: false,
    });

    expect(result.status).toBe(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      version: "test",
      status: "FAIL",
    });
  });

  it.each([
    ["external", '<script type="module" src="https://example.invalid/app.js"></script>'],
    ["root escape", '<script type="module" src="/../outside.js"></script>'],
    ["missing", '<script type="module" src="/assets/missing.js"></script>'],
  ])("fails closed for an unsafe or unresolved %s initial asset", async (_label, reference) => {
    const fixture = await createFixture(1024);
    await writeFile(
      path.join(fixture.dist, "index.html"),
      [
        '<link rel="stylesheet" href="/assets/app.css">',
        "<main>RedAgent</main>",
        reference,
      ].join("\n"),
      "utf8",
    );

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT,
      encoding: "utf8",
      shell: false,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("ui_foundation_bundle_check_error:");
  });

  it("charges transitive eager chunks while excluding unreferenced lazy chunks", async () => {
    const fixture = await createFixture(1024);
    await writeFile(path.join(fixture.dist, "assets", "eager.js"), Buffer.alloc(4096, 0x5a));
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/app.js", css: ["assets/app.css"], isEntry: true, imports: ["_eager.js"] },
      "_eager.js": { file: "assets/eager.js" },
    }), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ files: { javascript: 2 } });
  });

  it("charges executable inline script and style content to their individual budgets", async () => {
    const fixture = await createFixture(1024);
    const bytes = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-inline-budget-${index}`)
      .digest()));
    const noisy = bytes.toString("base64");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      `<style>:root{--payload:"${noisy}"}</style>`,
      `<script>const payload="${noisy}";</script>`,
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toEqual(expect.arrayContaining([
      "javascriptGzipBytes",
      "cssGzipBytes",
    ]));
  });

  it("rejects a lexical in-dist asset whose real path escapes through a directory link", async () => {
    const fixture = await createFixture(1024);
    const outside = path.join(FIXTURE_ROOT, "outside");
    await mkdir(outside, { recursive: true });
    await writeFile(path.join(outside, "external.js"), "export const escaped = true;", "utf8");
    await symlink(outside, path.join(fixture.dist, "assets", "linked"), "junction");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      '<script type="module" src="/assets/linked/external.js"></script>',
    ].join("\n"), "utf8");
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/linked/external.js", css: ["assets/app.css"], isEntry: true, imports: [] },
    }), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("real path escapes dist");
  });

  it("rejects malformed eager dependency lists instead of iterating strings", async () => {
    const fixture = await createFixture(1024);
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/app.js", css: "assets/app.css", isEntry: true, imports: "_eager.js" },
    }), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Vite manifest css list is invalid");
  });

  it("counts valid unquoted HTML asset attributes", async () => {
    const fixture = await createFixture(1024);
    await writeFile(path.join(fixture.dist, "index.html"), [
      "<link rel=stylesheet href=/assets/app.css>",
      "<main>RedAgent</main>",
      "<script type=module src=/assets/app.js></script>",
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ files: { javascript: 1, css: 1 } });
  });

  it("charges an eager dependency imported by an inline module", async () => {
    const fixture = await createFixture(1024);
    const eagerBytes = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-inline-module-import-${index}`)
      .digest()));
    await writeFile(path.join(fixture.dist, "assets", "inline-eager.js"), eagerBytes);
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/app.js", css: ["assets/app.css"], isEntry: true, imports: [] },
      "_inline-eager.js": { file: "assets/inline-eager.js", imports: [] },
    }), "utf8");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      '<script type="module">import "/assets/inline-eager.js";</script>',
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toContain("javascriptGzipBytes");
  });

  it("charges an immediately requested dynamic import from an inline module", async () => {
    const fixture = await createFixture(1024);
    const eagerBytes = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-inline-dynamic-import-${index}`)
      .digest()));
    await writeFile(path.join(fixture.dist, "assets", "inline-dynamic.js"), eagerBytes);
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/app.js", css: ["assets/app.css"], isEntry: true, imports: [] },
      "_inline-dynamic.js": { file: "assets/inline-dynamic.js", imports: [] },
    }), "utf8");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      '<script type="module">import("/assets/inline-dynamic.js");</script>',
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toContain("javascriptGzipBytes");
  });

  it("charges a minified static import from an inline module", async () => {
    const fixture = await createFixture(1024);
    const eagerBytes = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-inline-minified-import-${index}`)
      .digest()));
    await writeFile(path.join(fixture.dist, "assets", "inline-minified.js"), eagerBytes);
    await writeFile(path.join(fixture.dist, ".vite", "manifest.json"), JSON.stringify({
      "index.html": { file: "assets/app.js", css: ["assets/app.css"], isEntry: true, imports: [] },
      "_inline-minified.js": { file: "assets/inline-minified.js", imports: [] },
    }), "utf8");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      '<script type="module">import{ready}from"/assets/inline-minified.js";</script>',
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toContain("javascriptGzipBytes");
  });

  it("fails closed for a non-literal dynamic import in an inline module", async () => {
    const fixture = await createFixture(1024);
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<link rel="stylesheet" href="/assets/app.css">',
      '<script type="module">const target="/assets/app.js";import(target);</script>',
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("non-literal dynamic import in inline JavaScript");
  });

  it("charges a dependency imported by an inline style block", async () => {
    const fixture = await createFixture(1024);
    const noisy = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-inline-style-import-${index}`)
      .digest())).toString("base64");
    await writeFile(path.join(fixture.dist, "assets", "inline-eager.css"), `:root{--payload:"${noisy}"}`, "utf8");
    await writeFile(path.join(fixture.dist, "index.html"), [
      '<style>@import "/assets/inline-eager.css";</style>',
      '<script type="module" src="/assets/app.js"></script>',
    ].join("\n"), "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toContain("cssGzipBytes");
  });

  it("recursively charges stylesheets imported by an external initial stylesheet", async () => {
    const fixture = await createFixture(1024);
    const noisy = Buffer.concat(Array.from({ length: 128 }, (_, index) => createHash("sha256")
      .update(`r126-nested-style-import-${index}`)
      .digest())).toString("base64");
    await mkdir(path.join(fixture.dist, "assets", "nested"), { recursive: true });
    await writeFile(path.join(fixture.dist, "assets", "app.css"), '@import "./nested/large.css";', "utf8");
    await writeFile(path.join(fixture.dist, "assets", "nested", "large.css"), `:root{--payload:"${noisy}"}`, "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as { exceeded: Array<{ name: string }> };
    expect(output.exceeded.map(({ name }) => name)).toContain("cssGzipBytes");
  });

  it("fails closed for an external import nested in an initial stylesheet", async () => {
    const fixture = await createFixture(1024);
    await writeFile(path.join(fixture.dist, "assets", "app.css"), '@import url("https://example.invalid/remote.css");', "utf8");

    const result = spawnSync(process.execPath, [SCRIPT, "--dist", fixture.dist, "--manifest", fixture.manifest], {
      cwd: ROOT, encoding: "utf8", shell: false,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("unsafe initial asset reference");
  });
});
