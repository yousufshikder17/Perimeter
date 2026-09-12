import { createServer } from "node:http";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);
const cli = resolve("packages/cli/dist/bin.js");
const generatedFiles = ["config.schema.json", "manifest.ts", "package.json", "probe.test.ts", "probe.ts"];

it("generates a typechecked, fixture-tested loadable package from the shipped CLI and templates", async () => {
  // Stay inside the existing project so generated sources resolve its SDK/core/toolchain.
  const directory = await mkdtemp(join(resolve("packages/cli"), ".perimeter-scaffold-"));
  let calls = 0;
  const server = createServer((_req, res) => { calls++; res.end("ready"); });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const bundle = join(directory, "bundle");
    await cp(resolve("packages/cli/dist"), join(bundle, "dist"), { recursive: true });
    await cp(resolve("packages/cli/templates"), join(bundle, "templates"), { recursive: true });
    await cp(resolve("packages/cli/package.json"), join(bundle, "package.json"));
    const output = join(directory, "probes");
    await execute(process.execPath, [join(bundle, "dist/bin.js"), "probe", "new", "diagnostics/1-read", "--dir", output], { cwd: directory });
    const scaffold = join(output, "diagnostics", "1-read");
    expect((await readdir(scaffold)).sort()).toEqual(generatedFiles);
    const schema = JSON.parse(await readFile(join(scaffold, "config.schema.json"), "utf8"));
    expect(schema).toMatchObject({ title: "diagnostics/1-read configuration", type: "object", properties: {}, additionalProperties: false });
    const pkg = JSON.parse(await readFile(join(scaffold, "package.json"), "utf8"));
    expect(pkg).toMatchObject({ private: true, type: "module" });
    // Exercise the actual generated build/test script under the same pnpm as CI.
    const pnpm = process.env.npm_execpath;
    if (!pnpm) throw new Error("Run scaffold integration through pnpm test so the package runner is available");
    const tested = await execute(process.execPath, [pnpm, "--dir", scaffold, "test"]);
    expect(tested.stdout).toMatch(/pass 3/);
    await execute(process.execPath, [cli, "probe", "lint", scaffold]);
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = { name: "scaffold-live", baseUrl: `http://127.0.0.1:${address.port}`, auth: { scheme: "bearer" },
      identities: [{ ref: "member", tenant: "one" }], tenancy: { model: "header_scoped", discriminator: { location: "header", name: "x-tenant" }, tenants: ["one"] },
      endpoints: [{ id: "health", method: "GET", path: "/health", auth: "none" }],
      authorization: { iAmAuthorizedToTest: true, environment: "local", contact: "test", rateLimit: { globalRps: 100, perHostRps: 100, burst: 100 } } };
    const targetPath = join(directory, "target.json"); await writeFile(targetPath, JSON.stringify(target));
    const json = join(directory, "findings.json");
    const scan = join(directory, "scan.json"); await writeFile(scan, JSON.stringify({ target: targetPath,
      probePaths: [join(scaffold, "dist/probe.js")], include: ["diagnostics/1-read"],
      output: { json, markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") }, failOn: "none" }));
    expect(calls).toBe(0);
    await execute(process.execPath, [cli, "scan", "--config", scan]).catch((error) => { throw new Error(`${error.stdout}\n${error.stderr}`); });
    const result = JSON.parse(await readFile(json, "utf8"));
    expect(calls).toBe(1); expect(result.findings).toEqual([]); expect(result.passes).toHaveLength(1);
    expect(result.passes[0].probeId).toBe("diagnostics/1-read");
    expect(result.passes[0].summary).toContain("not evidence of security");
    const installed = join(bundle, "node_modules/@scaffold/example");
    await cp(join(scaffold, "dist"), installed, { recursive: true });
    await writeFile(join(installed, "package.json"), JSON.stringify({ name: "@scaffold/example", type: "module", exports: "./probe.js" }));
    const scoped = JSON.parse(await readFile(scan, "utf8")); scoped.probePaths = ["@scaffold/example"];
    await writeFile(scan, JSON.stringify(scoped));
    await execute(process.execPath, [join(bundle, "dist/bin.js"), "scan", "--config", scan]).catch((error) => { throw new Error(`${error.stdout}\n${error.stderr}`); });
    expect(calls).toBe(2);
  } finally { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
});

it("rejects unsafe names, duplicate/concurrent destinations and redirected family directories without overwriting files", async () => {
  const directory = await mkdtemp(join(resolve("."), ".perimeter-scaffold-"));
  try {
    const output = join(directory, "probes");
    const generate = (ref: string, root = output) => execute(process.execPath, [cli, "probe", "new", ref, "--dir", root]);
    for (const ref of ["../escape", "auth/name/extra", "auth/../name", "auth/name';bad", "auth/con", "nul/test", "auth/name--part"]) {
      await expect(generate(ref)).rejects.toThrow();
    }
    expect(await readdir(directory)).toEqual([]);
    await generate("auth/example");
    const original = join(output, "auth/example/probe.ts");
    await writeFile(original, "// user-owned edit\n");
    await expect(generate("auth/example")).rejects.toThrow();
    expect(await readFile(original, "utf8")).toBe("// user-owned edit\n");
    const concurrent = await Promise.allSettled([generate("auth/concurrent"), generate("auth/concurrent")]);
    expect(concurrent.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await readdir(join(output, "auth/concurrent"))).sort()).toEqual(generatedFiles);
    const outside = join(directory, "outside"); const links = join(directory, "links");
    await mkdir(outside); await mkdir(links);
    await symlink(outside, join(links, "auth"), process.platform === "win32" ? "junction" : "dir");
    await expect(generate("auth/escape", links)).rejects.toThrow();
    expect(await readdir(outside)).toEqual([]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
