import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);

it("compiles an external consumer against the SDK archive and runs its public lifecycle through the harness and CLI", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-sdk-compat-"));
  let requests = 0;
  const server = createServer((_req, res) => { requests++; res.end("ready"); });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  try {
    const pnpm = process.env.npm_execpath;
    if (!pnpm) throw new Error("Run compatibility checks through pnpm test");
    const consumer = join(directory, "consumer");
    await cp(resolve("tests/fixtures/sdk-consumer"), consumer, { recursive: true });
    await execute(process.execPath, [pnpm, "--dir", resolve("packages/sdk"), "pack", "--pack-destination", directory]);
    const archives = (await readdir(directory)).filter(name => name.endsWith(".tgz"));
    expect(archives).toHaveLength(1);
    const installedSdk = join(consumer, "node_modules/@perimeter/sdk");
    await mkdir(installedSdk, { recursive: true });
    await execute("tar", ["-xf", join(directory, archives[0]!), "-C", installedSdk, "--strip-components=1"]);
    const sdkPackage = JSON.parse(await readFile(join(installedSdk, "package.json"), "utf8"));
    expect(Object.keys(sdkPackage.exports).sort()).toEqual([".", "./finding", "./manifest", "./target-model"]);
    await expect(readFile(join(installedSdk, "src/index.ts"))).rejects.toThrow();
    // Copy only declared, installed SDK dependencies. No workspace links, installs or registry access.
    for (const name of Object.keys(sdkPackage.dependencies)) {
      const dependency = await realpath(resolve("packages/sdk/node_modules", name));
      const metadata = JSON.parse(await readFile(join(dependency, "package.json"), "utf8"));
      expect(Object.keys(metadata.dependencies ?? {}), `Review dependency closure for ${name}`).toEqual([]);
      await cp(dependency, join(consumer, "node_modules", name), { recursive: true });
    }
    const compile = () => execute(process.execPath, [resolve("node_modules/typescript/bin/tsc"), "--project", join(consumer, "tsconfig.json")], { cwd: consumer });
    await compile();
    const declarations = await readFile(join(consumer, "dist/probe.d.ts"), "utf8");
    expect(declarations).toContain("ProbePackage");
    expect(declarations).not.toContain("@perimeter/sdk/dist/");
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = { name: "sdk-compatibility", baseUrl: `http://127.0.0.1:${address.port}`, auth: { scheme: "bearer" },
      identities: [{ ref: "member", tenant: "one", role: "member" }],
      tenancy: { model: "header_scoped", discriminator: { location: "header", name: "x-tenant" }, tenants: ["one"] },
      endpoints: [{ id: "health", method: "GET", path: "/health", auth: "none" }],
      authorization: { iAmAuthorizedToTest: true, environment: "local", contact: "compatibility-fixture", rateLimit: { globalRps: 100, perHostRps: 100, burst: 100 } } };
    const harness = `import assert from 'node:assert/strict';
import { checkExports, probe } from '@perimeter-compat/consumer';
import { SDK_VERSION, parseTargetModel } from '@perimeter/sdk';
import { runProbeAgainstFixtures } from ${JSON.stringify(pathToFileURL(resolve("packages/core/dist/index.js")).href)};
checkExports(); assert.equal(SDK_VERSION, ${JSON.stringify(sdkPackage.version)});
await assert.rejects(import('@perimeter/sdk/dist/index.js'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
const target = parseTargetModel(${JSON.stringify(target)});
for (const mode of ['pass', 'finding', 'skip']) {
 const result = await runProbeAgainstFixtures(probe, { target, probeOptions: { mode }, fixtures: [{ match: { method: 'GET', urlIncludes: '/health' }, respond: { status: 200 } }] });
 assert.equal(result.requests.length, mode === 'skip' ? 0 : 1);
 assert.equal(result.reports.length, mode === 'skip' ? 0 : 1);
 if (mode === 'skip') assert.equal(result.skipped, 'configured compatibility skip');
 else if (mode === 'pass') assert.equal(result.reports[0].kind, 'pass');
 else assert.equal(result.reports[0].evidence.exchanges.length, 1);
}
await assert.rejects(runProbeAgainstFixtures(probe, { target, probeOptions: { mode: 'invalid' }, fixtures: [] }), /Invalid options/);
assert.equal((await runProbeAgainstFixtures(probe, { target, fixtures: [{ match: { method: 'GET', urlIncludes: '/health' }, respond: { status: 200 } }] })).reports.length, 1);`;
    await writeFile(join(consumer, "verify.mjs"), harness);
    await execute(process.execPath, [join(consumer, "verify.mjs")], { cwd: consumer });
    expect(requests).toBe(0);

    // Host uses its built runtime; the external plugin keeps its own archived SDK copy.
    const host = join(directory, "host");
    await cp(resolve("packages/cli/dist"), join(host, "dist"), { recursive: true });
    await cp(resolve("packages/cli/package.json"), join(host, "package.json"));
    const cliPackage = JSON.parse(await readFile("packages/cli/package.json", "utf8"));
    for (const name of [...Object.keys(cliPackage.dependencies), "@perimeter-compat/consumer"]) {
      const destination = join(host, "node_modules", name);
      await mkdir(dirname(destination), { recursive: true });
      const source = name === "@perimeter-compat/consumer" ? consumer : await realpath(resolve("packages/cli/node_modules", name));
      await symlink(source, destination, process.platform === "win32" ? "junction" : "dir");
    }
    await writeFile(join(directory, "target.json"), JSON.stringify(target));
    const scanPath = join(directory, "scan.json");
    const json = join(directory, "findings.json");
    for (const mode of ["pass", "finding", "skip", "invalid"]) {
      await writeFile(scanPath, JSON.stringify({ target: join(directory, "target.json"), probePaths: ["@perimeter-compat/consumer"],
        include: ["compat/consumer"], probeOptions: { "compat/consumer": { mode } }, failOn: "HIGH",
        output: { json, markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") } }));
      const code = await execute(process.execPath, [join(host, "dist/bin.js"), "scan", "--config", scanPath], { cwd: directory }).then(() => 0, error => error.code);
      expect(code).toBe(mode === "finding" || mode === "invalid" ? 1 : 0);
      if (mode !== "invalid") {
        const result = JSON.parse(await readFile(json, "utf8"));
        expect(result.findings).toHaveLength(mode === "finding" ? 1 : 0);
        expect(result.passes).toHaveLength(mode === "pass" ? 1 : 0);
        expect(result.skipped.some((entry: { probeId: string; reason: string }) => entry.probeId === "compat/consumer" && entry.reason === "configured compatibility skip")).toBe(mode === "skip");
        if (mode === "finding") expect(result.findings[0].evidence.exchanges[0].response.status).toBe(200);
      }
    }
    expect(requests).toBe(2);
    // Mutation control: a missing shipped declaration must fail this standalone build.
    await rm(join(installedSdk, "dist/index.d.ts"));
    await expect(compile()).rejects.toThrow();
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
}, 60000);
