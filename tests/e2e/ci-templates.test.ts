import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { loadTargetModel } from "../../packages/core/src/target/loader.js";

const require = createRequire(resolve("packages/core/package.json"));
const { parse } = require("yaml") as { parse: (text: string) => Record<string, any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
const runner = resolve("ci/run-scan.mjs");
const artifacts = ["findings.json", "report.md", "report.html", "report.sarif", "report.junit.xml"];

it("keeps both CI templates blocking, artifact-limited and wired to the same tested CLI runner", async () => {
  const gitlab = parse(await readFile("ci/gitlab.yml", "utf8")).perimeter;
  expect(gitlab.script).toEqual(["node ci/run-scan.mjs"]);
  expect(gitlab.allow_failure).toBe(false);
  expect(gitlab.rules).toEqual([{ if: '$CI_COMMIT_REF_PROTECTED == "true"', when: "manual" }, { when: "never" }]);
  expect(gitlab.artifacts).toMatchObject({ when: "always", access: "developer", expire_in: "7 days", reports: { junit: ".perimeter-ci/report.junit.xml" } });
  expect(gitlab.artifacts.paths).toEqual(artifacts.map(name => `.perimeter-ci/${name}`));
  const jenkins = await readFile("ci/Jenkinsfile", "utf8");
  expect(jenkins).toContain("sh 'node ci/run-scan.mjs'");
  expect(jenkins).toMatch(/post\s*\{\s*always\s*\{/);
  expect(jenkins).toContain("skipMarkingBuildUnstable: true");
  expect(jenkins).toContain("deleteDir(); checkout scm");
  expect(jenkins).toContain("input message:");
  expect(jenkins).not.toMatch(/catchError|returnStatus|\|\| true/);
  expect(jenkins).toContain(artifacts.map(name => `.perimeter-ci/${name}`).join(","));
  expect(jenkins).not.toContain("audit.ndjson");
});

it("preserves real CLI gates and artifacts, clears stale evidence on failure and refuses symlink outputs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-ci-test-"));
  let calls = 0;
  const server = createServer((_req, res) => { calls++; res.end("fixture"); });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = await loadTargetModel("examples/target.yaml"); target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.endpoints = [{ id: "health", path: "/health", method: "GET", auth: "none", tenantScoped: false, rateSensitive: false }];
    await writeFile(join(directory, "target.json"), JSON.stringify(target));
    await writeFile(join(directory, "probe.mjs"), `export const perimeter = { probes: [{
manifest: { id: 'test/ci', family: 'test', version: '1', schemaVersion: '1', requires: {}, safety: { class: 'read-only', maxRequests: 1, destructive: false } },
async plan() { return { probeId: 'test/ci', steps: [] }; },
async run(plan, ctx) { const response = await ctx.http.get('/health'); ctx.report({
id: 'ci-fixture', fingerprint: 'ci-fixture', schemaVersion: '1.0', probeId: 'test/ci', family: 'test', title: 'Fixture evidence', severity: 'HIGH', confidence: 'FIRM',
target: { endpointId: 'health', method: 'GET', path: '/health' }, affectedIdentities: [],
evidence: { summary: 'Synthetic finding for gate regression', exchanges: [response.exchange], auditRefs: [response.exchange.ref], reproduction: { seed: 'ci', steps: ['GET /health'] } },
remediation: { guidance: 'Fixture only', references: [] }, status: 'open', firstSeen: '2026-09-16', lastSeen: '2026-09-16' }); }
}] };`);
    const configPath = join(directory, "scan.json");
    const config = { target: "target.json", probePaths: ["./probe.mjs"], include: ["test/ci"], failOn: "HIGH" };
    await writeFile(configPath, JSON.stringify(config));
    const run = () => promisify(execFile)(process.execPath, [runner], { cwd: directory, env: { ...process.env, PERIMETER_SCAN_CONFIG: configPath } }).then(() => 0, error => error.code);
    expect(await run()).toBe(1); expect(calls).toBe(1);
    const output = join(directory, ".perimeter-ci");
    for (const name of artifacts) expect((await readFile(join(output, name), "utf8")).length).toBeGreaterThan(0);
    expect(JSON.parse(await readFile(join(output, "findings.json"), "utf8")).findings).toHaveLength(1);
    await writeFile(configPath, JSON.stringify({ ...config, failOn: "none" }));
    expect(await run()).toBe(0); expect(calls).toBe(2);
    const original = await readFile(join(output, "findings.json"), "utf8");
    const alias = process.platform === "win32" ? ".PERIMETER-CI/FINDINGS.JSON" : ".perimeter-ci/findings.json";
    await writeFile(configPath, JSON.stringify({ ...config, target: alias }));
    expect(await run()).toBe(1); expect(calls).toBe(2);
    expect(await readFile(join(output, "findings.json"), "utf8")).toBe(original);
    await writeFile(configPath, JSON.stringify({ ...config, checkpoint: "checkpoint.json" }));
    expect(await run()).toBe(1); expect(calls).toBe(2);
    expect(await readdir(output)).toEqual([]);
    await writeFile(join(output, "unrelated.txt"), "keep");
    await writeFile(configPath, "invalid-json-secret-canary");
    expect(await run()).toBe(1); expect(calls).toBe(2);
    expect(await readdir(output)).toEqual(["unrelated.txt"]);
    const sentinel = join(directory, "sentinel.txt"); await writeFile(sentinel, "keep");
    // A directory alias is portable on Windows without symlink privileges.
    const outside = await mkdtemp(join(directory, "outside-"));
    await rm(output, { recursive: true });
    await symlink(outside, output, process.platform === "win32" ? "junction" : "dir");
    expect(await run()).toBe(1);
    expect(await readdir(outside)).toEqual([]);
    expect(await readFile(sentinel, "utf8")).toBe("keep");
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
}, 30000);
