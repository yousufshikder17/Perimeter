import { createServer } from "node:http";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import type { Probe } from "@perimeter/sdk";
import { loadTargetModel } from "../../packages/core/src/target/loader.js";
import { parseScanConfig } from "../../packages/core/src/config/scan-config.js";
import { Orchestrator } from "../../packages/core/src/orchestrator.js";
import { ConsoleLogger } from "../../packages/core/src/runtime/logger.js";
import { createIsolatedProbe } from "../../packages/core/src/isolation/probe.js";
import { runProbeAgainstFixtures } from "../../packages/core/src/testing/harness.js";

const manifest = { id: "test/options", family: "test", version: "1", schemaVersion: "1", requires: {},
  safety: { class: "read-only" as const, maxRequests: 1, destructive: false },
  configSchema: { type: "object", properties: { path: { type: "string", enum: ["/health", "/other"] } }, required: ["path"], additionalProperties: false } };

it("validates before fixtures/hooks, delivers options to both lifecycle phases and harness, and rejects changed replay", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-options-"));
  let calls = 0;
  const server = createServer((_req, res) => { calls++; res.end("ready"); });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const probe: Probe = { manifest,
      async plan(ctx) { expect(ctx.options).toEqual({ path: "/health" }); expect(Object.isFrozen(ctx.options)).toBe(true); return { probeId: manifest.id, steps: [] }; },
      async run(_plan, ctx) { await ctx.http.get(String(ctx.options!.path)); ctx.report({ kind: "pass", probeId: manifest.id, family: "test", title: "options", summary: "configured request" }); } };
    const config = parseScanConfig({ target: path, include: [manifest.id], probeOptions: { [manifest.id]: { path: "/health" } },
      checkpoint: join(directory, "checkpoint.json"), output: { auditLog: join(directory, "audit.ndjson") } });
    const logger = new ConsoleLogger("error");
    // Invalid options must win over loading an invalid auth hook or making scratch traffic.
    const invalidTarget = { ...target, auth: { scheme: "custom", customHook: "missing-secret-hook.mjs" } };
    await writeFile(path, JSON.stringify(invalidTarget));
    await expect(new Orchestrator(parseScanConfig({ ...config, probeOptions: { [manifest.id]: { path: "secret-canary" } } }), [probe], { logger }).run()).rejects.toThrow("Invalid options");
    expect(calls).toBe(0);
    await writeFile(path, JSON.stringify(target));
    expect((await new Orchestrator(config, [probe], { logger }).run()).passes).toHaveLength(1);
    expect(calls).toBe(1);
    expect((await new Orchestrator({ ...config, resume: true }, [probe], { logger }).run()).passes).toHaveLength(1);
    await expect(new Orchestrator({ ...config, resume: true, probeOptions: { [manifest.id]: { path: "/other" } } }, [probe], { logger }).run()).rejects.toThrow("incompatible");
    expect(calls).toBe(1);
    const result = await runProbeAgainstFixtures(probe, { target, probeOptions: { path: "/health" }, fixtures: [{ match: { method: "GET", urlIncludes: "/health" }, respond: { status: 200 } }] });
    expect(result.requests).toHaveLength(1);
    await expect(runProbeAgainstFixtures(probe, { target, fixtures: [], probeOptions: { path: "bad" } })).rejects.toThrow("Invalid options");
    expect(await readFile(config.output.auditLog, "utf8")).not.toContain("secret-canary");
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); await rm(directory, { recursive: true, force: true }); }
});

it("passes only a worker's validated options through the command runner and real CLI; bad options never start it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-worker-options-"));
  try {
    const marker = join(directory, "started");
    const worker = join(directory, "worker.mjs");
    await writeFile(worker, `import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(marker)}, 'started');
for await (const line of createInterface({ input: process.stdin })) {
 const start = JSON.parse(line);
 if (start.type !== 'start' || JSON.stringify(start.options) !== '{"path":"/health"}') process.exit(9);
 process.stdout.write(JSON.stringify({ type: 'done', version: 1 }) + '\\n'); break;
}`);
    const isolated = { manifest, runner: { kind: "command", command: [process.execPath, worker], acknowledgeExternalSecurity: true } };
    const config = parseScanConfig({ target: resolve("examples/target.yaml"), include: [manifest.id], isolatedProbes: [isolated],
      probeOptions: { [manifest.id]: { path: "/health" } }, output: { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") } });
    const probe = createIsolatedProbe(isolated);
    await expect(new Orchestrator({ ...config, probeOptions: { [manifest.id]: { typo: true } } }, [probe]).run()).rejects.toThrow("Invalid options");
    await expect(readFile(marker)).rejects.toThrow();
    const scan = join(directory, "scan.json"); await writeFile(scan, JSON.stringify(config));
    await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "scan", "--config", scan]);
    expect(await readFile(marker, "utf8")).toBe("started");
    expect(JSON.parse(await readFile(config.output.json, "utf8")).skipped.some((entry: { probeId: string }) => entry.probeId === manifest.id)).toBe(false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
