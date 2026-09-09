import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import type { Probe } from "@perimeter/sdk";
import { ScanCheckpoint, CheckpointError } from "./checkpoint.js";
import { loadTargetModel } from "../target/loader.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";
import { ConsoleLogger } from "./logger.js";

it("resumes completed results, retries interrupted probes, and retains request ceilings before traffic", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-resume-"));
  let requests = 0;
  const server = createServer((_req, res) => { requests++; res.end('{}'); });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.endpoints = [{ id: "profile", method: "GET", path: "/profile", auth: "none", tenantScoped: false, rateSensitive: false }];
    target.authorization.rateLimit = { globalRps: 1000, perHostRps: 1000, burst: 1000 };
    const targetPath = join(directory, "target.json");
    await writeFile(targetPath, JSON.stringify(target));
    const config = parseScanConfig({ target: targetPath, checkpoint: join(directory, "checkpoint.json"),
      concurrency: 1, maxTotalRequests: 3, output: { auditLog: join(directory, "audit.ndjson") } });
    const controller = new AbortController();
    let interrupt = true;
    const runs: string[] = [];
    const probes: Probe[] = ["first", "second"].map((name) => ({
      manifest: { id: `test/${name}`, family: "test", version: "1", schemaVersion: "1.0", requires: {},
        safety: { class: "read-only", maxRequests: 3, destructive: false } },
      async plan() { return { probeId: `test/${name}`, steps: [] }; },
      async run(_plan, ctx) {
        runs.push(name);
        const response = await ctx.http.get("/profile");
        ctx.report({ kind: "pass", probeId: `test/${name}`, family: "test", title: name, summary: "Local response observed" });
        if (name === "second") {
          if (interrupt) { controller.abort(); return; }
          await expect(ctx.http.get("/profile")).rejects.toThrow("budget exhausted");
          ctx.report({ id: "local-finding", fingerprint: "local-fingerprint", schemaVersion: "1.0", probeId: "test/second",
            family: "test", title: "Test evidence", severity: "INFO", confidence: "FIRM",
            target: { endpointId: "profile", method: "GET", path: "/profile" }, affectedIdentities: [],
            evidence: { summary: "Local test only", exchanges: [response.exchange], auditRefs: [response.exchange.ref],
              reproduction: { seed: "test", steps: ["GET /profile"] } },
            remediation: { guidance: "Test only", references: [] }, firstSeen: "2026-09-09", lastSeen: "2026-09-09", status: "open" });
        }
      },
    }));
    const logger = new ConsoleLogger("error");
    await expect(new Orchestrator(config, probes, { logger, signal: controller.signal }).run()).rejects.toThrow();
    const saved = JSON.parse(await readFile(config.checkpoint!, "utf8"));
    expect(saved.used).toBe(2);
    expect(saved.completed.map((r: { probeId: string }) => r.probeId)).toEqual(["test/first"]);
    expect(saved.completed[0].passes).toHaveLength(1);
    interrupt = false;
    const resumedConfig = parseScanConfig({ ...config, resume: true });
    const result = await new Orchestrator(resumedConfig, probes, { logger }).run();
    expect(result).toMatchObject({ scanId: saved.scanId, seed: saved.seed, startedAt: saved.startedAt });
    expect(result.passes).toHaveLength(2);
    expect(result.findings).toHaveLength(1);
    expect(requests).toBe(3);
    expect(runs).toEqual(["first", "second", "second"]);
    expect((await new Orchestrator(resumedConfig, probes, { logger }).run()).findings).toEqual(result.findings);
    expect(requests).toBe(3);
    const audit = (await readFile(config.output.auditLog, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    expect(audit.map((entry) => entry.seq)).toEqual([0, 1, 2]);
    await expect(new Orchestrator(config, probes, { logger }).run()).rejects.toThrow(CheckpointError);
    await expect(new Orchestrator(parseScanConfig({ ...resumedConfig, maxTotalRequests: 4 }), probes, { logger }).run())
      .rejects.toThrow(CheckpointError);
    await writeFile(config.checkpoint!, "invalid");
    await expect(new Orchestrator(resumedConfig, probes, { logger }).run()).rejects.toThrow(CheckpointError);
    expect(requests).toBe(3);

    const failure = vi.spyOn(ScanCheckpoint.prototype, "reserve").mockRejectedValue(new CheckpointError("disk failure"));
    try {
      await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: join(directory, "failure.json") }), probes, { logger }).run())
        .rejects.toThrow("disk failure");
      expect(requests).toBe(3);
    } finally { failure.mockRestore(); }
    await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: config.output.auditLog }), probes).run())
      .rejects.toThrow("separate");
    await expect(new Orchestrator(config, [{ ...probes[0]!, manifest: { ...probes[0]!.manifest,
      safety: { class: "idempotent-write", maxRequests: 1, destructive: false } } }]).run()).rejects.toThrow("read-only");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);

it("locks checkpoints, serializes reservations, rejects missing state, and resumes through the CLI", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-checkpoint-"));
  try {
    const path = join(directory, "state.json");
    const meta = { scanId: "test", seed: "test", startedAt: "test" };
    await expect(ScanCheckpoint.open(path, true, {}, meta)).rejects.toThrow(CheckpointError);
    const checkpoint = await ScanCheckpoint.open(path, false, {}, meta);
    try {
      await expect(ScanCheckpoint.open(path, true, {}, meta)).rejects.toThrow("locked");
      await Promise.all([checkpoint.reserve(1), checkpoint.reserve(3), checkpoint.reserve(2)]);
      expect(JSON.parse(await readFile(path, "utf8")).used).toBe(3);
    } finally { await checkpoint.release(); }
    expect(() => parseScanConfig({ target: "target.yaml", resume: true })).toThrow("checkpoint");
    const configPath = join(directory, "scan.json");
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    await writeFile(configPath, JSON.stringify({ target: resolve("examples/target.yaml"), include: ["test/not-installed"],
      checkpoint: join(directory, "cli.json"), output }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    await promisify(execFile)(process.execPath, cli);
    const original = JSON.parse(await readFile(output.json, "utf8"));
    await promisify(execFile)(process.execPath, [...cli, "--resume"]);
    expect(JSON.parse(await readFile(output.json, "utf8")).scanId).toBe(original.scanId);
  } finally { await rm(directory, { recursive: true, force: true }); }
}, 20000);
