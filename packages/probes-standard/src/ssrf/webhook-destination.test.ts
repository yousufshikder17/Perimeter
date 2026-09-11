import { createServer } from "node:http";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel, Orchestrator, parseScanConfig, ConsoleLogger, startCallbackCollector } from "@perimeter/core";
import { webhookDestination } from "./webhook-destination.js";

it("proves actual forbidden callbacks with a positive control, opt-in, scratch cleanup, CLI and false-positive controls", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-ssrf-"));
  const receiptFile = join(directory, "receipts.ndjson");
  const collector = await startCallbackCollector({ receiptFile, controlPort: 0, prohibitedPort: 0 });
  const objects = new Set(["real"]);
  const requests: string[] = [];
  const dispatches: Array<{ id: string; url: string }> = [];
  let serial = 0;
  let mode = "vulnerable";
  vi.stubEnv("PERIMETER_WEBHOOK_TEST", "private-webhook-credential");
  const server = createServer(async (req, res) => {
    requests.push(`${req.method} ${req.url}`);
    res.setHeader("content-type", "application/json");
    if (req.headers.authorization !== "Bearer private-webhook-credential") { res.writeHead(401).end('{}'); return; }
    let text = ""; for await (const chunk of req) text += String(chunk);
    if (req.method === "POST" && req.url === "/webhooks") {
      if (mode === "no-fixture") { res.writeHead(422).end('{}'); return; }
      const id = `scratch-${++serial}`; objects.add(id); res.writeHead(201).end(JSON.stringify({ id })); return;
    }
    const id = req.url?.split("/")[2] ?? "";
    if (!objects.has(id)) { res.writeHead(404).end('{}'); return; }
    if (req.method === "DELETE") { objects.delete(id); res.writeHead(204).end(); return; }
    if (req.method !== "POST" || !req.url?.endsWith("/test")) { res.writeHead(405).end('{}'); return; }
    const body = JSON.parse(text) as { callbackUrl: string; event: string };
    const url = new URL(body.callbackUrl);
    dispatches.push({ id, url: url.href });
    const allowed = url.origin === collector.controlOrigin;
    // This test target may contact only these two ephemeral owned listeners.
    if (![collector.controlOrigin, collector.prohibitedOrigin].includes(url.origin)) { res.writeHead(422).end('{}'); return; }
    if ((allowed && mode === "missing-control") || (!allowed && ["accepted-without-delivery", "server-error"].includes(mode))) {
      res.writeHead(mode === "server-error" ? 500 : 202).end(JSON.stringify(body)); return;
    }
    if (!allowed && ["denied", "rejected"].includes(mode)) { res.writeHead(mode === "denied" ? 403 : 422).end('{}'); return; }
    if (!allowed && mode === "wrong-token") url.pathname = `/perimeter-callback/${"a".repeat(32)}`;
    await fetch(url, { method: "POST", body: "harmless callback" });
    if (mode === "invalid-receipt") await appendFile(receiptFile, '{"invalid":true}\n');
    res.writeHead((allowed && mode === "control-error") || (!allowed && mode === "delivered-error") ? 500 : 200).end(JSON.stringify(body));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const original = await loadTargetModel("examples/target.yaml");
    const objectRef = { param: "id", kind: "webhook", ownership: "user" };
    const target = parseTargetModel({ ...original, baseUrl: `http://127.0.0.1:${address.port}`,
      identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "PERIMETER_WEBHOOK_TEST" } }],
      endpoints: [{ id: "create", method: "POST", path: "/webhooks", creates: "webhook" },
        { id: "delete", method: "DELETE", path: "/webhooks/{id}", objectRef },
        { id: "dispatch", method: "POST", path: "/webhooks/{id}/test", objectRef,
          webhook: { identity: "owner", urlField: "callbackUrl", body: { event: "perimeter-canary" },
            controlOrigin: collector.controlOrigin, prohibitedOrigin: collector.prohibitedOrigin, receiptFile: "receipts.ndjson",
            iOwnBothDestinations: true, prohibitedByPolicy: true, timeoutMs: 100 } }],
      authorization: { ...original.authorization, environment: "local", rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["ssrf"], allowMutating: true, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    const fingerprints = new Set<string>();
    for (mode of ["vulnerable", "denied", "rejected", "delivered-error", "accepted-without-delivery", "server-error",
      "missing-control", "control-error", "wrong-token", "no-fixture", "invalid-receipt"]) {
      dispatches.length = 0;
      const result = await new Orchestrator(config, [webhookDestination], { logger }).run();
      expect(result.findings, mode).toHaveLength(["vulnerable", "delivered-error"].includes(mode) ? 1 : 0);
      expect(result.passes, mode).toHaveLength(["denied", "rejected"].includes(mode) ? 1 : 0);
      expect([...objects], mode).toEqual(["real"]);
      expect(dispatches.every((d) => d.id.startsWith("scratch-"))).toBe(true);
      if (["missing-control", "control-error"].includes(mode)) expect(dispatches).toHaveLength(1);
      if (result.findings.length) {
        const finding = result.findings[0]!; fingerprints.add(finding.fingerprint);
        expect(finding.evidence.exchanges).toHaveLength(4);
        expect(finding.evidence.exchanges.filter((e) => e.direction === "incoming")).toHaveLength(2);
        const audit = (await readFile(output.auditLog, "utf8")).trim().split("\n").map((line) => JSON.parse(line).ref);
        expect(finding.evidence.auditRefs.every((ref) => audit.includes(ref))).toBe(true);
      }
    }
    expect(fingerprints.size).toBe(1);
    mode = "vulnerable"; requests.length = 0; dispatches.length = 0;
    const disabled = await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [webhookDestination], { logger }).run();
    expect(disabled.skipped[0]!.reason).toContain("--allow-mutating"); expect(requests).toEqual([]);
    await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: join(directory, "state.json") }), [webhookDestination], { logger }).run()).rejects.toThrow("read-only");
    expect(requests).toEqual([]);
    const limited = await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 3 }), [webhookDestination], { logger }).run();
    expect(limited.findings).toEqual([]); expect(dispatches).toEqual([]); expect([...objects]).toEqual(["real"]);
    const hidden = await new Orchestrator(config, [webhookDestination], { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(dispatches).toHaveLength(1);
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, allowMutating: false }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    requests.length = 0;
    await promisify(execFile)(process.execPath, cli); expect(requests).toEqual([]);
    await promisify(execFile)(process.execPath, [...cli, "--allow-mutating"]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect([...objects]).toEqual(["real"]);
    expect(await readFile(output.auditLog, "utf8")).not.toContain("private-webhook-credential");
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await collector.stop(); await rm(directory, { recursive: true, force: true });
  }
}, 20000);
