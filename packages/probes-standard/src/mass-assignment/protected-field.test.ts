import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";
import { loadTargetModel, runProbeAgainstFixtures, Orchestrator, parseScanConfig, ConsoleLogger } from "@perimeter/core";
import { massAssignment } from "./protected-field.js";

async function model(): Promise<TargetModel> {
  const original = await loadTargetModel("examples/target.yaml");
  const objectRef = { param: "id", kind: "note", ownership: "user" };
  return parseTargetModel({ ...original,
    identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "PERIMETER_MASS_TEST" } }],
    endpoints: [
      { id: "update", method: "PATCH", path: "/notes/{id}", objectRef,
        massAssignment: { identity: "owner", readEndpointId: "read",
          control: { field: "label", value: "checked", resultPath: ["label"] },
          protected: { field: "approved", value: true, resultPath: ["approved"] } } },
      { id: "read", method: "GET", path: "/notes/{id}", objectRef },
      { id: "create", method: "POST", path: "/notes", creates: "note", fixture: { body: { label: "initial", approved: false } } },
      { id: "delete", method: "DELETE", path: "/notes/{id}", objectRef },
    ], authorization: { ...original.authorization, rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } },
  });
}

it("does not request or report anything without the owner scratch object", async () => {
  const result = await runProbeAgainstFixtures(massAssignment, { target: await model(), fixtures: [] });
  expect(result.requests).toEqual([]); expect(result.reports).toEqual([]);
});

it("proves persisted over-posting, rejects false positives, and exercises CLI opt-in, budgets, capture, cleanup and replay refusal", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-mass-"));
  const real = { id: "real", label: "untouched", approved: false };
  const objects = new Map<string, Record<string, unknown>>([["real", { ...real }]]);
  const patches: Array<{ id: string; body: Record<string, unknown> }> = [];
  const requests: string[] = [];
  let serial = 0;
  let reads = 0;
  let mode = "vulnerable";
  vi.stubEnv("PERIMETER_MASS_TEST", "private-mass-credential");
  const server = createServer(async (req, res) => {
    requests.push(`${req.method} ${req.url}`);
    res.setHeader("content-type", "application/json");
    if (req.headers.authorization !== "Bearer private-mass-credential") { res.statusCode = 401; res.end('{}'); return; }
    let text = ""; for await (const chunk of req) text += String(chunk);
    if (req.method === "POST") {
      if (mode === "no-fixture") { res.statusCode = 422; res.end('{}'); return; }
      const id = `scratch-${++serial}`;
      objects.set(id, { ...JSON.parse(text), id, ...(mode === "already-set" ? { approved: true } : {}) });
      res.statusCode = 201; res.end(JSON.stringify({ id })); return;
    }
    const id = req.url!.split("/").pop()!;
    const object = objects.get(id);
    if (!object) { res.statusCode = 404; res.end('{}'); return; }
    if (req.method === "DELETE") { objects.delete(id); res.statusCode = 204; res.end(); return; }
    if (req.method === "GET") {
      reads++;
      if (mode === "oversized") { res.end("x".repeat(16385)); return; }
      if (mode === "read-error") { res.statusCode = 500; res.end('{}'); return; }
      if (mode === "cached") res.setHeader("age", "10");
      if (mode === "malformed-verify" && reads === 3) { res.end('{"id":'); return; }
      res.end(JSON.stringify({ ...object,
        ...(mode === "wrong-id" ? { id: "real" } : {}),
        ...(mode === "redacted" ? { label: "Bearer sensitive-value" } : {}),
        ...(mode === "missing-field" ? { approved: undefined } : {}),
      })); return;
    }
    if (req.method === "PATCH") {
      const body = JSON.parse(text) as Record<string, unknown>;
      patches.push({ id, body });
      if (mode !== "bad-control") object.label = body.label;
      if (mode === "control-side-effect") object.approved = true;
      if (Object.hasOwn(body, "approved")) {
        if (["vulnerable", "persisted-error", "malformed-verify"].includes(mode)) object.approved = body.approved;
        if (mode === "unexpected-value") object.approved = "unknown";
        if (mode === "denied") res.statusCode = 403;
        if (mode === "rejected") res.statusCode = 422;
        if (["server-error", "persisted-error"].includes(mode)) res.statusCode = 500;
        if (mode === "async") res.statusCode = 202;
      }
      // Reflecting the entire request must not by itself produce a finding.
      res.end(JSON.stringify(body)); return;
    }
    res.statusCode = 405; res.end('{}');
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = await model(); target.baseUrl = `http://127.0.0.1:${address.port}`;
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["mass-assignment"], allowMutating: true, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    const fingerprints = new Set<string>();
    for (mode of ["vulnerable", "patched", "denied", "rejected", "persisted-error", "server-error", "async", "bad-control",
      "control-side-effect", "already-set", "wrong-id", "missing-field", "redacted", "read-error", "cached", "unexpected-value", "malformed-verify", "oversized", "no-fixture"]) {
      reads = 0; patches.length = 0; requests.length = 0;
      const result = await new Orchestrator(config, [massAssignment], { logger }).run();
      expect(result.findings, mode).toHaveLength(["vulnerable", "persisted-error"].includes(mode) ? 1 : 0);
      expect(result.passes, mode).toHaveLength(["patched", "denied", "rejected"].includes(mode) ? 1 : 0);
      expect(objects.size, mode).toBe(1);
      expect(objects.get("real")).toEqual(real);
      expect(patches.every((p) => p.id.startsWith("scratch-"))).toBe(true);
      if (result.findings.length) {
        fingerprints.add(result.findings[0]!.fingerprint);
        expect(result.findings[0]!.evidence.exchanges).toHaveLength(5);
        expect(patches.map((p) => p.body)).toEqual([{ label: "checked" }, { label: "checked", approved: true }]);
      }
      if (["bad-control", "control-side-effect"].includes(mode)) expect(patches).toHaveLength(1);
      if (["already-set", "wrong-id", "missing-field", "redacted", "read-error", "cached", "oversized", "no-fixture"].includes(mode)) expect(patches).toEqual([]);
    }
    expect(fingerprints.size).toBe(1);
    mode = "vulnerable"; patches.length = 0; requests.length = 0;
    const disabled = await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [massAssignment], { logger }).run();
    expect(disabled.skipped[0]!.reason).toContain("--allow-mutating"); expect(requests).toEqual([]);
    await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: join(directory, "state.json") }), [massAssignment], { logger }).run()).rejects.toThrow("read-only");
    expect(requests).toEqual([]);
    const limited = await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 6 }), [massAssignment], { logger }).run();
    expect(limited.findings).toEqual([]); expect(limited.passes).toEqual([]); expect(patches).toEqual([]); expect(objects.size).toBe(1);
    const hidden = await new Orchestrator(config, [massAssignment], { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(patches).toEqual([]); expect(objects.size).toBe(1);
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, allowMutating: false }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    requests.length = 0;
    await promisify(execFile)(process.execPath, cli);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toEqual([]); expect(requests).toEqual([]);
    await promisify(execFile)(process.execPath, [...cli, "--allow-mutating"]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect(objects.size).toBe(1); expect(objects.get("real")).toEqual(real);
    expect(await readFile(output.auditLog, "utf8")).not.toContain("private-mass-credential");
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
