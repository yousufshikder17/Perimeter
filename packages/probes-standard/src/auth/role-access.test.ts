import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { FindingSchema, parseTargetModel } from "@perimeter/sdk";
import { ConsoleLogger, loadTargetModel, Orchestrator, parseScanConfig, runProbeAgainstFixtures } from "@perimeter/core";
import { roleAccess } from "./role-access.js";

async function model() {
  const original = await loadTargetModel("examples/target.yaml");
  return parseTargetModel({ ...original, identities: [
    { ref: "admin", tenant: "tenant-a", role: "admin", credentials: { env: "ROLE_TEST_ADMIN" } },
    { ref: "member", tenant: "tenant-a", role: "member", credentials: { env: "ROLE_TEST_MEMBER" } },
  ], endpoints: [{ id: "profile", method: "GET", path: "/profile" },
    { id: "admin", method: "GET", path: "/admin/report", roleAccess: { readOnly: true, deniedByPolicy: true,
      allowedIdentity: "admin", deniedIdentity: "member", resultPath: ["reportId"],
      control: { endpointId: "profile", resultPath: ["id"], expectedValue: "member-id" } } }],
    authorization: { ...original.authorization, environment: "local", rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
}

it("uses recorded vulnerable/patched controls and skips unmodeled role checks", async () => {
  const target = await model();
  const headers = { "content-type": "application/json" };
  for (const vulnerable of [true, false]) {
    const result = await runProbeAgainstFixtures(roleAccess, { target, fixtures: [
      { match: { method: "GET", urlIncludes: "/profile", as: "member" }, respond: { status: 200, headers, body: '{"id":"member-id"}' } },
      { match: { method: "GET", urlIncludes: "/profile" }, respond: { status: 401, headers, body: '{}' } },
      { match: { method: "GET", urlIncludes: "/admin/report", as: "admin" }, respond: { status: 200, headers, body: '{"reportId":"private-report"}' } },
      { match: { method: "GET", urlIncludes: "/admin/report", as: "member" }, respond: { status: vulnerable ? 200 : 403, headers, body: vulnerable ? '{"reportId":"private-report"}' : '{}' } },
    ] });
    expect(result.requests).toHaveLength(4); expect(result.reports).toHaveLength(1);
    if (vulnerable) expect(FindingSchema.parse(result.reports[0]).severity).toBe("HIGH");
    else expect(result.reports[0]).toMatchObject({ kind: "pass" });
  }
  target.endpoints = [];
  const skipped = await runProbeAgainstFixtures(roleAccess, { target, fixtures: [] });
  expect(skipped.skipped).toContain("no reviewed"); expect(skipped.requests).toEqual([]);
});

it("runs guarded role checks through the engine and CLI with valid-session, evidence, budget and replay controls", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-roles-"));
  const requests: string[] = [];
  let mode = "vulnerable";
  vi.stubEnv("ROLE_TEST_ADMIN", "private-admin-token"); vi.stubEnv("ROLE_TEST_MEMBER", "private-member-token");
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    res.setHeader("content-type", "application/json");
    if (req.method !== "GET") { res.writeHead(405).end('{}'); return; }
    const credential = req.headers.authorization;
    if (req.url === "/profile") {
      if (!credential) { res.writeHead(mode === "anonymous-control-open" ? 200 : 401).end('{}'); return; }
      if (mode === "invalid-session") { res.writeHead(401).end('{}'); return; }
      res.end(JSON.stringify({ id: mode === "wrong-session" ? "admin-id" : "member-id" })); return;
    }
    if (req.url !== "/admin/report") { res.writeHead(404).end('{}'); return; }
    if (credential === "Bearer private-admin-token") {
      if (mode === "admin-denied") { res.writeHead(403).end('{}'); return; }
      res.end(JSON.stringify({ reportId: mode === "admin-redacted" ? "Bearer hidden-secret" : "private-report" })); return;
    }
    if (credential !== "Bearer private-member-token") { res.writeHead(401).end('{}'); return; }
    if (mode === "oversized") { res.end("x".repeat(16385)); return; }
    if (mode === "html") { res.setHeader("content-type", "text/html"); res.end("<h1>Login</h1>"); return; }
    if (mode === "redirect") { res.writeHead(302, { location: "/profile" }).end('{}'); return; }
    if (mode === "cached-denial") res.setHeader("age", "10");
    const exposed = ["vulnerable", "error-leak"].includes(mode);
    res.writeHead(exposed ? mode === "error-leak" ? 403 : 200 : mode === "public-data" ? 200 : 403)
      .end(JSON.stringify(exposed ? { reportId: "private-report" } : mode === "public-data" ? { reportId: "public" } :
        mode === "redacted-denial" ? { password: "not-evidence" } : {}));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = await model(); target.baseUrl = `http://127.0.0.1:${address.port}`;
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["auth/role-access"], output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    const fingerprints = new Set<string>();
    for (mode of ["vulnerable", "patched", "error-leak", "public-data", "html", "redirect", "invalid-session", "wrong-session",
      "anonymous-control-open", "admin-denied", "admin-redacted", "cached-denial", "redacted-denial", "oversized"]) {
      requests.length = 0;
      const result = await new Orchestrator(config, [roleAccess], { logger }).run();
      expect(result.findings, mode).toHaveLength(["vulnerable", "error-leak"].includes(mode) ? 1 : 0);
      expect(result.passes, mode).toHaveLength(mode === "patched" ? 1 : 0);
      expect(requests.every((r) => r.startsWith("GET "))).toBe(true);
      expect(requests.length).toBe(mode === "anonymous-control-open" ? 1 : ["invalid-session", "wrong-session"].includes(mode) ? 2 :
        ["admin-denied", "admin-redacted"].includes(mode) ? 3 : 4);
      if (result.findings.length) { fingerprints.add(result.findings[0]!.fingerprint); expect(result.findings[0]!.evidence.exchanges).toHaveLength(4); }
    }
    expect(fingerprints.size).toBe(1);
    mode = "vulnerable"; requests.length = 0;
    await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 3 }), [roleAccess], { logger }).run(); expect(requests).toEqual([]);
    const hidden = await new Orchestrator(config, [roleAccess], { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(requests).toHaveLength(2);
    const controller = new AbortController(); controller.abort(); requests.length = 0;
    await expect(new Orchestrator(config, [roleAccess], { logger, signal: controller.signal }).run()).rejects.toThrow(); expect(requests).toEqual([]);
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, checkpoint: join(directory, "state.json") }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    await promisify(execFile)(process.execPath, cli);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    const before = requests.length; await promisify(execFile)(process.execPath, [...cli, "--resume"]); expect(requests).toHaveLength(before);
    expect(await readFile(output.auditLog, "utf8")).not.toMatch(/private-admin-token|private-member-token/);
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
