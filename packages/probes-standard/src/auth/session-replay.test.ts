import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { FindingSchema, parseTargetModel, type HttpExchange } from "@perimeter/sdk";
import { ConsoleLogger, loadTargetModel, Orchestrator, parseScanConfig, runProbeAgainstFixtures } from "@perimeter/core";
import { sessionReplay } from "./session-replay.js";
import { observeJson } from "../_shared/json-observation.js";

it("distinguishes absent protected scalars from unusable JSON evidence", () => {
  const exchange: HttpExchange = { ref: "control", request: { method: "GET", url: "/profile", headers: {} },
    response: { status: 200, headers: { "content-type": "application/json" }, body: '{"account":{"id":0}}' } };
  expect(observeJson(exchange, ["account", "id"])).toEqual({ value: 0 });
  expect(observeJson(exchange, ["constructor"])).toEqual({ value: undefined });
  for (const body of [undefined, '{"account":', '{"id":"«redacted»"}', '«truncated»', '<h1>Login</h1>']) {
    expect(observeJson({ ...exchange, response: { ...exchange.response, body } }, ["id"])).toBeUndefined();
  }
  expect(observeJson({ ...exchange, response: { ...exchange.response, headers: { ...exchange.response.headers, age: "1" } } }, ["id"])).toBeUndefined();
});

it("checks real logout/replay with positive controls, safety limits, cleanup and registered CLI coverage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-session-probe-"));
  let mode = "patched";
  let serial = 0;
  let logins = 0;
  let originalCookie = "";
  let loggedOut = false;
  let controller: AbortController | undefined;
  const active = new Set<string>(["session=preexisting-session-secret"]);
  const requests: { path: string; cookie: string | undefined }[] = [];
  vi.stubEnv("SESSION_PROBE_TEST", '{"username":"disposable","password":"login-password-secret"}');
  const server = createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    const cookie = req.headers.cookie;
    requests.push({ path: req.url!, cookie });
    res.setHeader("content-type", "application/json");
    if (req.method === "POST" && req.url === "/login") {
      ++logins;
      if (mode === "login-failed" || (mode === "fresh-login-failed" && logins === 2)) { res.writeHead(401).end('{"error":"private-login-error"}'); return; }
      const token = `session-cookie-secret-${mode === "reused" ? 0 : ++serial}`;
      const value = `session=${token}`;
      if (logins === 1) originalCookie = value;
      active.add(value);
      res.setHeader("set-cookie", `session=${token}; Max-Age=3600`);
      res.end('{}'); return;
    }
    if (req.method === "POST" && req.url === "/logout") {
      if (cookie === originalCookie) {
        loggedOut = true;
        if (mode === "logout-failed") { res.writeHead(500).end('{}'); return; }
        if (mode === "logout-redirect") { res.writeHead(302, { location: "/unexpected" }).end('{}'); return; }
        if (!["vulnerable", "error-leak"].includes(mode)) active.delete(cookie);
      } else active.delete(cookie!);
      res.setHeader("set-cookie", mode === "rotated" ? "session=rotated-cookie-secret; Max-Age=3600" : "session=; Max-Age=0");
      res.writeHead(mode === "logout-200" ? 200 : 204).end(mode === "logout-200" ? '{}' : undefined); return;
    }
    if (req.method !== "GET" || req.url !== "/profile") { res.writeHead(404).end('{}'); return; }
    if (!cookie) {
      res.writeHead(mode === "anonymous-open" ? 200 : 401).end(mode === "anonymous-redacted" ? '{"password":"not-evidence"}' : '{}'); return;
    }
    if (cookie === originalCookie && loggedOut) {
      if (mode === "abort") { controller!.abort(); res.end('{}'); return; }
      if (mode === "oversized") { res.end("x".repeat(16385)); return; }
      if (mode === "html") { res.setHeader("content-type", "text/html"); res.end("<h1>Login</h1>"); return; }
      if (mode === "redirect") { res.writeHead(302, { location: "/unexpected" }).end('{}'); return; }
      if (mode === "cached") res.setHeader("age", "10");
      if (mode === "malformed") { res.writeHead(401).end('{"id":'); return; }
      if (mode === "redacted") { res.writeHead(401).end('{"password":"not-evidence"}'); return; }
      if (mode === "wrong-data") { res.writeHead(401).end('{"id":"another-account"}'); return; }
      if (mode === "public-data") { res.writeHead(200).end('{}'); return; }
      if (mode === "error-leak") { res.writeHead(403).end('{"id":"test-user"}'); return; }
    }
    if ((cookie !== originalCookie && mode === "fresh-denied") || (!loggedOut && mode === "initial-denied")) {
      res.writeHead(401).end('{}'); return;
    }
    const wrong = (!loggedOut && mode === "initial-wrong") || (cookie !== originalCookie && mode === "fresh-wrong");
    res.writeHead(active.has(cookie) ? 200 : 401).end(JSON.stringify(active.has(cookie) ? { id: wrong ? "another-account" : "test-user" } : {}));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const original = await loadTargetModel("examples/target.yaml");
    const target = parseTargetModel({ ...original, baseUrl: `http://127.0.0.1:${address.port}`,
      auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
      identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "SESSION_PROBE_TEST" } }],
      endpoints: [{ id: "logout", method: "POST", path: "/logout" }, { id: "profile", method: "GET", path: "/profile",
        sessionReplay: { readOnly: true, disposableIdentity: true, currentSessionOnly: true, identity: "owner", resultPath: ["id"], expectedValue: "test-user", logoutEndpointId: "logout" } }],
      authorization: { ...original.authorization, environment: "local", rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["auth/session-replay"], allowMutating: true, maxTotalRequests: 8, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    const reset = () => { requests.length = 0; logins = 0; loggedOut = false; originalCookie = "";
      active.clear(); active.add("session=preexisting-session-secret"); };
    const fingerprints = new Set<string>();
    for (mode of ["vulnerable", "patched", "rotated", "error-leak", "fresh-denied", "fresh-wrong", "initial-denied", "initial-wrong",
      "anonymous-open", "anonymous-redacted", "logout-failed", "logout-redirect", "reused", "oversized", "html", "redirect", "cached", "malformed", "redacted", "wrong-data", "public-data"]) {
      reset();
      const result = await new Orchestrator(config, [sessionReplay], { logger }).run();
      expect(result.findings, mode).toHaveLength(["vulnerable", "error-leak"].includes(mode) ? 1 : 0);
      expect(result.passes, mode).toHaveLength(["patched", "rotated"].includes(mode) ? 1 : 0);
      expect(requests.length, mode).toBeLessThanOrEqual(8);
      expect(requests.some((r) => r.cookie === "session=preexisting-session-secret" || r.path === "/unexpected"), mode).toBe(false);
      expect(active.has("session=preexisting-session-secret"), mode).toBe(true);
      if (!["vulnerable", "error-leak", "logout-failed", "logout-redirect"].includes(mode)) expect(active.size, mode).toBe(1);
      if (["patched", "rotated", "vulnerable", "error-leak"].includes(mode)) {
        expect(requests.map((r) => r.path)).toEqual(["/profile", "/login", "/profile", "/logout", "/profile", "/login", "/profile", "/logout"]);
        expect(requests[2]!.cookie).toBe(requests[4]!.cookie);
        expect(requests[6]!.cookie).not.toBe(requests[4]!.cookie);
      }
      const audit = await readFile(output.auditLog, "utf8");
      expect(audit).not.toMatch(/session-cookie-secret|rotated-cookie-secret|login-password-secret|preexisting-session-secret/);
      if (result.findings.length) {
        const finding = FindingSchema.parse(result.findings[0]); fingerprints.add(finding.fingerprint);
        expect(finding.evidence.exchanges).toHaveLength(5);
        const refs = audit.trim().split("\n").map((line) => JSON.parse(line).ref);
        expect(finding.evidence.auditRefs.every((ref) => refs.includes(ref))).toBe(true);
      }
    }
    expect(fingerprints.size).toBe(1);
    mode = "logout-200"; reset();
    const unacknowledged = await new Orchestrator(config, [sessionReplay], { logger }).run();
    expect(unacknowledged.findings).toEqual([]); expect(unacknowledged.passes).toEqual([]);
    target.endpoints[1]!.sessionReplay!.logoutSuccessStatus = 200;
    await writeFile(path, JSON.stringify(target)); reset();
    const acknowledged = await new Orchestrator(config, [sessionReplay], { logger }).run();
    expect(acknowledged.passes).toHaveLength(1); expect(active.size).toBe(1);
    target.endpoints[1]!.sessionReplay!.logoutSuccessStatus = 204;
    mode = "patched"; reset();
    await writeFile(path, JSON.stringify({ ...target, endpoints: [...target.endpoints, { ...target.endpoints[1], id: "profile-second" }] }));
    const multiple = await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 16 }), [sessionReplay], { logger }).run();
    expect(multiple.passes).toHaveLength(2); expect(requests).toHaveLength(16); expect(active.size).toBe(1);
    expect(requests[7]!.path).toBe("/logout"); expect(requests[8]!.path).toBe("/profile");
    await writeFile(path, JSON.stringify(target));
    for (mode of ["login-failed", "fresh-login-failed"]) {
      reset(); await expect(new Orchestrator(config, [sessionReplay], { logger }).run()).rejects.toThrow("Authentication exchange failed");
      expect(active.size).toBe(1); expect(await readFile(output.auditLog, "utf8")).not.toContain("private-login-error");
    }
    mode = "patched"; reset();
    const disabled = await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [sessionReplay], { logger }).run();
    expect(disabled.skipped[0]!.reason).toContain("--allow-mutating"); expect(requests).toEqual([]);
    await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: join(directory, "state.json") }), [sessionReplay], { logger }).run()).rejects.toThrow("read-only");
    expect(requests).toEqual([]);
    await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 7 }), [sessionReplay], { logger }).run(); expect(requests).toEqual([]);
    const limited = { ...sessionReplay, manifest: { ...sessionReplay.manifest, safety: { ...sessionReplay.manifest.safety, maxRequests: 7 } } };
    await new Orchestrator(config, [limited], { logger }).run(); expect(requests).toEqual([]);
    const hidden = await new Orchestrator(config, [sessionReplay], { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(logins).toBe(0);
    mode = "abort"; reset(); controller = new AbortController();
    await expect(new Orchestrator(config, [sessionReplay], { logger, signal: controller.signal }).run()).rejects.toThrow();
    expect(requests).toHaveLength(5); expect(active.size).toBe(1);
    const harness = await runProbeAgainstFixtures(sessionReplay, { target, fixtures: [] });
    expect(harness.skipped).toContain("engine session capability"); expect(harness.requests).toEqual([]);
    const unmodeled = await runProbeAgainstFixtures(sessionReplay, { target: { ...target, endpoints: [] }, fixtures: [] });
    expect(unmodeled.skipped).toContain("no reviewed"); expect(unmodeled.requests).toEqual([]);
    mode = "vulnerable"; reset();
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, allowMutating: false }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    await promisify(execFile)(process.execPath, cli); expect(requests).toEqual([]);
    await promisify(execFile)(process.execPath, [...cli, "--allow-mutating"]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect(requests).toHaveLength(8);
    expect(await readFile(output.auditLog, "utf8")).not.toMatch(/session-cookie-secret|login-password-secret/);
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 30000);
