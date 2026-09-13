import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { FindingSchema, parseTargetModel } from "@perimeter/sdk";
import { ConsoleLogger, loadTargetModel, Orchestrator, parseScanConfig, runProbeAgainstFixtures } from "@perimeter/core";
import { sessionFixation } from "./session-fixation.js";

it("proves pre-login cookie promotion with guarded controls, cleanup, bounds and the registered CLI", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-fixation-probe-"));
  let mode = "patched";
  let serial = 0;
  let preCookie = "";
  let currentCookie = "";
  let loggedIn = false;
  let readsAfterLogin = 0;
  let currentReads = 0;
  let controller: AbortController | undefined;
  const sessions = new Map<string, boolean>([["session=preexisting-secret", true]]);
  const requests: { path: string; cookie: string | undefined }[] = [];
  vi.stubEnv("FIXATION_PROBE_TEST", '{"username":"disposable","password":"fixation-password-secret"}');
  const server = createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    const cookie = req.headers.cookie;
    requests.push({ path: req.url!, cookie });
    res.setHeader("content-type", "application/json");
    if (req.method === "GET" && req.url === "/bootstrap") {
      loggedIn = false; readsAfterLogin = 0; currentReads = 0;
      preCookie = "session=anonymous-fix-secret-" + ++serial;
      if (mode === "bootstrap-redirect") { res.writeHead(302, { location: "/unexpected" }).end('{}'); return; }
      if (mode === "missing-cookie") { res.end('{}'); return; }
      if (mode === "duplicate-cookie") { res.setHeader("set-cookie", [preCookie, preCookie]); res.end('{}'); return; }
      if (mode === "expired-cookie") { res.setHeader("set-cookie", preCookie + "; Max-Age=0"); res.end('{}'); return; }
      if (mode === "bootstrap-cache") { res.setHeader("age", "10"); res.setHeader("set-cookie", preCookie); res.end('{}'); return; }
      sessions.set(preCookie, false);
      res.setHeader("set-cookie", preCookie + "; Max-Age=3600");
      res.end('{}'); return;
    }
    if (req.method === "POST" && req.url === "/login") {
      if (cookie !== preCookie || mode === "login-failed") { res.writeHead(401).end('{"error":"private-login-error"}'); return; }
      if (mode === "login-deletes") { res.setHeader("set-cookie", "session=; Max-Age=0"); res.end('{}'); return; }
      loggedIn = true;
      const retained = ["retained", "omitted", "error-leak", "retained-denial"].includes(mode);
      currentCookie = retained ? preCookie : "session=authenticated-fix-secret-" + serial;
      if (!retained && !["alias", "lost-control"].includes(mode)) sessions.delete(preCookie);
      else sessions.set(preCookie, true);
      sessions.set(currentCookie, true);
      if (mode !== "omitted") res.setHeader("set-cookie", currentCookie + "; Max-Age=3600");
      res.end('{}'); return;
    }
    if (req.method === "POST" && req.url === "/logout") {
      const wasAuthenticated = sessions.get(cookie!) === true;
      sessions.delete(cookie!);
      res.writeHead(wasAuthenticated ? 204 : 401).end(wasAuthenticated ? undefined : '{}'); return;
    }
    if (req.method !== "GET" || req.url !== "/profile") { res.writeHead(404).end('{}'); return; }
    if (!cookie) { res.writeHead(mode === "anonymous-open" ? 200 : 401).end('{}'); return; }
    if (!loggedIn) {
      if (mode === "preauthenticated") { res.end('{"id":"test-user"}'); return; }
      if (mode === "pre-rotation") res.setHeader("set-cookie", "session=read-rotated-secret; Max-Age=3600");
      res.writeHead(401).end(mode === "echo" ? JSON.stringify({ diagnostic: cookie }) : '{}'); return;
    }
    ++readsAfterLogin;
    if (cookie === currentCookie) ++currentReads;
    if (mode === "control-denied" || (mode === "lost-control" && cookie === currentCookie && currentReads === 2)) {
      res.writeHead(401).end('{}'); return;
    }
    if (mode === "control-rotation" && cookie === currentCookie) res.setHeader("set-cookie", "session=read-rotated-secret");
    if (cookie === preCookie && readsAfterLogin === 2) {
      if (mode === "abort") { controller!.abort(); res.end('{}'); return; }
      if (mode === "oversized") { res.end("x".repeat(16385)); return; }
      if (mode === "html") { res.setHeader("content-type", "text/html"); res.end("<h1>Login</h1>"); return; }
      if (mode === "redirect") { res.writeHead(302, { location: "/unexpected" }).end('{}'); return; }
      if (mode === "cached") res.setHeader("age", "10");
      if (mode === "replay-rotation") res.setHeader("set-cookie", "session=read-rotated-secret");
      if (mode === "malformed") { res.writeHead(401).end('{"id":'); return; }
      if (mode === "redacted") { res.writeHead(401).end('{"password":"not-evidence"}'); return; }
      if (mode === "wrong-data") { res.writeHead(403).end('{"id":"another-account"}'); return; }
      if (mode === "public-data") { res.writeHead(200).end('{}'); return; }
      if (mode === "error-leak") { res.writeHead(403).end('{"id":"test-user"}'); return; }
      if (mode === "retained-denial") { res.writeHead(401).end('{}'); return; }
    }
    res.writeHead(sessions.get(cookie) ? 200 : 401).end(JSON.stringify(sessions.get(cookie) ? { id: mode === "wrong-account" ? "another-account" : "test-user" } : {}));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const original = await loadTargetModel("examples/target.yaml");
    const target = parseTargetModel({ ...original, baseUrl: "http://127.0.0.1:" + address.port,
      auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
      identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "FIXATION_PROBE_TEST" } }],
      endpoints: [{ id: "bootstrap", method: "GET", path: "/bootstrap", auth: "none" },
        { id: "logout", method: "POST", path: "/logout" }, { id: "profile", method: "GET", path: "/profile",
          sessionReplay: { readOnly: true, disposableIdentity: true, currentSessionOnly: true, identity: "owner", resultPath: ["id"],
            expectedValue: "test-user", logoutEndpointId: "logout", fixation: { bootstrapEndpointId: "bootstrap", issuesAnonymousSession: true } } }],
      authorization: { ...original.authorization, environment: "local", rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["auth/session-fixation"], allowMutating: true, maxTotalRequests: 9, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    const reset = () => { requests.length = 0; loggedIn = false; readsAfterLogin = 0; currentReads = 0;
      sessions.clear(); sessions.set("session=preexisting-secret", true); };
    const fingerprints = new Set<string>();
    for (mode of ["retained", "omitted", "patched", "alias", "error-leak", "retained-denial", "anonymous-open", "preauthenticated",
      "pre-rotation", "control-rotation", "replay-rotation", "echo", "control-denied", "lost-control", "wrong-account",
      "bootstrap-redirect", "bootstrap-cache", "oversized", "html", "redirect", "cached", "malformed", "redacted", "wrong-data", "public-data"]) {
      reset();
      const result = await new Orchestrator(config, [sessionFixation], { logger }).run();
      const vulnerable = ["retained", "omitted", "alias", "error-leak"].includes(mode);
      expect(result.findings, mode).toHaveLength(vulnerable ? 1 : 0);
      expect(result.passes, mode).toHaveLength(mode === "patched" ? 1 : 0);
      expect([...sessions], mode).toEqual([["session=preexisting-secret", true]]);
      expect(requests.length, mode).toBeLessThanOrEqual(9);
      expect(requests.some((r) => r.cookie === "session=preexisting-secret" || r.path === "/unexpected"), mode).toBe(false);
      if (vulnerable || mode === "patched") {
        expect(requests.slice(0, 7).map((r) => r.path)).toEqual(["/profile", "/bootstrap", "/profile", "/login", "/profile", "/profile", "/profile"]);
        expect(requests[2]!.cookie).toBe(requests[3]!.cookie); expect(requests[5]!.cookie).toBe(requests[2]!.cookie);
        expect(requests[4]!.cookie).toBe(requests[6]!.cookie);
        expect(requests).toHaveLength(["patched", "alias"].includes(mode) ? 9 : 8);
      }
      const audit = await readFile(output.auditLog, "utf8");
      expect(audit).not.toMatch(/anonymous-fix-secret|authenticated-fix-secret|fixation-password-secret|preexisting-secret|read-rotated-secret/);
      if (result.findings.length) {
        const finding = FindingSchema.parse(result.findings[0]); fingerprints.add(finding.fingerprint);
        expect(finding.cwe).toEqual(["CWE-384"]); expect(finding.evidence.exchanges).toHaveLength(6);
        const refs = audit.trim().split("\n").map((line) => JSON.parse(line).ref);
        expect(finding.evidence.auditRefs.every((ref) => refs.includes(ref))).toBe(true);
      }
    }
    expect(fingerprints.size).toBe(1);
    for (mode of ["missing-cookie", "duplicate-cookie", "expired-cookie", "login-failed", "login-deletes"]) {
      reset(); await expect(new Orchestrator(config, [sessionFixation], { logger }).run()).rejects.toThrow();
      expect([...sessions]).toEqual([["session=preexisting-secret", true]]);
      expect(await readFile(output.auditLog, "utf8")).not.toMatch(/fix-secret|private-login-error|fixation-password-secret/);
    }
    mode = "patched"; reset();
    const disabled = await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [sessionFixation], { logger }).run();
    expect(disabled.skipped[0]!.reason).toContain("--allow-mutating"); expect(requests).toEqual([]);
    await expect(new Orchestrator(parseScanConfig({ ...config, checkpoint: join(directory, "state.json") }), [sessionFixation], { logger }).run()).rejects.toThrow("read-only");
    expect(requests).toEqual([]);
    await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 8 }), [sessionFixation], { logger }).run(); expect(requests).toEqual([]);
    const limited = { ...sessionFixation, manifest: { ...sessionFixation.manifest, safety: { ...sessionFixation.manifest.safety, maxRequests: 8 } } };
    await new Orchestrator(config, [limited], { logger }).run(); expect(requests).toEqual([]);
    const hidden = await new Orchestrator(config, [sessionFixation], { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(requests).toHaveLength(1);
    reset();
    await writeFile(path, JSON.stringify({ ...target, endpoints: [...target.endpoints, { ...target.endpoints[2], id: "profile-second" }] }));
    const multiple = await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 18 }), [sessionFixation], { logger }).run();
    expect(multiple.passes).toHaveLength(2); expect(requests).toHaveLength(18); expect(sessions.size).toBe(1);
    expect(requests[8]!.path).toBe("/logout"); expect(requests[9]!.cookie).toBeUndefined();
    await writeFile(path, JSON.stringify(target));
    reset(); controller = new AbortController(); controller.abort();
    await expect(new Orchestrator(config, [sessionFixation], { logger, signal: controller.signal }).run()).rejects.toThrow(); expect(requests).toEqual([]);
    mode = "abort"; controller = new AbortController();
    await expect(new Orchestrator(config, [sessionFixation], { logger, signal: controller.signal }).run()).rejects.toThrow(); expect(requests).toHaveLength(6);
    const harness = await runProbeAgainstFixtures(sessionFixation, { target, fixtures: [] });
    expect(harness.skipped).toContain("engine capability"); expect(harness.requests).toEqual([]);
    const unmodeled = await runProbeAgainstFixtures(sessionFixation, { target: { ...target, endpoints: [] }, fixtures: [] });
    expect(unmodeled.skipped).toContain("no reviewed"); expect(unmodeled.requests).toEqual([]);
    mode = "retained"; reset();
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, allowMutating: false }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    await promisify(execFile)(process.execPath, cli); expect(requests).toEqual([]);
    await promisify(execFile)(process.execPath, [...cli, "--allow-mutating"]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect(requests).toHaveLength(8); expect(sessions.size).toBe(1);
    expect(await readFile(output.auditLog, "utf8")).not.toMatch(/fix-secret|fixation-password-secret/);
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 30000);
