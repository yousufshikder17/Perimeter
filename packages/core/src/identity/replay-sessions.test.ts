import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { parseTargetModel, type Probe, type ReplaySession } from "@perimeter/sdk";
import { ConsoleLogger, loadTargetModel, Orchestrator, parseScanConfig } from "../index.js";

it("owns frozen sessions, gates writes, rejects reused cookies, redacts echoes and cleans up on probe failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-session-core-"));
  const requests: { path: string; cookie: string | undefined }[] = [];
  let serial = 0;
  let mode = "normal";
  const active = new Set<string>();
  vi.stubEnv("SESSION_CORE_TEST", '{"username":"disposable","password":"login-password-secret"}');
  const server = createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    const cookie = req.headers.cookie;
    requests.push({ path: req.url!, cookie });
    res.setHeader("content-type", "application/json");
    if (req.url === "/login") {
      const token = `cookie-secret-${mode === "reuse" ? 0 : ++serial}`;
      active.add(`session=${token}`);
      res.setHeader("set-cookie", `session=${token}; Max-Age=3600`);
      res.setHeader("x-echo", token);
      res.end(JSON.stringify({ diagnostic: token })); return;
    }
    if (req.url === "/logout") {
      active.delete(cookie!);
      res.setHeader("set-cookie", "session=; Max-Age=0");
      res.writeHead(204).end(); return;
    }
    if (mode === "echo") res.setHeader("x-echo", cookie ?? "");
    res.writeHead(active.has(cookie!) ? 200 : 401).end(JSON.stringify(mode === "echo" ? { id: "user", diagnostic: cookie } : active.has(cookie!) ? { id: "user" } : {}));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const original = await loadTargetModel("examples/target.yaml");
    const target = parseTargetModel({ ...original, baseUrl: `http://127.0.0.1:${address.port}`,
      auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
      identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "SESSION_CORE_TEST" } }],
      endpoints: [{ id: "logout", method: "POST", path: "/logout" }, { id: "profile", method: "GET", path: "/profile",
        sessionReplay: { readOnly: true, disposableIdentity: true, currentSessionOnly: true, identity: "owner",
          resultPath: ["id"], expectedValue: "user", logoutEndpointId: "logout" } }],
      authorization: { ...original.authorization, rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, allowMutating: true, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    let held: ReplaySession | undefined;
    const evidence: unknown[] = [];
    const probe: Probe = { manifest: { id: "auth/session-transport-test", family: "auth", version: "0.1.0", schemaVersion: "1",
      requires: {}, safety: { class: "mutating", maxRequests: 20, destructive: false } },
      async plan() { return { probeId: this.manifest.id, steps: [] }; },
      async run(_plan, ctx) {
        held = await ctx.sessions!.open("profile");
        evidence.push(await held.read());
        if (mode === "crash") throw new Error("deliberate failure");
        await expect(ctx.http.request({ method: "POST", url: "/logout", as: "owner" })).rejects.toThrow("scratch object");
        evidence.push(await held.logout(), await held.read());
        const fresh = await ctx.sessions!.open("profile");
        evidence.push(await fresh.read());
      } };
    const normal = await new Orchestrator(config, [probe], { logger }).run();
    expect(normal.skipped).toEqual([]);
    expect(requests.map((r) => r.path)).toEqual(["/login", "/profile", "/logout", "/profile", "/login", "/profile", "/logout"]);
    expect(requests[1]!.cookie).toBe(requests[2]!.cookie);
    expect(requests[3]!.cookie).toBe(requests[1]!.cookie);
    expect(requests[5]!.cookie).not.toBe(requests[1]!.cookie);
    expect(active.size).toBe(0);
    await expect(held!.read()).rejects.toThrow("closed");
    const audit = await readFile(output.auditLog, "utf8");
    expect(audit).not.toMatch(/cookie-secret|login-password-secret/);
    expect(audit.trim().split("\n")).toHaveLength(7);
    for (mode of ["echo", "crash", "reuse"]) {
      requests.length = 0; evidence.length = 0;
      const result = await new Orchestrator(config, [probe], { logger }).run();
      expect(active.size, mode).toBe(0);
      if (mode === "echo") { expect(result.skipped).toEqual([]); expect(evidence[0]).toMatchObject({ response: { body: undefined } }); }
      if (mode === "crash") expect(requests.map((r) => r.path)).toEqual(["/login", "/profile", "/logout"]);
      if (mode === "reuse") expect(result.skipped[0]!.reason).toContain("reused an earlier cookie");
      expect(await readFile(output.auditLog, "utf8")).not.toMatch(/cookie-secret|login-password-secret/);
      expect(JSON.stringify(evidence)).not.toMatch(/cookie-secret/);
    }
    requests.length = 0;
    await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [probe], { logger }).run();
    expect(requests).toEqual([]);
    const readonly = { ...probe, manifest: { ...probe.manifest, safety: { ...probe.manifest.safety, class: "read-only" as const } } };
    const denied = await new Orchestrator(config, [readonly], { logger }).run();
    expect(denied.skipped[0]!.reason).toContain("explicitly authorized mutating probe"); expect(requests).toEqual([]);
    const controller = new AbortController(); controller.abort();
    await expect(new Orchestrator(config, [probe], { logger, signal: controller.signal }).run()).rejects.toThrow();
    expect(requests).toEqual([]);
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
