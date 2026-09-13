import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { parseTargetModel, type FixationSession, type HttpExchange, type Probe } from "@perimeter/sdk";
import { ConsoleLogger, loadTargetModel, Orchestrator, parseScanConfig, VirtualClock } from "../index.js";
import { readSessionCookie } from "./token-exchange.js";

it("extracts a single live cookie and permits omission only for an explicitly retained session", () => {
  expect(readSessionCookie({}, "sid", 60, "sid=owned-cookie").headers).toEqual({ cookie: "sid=owned-cookie" });
  for (const setCookies of [[], ["sid=; Max-Age=60"], ["sid=x; Max-Age=0"], ["sid=x; Max-Age=-1"],
    ["sid=x; Expires=Wed, 21 Oct 2015 07:28:00 GMT"], ["sid=x", "sid=y"], ["other=x"]]) {
    expect(() => readSessionCookie({ setCookies }, "sid", 60)).toThrow();
  }
  expect(() => readSessionCookie({ setCookies: ["sid=; Max-Age=0"] }, "sid", 60, "sid=owned-cookie")).toThrow();
  expect(readSessionCookie({ setCookies: ["other=x", "sid=new-cookie; Max-Age=30"] }, "sid", 60, "sid=owned-cookie"))
    .toEqual({ headers: { cookie: "sid=new-cookie" }, ttlSeconds: 30 });
});

it("freezes the pre-login cookie, authenticates once, guards egress and cleans both owned sessions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-fixation-core-"));
  const requests: { path: string; cookie: string | undefined }[] = [];
  const authenticated = new Set<string>();
  let mode = "rotated";
  vi.stubEnv("FIXATION_CORE_TEST", '{"username":"disposable","password":"fixation-password-secret"}');
  const server = createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    const cookie = req.headers.cookie;
    requests.push({ path: req.url!, cookie });
    res.setHeader("content-type", "application/json");
    if (req.url === "/bootstrap") { res.setHeader("set-cookie", "session=anonymous-cookie-secret; Max-Age=3600"); res.end('{}'); return; }
    if (req.url === "/login") {
      if (cookie !== "session=anonymous-cookie-secret") { res.writeHead(401).end('{}'); return; }
      const current = mode === "rotated" ? "session=authenticated-cookie-secret" : cookie;
      authenticated.add(current);
      if (mode !== "omitted") res.setHeader("set-cookie", current + "; Max-Age=3600");
      res.end('{}'); return;
    }
    if (req.url === "/logout") {
      const existed = authenticated.delete(cookie!);
      res.writeHead(existed ? 204 : 401).end(existed ? undefined : '{}'); return;
    }
    if (mode === "echo") res.setHeader("x-echo", cookie ?? "");
    res.writeHead(authenticated.has(cookie!) ? 200 : 401).end(JSON.stringify(mode === "echo" ? { diagnostic: cookie } : authenticated.has(cookie!) ? { id: "user" } : {}));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const original = await loadTargetModel("examples/target.yaml");
    const target = parseTargetModel({ ...original, baseUrl: "http://127.0.0.1:" + address.port,
      auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
      identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "FIXATION_CORE_TEST" } }],
      endpoints: [{ id: "bootstrap", method: "GET", path: "/bootstrap", auth: "none" },
        { id: "logout", method: "POST", path: "/logout" }, { id: "profile", method: "GET", path: "/profile",
          sessionReplay: { readOnly: true, disposableIdentity: true, currentSessionOnly: true, identity: "owner", resultPath: ["id"],
            expectedValue: "user", logoutEndpointId: "logout", fixation: { bootstrapEndpointId: "bootstrap", issuesAnonymousSession: true } } }],
      authorization: { ...original.authorization, rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } } });
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, allowMutating: true, maxTotalRequests: 8, output, failOn: "none" });
    const logger = new ConsoleLogger("error");
    let held: FixationSession | undefined;
    const evidence: HttpExchange[] = [];
    const probe: Probe = { manifest: { id: "auth/fixation-transport-test", family: "auth", version: "0.1.0", schemaVersion: "1",
      requires: {}, safety: { class: "mutating", maxRequests: 8, destructive: false } },
      async plan() { return { probeId: this.manifest.id, steps: [] }; },
      async run(_plan, ctx) {
        held = await ctx.sessions!.prepareFixation!("profile");
        evidence.push(held.bootstrap, await held.read());
        if (mode === "expired" && ctx.clock instanceof VirtualClock) ctx.clock.advance(3600001);
        const [current, shared] = await Promise.all([held.login(), held.login()]);
        if (current !== shared) throw new Error("Login was not memoized");
        expect(held.cookieRotated).toBe(mode === "rotated");
        evidence.push(await current.read(), await held.read());
        if (mode === "crash") throw new Error("deliberate failure");
        await expect(ctx.http.request({ method: "POST", url: "/login" })).rejects.toThrow("scratch object");
        await held.close();
      } };
    for (mode of ["rotated", "retained", "omitted", "echo", "crash"]) {
      requests.length = 0; evidence.length = 0;
      const result = await new Orchestrator(config, [probe], { logger }).run();
      expect(result.skipped).toHaveLength(mode === "crash" ? 1 : 0);
      expect(authenticated.size, mode).toBe(0);
      expect(requests.filter((r) => r.path === "/login")).toHaveLength(1);
      expect(requests[1]!.cookie).toBe(requests[2]!.cookie);
      expect(requests[4]!.cookie).toBe(requests[1]!.cookie);
      if (mode === "rotated") {
        expect(requests[3]!.cookie).not.toBe(requests[1]!.cookie);
        expect(evidence.map((e) => e.response.status)).toEqual([200, 401, 200, 401]);
        expect(requests).toHaveLength(7);
      } else if (mode !== "echo") expect(evidence.map((e) => e.response.status)).toEqual([200, 401, 200, 200]);
      if (mode === "echo") expect(evidence[1]!.response.body).toBeUndefined();
      await expect(held!.read()).rejects.toThrow("closed");
      await expect(held!.login()).rejects.toThrow("closed");
      expect(await readFile(output.auditLog, "utf8")).not.toMatch(/cookie-secret|fixation-password-secret/);
      expect(JSON.stringify(evidence)).not.toContain("cookie-secret");
    }
    requests.length = 0;
    mode = "expired";
    const expired = await new Orchestrator(config, [probe], { logger, clock: new VirtualClock() }).run();
    expect(expired.skipped[0]!.reason).toContain("lifetime elapsed");
    expect(requests.map((r) => r.path)).toEqual(["/bootstrap", "/profile", "/logout"]);
    expect(authenticated.size).toBe(0);
    requests.length = 0;
    await new Orchestrator(parseScanConfig({ ...config, allowMutating: false }), [probe], { logger }).run(); expect(requests).toEqual([]);
    const readonly = { ...probe, manifest: { ...probe.manifest, safety: { ...probe.manifest.safety, class: "read-only" as const } } };
    const denied = await new Orchestrator(config, [readonly], { logger }).run();
    expect(denied.skipped[0]!.reason).toContain("explicitly authorized mutating probe"); expect(requests).toEqual([]);
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
