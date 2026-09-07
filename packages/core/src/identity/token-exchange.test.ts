import { createServer } from "node:http";
import { expect, it, vi } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { GuardedHttpClientImpl } from "../http/guarded-http-client.js";
import { SafetyGuard } from "../safety/guard.js";
import { RateLimiter } from "../safety/rate-limiter.js";
import { SystemClock } from "../runtime/clock.js";
import { MutableBudget } from "../runtime/budget.js";
import { MemoryAuditLog } from "../audit/audit-log.js";
import { IdentityManager } from "./identity-manager.js";
import { createTokenExchange } from "./token-exchange.js";

it("exchanges and rotates OAuth credentials, renews sessions, and redacts all auth bodies", async () => {
  const requests: { path: string; fields: Record<string, string> }[] = [];
  let fail = false;
  const server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => { body += chunk; });
    req.on("end", () => {
      const fields = req.headers["content-type"] === "application/json"
        ? JSON.parse(body) as Record<string, string> : Object.fromEntries(new URLSearchParams(body));
      requests.push({ path: req.url!, fields });
      if (fail) { res.writeHead(302, { location: "http://example.com/escape" }); res.end("private-server-error"); return; }
      if (req.url === "/login") {
        res.writeHead(200, { "set-cookie": ["noise=other; Expires=Wed, 21 Oct 2037 07:28:00 GMT", "session=cookie-secret; Max-Age=1"] });
        res.end("private-session-body");
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: `token-secret-${requests.length}`, token_type: "Bearer", expires_in: 1,
          refresh_token: `refresh-secret-${requests.length}` }));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const time = vi.spyOn(Date, "now");
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.auth = { scheme: "oauth2_password", tokenEndpoint: "/token", refresh: { endpoint: "/refresh", ttlSeconds: 30 } };
    for (const [index, spec] of target.identities.entries()) {
      spec.credentials = { env: `PERIMETER_EXCHANGE_TEST_${index}` };
      vi.stubEnv(spec.credentials.env, JSON.stringify({ username: spec.ref, password: "password-secret", client_id: "client" }));
    }
    expect(() => parseTargetModel(target)).not.toThrow();
    expect(() => parseTargetModel({ ...target, auth: { ...target.auth, tokenEndpoint: "http://example.com/token" } })).toThrow("target origin");
    const audit = new MemoryAuditLog();
    const budget = new MutableBudget(20);
    const signal = new AbortController().signal;
    const http = new GuardedHttpClientImpl({
      baseUrl: target.baseUrl, probeId: "engine/authentication", probeSafetyClass: "idempotent-write",
      guard: new SafetyGuard({ allowedHosts: new Set([new URL(target.baseUrl).host]), allowMutating: false,
        scratchObjectIds: new Set(), authenticationUrls: new Set(["/token", "/refresh", "/login"].map((p) => target.baseUrl + p)) }),
      limiter: new RateLimiter({ globalRps: 100, perHostRps: 100, burst: 20 }, new SystemClock()),
      budget, audit, scanId: "auth-test", signal, captureBodies: false,
      resolveIdentity: () => { throw new Error("recursive identity"); },
    });
    const manager = new IdentityManager(target, undefined, signal, createTokenExchange(target, http));
    const a = manager.get(target.identities[0]!.ref);
    const b = manager.get(target.identities[1]!.ref);
    time.mockReturnValue(1000);
    const [first, shared] = await Promise.all([a.headers(), a.headers()]);
    expect(shared).toEqual(first);
    expect(requests).toHaveLength(1);
    await b.headers();
    expect(requests[0]!.fields).toMatchObject({ grant_type: "password", username: a.ref, password: "password-secret" });
    time.mockReturnValue(2000);
    expect(await a.headers()).not.toEqual(first);
    expect(requests[2]).toMatchObject({ path: "/refresh", fields: { grant_type: "refresh_token", refresh_token: "refresh-secret-1" } });
    expect(requests[2]!.fields).not.toHaveProperty("password");
    time.mockReturnValue(3000);
    await a.headers();
    expect(requests[3]!.fields.refresh_token).toBe("refresh-secret-3");

    target.auth = { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } };
    const sessions = new IdentityManager(target, undefined, signal, createTokenExchange(target, http));
    const session = sessions.get(a.ref);
    expect(await session.headers()).toEqual({ cookie: "session=cookie-secret" });
    time.mockReturnValue(4000);
    await session.headers();
    expect(requests.filter((r) => r.path === "/login")).toHaveLength(2);
    time.mockReturnValue(5000);
    fail = true;
    await expect(session.headers()).rejects.toThrow(/^Authentication exchange failed;/);
    fail = false;
    expect(await session.headers()).toEqual({ cookie: "session=cookie-secret" });
    const count = requests.length;
    await expect(http.request({ method: "POST", url: "/unmodeled", body: "{}" })).rejects.toThrow("safety guard blocked");
    expect(requests).toHaveLength(count);
    expect(budget.used).toBe(count + 1);
    const logged = JSON.stringify(audit.entries);
    for (const secret of ["password-secret", "token-secret", "refresh-secret", "cookie-secret", "private-server-error", "private-session-body"]) {
      expect(logged).not.toContain(secret);
    }
  } finally {
    time.mockRestore();
    vi.unstubAllEnvs();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  }
});
