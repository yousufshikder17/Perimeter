import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT, decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";
import { expect, it, vi } from "vitest";
import { loadTargetModel } from "../target/loader.js";
import { IdentityManager, AuthenticationError } from "./identity-manager.js";
import { createJwtVariants } from "./jwt-variants.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";
import { ConsoleLogger } from "../runtime/logger.js";
// Built workspace artifact, like the CLI/E2E suite: build before running tests.
import { tokenManipulation } from "../../../probes-standard/dist/index.js";

const key = new TextEncoder().encode("local-jwt-regression-key-not-a-production-secret");
const now = Math.floor(Date.now() / 1000);
const sign = (expires: number, tenant = "tenant-a") => new SignJWT({ tenant_id: tenant })
  .setProtectedHeader({ alg: "HS256" }).setSubject("local-user").setIssuer("local-test").setAudience("local-api")
  .setExpirationTime(expires).sign(key);

it("constructs JWT variants without mutating live credentials and validates expired samples", async () => {
  const target = await loadTargetModel("examples/target.yaml");
  const spec = target.identities[0]!;
  target.auth = { scheme: "bearer" };
  spec.credentials = { env: "PERIMETER_JWT_LIVE" };
  spec.expiredCredentials = { env: "PERIMETER_JWT_EXPIRED" };
  const live = await sign(now + 3600);
  const expired = await sign(now - 120);
  vi.stubEnv("PERIMETER_JWT_LIVE", live);
  vi.stubEnv("PERIMETER_JWT_EXPIRED", expired);
  try {
    const identity = new IdentityManager(target).get(spec.ref);
    const original = await identity.headers();
    expect(await identity.jwtVariants!()).toEqual(["none-alg", "signature-stripped", "tenant-swapped", "expired"]);
    for (const variant of ["none-alg", "signature-stripped", "tenant-swapped", "expired"] as const) {
      const token = (await identity.headers(variant)).authorization!.slice(7);
      await expect(jwtVerify(token, key, { algorithms: ["HS256"] })).rejects.toThrow();
      if (variant === "none-alg") expect(decodeProtectedHeader(token).alg).toBe("none");
      if (variant === "signature-stripped") expect(token).toBe(live.slice(0, live.lastIndexOf(".") + 1));
      if (variant === "tenant-swapped") {
        expect(decodeJwt(token).tenant_id).toBe("tenant-b");
        expect(token.split(".")[2]).toBe(live.split(".")[2]);
      }
      if (variant === "expired") {
        expect(token).toBe(expired);
        await expect(jwtVerify(token, key, { currentDate: new Date((now - 180) * 1000) })).resolves.toBeDefined();
      }
    }
    expect(await identity.headers()).toEqual(original);
    const edited = await identity.headers("none-alg");
    edited.authorization = "changed";
    expect(await identity.headers()).toEqual(original);

    for (const invalid of ["", "invalid-secret-value", live, await sign(now - 120, "tenant-b"), await sign(now - 1)]) {
      vi.stubEnv("PERIMETER_JWT_EXPIRED", invalid);
      await expect(identity.jwtVariants!()).rejects.toThrow(AuthenticationError);
      await expect(identity.headers("expired")).rejects.not.toThrow("invalid-secret-value");
    }
    delete spec.expiredCredentials;
    expect(await identity.jwtVariants!()).not.toContain("expired");
    expect(createJwtVariants({ "x-api-key": "opaque" }, target, spec)).toEqual({});
    expect(createJwtVariants({ authorization: `Bearer ${live}`, cookie: "session=other" }, target, spec)).toEqual({});
    expect(createJwtVariants({ authorization: "Bearer not.a.jwt" }, target, spec)).toEqual({});
    target.tenancy.tenants = [spec.tenant];
    expect(await identity.jwtVariants!()).not.toContain("tenant-swapped");
  } finally { vi.unstubAllEnvs(); }
});

it("regresses each JWT acceptance variant through guarded scans, with controls, budgets, and redacted evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-jwt-"));
  const live = await sign(now + 3600);
  const expired = await sign(now - 120);
  let mode = "patched";
  const requests: Array<{ path: string; credential: boolean }> = [];
  const server = createServer(async (req, res) => {
    const token = req.headers.authorization?.slice(7);
    requests.push({ path: req.url!, credential: !!token });
    res.setHeader("content-type", "application/json");
    if (!token) { res.statusCode = mode === "anonymous-success" ? 200 : 401; res.end('{}'); return; }
    res.setHeader("x-reflected-token", token);
    if (mode === "baseline-denied" && token === live) { res.statusCode = 403; res.end('{}'); return; }
    try {
      const header = decodeProtectedHeader(token);
      const claims = decodeJwt(token);
      const isVariant = token !== live;
      const accept = (mode === "none-alg" && header.alg === "none") ||
        (mode === "signature-stripped" && header.alg === "HS256" && token.endsWith(".")) ||
        (mode === "tenant-swapped" && claims.tenant_id === "tenant-b") ||
        (mode === "expired" && token === expired);
      if (mode === "server-error" && isVariant) { res.statusCode = 500; res.end('{}'); return; }
      if (!accept) await jwtVerify(token, key, { algorithms: ["HS256"], issuer: "local-test", audience: "local-api" });
      res.end('{"user":"local-user"}');
    } catch { res.statusCode = 401; res.end('{"error":"rejected"}'); }
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.auth = { scheme: "bearer" };
    const spec = target.identities[0]!;
    spec.credentials = { env: "PERIMETER_JWT_LIVE" };
    spec.expiredCredentials = { env: "PERIMETER_JWT_EXPIRED" };
    target.endpoints = [{ id: "profile", path: "/profile", method: "GET", auth: "required", tenantScoped: false, rateSensitive: false }];
    target.authorization.rateLimit = { globalRps: 1000, perHostRps: 1000, burst: 1000 };
    vi.stubEnv("PERIMETER_JWT_LIVE", live);
    vi.stubEnv("PERIMETER_JWT_EXPIRED", expired);
    const targetPath = join(directory, "target.json");
    const auditLog = join(directory, "audit.ndjson");
    const run = async (maxTotalRequests = 100) => {
      requests.length = 0;
      await writeFile(targetPath, JSON.stringify(target));
      return new Orchestrator(parseScanConfig({ target: targetPath, maxTotalRequests, output: { auditLog } }),
        [tokenManipulation], { logger: new ConsoleLogger("error") }).run();
    };
    const fingerprints = new Set<string>();
    for (mode of ["patched", "none-alg", "signature-stripped", "tenant-swapped", "expired"]) {
      const result = await run();
      expect(result.skipped).toEqual([]);
      expect(requests).toHaveLength(6);
      expect(result.findings).toHaveLength(mode === "patched" ? 0 : 1);
      if (mode !== "patched") {
        const finding = result.findings[0]!;
        expect(finding).toMatchObject({ severity: "HIGH", confidence: "FIRM", affectedIdentities: [spec.ref] });
        expect(finding.title).toContain(mode);
        expect(finding.evidence.exchanges).toHaveLength(3);
        expect(JSON.stringify(finding)).not.toContain(live);
        expect(JSON.stringify(finding)).not.toContain(expired);
        fingerprints.add(finding.fingerprint);
      }
    }
    expect(fingerprints.size).toBe(4);
    mode = "baseline-denied";
    expect((await run()).findings).toEqual([]);
    expect(requests).toHaveLength(2);
    mode = "anonymous-success";
    expect((await run()).findings[0]?.title).toContain("Missing authentication");
    expect(requests).toHaveLength(1);
    mode = "server-error";
    expect((await run()).findings).toEqual([]);
    mode = "none-alg";
    expect((await run(3)).findings).toHaveLength(1);
    expect(requests).toHaveLength(3);
    target.endpoints = Array.from({ length: 7 }, (_, n) => ({ ...target.endpoints[0]!, id: `profile-${n}`, path: `/profile/${n}` }));
    await run();
    expect(requests).toHaveLength(30);
    target.endpoints = [{ ...target.endpoints[0]!, path: "/profile/{id}" }];
    expect((await run()).findings).toEqual([]);
    expect(requests).toHaveLength(0);
    target.endpoints = [{ ...target.endpoints[0]!, path: "/profile" }];
    delete spec.expiredCredentials;
    vi.stubEnv("PERIMETER_JWT_LIVE", "opaque-credential");
    expect((await run()).findings).toEqual([]);
    expect(requests).toHaveLength(1);
    requests.length = 0;
    const guarded = await new Orchestrator(parseScanConfig({ target: targetPath, output: { auditLog } }), [{
      manifest: { ...tokenManipulation.manifest, requires: {} },
      async plan() { return { probeId: "auth/token-manipulation", steps: [] }; },
      async run(_plan, ctx) {
        await expect(ctx.http.get("/profile", { jwtVariant: "none-alg" })).rejects.toThrow("require an identity");
        await expect(ctx.http.request({ method: "POST", url: "/profile", as: spec.ref, jwtVariant: "none-alg" })).rejects.toThrow("GET/HEAD");
        await expect(ctx.http.get("http://localhost:1/outside", { as: spec.ref, jwtVariant: "none-alg" })).rejects.toThrow();
      },
    }], { logger: new ConsoleLogger("error") }).run();
    expect(guarded.skipped).toEqual([]);
    expect(requests).toHaveLength(0);
    const audit = await readFile(auditLog, "utf8");
    expect(audit).not.toContain(live);
    expect(audit).not.toContain(expired);
    expect(audit).toContain("«redacted»");
    for (const line of audit.trim().split("\n")) {
      const entry = JSON.parse(line) as { exchange: { response: { headers: Record<string, string> } } };
      const reflected = entry.exchange.response.headers["x-reflected-token"];
      if (reflected) expect(reflected).toBe("«redacted»");
    }
  } finally {
    vi.unstubAllEnvs();
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
