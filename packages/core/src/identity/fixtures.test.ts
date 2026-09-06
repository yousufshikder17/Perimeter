import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { FixtureManager } from "./fixtures.js";
import { loadTargetModel } from "../target/loader.js";
import { GuardedHttpClientImpl } from "../http/guarded-http-client.js";
import { SafetyGuard } from "../safety/guard.js";
import { RateLimiter } from "../safety/rate-limiter.js";
import { SystemClock } from "../runtime/clock.js";
import { MutableBudget } from "../runtime/budget.js";
import { MemoryAuditLog } from "../audit/audit-log.js";

describe("configured scratch factories", () => {
  it("sends required JSON fields through guarded provisioning and preserves the empty default", async () => {
    const received: unknown[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (chunk: string) => { body += chunk; });
      req.on("end", () => {
        received.push(JSON.parse(body) as unknown);
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: `scratch-${received.length}` }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing test server address");
      const target = await loadTargetModel("examples/target.yaml");
      target.baseUrl = `http://127.0.0.1:${address.port}`;
      const payload = { amountCents: 100, meta: { active: true, extra: null }, labels: ["test", 1] };
      target.endpoints = [{
        id: "createInvoice", method: "POST", path: "/api/invoices", creates: "invoice",
        auth: "required", tenantScoped: false, rateSensitive: false,
        fixture: { body: payload },
      }];
      const model = parseTargetModel(target);
      const audit = new MemoryAuditLog();
      const budget = new MutableBudget(3);
      const client = new GuardedHttpClientImpl({
        baseUrl: model.baseUrl, probeId: "engine/fixtures", probeSafetyClass: "idempotent-write",
        guard: new SafetyGuard({
          allowedHosts: new Set([new URL(model.baseUrl).host]), allowMutating: false,
          scratchObjectIds: new Set(), fixtureFactoryPaths: FixtureManager.factoryPaths(model),
        }),
        limiter: new RateLimiter({ globalRps: 100, perHostRps: 100, burst: 10 }, new SystemClock()),
        budget, audit, scanId: "fixture-payload", signal: new AbortController().signal,
        resolveIdentity: (ref) => ({ ref, tenant: "tenant-a", role: "member",
          headers: async () => ({ authorization: "Bearer fixture-secret" }) }),
      });
      const manager = new FixtureManager(model, client);
      expect(await manager.create("invoice", "tenantA.user")).toMatchObject({ id: "scratch-1", ownerTenant: "tenant-a" });
      expect(received).toEqual([payload]);
      expect(audit.entries[0]!.exchange.request.body).toBe(JSON.stringify(payload));
      expect(audit.entries[0]!.exchange.request.headers.authorization).not.toContain("fixture-secret");

      delete model.endpoints[0]!.fixture;
      await manager.create("invoice", "tenantA.user");
      expect(received).toEqual([payload, {}]);
      model.endpoints[0]!.fixture = { body: { query: "DROP TABLE invoices" } };
      await expect(manager.create("invoice", "tenantA.user")).rejects.toThrow("safety guard blocked");
      expect(received).toHaveLength(2);
      expect(budget.used).toBe(3);
      await expect(manager.create("invoice", "tenantA.user")).rejects.toThrow("request budget exhausted");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
    }
  });

  it("rejects non-JSON data and fixture annotations on non-factories", async () => {
    const target = await loadTargetModel("examples/target.yaml");
    const endpoint = { id: "factory", path: "/objects", method: "POST", creates: "object" };
    for (const body of [[], null, "text", { number: Infinity }, { fn: () => 1 }, { value: undefined }]) {
      expect(() => parseTargetModel({ ...target, endpoints: [{ ...endpoint, fixture: { body } }] })).toThrow();
    }
    for (const factory of [{ ...endpoint, method: "GET" }, { ...endpoint, creates: undefined }]) {
      expect(() => parseTargetModel({ ...target, endpoints: [{ ...factory, fixture: { body: {} } }] }))
        .toThrow("fixture configuration requires a POST endpoint with creates");
    }
  });
});
