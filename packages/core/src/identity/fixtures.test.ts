import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { parseTargetModel, type GuardedResponse } from "@perimeter/sdk";
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
    const deleted: string[] = [];
    let reply: unknown;
    const server = createServer((req, res) => {
      if (req.method === "DELETE") {
        deleted.push(req.url!);
        res.writeHead(204).end();
        return;
      }
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (chunk: string) => { body += chunk; });
      req.on("end", () => {
        received.push(JSON.parse(body) as unknown);
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify(reply ?? { id: `scratch-${received.length}` }));
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
      const budget = new MutableBudget(5);
      const scratchIds = new Set<string>();
      const client = new GuardedHttpClientImpl({
        baseUrl: model.baseUrl, probeId: "engine/fixtures", probeSafetyClass: "idempotent-write",
        guard: new SafetyGuard({
          allowedHosts: new Set([new URL(model.baseUrl).host]), allowMutating: false,
          scratchObjectIds: scratchIds, fixtureFactoryPaths: FixtureManager.factoryPaths(model),
          allowScratchWrites: true,
        }),
        limiter: new RateLimiter({ globalRps: 100, perHostRps: 100, burst: 10 }, new SystemClock()),
        budget, audit, scanId: "fixture-payload", signal: new AbortController().signal,
        resolveIdentity: (ref) => ({ ref, tenant: "tenant-a", role: "member",
          headers: async () => ({ authorization: "Bearer fixture-secret" }) }),
      });
      const manager = new FixtureManager(model, client, { ids: scratchIds });
      expect(await manager.create("invoice", "tenantA.user")).toMatchObject({ id: "scratch-1", ownerTenant: "tenant-a" });
      expect(received).toEqual([payload]);
      expect(audit.entries[0]!.exchange.request.body).toBe(JSON.stringify(payload));
      expect(audit.entries[0]!.exchange.request.headers.authorization).not.toContain("fixture-secret");

      delete model.endpoints[0]!.fixture;
      await manager.create("invoice", "tenantA.user");
      expect(received).toEqual([payload, {}]);
      reply = { id: "wrong-id", data: [{ uuid: "vendor/123" }] };
      model.endpoints[0]!.fixture = { responseIdPath: ["data", "0", "uuid"] };
      model.endpoints.push({
        id: "deleteInvoice", method: "DELETE", path: "/api/invoices/{invoiceId}",
        auth: "required", tenantScoped: true, rateSensitive: false,
        objectRef: { param: "invoiceId", kind: "invoice", ownership: "tenant" },
      });
      const mapped = await manager.create("invoice", "tenantA.user");
      expect(mapped.id).toBe("vendor/123");
      expect(manager.view().ofKind("invoice").map((fixture) => fixture.id)).toContain(mapped.id);
      expect(scratchIds.has(mapped.id)).toBe(true);
      await manager.teardownAll();
      expect(deleted).toEqual(["/api/invoices/vendor%2F123"]);
      expect(scratchIds.size).toBe(0);
      model.endpoints[0]!.fixture = { body: { query: "DROP TABLE invoices" } };
      await expect(manager.create("invoice", "tenantA.user")).rejects.toThrow("safety guard blocked");
      expect(received).toHaveLength(3);
      expect(budget.used).toBe(5);
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
    for (const responseIdPath of [[], [""], [0], "data.id"]) {
      expect(() => parseTargetModel({ ...target, endpoints: [{ ...endpoint, fixture: { responseIdPath } }] })).toThrow();
    }
  });

  it("requires the configured ID path even when heuristic IDs or Location are available", async () => {
    const target = await loadTargetModel("examples/target.yaml");
    target.endpoints = parseTargetModel({ ...target, endpoints: [{
      id: "create", method: "POST", path: "/objects", creates: "object",
      fixture: { responseIdPath: ["record", "uuid"] },
    }] }).endpoints;
    let body: unknown;
    let malformed = false;
    const response: GuardedResponse = {
      status: 201, headers: { location: "/objects/wrong-location-id" }, elapsedMs: 0,
      text: async () => JSON.stringify(body),
      json: async <T>() => {
        if (malformed) throw new Error("invalid JSON including private data");
        return body as T;
      },
      exchange: {
        ref: "fixture-response",
        request: { method: "POST", url: "http://localhost/objects", headers: {} },
        response: { status: 201, headers: {}, elapsedMs: 0 },
      },
    };
    const manager = new FixtureManager(target, {
      request: async () => response, get: async () => response,
    });
    for (const value of [undefined, null, "", "  ", {}, [], true, Infinity]) {
      body = { id: "wrong-heuristic-id", record: { uuid: value } };
      await expect(manager.create("object", "tenantA.user")).rejects.toThrow("fixture.responseIdPath");
      expect(manager.scratchObjectIds().size).toBe(0);
    }
    malformed = true;
    await expect(manager.create("object", "tenantA.user")).rejects.toThrow(
      /^fixture.responseIdPath for "object" requires a JSON response$/,
    );
    malformed = false;
    body = { record: { uuid: 0 } };
    expect(await manager.create("object", "tenantA.user")).toMatchObject({ id: "0" });
  });
});
