import { Server, ServerCredentials, status, type ServerUnaryCall, type sendUnaryData } from "@grpc/grpc-js";
import { expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { MemoryAuditLog } from "../audit/audit-log.js";
import { MutableBudget } from "../runtime/budget.js";
import { RateLimiter } from "../safety/rate-limiter.js";
import { SystemClock } from "../runtime/clock.js";
import { SafetyGuard } from "../safety/guard.js";
import { compileGrpc } from "./codec.js";
import { GuardedGrpcClientImpl } from "./client.js";

it("runs real unary traffic with exact methods, limits, credentials, native status evidence and cancellation", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original, baseUrl: "http://127.0.0.1:1", authorization: { ...original.authorization, environment: "local" }, endpoints: [
    { id: "read", method: "POST", path: "/test.Records/Get", grpc: { readOnly: true,
      proto: 'syntax = "proto3"; package test; message Request { string id = 1; } message Reply { string id = 1; } service Records { rpc Get(Request) returns (Reply); }',
      request: { id: "protected" }, resultPath: ["id"], ownerIdentity: "tenantA.user", otherIdentity: "tenantB.user", deadlineMs: 100 } },
  ] });
  const codec = compileGrpc(target.endpoints[0]!);
  let mode = "normal"; let calls = 0;
  const server = new Server();
  server.addService({ Get: { path: "/test.Records/Get", requestStream: false, responseStream: false,
    requestSerialize: codec.encode, requestDeserialize: codec.decode,
    responseSerialize: codec.encode, responseDeserialize: codec.decode } }, {
    Get(call: ServerUnaryCall<Record<string, unknown>, Record<string, unknown>>, callback: sendUnaryData<Record<string, unknown>>) {
      calls++;
      if (mode === "slow") return;
      if (mode === "denied") { callback({ code: status.PERMISSION_DENIED, details: "private-credential" }); return; }
      callback(null, { id: mode === "echo" ? String(call.metadata.get("authorization")[0]) : call.request.id });
    },
  });
  const port = await new Promise<number>((resolve, reject) => server.bindAsync("127.0.0.1:0", ServerCredentials.createInsecure(), (error, p) => error ? reject(error) : resolve(p)));
  target.baseUrl = `http://127.0.0.1:${port}`;
  const audit = new MemoryAuditLog(); const budget = new MutableBudget(20);
  const controller = new AbortController();
  const deps = { target, probeId: "test/grpc", scanId: "test", budget, audit, signal: controller.signal,
    limiter: new RateLimiter({ globalRps: 1000, perHostRps: 1000, burst: 1000 }, new SystemClock()),
    fixtures: { owned: () => undefined, ofKind: () => [] },
    resolveIdentity: (ref: string) => ({ ref, tenant: "tenant-a", role: "member", headers: async () => ({ authorization: "Bearer private-credential" }) }),
  };
  const client = new GuardedGrpcClientImpl(deps);
  try {
    expect(await client.request({ endpointId: "read", as: "tenantA.user" })).toMatchObject({ code: 0, exchange: { protocol: "grpc", response: { body: '{"id":"protected"}' } } });
    expect(budget.used).toBe(1);
    await expect(client.request({ endpointId: "other" })).rejects.toThrow();
    await expect(client.request({ endpointId: "read", as: "unknown" })).rejects.toThrow();
    await expect(client.request({ endpointId: "read", scratchObjectId: "real" })).rejects.toThrow();
    expect(calls).toBe(1);
    mode = "echo"; expect((await client.request({ endpointId: "read", as: "tenantA.user" })).exchange.response.body).not.toContain("private-credential");
    mode = "denied"; expect((await client.request({ endpointId: "read" })).code).toBe(7);
    expect(JSON.stringify(audit.entries)).not.toContain("private-credential");
    mode = "normal";
    expect((await new GuardedGrpcClientImpl({ ...deps, captureBodies: false }).request({ endpointId: "read" })).exchange.response.body).toBe("«redacted»");
    expect((await new GuardedGrpcClientImpl({ ...deps, maxResponseBytes: 1 }).request({ endpointId: "read" })).code).not.toBe(0);
    const exhausted = new GuardedGrpcClientImpl({ ...deps, budget: new MutableBudget(1) });
    await exhausted.request({ endpointId: "read" });
    await expect(exhausted.request({ endpointId: "read" })).rejects.toThrow("budget");
    const guard = new SafetyGuard({ allowedHosts: new Set([new URL(target.baseUrl).host]), allowMutating: true,
      scratchObjectIds: new Set(), grpcEndpoints: [`${target.baseUrl}/test.Records/Get`] });
    expect(() => guard.check({ method: "GET", url: `${target.baseUrl}/test.Records/Get?x=1`, probeSafetyClass: "read-only", payloadParts: [] })).toThrow("unary transport");
    mode = "slow"; expect((await client.request({ endpointId: "read" })).code).toBe(status.DEADLINE_EXCEEDED);
    const pending = client.request({ endpointId: "read" }); controller.abort();
    await expect(pending).rejects.toThrow();
  } finally { server.forceShutdown(); }
});
