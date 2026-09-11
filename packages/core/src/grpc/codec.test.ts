import { expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { compileGrpc } from "./codec.js";

export const testProto = 'syntax = "proto3"; package test; message Request { string id = 1; } message Reply { string id = 1; } service Records { rpc Get(Request) returns (Reply); }';
it("validates unary models and encodes/decodes bounded messages without imports or streaming", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const raw = { ...original, baseUrl: "http://127.0.0.1:9000", authorization: { ...original.authorization, environment: "local" }, endpoints: [
    { id: "read", method: "POST", path: "/test.Records/Get", grpc: { readOnly: true, proto: testProto,
      request: { id: "one" }, resultPath: ["id"], ownerIdentity: "tenantA.user", otherIdentity: "tenantB.user" } },
  ] };
  const target = parseTargetModel(raw);
  const endpoint = target.endpoints[0]!;
  const codec = compileGrpc(endpoint);
  expect(codec.decode(codec.encode({ id: "one" }))).toEqual({ id: "one" });
  expect(() => codec.encode({ typo: "one" })).toThrow("Unknown");
  expect(() => codec.encode({ id: "x".repeat(16385) })).toThrow();
  expect(() => codec.decode(Buffer.alloc(16385))).toThrow();
  for (const proto of [testProto.replace("rpc Get(Request)", "rpc Get(stream Request)"),
    testProto.replace("returns (Reply)", "returns (stream Reply)"), testProto + '\nimport "other.proto";', "invalid"]) {
    expect(() => compileGrpc({ ...endpoint, grpc: { ...endpoint.grpc!, proto } })).toThrow();
  }
  for (const origin of ["http://user:password@localhost", "http://localhost/path", "http://localhost?query=yes", "dns:///localhost"]) {
    expect(() => parseTargetModel({ ...raw, endpoints: [{ ...raw.endpoints[0], grpc: { ...raw.endpoints[0]!.grpc, origin } }] })).toThrow();
  }
  expect(() => parseTargetModel({ ...raw, authorization: { ...raw.authorization, environment: "staging" } })).toThrow("TLS");
  expect(() => parseTargetModel({ ...raw, endpoints: [{ ...raw.endpoints[0], method: "GET" }] })).toThrow();
});
