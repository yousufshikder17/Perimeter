import { Server, ServerCredentials, type ServerUnaryCall, type sendUnaryData } from "@grpc/grpc-js";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";
import { ConsoleLogger } from "../runtime/logger.js";
import { compileGrpc } from "./codec.js";
import { STANDARD_PROBES } from "../../../probes-standard/dist/index.js";

it("runs registered gRPC authorization through the engine and CLI, with real denial/data controls and stable evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-grpc-auth-"));
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original, baseUrl: "http://127.0.0.1:1", authorization: { ...original.authorization,
    environment: "local", rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } },
    identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "GRPC_TEST_OWNER" } },
      { ref: "reader", tenant: "tenant-b", credentials: { env: "GRPC_TEST_READER" } }],
    endpoints: [{ id: "read", method: "POST", path: "/test.Records/Get", tenantScoped: true, rateSensitive: true, injectable: ["id"],
      grpc: { readOnly: true, proto: 'syntax = "proto3"; package test; message Request { string id = 1; } message Reply { string id = 1; } service Records { rpc Get(Request) returns (Reply); }',
        request: { id: "protected" }, resultPath: ["id"], ownerIdentity: "owner", otherIdentity: "reader" } }] });
  vi.stubEnv("GRPC_TEST_OWNER", "owner-private-token"); vi.stubEnv("GRPC_TEST_READER", "reader-private-token");
  const codec = compileGrpc(target.endpoints[0]!);
  let mode = "patched"; let calls = 0;
  const server = new Server();
  server.addService({ Get: { path: "/test.Records/Get", requestStream: false, responseStream: false,
    requestSerialize: codec.encode, requestDeserialize: codec.decode, responseSerialize: codec.encode, responseDeserialize: codec.decode } }, {
    Get(call: ServerUnaryCall<Record<string, unknown>, Record<string, unknown>>, callback: sendUnaryData<Record<string, unknown>>) {
      calls++; const credential = call.metadata.get("authorization")[0]; const owner = credential === "Bearer owner-private-token";
      if (owner && mode !== "owner-denied") { callback(null, call.request); return; }
      if ((mode === "cross" && credential) || (mode === "anonymous" && !credential)) { callback(null, call.request); return; }
      if (mode === "wrong-data") { callback(null, { id: "public" }); return; }
      callback({ code: mode === "internal" ? 13 : credential ? 7 : 16, details: "denied" });
    },
  });
  const port = await new Promise<number>((resolve, reject) => server.bindAsync("127.0.0.1:0", ServerCredentials.createInsecure(), (error, p) => error ? reject(error) : resolve(p)));
  target.baseUrl = `http://127.0.0.1:${port}`;
  try {
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, output, failOn: "none" }); const logger = new ConsoleLogger("error");
    for (mode of ["patched", "cross", "anonymous", "owner-denied", "internal", "wrong-data"]) {
      calls = 0;
      const result = await new Orchestrator(config, STANDARD_PROBES, { logger }).run();
      expect(result.findings, mode).toHaveLength(["cross", "anonymous"].includes(mode) ? 1 : 0);
      expect(result.passes, mode).toHaveLength(mode === "patched" ? 2 : ["cross", "anonymous"].includes(mode) ? 1 : 0);
      expect(calls).toBe(mode === "owner-denied" ? 1 : 3);
      if (result.findings.length) expect(result.findings[0]!.evidence.exchanges.every((e) => e.protocol === "grpc")).toBe(true);
    }
    mode = "cross"; calls = 0;
    const hidden = await new Orchestrator(config, STANDARD_PROBES, { logger, captureBodies: false }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]); expect(calls).toBe(1);
    calls = 0;
    await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 2 }), STANDARD_PROBES, { logger }).run(); expect(calls).toBe(0);
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify({ ...config, checkpoint: join(directory, "state.json") }));
    const cli = [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath];
    await promisify(execFile)(process.execPath, cli);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    const before = calls; await promisify(execFile)(process.execPath, [...cli, "--resume"]); expect(calls).toBe(before);
    expect(await readFile(output.auditLog, "utf8")).not.toContain("private-token");
  } finally { vi.unstubAllEnvs(); server.forceShutdown(); await rm(directory, { recursive: true, force: true }); }
}, 20000);
