import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parseTargetModel, scratchPath, type Probe } from "@perimeter/sdk";
import { loadTargetModel } from "./loader.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";
import { ConsoleLogger } from "../runtime/logger.js";

it("validates reviewed PATCH/read/cleanup contracts and rejects ambiguous or non-scratch routes", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const objectRef = { param: "id", kind: "note", ownership: "user" };
  const target = parseTargetModel({ ...original, endpoints: [
    { id: "patch", method: "PATCH", path: "/notes/{id}", objectRef,
      massAssignment: { identity: "tenantA.user", readEndpointId: "read",
        control: { field: "label", value: "checked", resultPath: ["label"] },
        protected: { field: "approved", value: true, resultPath: ["approved"] } } },
    { id: "read", method: "GET", path: "/notes/{id}", objectRef },
    { id: "create", method: "POST", path: "/notes", creates: "note" },
    { id: "delete", method: "DELETE", path: "/notes/{id}", objectRef },
  ] });
  expect(target.endpoints[0]!.massAssignment!.resultIdPath).toEqual(["id"]);
  expect(scratchPath(target.endpoints[0]!, "vendor/123")).toBe("/notes/vendor%2F123");
  for (const path of ["/notes/fixed", "/notes/{id}/{id}", "/notes/{other}", "/notes/prefix-{id}",
    "//elsewhere/{id}", "/notes/../{id}", "/notes/{id}?all=true", "/notes/{id}#fragment", "/notes\\{id}"]) {
    const invalid = structuredClone(target); invalid.endpoints[0]!.path = path;
    expect(() => parseTargetModel(invalid)).toThrow();
  }
  for (const id of ["", ".", ".."]) expect(scratchPath(target.endpoints[0]!, id)).toBeUndefined();
  for (const change of [
    (t: typeof target) => { t.endpoints.pop(); },
    (t: typeof target) => { t.endpoints[1]!.method = "POST"; },
    (t: typeof target) => { t.endpoints[1]!.objectRef!.kind = "other"; },
    (t: typeof target) => { t.endpoints[0]!.massAssignment!.identity = "missing"; },
    (t: typeof target) => { t.endpoints[0]!.massAssignment!.protected.field = "label"; },
    (t: typeof target) => { t.endpoints[0]!.massAssignment!.protected.resultPath = ["id"]; },
    (t: typeof target) => { t.endpoints[0]!.massAssignment!.protected.field = "constructor"; },
    (t: typeof target) => { t.endpoints[0]!.method = "PUT"; },
    (t: typeof target) => { t.endpoints.push(t.endpoints[1]!); },
  ]) {
    const invalid = structuredClone(target); change(invalid);
    expect(() => parseTargetModel(invalid)).toThrow();
  }
});

it("skips unapproved write probes before setup and serializes approved writes after all reads", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-write-order-"));
  try {
    const target = await loadTargetModel("examples/target.yaml"); target.endpoints = [];
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const config = parseScanConfig({ target: path, concurrency: 4, output: { auditLog: join(directory, "audit.ndjson") } });
    const events: string[] = [];
    const probes: Probe[] = ["write-one", "read-one", "write-two", "read-two"].map((name) => ({
      manifest: { id: `test/${name}`, family: "test", version: "1", schemaVersion: "1", requires: {},
        safety: { class: name.startsWith("write") ? "idempotent-write" : "read-only", maxRequests: 1, destructive: false } },
      async plan() { return { probeId: `test/${name}`, steps: [] }; },
      async run() { events.push(`${name}:start`); await Promise.resolve(); events.push(`${name}:end`); },
    }));
    const logger = new ConsoleLogger("error");
    const result = await new Orchestrator(config, probes, { logger }).run();
    expect(result.skipped).toHaveLength(2);
    expect(events.every((e) => e.startsWith("read"))).toBe(true);
    events.length = 0;
    await new Orchestrator(parseScanConfig({ ...config, allowMutating: true }), probes, { logger }).run();
    expect(events.slice(0, 4).every((e) => e.startsWith("read"))).toBe(true);
    expect(events.slice(4)).toEqual(["write-one:start", "write-one:end", "write-two:start", "write-two:end"]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
