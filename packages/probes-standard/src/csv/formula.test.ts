import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";
import { loadTargetModel, runProbeAgainstFixtures, Orchestrator, parseScanConfig, ConsoleLogger } from "@perimeter/core";
import { csvFormula } from "./formula.js";
import { parseCsv } from "./parse.js";

async function model(): Promise<TargetModel> {
  const original = await loadTargetModel("examples/target.yaml");
  return parseTargetModel({ ...original,
    identities: [{ ref: "owner", tenant: "tenant-a", credentials: { env: "PERIMETER_CSV_TEST" } }],
    endpoints: [
      { id: "export", method: "GET", path: "/export", objectRef: { param: "id", kind: "note", ownership: "user" },
        csv: { identity: "owner", column: "note", idColumn: "id", fixtureField: "note" } },
      { id: "create", method: "POST", path: "/notes", creates: "note", fixture: { body: { note: "=1+1" } } },
      { id: "delete", method: "DELETE", path: "/notes/{id}", objectRef: { param: "id", kind: "note", ownership: "user" } },
    ], authorization: { ...original.authorization, rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } },
  });
}

it("parses CSV quoting, BOM, multiline fields, alternate delimiters and rejects malformed/oversized input", () => {
  expect(parseCsv('\uFEFFid,note\r\na,"one,""two""\nthree"\r\n', ",")).toEqual([["id", "note"], ["a", 'one,"two"\nthree']]);
  expect(parseCsv("id;note\na;=1+1", ";")).toEqual([["id", "note"], ["a", "=1+1"]]);
  expect(parseCsv("id\tnote\na\t'=1+1", "\t")[1]).toEqual(["a", "'=1+1"]);
  expect(parseCsv("a,b\n1,", ",")[1]).toEqual(["1", ""]);
  for (const value of ['', 'a,b\n1', 'a,b\n1,"x', 'a,b\n1,"x"garbage', 'a,b\n1,x"', "x".repeat(16385), "a\n".repeat(1001), Array(129).fill("a").join(",")]) {
    expect(() => parseCsv(value, ",")).toThrow();
  }
});

it("requires reviewed canary contracts and distinguishes vulnerability, text prefix, and inconclusive exports", async () => {
  const target = await model();
  const run = (body: string, status = 200, type = "text/csv", scratch = true) => runProbeAgainstFixtures(csvFormula, {
    target, scratchObjects: scratch ? [{ id: "scratch", kind: "note", ownerIdentity: "owner", ownerTenant: "tenant-a" }] : [],
    fixtures: [{ match: { method: "GET", urlIncludes: "/export", as: "owner" }, respond: { status, headers: { "content-type": type }, body } }],
  });
  for (const value of ["=1+1", '"=1+1"']) {
    const result = await run(`id,note\nscratch,${value}\n`);
    expect(result.reports).toHaveLength(1);
    expect(result.reports[0]).toMatchObject({ severity: "MEDIUM", confidence: "FIRM" });
  }
  expect((await run("id,note\nscratch,'=1+1\n")).reports[0]).toMatchObject({ kind: "pass" });
  for (const body of ["id,note\nother,=1+1\n", "id,note\nscratch,42\n", "id,note\nscratch,\t=1+1\n",
    'id,note\nscratch,"=1+1', "id,note\nscratch,=1+1\nscratch,=1+1\n", "id,id\nscratch,=1+1\n", "id,note\nscratch,=1+1\nother"])
    expect((await run(body)).reports).toEqual([]);
  expect((await run("id,note\nscratch,=1+1", 403)).reports).toEqual([]);
  expect((await run("id,note\nscratch,=1+1", 200, "text/html")).reports).toEqual([]);
  expect((await run("", 200, "text/csv", false)).requests).toEqual([]);
  for (const change of [{ method: "POST" }, { path: "//elsewhere/export" }, { path: "/export?all=true" }, { path: "/{unknown}" }]) {
    expect(() => parseTargetModel({ ...target, endpoints: [{ ...target.endpoints[0], ...change }, ...target.endpoints.slice(1)] })).toThrow();
  }
  const invalid = structuredClone(target);
  invalid.endpoints[1]!.fixture!.body!.note = "not a canary";
  expect(() => parseTargetModel(invalid)).toThrow();
  invalid.endpoints[1]!.fixture!.body!.note = "=1+1";
  invalid.endpoints[0]!.csv!.identity = "missing";
  expect(() => parseTargetModel(invalid)).toThrow();
});

it("runs the registered CLI probe with real scratch creation, cleanup, bounded capture and redacted authentication", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-csv-"));
  const objects = new Map<string, string>();
  let serial = 0;
  let mode = "vulnerable";
  vi.stubEnv("PERIMETER_CSV_TEST", "private-csv-credential");
  const server = createServer(async (req, res) => {
    if (req.headers.authorization !== "Bearer private-csv-credential") { res.statusCode = 401; res.end(); return; }
    if (req.method === "POST") {
      let body = ""; for await (const chunk of req) body += String(chunk);
      const id = `scratch-${++serial}`; objects.set(id, String(JSON.parse(body).note));
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ id })); return;
    }
    if (req.method === "DELETE") { objects.delete(req.url!.split("/").pop()!); res.statusCode = 204; res.end(); return; }
    res.setHeader("content-type", "text/csv");
    res.end(mode === "oversized" ? "x".repeat(16385) : "id,note\r\n" + [...objects].map(([id, value]) => `${id},"${mode === "patched" ? "'" : ""}${value}"\r\n`).join(""));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address(); if (!address || typeof address === "string") throw new Error("No address");
    const target = await model(); target.baseUrl = `http://127.0.0.1:${address.port}`;
    const path = join(directory, "target.json"); await writeFile(path, JSON.stringify(target));
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, include: ["csv"], output, failOn: "none" });
    for (mode of ["vulnerable", "patched", "oversized"]) {
      const result = await new Orchestrator(config, [csvFormula], { logger: new ConsoleLogger("error") }).run();
      expect(result.findings).toHaveLength(mode === "vulnerable" ? 1 : 0);
      expect(result.passes).toHaveLength(mode === "patched" ? 1 : 0);
      expect(objects.size).toBe(0);
    }
    mode = "vulnerable";
    const hidden = await new Orchestrator(config, [csvFormula], { captureBodies: false, logger: new ConsoleLogger("error") }).run();
    expect(hidden.findings).toEqual([]); expect(hidden.passes).toEqual([]);
    const configPath = join(directory, "scan.json"); await writeFile(configPath, JSON.stringify(config));
    await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect(objects.size).toBe(0);
    expect(await readFile(output.auditLog, "utf8")).not.toContain("private-csv-credential");
  } finally {
    vi.unstubAllEnvs(); server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
