import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel, runProbeAgainstFixtures, Orchestrator, parseScanConfig, ConsoleLogger } from "@perimeter/core";
import { graphqlAuthorization } from "./authorization.js";
import { STANDARD_PROBES } from "../index.js";

it("distinguishes protected data, errors, incomplete controls, missing fixtures, and REST plans", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original, endpoints: [{ id: "query", method: "GET", path: "/graphql", auth: "required",
    tenantScoped: true, rateSensitive: true, injectable: ["search"], objectRef: { param: "id", kind: "invoice", ownership: "tenant" },
    graphql: { query: "query Q($id: ID!) { invoice(id: $id) { id } }", resultPath: ["invoice", "id"],
      ownerIdentity: "tenantB.user", otherIdentity: "tenantA.user" } }] });
  const data = '{"data":{"invoice":{"id":"scratch-owner"}}}';
  const denied = '{"data":{"invoice":null},"errors":[{"message":"Denied","extensions":{"code":"FORBIDDEN"}}]}';
  const run = (body: string, owner = data, status = 200, fixtures = true) => runProbeAgainstFixtures(graphqlAuthorization, {
    target,
    scratchObjects: fixtures ? [{ id: "scratch-owner", kind: "invoice", ownerIdentity: "tenantB.user", ownerTenant: "tenant-b" }] : [],
    fixtures: [
      { match: { method: "GET", urlIncludes: "/graphql", as: "tenantB.user" }, respond: { status: 200, body: owner } },
      { match: { method: "GET", urlIncludes: "/graphql", as: "tenantA.user" }, respond: { status, body } },
      { match: { method: "GET", urlIncludes: "/graphql" }, respond: { status: 200, body: denied } },
    ],
  });
  const vulnerable = await run(data);
  expect(vulnerable.reports.filter((r) => "severity" in r)).toHaveLength(1);
  expect(vulnerable.reports[1]).toMatchObject({ severity: "HIGH", confidence: "FIRM" });
  expect((await run(denied)).reports).toHaveLength(2);
  expect((await run(denied)).reports.every((r) => "kind" in r && r.kind === "pass")).toBe(true);
  const partial = JSON.stringify({ data: { invoice: { id: "scratch-owner" } }, errors: [{ message: "Other field failed" }] });
  expect((await run(partial)).reports.filter((r) => "severity" in r)).toHaveLength(1);
  expect((await run(data, data, 403)).reports.filter((r) => "severity" in r)).toHaveLength(1);
  for (const body of ['<html>error</html>', '{"errors":[{"message":"Internal error"}]}', '{"data":{"invoice":{"id":"different"}}}', '{"data":',
    '{"data":{"invoice":{"id":"«redacted»"}}}']) {
    const result = await run(body);
    expect(result.reports).toHaveLength(1); // anonymous denial only; other access is inconclusive
    expect(result.reports[0]).toMatchObject({ kind: "pass" });
  }
  expect((await run(data, denied)).requests).toHaveLength(1);
  expect((await run(data, denied)).reports).toEqual([]);
  expect((await run(data, partial)).reports).toEqual([]);
  expect((await run(data, data, 200, false)).requests).toEqual([]);
  expect(target.endpoints[0]!.graphql!.variables).toEqual({});
  const field = { ...target.endpoints[0]!, graphql: { ...target.endpoints[0]!.graphql!,
    query: "{ items { marker } }", resultPath: ["items", "0", "marker"] } };
  delete field.objectRef;
  const fieldResult = await runProbeAgainstFixtures(graphqlAuthorization, {
    target: parseTargetModel({ ...target, endpoints: [field] }),
    fixtures: [
      { match: { method: "GET", urlIncludes: "/graphql", as: "tenantB.user" }, respond: { status: 200, body: '{"data":{"items":[{"marker":0}]}}' } },
      { match: { method: "GET", urlIncludes: "/graphql", as: "tenantA.user" }, respond: { status: 200, body: '{"data":{"items":[{"marker":0}]}}' } },
      { match: { method: "GET", urlIncludes: "/graphql" }, respond: { status: 403, body: '{}' } },
    ],
  });
  expect(fieldResult.reports.filter((r) => "severity" in r)).toHaveLength(1);
  expect(fieldResult.requests).toHaveLength(3);
  for (const probe of STANDARD_PROBES.filter((p) => p !== graphqlAuthorization)) {
    const result = await runProbeAgainstFixtures(probe, { target, fixtures: [] });
    expect(result.requests).toEqual([]);
    expect(result.skipped).not.toBeNull();
  }
});

it("runs bounded GET/POST GraphQL scans and the CLI with owner fixtures, denial controls, and redacted evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-graphql-probe-"));
  const objects = new Map<string, string>();
  const queries: Array<{ method: string; id: string }> = [];
  let serial = 0;
  let mode = "patched";
  vi.stubEnv("PERIMETER_GRAPHQL_OWNER", "graphql-owner-private-token");
  vi.stubEnv("PERIMETER_GRAPHQL_READER", "graphql-reader-private-token");
  const server = createServer(async (req, res) => {
    let text = "";
    for await (const chunk of req) text += String(chunk);
    const url = new URL(req.url!, "http://localhost");
    res.setHeader("content-type", "application/json");
    if (url.pathname === "/fixtures" && req.method === "POST") {
      const id = `scratch-${++serial}`;
      objects.set(id, req.headers.authorization!);
      res.end(JSON.stringify({ id })); return;
    }
    if (url.pathname.startsWith("/fixtures/") && req.method === "DELETE") {
      objects.delete(url.pathname.split("/").pop()!); res.statusCode = 204; res.end(); return;
    }
    const envelope = req.method === "GET" ? { variables: JSON.parse(url.searchParams.get("variables")!) } : JSON.parse(text);
    const id = String(envelope.variables.id);
    queries.push({ method: req.method!, id });
    const owner = objects.get(id) === req.headers.authorization;
    if (mode === "owner-denied" && owner) { res.statusCode = 403; res.end('{}'); return; }
    if (mode === "generic" && !owner) { res.statusCode = 500; res.end('{"errors":[{"message":"Internal error"}]}'); return; }
    const expose = owner || (mode === "anonymous" && !req.headers.authorization) ||
      (["cross", "partial"].includes(mode) && !!req.headers.authorization);
    res.end(JSON.stringify({ data: { invoice: expose ? { id } : null },
      ...(!expose ? { errors: [{ message: "Denied", extensions: { code: "FORBIDDEN" } }] } :
        mode === "partial" && !owner ? { errors: [{ message: "Unrelated field denied" }] } : {}) }));
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const original = await loadTargetModel("examples/target.yaml");
    const target = parseTargetModel({ ...original, baseUrl: `http://127.0.0.1:${address.port}`,
      identities: [{ ref: "owner", tenant: "tenant-b", credentials: { env: "PERIMETER_GRAPHQL_OWNER" } },
        { ref: "reader", tenant: "tenant-a", credentials: { env: "PERIMETER_GRAPHQL_READER" } }],
      endpoints: [
        { id: "query", method: "POST", path: "/graphql", tenantScoped: true, auth: "required", rateSensitive: true, injectable: ["id"],
          objectRef: { param: "id", kind: "invoice", ownership: "tenant" },
          graphql: { query: "query Q($id: ID!) { invoice(id: $id) { id } }", resultPath: ["invoice", "id"], ownerIdentity: "owner", otherIdentity: "reader" } },
        { id: "factory", method: "POST", path: "/fixtures", creates: "invoice" },
        { id: "cleanup", method: "DELETE", path: "/fixtures/{id}", objectRef: { param: "id", kind: "invoice", ownership: "tenant" } },
      ], authorization: { ...original.authorization, rateLimit: { globalRps: 1000, perHostRps: 1000, burst: 1000 } },
    });
    const path = join(directory, "target.json");
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = parseScanConfig({ target: path, output, failOn: "none" });
    const fingerprints = new Set<string>();
    for (const method of ["GET", "POST"] as const) {
      target.endpoints[0]!.method = method;
      await writeFile(path, JSON.stringify(target));
      for (mode of ["patched", "anonymous", "cross", "partial", "generic", "owner-denied"]) {
        queries.length = 0;
        const result = await new Orchestrator(config, STANDARD_PROBES, { logger: new ConsoleLogger("error") }).run();
        expect(result.findings).toHaveLength(["anonymous", "cross", "partial"].includes(mode) ? 1 : 0);
        expect(queries).toHaveLength(mode === "owner-denied" ? 1 : 3);
        expect(new Set(queries.map((q) => q.id)).size).toBe(1);
        expect(queries.every((q) => q.method === method)).toBe(true);
        expect(objects.size).toBe(0);
        if (mode === "patched") expect(result.passes).toHaveLength(2);
        if (["generic", "owner-denied"].includes(mode)) expect(result.passes).toEqual([]);
        if (mode === "cross") fingerprints.add(result.findings[0]!.fingerprint);
        if (result.findings.length) expect(result.findings[0]!.evidence.exchanges).toHaveLength(2);
      }
    }
    expect(fingerprints.size).toBe(1);
    queries.length = 0;
    await new Orchestrator(parseScanConfig({ ...config, maxTotalRequests: 4 }), [graphqlAuthorization], { logger: new ConsoleLogger("error") }).run();
    expect(queries).toEqual([]); // two fixture creations leave insufficient query-control budget
    expect(objects.size).toBe(0);
    mode = "cross";
    const configPath = join(directory, "scan.json");
    await writeFile(configPath, JSON.stringify(config));
    await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath]);
    expect(JSON.parse(await readFile(output.json, "utf8")).findings).toHaveLength(1);
    expect(objects.size).toBe(0);
    const audit = await readFile(output.auditLog, "utf8");
    expect(audit).not.toContain("graphql-owner-private-token");
    expect(audit).not.toContain("graphql-reader-private-token");
  } finally {
    vi.unstubAllEnvs();
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
