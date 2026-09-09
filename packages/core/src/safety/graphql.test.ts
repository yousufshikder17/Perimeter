import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { GraphqlQuerySchema, graphqlRequest, parseTargetModel, type Probe, type GuardedRequest } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { parseScanConfig } from "../config/scan-config.js";
import { Orchestrator } from "../orchestrator.js";
import { SafetyViolation } from "./guard.js";
import { ConsoleLogger } from "../runtime/logger.js";

it("accepts bounded query syntax and rejects mutation, batching, directives, and malformed models", async () => {
  expect(GraphqlQuerySchema.parse('query Read($id: ID!) { item: invoice(id: $id) { id } }')).toContain("Read");
  for (const query of ["mutation { change }", "subscription { events }", "query A { a } query B { b }",
    "{ a } mutation { b }", "{ ...F } fragment F on Query { a }", "{ a @skip(if: true) }", "{ ... on Query { a } }",
    "{", `{ ${"a { ".repeat(9)}id${" }".repeat(9)} }`, `{ ${Array.from({ length: 51 }, (_, n) => `a${n}: id`).join(" ")} }`]) {
    expect(GraphqlQuerySchema.safeParse(query).success).toBe(false);
  }
  const target = await loadTargetModel("examples/target.yaml");
  const endpoint = { id: "query", method: "POST", path: "/graphql", tenantScoped: true,
    graphql: { query: "query Read($id: ID!) { invoice(id: $id) { id } }", resultPath: ["invoice", "id"],
      ownerIdentity: "tenantB.user", otherIdentity: "tenantA.user" },
    objectRef: { param: "id", kind: "invoice", ownership: "tenant" } };
  expect(parseTargetModel({ ...target, endpoints: [endpoint] }).endpoints[0]!.graphql?.variables).toEqual({});
  for (const change of [{ method: "DELETE" }, { path: "//other/graphql" }, { path: "/graphql?query=override" },
    { creates: "invoice" }, { objectRef: { ...endpoint.objectRef, param: "missing" } },
    { graphql: { ...endpoint.graphql, ownerIdentity: "unknown" } },
    { graphql: { ...endpoint.graphql, ownerIdentity: "tenantA.user" } }]) {
    expect(() => parseTargetModel({ ...target, endpoints: [{ ...endpoint, ...change }] })).toThrow();
  }
});

it("guards real GraphQL GET/POST traffic without opening ordinary POSTs or query overrides", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-graphql-"));
  const received: unknown[] = [];
  let fixtures = 0;
  vi.stubEnv("PERIMETER_GRAPHQL_FIXTURE_TOKEN", "local-fixture-credential");
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += String(chunk);
    const url = new URL(req.url!, "http://localhost");
    if (url.pathname === "/fixtures") { fixtures++; res.end(JSON.stringify({ id: `scratch-${fixtures}` })); return; }
    received.push(req.method === "POST" ? JSON.parse(body) : { query: url.searchParams.get("query"), variables: JSON.parse(url.searchParams.get("variables")!) });
    res.setHeader("content-type", "application/graphql-response+json");
    res.end('{"data":{"invoice":{"id":"scratch-id"}}}');
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const original = await loadTargetModel("examples/target.yaml");
    const query = "query Read($id: ID!) { invoice(id: $id) { id } }";
    const target = parseTargetModel({ ...original, baseUrl: `http://127.0.0.1:${address.port}`,
      identities: original.identities.map((identity) => ({ ...identity, credentials: { env: "PERIMETER_GRAPHQL_FIXTURE_TOKEN" } })), endpoints: [
      { id: "query", method: "POST", path: "/graphql", graphql: { query, variables: { id: "scratch-id" },
        resultPath: ["invoice", "id"], ownerIdentity: "tenantB.user", otherIdentity: "tenantA.user" } },
      { id: "factory", method: "POST", path: "/fixtures", creates: "invoice" },
    ] });
    const endpoint = target.endpoints[0]!;
    const post = graphqlRequest(endpoint);
    const get = graphqlRequest({ ...endpoint, method: "GET" });
    const probe: Probe = {
      manifest: { id: "test/graphql", family: "test", version: "1", schemaVersion: "1", requires: { allIdentities: true },
        safety: { class: "read-only", maxRequests: 30, destructive: false } },
      async plan() { return { probeId: "test/graphql", steps: [] }; },
      async run(_plan, ctx) {
        expect((await ctx.http.request(post)).status).toBe(200);
        expect((await ctx.http.request(get)).status).toBe(200);
        const rejected: GuardedRequest[] = [
          { ...post, body: JSON.stringify({ query: "mutation { change }" }) },
          { ...post, body: JSON.stringify([{ query }]) },
          { ...post, body: JSON.stringify({ query, extensions: { persistedQuery: {} } }) },
          { ...post, body: JSON.stringify({ query, operationName: "Other" }) },
          { ...post, body: JSON.stringify({ query, variables: [] }) },
          { ...post, body: JSON.stringify({ query: "{ other }" }) },
          { ...post, headers: { "content-type": "text/plain" } },
          { ...post, url: "/graphql?query=override" },
          { ...get, url: `${get.url}&query=mutation` },
          { ...get, url: `${get.url}&variables={}` },
          { ...get, url: `${get.url}&extensions={}` },
          { ...get, body: JSON.stringify({ query: "mutation { change }" }) },
          { ...post, url: "/not-graphql" },
          { ...get, url: "http://127.0.0.1:1/graphql?query=mutation" },
          { ...post, method: "DELETE" },
        ];
        for (const request of rejected) await expect(ctx.http.request(request)).rejects.toThrow(SafetyViolation);
      },
    };
    const path = join(directory, "target.json");
    const auditLog = join(directory, "audit.ndjson");
    await writeFile(path, JSON.stringify(target));
    const result = await new Orchestrator(parseScanConfig({ target: path, output: { auditLog } }), [probe], { logger: new ConsoleLogger("error") }).run();
    expect(result.skipped).toEqual([]);
    expect(received).toEqual([{ query, variables: { id: "scratch-id" } }, { query, variables: { id: "scratch-id" } }]);
    expect(fixtures).toBe(target.identities.length);
    const audit = await readFile(auditLog, "utf8");
    expect(audit.trim().split("\n")).toHaveLength(2 + fixtures);
    expect(audit).not.toContain("local-fixture-credential");
  } finally {
    vi.unstubAllEnvs();
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
