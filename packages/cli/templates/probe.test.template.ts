import { test } from "node:test";
import assert from "node:assert/strict";
import { parseManifest, parseTargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures } from "@perimeter/core";
import { probe } from "./probe.js";

const target = parseTargetModel({
  name: "recorded-diagnostic", baseUrl: "http://127.0.0.1:1", auth: { scheme: "bearer" },
  identities: [{ ref: "member", tenant: "one", role: "member" }],
  tenancy: { model: "header_scoped", discriminator: { location: "header", name: "x-tenant" }, tenants: ["one"] },
  endpoints: [{ id: "health", method: "GET", path: "/health", auth: "none" }],
  authorization: { iAmAuthorizedToTest: true, environment: "local", contact: "local-fixture",
    rateLimit: { globalRps: 1, perHostRps: 1, burst: 1 } },
});

test("records a successful diagnostic without claiming a vulnerability", async () => {
  assert.equal(parseManifest(probe.manifest).id, "__ID__");
  const result = await runProbeAgainstFixtures(probe, { target, fixtures: [
    { match: { method: "GET", urlIncludes: "/health" }, respond: { status: 200, body: "ready" } },
  ] });
  assert.equal(result.requests.length, 1);
  assert.equal(result.reports.length, 1);
  const report = result.reports[0]!;
  assert.equal("kind" in report && report.kind, "pass");
});

test("does not report success or a finding for a rejected response", async () => {
  const result = await runProbeAgainstFixtures(probe, { target, fixtures: [
    { match: { method: "GET", urlIncludes: "/health" }, respond: { status: 403, body: "denied" } },
  ] });
  assert.equal(result.requests.length, 1);
  assert.deepEqual(result.reports, []);
});

test("skips missing or protected endpoints without network activity", async () => {
  for (const endpoints of [[], target.endpoints.map((e) => ({ ...e, auth: "required" as const }))]) {
    const result = await runProbeAgainstFixtures(probe, { target: { ...target, endpoints }, fixtures: [] });
    assert.match(result.skipped ?? "", /no explicitly public/);
    assert.deepEqual(result.requests, []);
    assert.deepEqual(result.reports, []);
  }
});
