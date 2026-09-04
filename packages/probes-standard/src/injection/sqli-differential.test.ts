import { describe, expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures, type RecordedExchange } from "@perimeter/core";
import { sqliDifferential } from "./sqli-differential.js";

const target = parseTargetModel({
  name: "fixture-saas",
  baseUrl: "http://localhost:8080",
  auth: { scheme: "bearer" },
  identities: [{ ref: "tenantA.user", tenant: "tenant-a", role: "member" }],
  tenancy: {
    model: "shared_db_rls",
    discriminator: { location: "jwt_claim", name: "tenant_id" },
    tenants: ["tenant-a"],
  },
  endpoints: [
    {
      id: "searchInvoices",
      method: "GET",
      path: "/api/invoices",
      injectable: ["query"],
      auth: "required",
    },
  ],
  authorization: {
    iAmAuthorizedToTest: true,
    environment: "staging",
    contact: "secops@example.com",
    rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 },
  },
});

function fixtures(truthyBody: string, falsyBody: string): RecordedExchange[] {
  return [
    {
      match: { method: "GET", urlIncludes: "1%3D1", as: "tenantA.user" },
      respond: { status: 200, body: truthyBody },
    },
    {
      match: { method: "GET", urlIncludes: "1%3D2", as: "tenantA.user" },
      respond: { status: 200, body: falsyBody },
    },
  ];
}

describe("injection/sqli-differential", () => {
  it("flags a differential response and ignores matching responses", async () => {
    const vulnerable = await runProbeAgainstFixtures(sqliDifferential, {
      target,
      fixtures: fixtures('[{"id":1}]', "[]"),
    });
    const patched = await runProbeAgainstFixtures(sqliDifferential, {
      target,
      fixtures: fixtures("[]", "[]"),
    });

    expect(vulnerable.reports).toHaveLength(1);
    expect(vulnerable.reports[0]).toMatchObject({ severity: "MEDIUM", confidence: "TENTATIVE" });
    expect(patched.reports).toHaveLength(0);
  });
});
