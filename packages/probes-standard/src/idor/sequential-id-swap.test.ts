import { describe, it, expect } from "vitest";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures, type RecordedExchange } from "@perimeter/core";
import { sequentialIdSwap } from "./sequential-id-swap.js";

/**
 * Every standard-library probe ships BOTH fixtures (spec §3.4): a vulnerable
 * target that proves the true-positive, and a patched target that proves the
 * true-negative. A probe without a passing patched-fixture test does not ship.
 */

const target: TargetModel = parseTargetModel({
  name: "fixture-saas",
  baseUrl: "http://localhost:8080",
  auth: { scheme: "bearer" },
  identities: [
    { ref: "tenantA.user", tenant: "tenant-a", role: "member" },
    { ref: "tenantB.user", tenant: "tenant-b", role: "member" },
  ],
  tenancy: {
    model: "shared_db_rls",
    discriminator: { location: "jwt_claim", name: "tenant_id" },
    tenants: ["tenant-a", "tenant-b"],
  },
  endpoints: [
    {
      id: "getInvoice",
      method: "GET",
      path: "/api/invoices/{invoiceId}",
      objectRef: { param: "invoiceId", kind: "invoice", ownership: "tenant" },
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

// Own object (tenant A) and another principal's (tenant B), both engine-provisioned.
const scratchObjects = [
  { id: "inv-a-7", kind: "invoice", ownerTenant: "tenant-a", ownerIdentity: "tenantA.user" },
  { id: "inv-b-8", kind: "invoice", ownerTenant: "tenant-b", ownerIdentity: "tenantB.user" },
];

describe("idor/sequential-id-swap", () => {
  it("flags a HIGH IDOR when a not-owned id is readable (true-positive)", async () => {
    const fixtures: RecordedExchange[] = [
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-a-7", as: "tenantA.user" }, respond: { status: 200, body: '{"id":"inv-a-7"}' } },
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-8", as: "tenantA.user" }, respond: { status: 200, body: '{"id":"inv-b-8"}' } },
    ];
    const { reports } = await runProbeAgainstFixtures(sequentialIdSwap, { target, fixtures, scratchObjects });
    const findings = reports.filter((r) => "severity" in r);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "HIGH", confidence: "FIRM" });
  });

  it("emits no finding when the not-owned id is denied (true-negative)", async () => {
    const fixtures: RecordedExchange[] = [
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-a-7", as: "tenantA.user" }, respond: { status: 200, body: '{"id":"inv-a-7"}' } },
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-8", as: "tenantA.user" }, respond: { status: 404, body: '{"error":"not found"}' } },
    ];
    const { reports } = await runProbeAgainstFixtures(sequentialIdSwap, { target, fixtures, scratchObjects });
    const findings = reports.filter((r) => "severity" in r);
    expect(findings).toHaveLength(0);
  });
});
