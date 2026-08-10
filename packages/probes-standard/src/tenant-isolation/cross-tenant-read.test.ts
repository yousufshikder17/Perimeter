import { describe, it, expect } from "vitest";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures, type RecordedExchange } from "@perimeter/core";
import { crossTenantRead } from "./cross-tenant-read.js";

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
      tenantScoped: true,
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

// The engine provisions this scratch object (owned by tenant B) before the probe
// runs (spec §4.3); the probe reads its id from ctx.fixtures.
const scratchObjects = [
  { id: "inv-b-42", kind: "invoice", ownerTenant: "tenant-b", ownerIdentity: "tenantB.user" },
];

describe("tenant-isolation/cross-tenant-read", () => {
  it("flags a CRITICAL cross-tenant read on a vulnerable target (true-positive)", async () => {
    // Vulnerable: tenant A gets a 200 for tenant B's invoice (missing RLS USING).
    const fixtures: RecordedExchange[] = [
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-42", as: "tenantB.user" }, respond: { status: 200, body: '{"id":"inv-b-42","tenant":"tenant-b"}' } },
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-42", as: "tenantA.user" }, respond: { status: 200, body: '{"id":"inv-b-42","tenant":"tenant-b"}' } },
    ];
    const { reports } = await runProbeAgainstFixtures(crossTenantRead, { target, fixtures, scratchObjects });
    const findings = reports.filter((r) => "severity" in r);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "CRITICAL", confidence: "CONFIRMED" });
  });

  it("emits no finding on a patched target (true-negative)", async () => {
    // Patched: tenant A gets 404 for tenant B's invoice (RLS partitions rows).
    const fixtures: RecordedExchange[] = [
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-42", as: "tenantB.user" }, respond: { status: 200, body: '{"id":"inv-b-42","tenant":"tenant-b"}' } },
      { match: { method: "GET", urlIncludes: "/api/invoices/inv-b-42", as: "tenantA.user" }, respond: { status: 404, body: '{"error":"not found"}' } },
    ];
    const { reports } = await runProbeAgainstFixtures(crossTenantRead, { target, fixtures, scratchObjects });
    const findings = reports.filter((r) => "severity" in r);
    const passes = reports.filter((r) => "kind" in r && (r as { kind: string }).kind === "pass");
    expect(findings).toHaveLength(0);
    expect(passes).toHaveLength(1);
  });

  it("skips an endpoint with no provisioned tenant-B fixture (no false pass)", async () => {
    const { reports } = await runProbeAgainstFixtures(crossTenantRead, { target, fixtures: [], scratchObjects: [] });
    // No fixture ⇒ nothing was probed ⇒ neither a finding nor a (misleading) pass.
    expect(reports).toHaveLength(0);
  });
});
