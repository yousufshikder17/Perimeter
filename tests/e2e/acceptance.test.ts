import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Orchestrator, parseScanConfig, type ScanConfig } from "@perimeter/core";
import type { Probe } from "@perimeter/sdk";
// Built artifacts, imported by relative path so this root-level test needs no extra
// workspace wiring. Requires a prior `pnpm build` — the same contract the unit tests
// rely on (they import @perimeter/core, i.e. dist). CI builds before it tests.
import { STANDARD_PROBES } from "../../packages/probes-standard/dist/index.js";

/**
 * The spec §8 acceptance scenario, end-to-end and automated. Boots the
 * deliberately-vulnerable reference target on an ephemeral port and runs a full,
 * rate-limited `Orchestrator` scan through the real engine — the wired path the
 * unit fixture tests don't cover. This is the regression guard for the fixture
 * provisioning fix: if cross-tenant/IDOR silently stops firing, this goes red.
 */

let server: { close: (cb?: (err?: Error) => void) => void };
let workdir: string;
let config: ScanConfig;
const probes: Probe[] = STANDARD_PROBES;

function targetYaml(baseUrl: string): string {
  return `
name: reference-saas
baseUrl: ${baseUrl}
auth:
  scheme: bearer
  tokenEndpoint: /auth/login
identities:
  - ref: tenantA.admin
    tenant: tenant-a
    role: admin
    credentials: { env: PERIMETER_TENANT_A_ADMIN }
  - ref: tenantA.user
    tenant: tenant-a
    role: member
    credentials: { env: PERIMETER_TENANT_A_USER }
  - ref: tenantB.user
    tenant: tenant-b
    role: member
    credentials: { env: PERIMETER_TENANT_B_USER }
tenancy:
  model: shared_db_rls
  discriminator: { location: jwt_claim, name: tenant_id }
  tenants: [tenant-a, tenant-b]
endpoints:
  - id: getInvoice
    method: GET
    path: /api/invoices/{invoiceId}
    tenantScoped: true
    objectRef: { param: invoiceId, kind: invoice, ownership: tenant }
    auth: required
  - id: createInvoice
    method: POST
    path: /api/invoices
    creates: invoice
    auth: required
  - id: login
    method: POST
    path: /auth/login
    rateSensitive: true
    injectable: [email, password]
    auth: none
authorization:
  iAmAuthorizedToTest: true
  environment: staging
  contact: secops@example.com
  rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 }
`;
}

beforeAll(async () => {
  // Rate limiting ON (so the rate-limit probe PASSES), tenant-isolation + IDOR
  // vulns ON — exactly the §8 target. These flags are read at reference-app import
  // time, so set them before the dynamic import below.
  process.env.FIX_RATE_LIMIT = "1";
  process.env.PERIMETER_TENANT_A_ADMIN = "tenant-a:admin-a";
  process.env.PERIMETER_TENANT_A_USER = "tenant-a:user-a";
  process.env.PERIMETER_TENANT_B_USER = "tenant-b:user-b";

  const ref = await import("../../apps/reference-target/dist/server.js");
  const started = await ref.start(0);
  server = started.server;

  workdir = mkdtempSync(join(tmpdir(), "perimeter-e2e-"));
  const targetPath = join(workdir, "target.yaml");
  writeFileSync(targetPath, targetYaml(`http://localhost:${started.port}`), "utf8");

  config = parseScanConfig({
    target: targetPath,
    seed: "e2e-acceptance-001",
    // Sequential so the rate-limit probe's bounded burst hits the login path in an
    // unbroken run — guarantees it crosses the target's every-10th-request throttle.
    concurrency: 1,
    maxTotalRequests: 500,
    output: {
      json: join(workdir, "findings.json"),
      markdown: join(workdir, "report.md"),
      auditLog: join(workdir, "audit.ndjson"),
    },
    failOn: "HIGH",
  });
});

afterAll(async () => {
  await new Promise<void>((res) => (server ? server.close(() => res()) : res()));
  if (workdir) rmSync(workdir, { recursive: true, force: true });
});

describe("§8 acceptance scenario (end-to-end)", () => {
  it("flags CRITICAL cross-tenant + HIGH IDOR, passes rate-limit, finds no SQLi", async () => {
    const registry = await new Orchestrator(config, probes).run();
    const bySeverity = (s: string) => registry.findings.filter((f) => f.severity === s);
    const byFamily = (f: string) => registry.findings.filter((x) => x.family === f);

    // Headline — the two isolation findings the fixture-provisioning fix restored.
    const critical = bySeverity("CRITICAL");
    expect(critical).toHaveLength(1);
    expect(critical[0]).toMatchObject({ family: "tenant-isolation", confidence: "CONFIRMED" });

    const high = bySeverity("HIGH");
    expect(high).toHaveLength(1);
    expect(high[0]).toMatchObject({ family: "idor" });

    // No SQLi on the reference target.
    expect(byFamily("injection")).toHaveLength(0);

    // Rate-limit probe PASSES (throttle engaged) → a pass, not a finding.
    expect(byFamily("rate-limit")).toHaveLength(0);
    expect(registry.passes.some((p) => p.family === "rate-limit")).toBe(true);

    // This target intentionally has no GraphQL query or CSV export contract.
    expect(registry.skipped).toEqual([{
      probeId: "graphql/authorization", reason: 'no endpoint provides capability "graphqlQuery"',
    }, {
      probeId: "csv/formula", reason: 'no endpoint provides capability "csvExport"',
    }, {
      probeId: "mass-assignment/protected-field", reason: 'no endpoint provides capability "massAssignment"',
    }, {
      probeId: "grpc/authorization", reason: 'no endpoint provides capability "grpcUnary"',
    }, {
      probeId: "ssrf/webhook-destination", reason: 'no endpoint provides capability "webhookCallback"',
    }]);
  });
});
