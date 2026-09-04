import { describe, expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures } from "@perimeter/core";
import { burstThrottle } from "./burst-throttle.js";

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
  endpoints: [{ id: "login", method: "POST", path: "/auth/login", rateSensitive: true }],
  authorization: {
    iAmAuthorizedToTest: true,
    environment: "staging",
    contact: "secops@example.com",
    rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 },
  },
});

describe("rate-limit/burst-throttle", () => {
  it("stops on a throttle and flags a target that accepts the bounded burst", async () => {
    const run = (status: number, headers: Record<string, string> = {}) =>
      runProbeAgainstFixtures(burstThrottle, {
        target,
        fixtures: [
          {
            match: { method: "HEAD", urlIncludes: "/auth/login", as: "tenantA.user" },
            respond: { status, headers },
          },
        ],
      });

    const patched = await run(429, { "retry-after": "60" });
    const vulnerable = await run(200);

    expect(patched.requests).toHaveLength(1);
    expect(patched.reports[0]).toMatchObject({ kind: "pass" });
    expect(vulnerable.requests).toHaveLength(15);
    expect(vulnerable.reports[0]).toMatchObject({ severity: "MEDIUM", confidence: "FIRM" });
  });
});
