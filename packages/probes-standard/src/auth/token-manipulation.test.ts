import { describe, expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { runProbeAgainstFixtures } from "@perimeter/core";
import { tokenManipulation } from "./token-manipulation.js";

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
  endpoints: [{ id: "profile", method: "GET", path: "/api/profile", auth: "required" }],
  authorization: {
    iAmAuthorizedToTest: true,
    environment: "staging",
    contact: "secops@example.com",
    rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 },
  },
});

describe("auth/token-manipulation", () => {
  it("flags anonymous access and accepts an authentication rejection", async () => {
    const run = (status: number) =>
      runProbeAgainstFixtures(tokenManipulation, {
        target,
        fixtures: [
          {
            match: { method: "GET", urlIncludes: "/api/profile" },
            respond: {
              status,
              body: status === 200 ? '{"user":"alice"}' : '{"error":"unauthorized"}',
            },
          },
        ],
      });

    const vulnerable = await run(200);
    const patched = await run(401);

    expect(vulnerable.reports).toHaveLength(1);
    expect(vulnerable.reports[0]).toMatchObject({ severity: "CRITICAL", confidence: "CONFIRMED" });
    expect(patched.reports).toHaveLength(0);
  });
});
