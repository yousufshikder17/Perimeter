import { describe, it, expect } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";

/**
 * The engine refuses to run without an explicit authorization assertion (spec
 * §5.5, §8.9). The Zod schema is the first gate: `iAmAuthorizedToTest` is a
 * literal `true`, so any other value fails validation before a scan can start.
 */
const base = {
  name: "t",
  baseUrl: "http://localhost:8080",
  auth: { scheme: "bearer" },
  identities: [{ ref: "tenantA.user", tenant: "tenant-a", role: "member" }],
  tenancy: { model: "shared_db_rls", discriminator: { location: "jwt_claim", name: "tenant_id" }, tenants: ["tenant-a"] },
  endpoints: [],
};

describe("mandatory authorization block (spec §5.5)", () => {
  it("rejects a model missing the authorization block", () => {
    expect(() => parseTargetModel(base)).toThrow();
  });

  it("rejects iAmAuthorizedToTest: false", () => {
    expect(() =>
      parseTargetModel({
        ...base,
        authorization: { iAmAuthorizedToTest: false, environment: "staging", contact: "x@y.z", rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 } },
      }),
    ).toThrow();
  });

  it("accepts a properly-authorized staging model", () => {
    const model = parseTargetModel({
      ...base,
      authorization: { iAmAuthorizedToTest: true, environment: "staging", contact: "x@y.z", rateLimit: { globalRps: 5, perHostRps: 5, burst: 10 } },
    });
    expect(model.authorization.environment).toBe("staging");
  });
});
