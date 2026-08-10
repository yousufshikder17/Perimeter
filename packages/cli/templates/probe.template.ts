import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";

/**
 * __ID__ — TODO: one-line description of the vulnerability behavior this probes.
 *
 * Safety contract (spec §3.2): all egress via ctx.http (never fetch), all
 * randomness via ctx.rng, all time via ctx.clock, evidence mandatory on every
 * finding, and cooperative cancellation on ctx.signal. `perimeter probe lint`
 * enforces these statically.
 */
export const __CAMEL__: Probe = {
  manifest: {
    id: "__ID__",
    family: "__FAMILY__",
    version: "0.1.0",
    schemaVersion: "1",
    requires: {
      // TODO: declare what the Target Model must satisfy for this probe to apply.
      // e.g. minTenants: 2, identities: ["tenantA.user"], endpoints: ["hasObjectRef"]
    },
    safety: { class: "read-only", maxRequests: 25, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    // MUST NOT issue network requests here. Decide applicability and return a
    // concrete plan, or skip("reason").
    // TODO: pick target endpoints from ctx.target.endpoints.
    return skip("not implemented");
  },

  async run(plan, ctx) {
    // Execute the planned steps. Emit findings/passes via ctx.report(); every
    // finding MUST carry an evidence bundle. Stop on ctx.signal / budget.
    // TODO: implement.
    void plan;
    void ctx;
  },
};

/**
 * TODO: add a fixture-backed test alongside this file (see
 * cross-tenant-read.test.ts) proving BOTH the vulnerable true-positive and the
 * patched true-negative. A probe without a passing patched fixture does not ship.
 */
