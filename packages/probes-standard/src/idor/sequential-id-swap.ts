import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/**
 * idor/sequential-id-swap (spec §3.3, IDOR family).
 *
 * Core question: are object references authorization-checked, or just
 * unguessable? Strategy: under a lower-privileged but authenticated identity,
 * swap a known-own id for a known-other id and distinguish a 404-by-design from
 * a 200-leak. A finding is: a reference owned by another principal returned data.
 */
export const sequentialIdSwap: Probe = {
  manifest: {
    id: "idor/sequential-id-swap",
    family: "idor",
    version: "0.1.1",
    schemaVersion: "1",
    requires: { identities: ["tenantA.user"], endpoints: ["hasObjectRef", "authRequired"] },
    safety: { class: "read-only", maxRequests: 30, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    const targets = ctx.target.endpoints.filter((e) => !e.graphql && e.objectRef && e.method === "GET");
    if (targets.length === 0) return skip("no endpoint with an objectRef to enumerate");
    return {
      probeId: this.manifest.id,
      steps: targets.map((e) => ({
        id: `swap:${e.id}`,
        description: `swap own→other id on ${e.path}`,
        endpointId: e.id,
        estimatedRequests: 2,
      })),
    };
  },

  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.objectRef) continue;

      // Own object (scratch fixture owned by tenantA) vs. another principal's
      // (owned by tenantB) — both provisioned by the engine at setup (§4.3).
      const ownObject = ctx.fixtures.owned(endpoint.objectRef.kind, "tenantA.user");
      const otherObject = ctx.fixtures.owned(endpoint.objectRef.kind, "tenantB.user");
      if (!ownObject || !otherObject) {
        ctx.logger.warn("missing scratch fixtures; cannot probe endpoint for IDOR", {
          endpoint: endpoint.id,
          kind: endpoint.objectRef.kind,
        });
        continue;
      }
      const ownPath = endpoint.path.replace(`{${endpoint.objectRef.param}}`, ownObject.id);
      const otherPath = endpoint.path.replace(`{${endpoint.objectRef.param}}`, otherObject.id);

      const own = await ctx.http.get(ownPath, { as: "tenantA.user" });
      const other = await ctx.http.get(otherPath, { as: "tenantA.user" });

      // Leak: the not-owned reference returned success just like the owned one.
      const leak = own.status >= 200 && own.status < 300 && other.status === own.status;
      if (!leak) continue;

      ctx.report(
        buildFinding({
          probeId: this.manifest.id,
          family: "idor",
          title: `IDOR: another principal's ${endpoint.objectRef.kind} was readable`,
          severity: "HIGH",
          confidence: "FIRM",
          cwe: ["CWE-639"],
          owaspApi: ["API1:2023 BOLA"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path, objectRef: endpoint.objectRef },
          affectedIdentities: ["tenantA.user"],
          locator: `${endpoint.objectRef.param}-swap`,
          evidence: {
            summary: `Swapping a known-own id for a not-owned id still returned ${other.status}.`,
            exchanges: [own.exchange, other.exchange],
            differential: { baseline: own.exchange.ref, probe: other.exchange.ref, diff: `own id → 2xx\nother id → 2xx (should be 403/404)` },
            reproduction: {
              seed: "see scan config",
              steps: [`GET ${endpoint.path} with your own id (2xx).`, `GET the same endpoint with another principal's id.`, `Observe a 2xx instead of 403/404.`],
            },
            auditRefs: [other.exchange.ref],
          },
          remediation: {
            guidance: "Enforce object-level authorization keyed on the authenticated principal for every object reference — do not rely on ids being unguessable.",
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
            codeHints: ["Add an ownership check: the object's owner must equal the authenticated principal/tenant."],
            effort: "moderate",
          },
        }),
      );
    }
  },
};
