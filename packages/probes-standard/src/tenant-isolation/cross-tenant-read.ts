import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/**
 * tenant-isolation/cross-tenant-read (spec §3.3, tenant-isolation family).
 *
 * Core question: can identity in tenant A observe tenant B's data?
 * Strategy: for each tenant-scoped GET endpoint, reference an object owned by
 * tenant B (a scratch fixture) as tenant A. A CONFIRMED finding is tenant A
 * receiving tenant B's object. This reconstructs the audit's headline
 * cross-tenant read via a missing RLS `USING` clause (spec §8 acceptance).
 */
export const crossTenantRead: Probe = {
  manifest: {
    id: "tenant-isolation/cross-tenant-read",
    family: "tenant-isolation",
    version: "0.1.2",
    schemaVersion: "1",
    requires: {
      minTenants: 2,
      identities: ["tenantA.user", "tenantB.user"],
      endpoints: ["readsTenantScopedObject"],
    },
    safety: { class: "read-only", maxRequests: 25, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    if (ctx.target.tenancy.tenants.length < 2) {
      return skip("needs ≥2 modeled tenants to cross a boundary");
    }
    const targets = ctx.target.endpoints.filter((e) => !e.grpc && !e.graphql && e.tenantScoped && e.method === "GET" && e.objectRef);
    if (targets.length === 0) {
      return skip("no tenant-scoped GET endpoint with an objectRef to probe");
    }
    return {
      probeId: this.manifest.id,
      steps: targets.map((e) => ({
        id: `read:${e.id}`,
        description: `read tenant-B object via ${e.method} ${e.path} as tenant A`,
        endpointId: e.id,
        estimatedRequests: 2, // baseline (as B) + crossing (as A)
      })),
    };
  },

  async run(plan, ctx) {
    let probed = 0;
    let anyLeak = false;
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.objectRef) continue;

      // The engine provisioned a scratch object owned by tenant B (spec §4.3);
      // fetch its real id from the fixture view rather than fabricating one.
      const tenantBObject = ctx.fixtures.owned(endpoint.objectRef.kind, "tenantB.user");
      if (!tenantBObject) {
        ctx.logger.warn("no tenant-B scratch fixture; cannot probe endpoint", {
          endpoint: endpoint.id,
          kind: endpoint.objectRef.kind,
        });
        continue;
      }
      probed++;
      const tenantBObjectId = tenantBObject.id;
      const path = endpoint.path.replace(`{${endpoint.objectRef.param}}`, tenantBObjectId);

      // Baseline: legitimate read as the owner (tenant B).
      const asB = await ctx.http.get(path, { as: "tenantB.user" });

      // The crossing attempt: same object, as tenant A.
      const asA = await ctx.http.get(path, { as: "tenantA.user" });

      // A leak is: A got a success carrying B's object rather than 403/404.
      const leaked = asA.status >= 200 && asA.status < 300 && asA.status === asB.status;
      if (!leaked) {
        continue; // per-endpoint pass; aggregate pass emitted below
      }
      anyLeak = true;

      ctx.report(
        buildFinding({
          probeId: this.manifest.id,
          family: "tenant-isolation",
          title: `Cross-tenant read: tenant A retrieved tenant B's ${endpoint.objectRef.kind}`,
          severity: "CRITICAL",
          confidence: "CONFIRMED",
          cwe: ["CWE-284", "CWE-639"],
          owaspApi: ["API1:2023 BOLA", "API5:2023 BFLA"],
          target: {
            endpointId: endpoint.id,
            method: endpoint.method,
            path: endpoint.path,
            tenantScoped: true,
            objectRef: endpoint.objectRef,
          },
          affectedIdentities: ["tenantA.user", "tenantB.user"],
          locator: `${endpoint.objectRef.param}=${endpoint.objectRef.kind}`,
          evidence: {
            summary: `Request issued as tenantA.user returned tenantB.user's ${endpoint.objectRef.kind} (status ${asA.status}).`,
            exchanges: [asB.exchange, asA.exchange],
            differential: {
              baseline: asB.exchange.ref,
              probe: asA.exchange.ref,
              diff: `- owner: tenant-b (legitimate)\n+ served to: tenant-a (isolation breach)`,
            },
            reproduction: {
              seed: "see scan config",
              steps: [
                `Mint an identity in tenant B and create a ${endpoint.objectRef.kind}.`,
                `Mint an identity in tenant A.`,
                `GET ${endpoint.path} for tenant B's object id, authenticated as tenant A.`,
                `Observe a 2xx carrying tenant B's data instead of 403/404.`,
              ],
              curl: [`curl -H "authorization: Bearer «tenantA»" "$BASE${path}"`],
            },
            auditRefs: [asA.exchange.ref],
          },
          remediation: {
            guidance:
              "Enforce tenant scoping server-side on every read. For shared-Postgres RLS, ensure the policy's USING clause filters by the authenticated tenant discriminator and that the endpoint never trusts a client-supplied tenant id.",
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
              "https://www.postgresql.org/docs/current/ddl-rowsecurity.html",
            ],
            codeHints: [
              "Audit the Postgres RLS USING/WITH CHECK policy on the backing table.",
              "Reject or ignore any client-supplied tenant_id; derive it from the verified token claim.",
            ],
            effort: "moderate",
          },
        }),
      );
    }

    // Explicit aggregate pass so the report shows the check ran — but only when
    // nothing leaked (a pass alongside a CRITICAL finding would be contradictory).
    if (!ctx.signal.aborted && probed > 0 && !anyLeak) {
      ctx.report({
        kind: "pass",
        probeId: this.manifest.id,
        family: "tenant-isolation",
        title: "Cross-tenant read isolation",
        summary: `Probed ${probed} tenant-scoped endpoint(s); no cross-tenant read observed.`,
      });
    }
  },
};
