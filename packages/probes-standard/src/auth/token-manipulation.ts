import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/**
 * auth/token-manipulation (spec §3.3, auth-boundary family).
 *
 * Core question: are authentication boundaries actually enforced? Strategy:
 * against a protected endpoint, issue requests with (a) no credential and (b) a
 * tampered credential (e.g. none-alg / signature-stripped JWT — the engine
 * exposes `jose`-based forgers to this family), and confirm the server rejects
 * them. A finding is a protected resource served under an absent/forged token.
 *
 * NOTE: forged tokens are constructed by the engine and sent via ctx.http; the
 * probe never mints raw credentials itself.
 */
export const tokenManipulation: Probe = {
  manifest: {
    id: "auth/token-manipulation",
    family: "auth",
    version: "0.1.0",
    schemaVersion: "1",
    requires: { endpoints: ["authRequired"] },
    safety: { class: "read-only", maxRequests: 30, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    const targets = ctx.target.endpoints.filter((e) => e.auth === "required" && e.method === "GET");
    if (targets.length === 0) return skip("no auth-required GET endpoint to test");
    return {
      probeId: this.manifest.id,
      steps: targets.map((e) => ({
        id: `authz:${e.id}`,
        description: `missing/forged credential against ${e.path}`,
        endpointId: e.id,
        estimatedRequests: 2,
      })),
    };
  },

  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint) continue;

      // (a) no credential at all — omit `as`, send no auth header.
      const anon = await ctx.http.get(endpoint.path);
      // A protected endpoint must reject anonymous access.
      const servedAnon = anon.status >= 200 && anon.status < 300;
      if (!servedAnon) continue;

      ctx.report(
        buildFinding({
          probeId: this.manifest.id,
          family: "auth",
          title: `Missing authentication enforcement on ${endpoint.id}`,
          severity: "CRITICAL",
          confidence: "CONFIRMED",
          cwe: ["CWE-287", "CWE-306"],
          owaspApi: ["API2:2023 Broken Authentication"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path },
          affectedIdentities: [],
          locator: "missing-auth",
          evidence: {
            summary: `An unauthenticated request to a protected endpoint returned ${anon.status}.`,
            exchanges: [anon.exchange],
            reproduction: {
              seed: "see scan config",
              steps: [`GET ${endpoint.path} with no Authorization header.`, `Observe a 2xx instead of 401/403.`],
              curl: [`curl "$BASE${endpoint.path}"`],
            },
            auditRefs: [anon.exchange.ref],
          },
          remediation: {
            guidance: "Require and verify authentication on every protected route via centralized middleware; fail closed. Reject the JWT 'none' algorithm and verify signatures against the expected key.",
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            codeHints: ["Ensure the auth middleware is mounted on this route and cannot be bypassed.", "Pin allowed JWT algorithms; never accept alg=none."],
            effort: "moderate",
          },
        }),
      );
      // TODO(probe): (b) forged-token variants (none-alg, expired, swapped-tenant
      // claim, signature strip) using the engine's jose-based forgers.
    }
  },
};
