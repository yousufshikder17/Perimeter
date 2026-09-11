import { type Probe, type ProbePlan, type ProbeContext, type Endpoint, type GuardedResponse, skip } from "@perimeter/sdk";
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
    version: "0.2.2",
    schemaVersion: "1",
    requires: { endpoints: ["authRequired"] },
    safety: { class: "read-only", maxRequests: 30, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    const targets = ctx.target.endpoints.filter((e) => !e.grpc && !e.graphql && e.auth === "required" && e.method === "GET");
    if (targets.length === 0) return skip("no auth-required GET endpoint to test");
    return {
      probeId: this.manifest.id,
      steps: targets.map((e) => ({
        id: `authz:${e.id}`,
        description: `missing/forged credential against ${e.path}`,
        endpointId: e.id,
        estimatedRequests: 6,
      })),
    };
  },

  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint) continue;
      // Reuse provisioned objects; auth-only scans never guess IDs or create fixtures.
      const owner = endpoint.objectRef
        ? ctx.fixtures.ofKind(endpoint.objectRef.kind)[0]?.ownerIdentity : undefined;
      const ref = owner ?? ctx.target.identities[0]!.ref;
      const fixture = endpoint.objectRef ? ctx.fixtures.owned(endpoint.objectRef.kind, ref) : undefined;
      const path = fixture && endpoint.objectRef
        ? endpoint.path.replace(`{${endpoint.objectRef.param}}`, encodeURIComponent(fixture.id)) : endpoint.path;
      if (/\{[^}]+\}/.test(path)) {
        ctx.logger.warn("auth checks omitted: unresolved path parameters", { endpoint: endpoint.id });
        continue;
      }

      // (a) no credential at all — omit `as`, send no auth header.
      const anon = await ctx.http.get(path);
      // A protected endpoint must reject anonymous access.
      const servedAnon = anon.status >= 200 && anon.status < 300;
      if (!servedAnon) {
        if (anon.status === 401 || anon.status === 403) {
          await checkJwtVariants(ctx, endpoint, path, ref, anon, this.manifest.id);
        } else {
          ctx.logger.warn("auth checks inconclusive: anonymous control did not return 401/403", { endpoint: endpoint.id, status: anon.status });
        }
        continue;
      }

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
    }
  },
};

async function checkJwtVariants(
  ctx: ProbeContext, endpoint: Endpoint, path: string, ref: string,
  anon: GuardedResponse, probeId: string,
): Promise<void> {
  if (ctx.signal.aborted || !ctx.budget.available()) return;
  const variants = await ctx.identity(ref).jwtVariants?.() ?? [];
  if (!variants.length) {
    ctx.logger.warn("JWT checks omitted: identity has no supported single Bearer JWT", { endpoint: endpoint.id, identity: ref });
    return;
  }
  if (!variants.includes("expired")) ctx.logger.warn("Expired-token check omitted: configure expiredCredentials.env", { identity: ref });
  if (!variants.includes("tenant-swapped")) ctx.logger.warn("Tenant-claim check omitted: requires a matching JWT claim and a second modeled tenant", { identity: ref });
  if (ctx.signal.aborted || !ctx.budget.available()) return;
  const baseline = await ctx.http.get(path, { as: ref });
  if (baseline.status < 200 || baseline.status >= 300) {
    ctx.logger.warn("JWT checks inconclusive: live credential did not return success", { endpoint: endpoint.id, status: baseline.status });
    return;
  }
  for (const jwtVariant of variants) {
    if (ctx.signal.aborted || !ctx.budget.available()) {
      ctx.logger.warn("JWT checks incomplete: cancelled or request budget exhausted", { endpoint: endpoint.id });
      return;
    }
    const response = await ctx.http.get(path, { as: ref, jwtVariant });
    if (response.status < 200 || response.status >= 300) {
      if (response.status !== 401 && response.status !== 403) ctx.logger.warn("JWT rejection inconclusive", { endpoint: endpoint.id, jwtVariant, status: response.status });
      continue;
    }
    ctx.report(buildFinding({
      probeId, family: "auth", title: `Possible ${jwtVariant} JWT acceptance on ${endpoint.id}`,
      severity: "HIGH", confidence: "FIRM", cwe: [jwtVariant === "expired" ? "CWE-613" : "CWE-347"],
      owaspApi: ["API2:2023 Broken Authentication"],
      target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path },
      affectedIdentities: [ref], locator: `jwt-${jwtVariant}`,
      evidence: {
        summary: `Anonymous access returned ${anon.status}; a live credential and the ${jwtVariant} test credential returned success. Review response semantics before confirming a bypass.`,
        exchanges: [anon.exchange, baseline.exchange, response.exchange],
        differential: { baseline: baseline.exchange.ref, probe: response.exchange.ref, diff: `${jwtVariant} credential returned ${response.status}; expected 401/403` },
        reproduction: { seed: "see scan config", steps: [
          `GET ${path} without credentials and confirm 401/403.`,
          `GET the same path as configured identity ${ref} and confirm successful access.`,
          `Repeat with the engine's ${jwtVariant} test credential; inspect whether the response actually serves protected data.`,
          ...(jwtVariant === "expired" ? ["Verify the supplied sample has a valid target-issued signature and is expired beyond the target's allowed clock skew."] : []),
          ...(jwtVariant === "tenant-swapped" ? ["The tenant claim was changed without re-signing; this does not by itself prove cross-tenant data disclosure."] : []),
        ] },
        auditRefs: [anon.exchange.ref, baseline.exchange.ref, response.exchange.ref],
      },
      remediation: {
        guidance: "Validate the signature, explicitly allowed algorithm, issuer, audience, and token lifetime before trusting JWT claims. Fail closed on invalid credentials.",
        references: ["https://www.rfc-editor.org/rfc/rfc8725.html"], effort: "moderate",
      },
    }));
  }
}
