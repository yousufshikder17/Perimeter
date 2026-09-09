import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/**
 * rate-limit/burst-throttle (spec §3.3, rate-limit family).
 *
 * Core question: are abuse-sensitive endpoints actually throttled? Strategy:
 * issue a *bounded* burst (capped by the global limiter AND a per-probe ceiling)
 * at rate-sensitive endpoints and measure whether a limit engages (429 /
 * Retry-After) before the ceiling. Tuned to detect ABSENCE of limits without
 * becoming a DoS — it STOPS the moment a throttle is observed (spec §3.3, §4.2).
 */
const BURST_CEILING = 15; // per-probe hard ceiling; also bounded by maxRequests

export const burstThrottle: Probe = {
  manifest: {
    id: "rate-limit/burst-throttle",
    family: "rate-limit",
    version: "0.1.1",
    schemaVersion: "1",
    requires: { endpoints: ["rateSensitive"] },
    safety: { class: "read-only", maxRequests: BURST_CEILING + 1, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    const targets = ctx.target.endpoints.filter((e) => !e.graphql && e.rateSensitive);
    if (targets.length === 0) return skip("no rate-sensitive endpoint modeled");
    return {
      probeId: this.manifest.id,
      steps: targets.map((e) => ({
        id: `burst:${e.id}`,
        description: `bounded burst against ${e.path}`,
        endpointId: e.id,
        estimatedRequests: BURST_CEILING,
      })),
    };
  },

  async run(plan, ctx) {
    for (const step of plan.steps) {
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint) continue;

      let throttledAt: number | null = null;
      let sent = 0;
      let lastExchange: import("@perimeter/sdk").HttpExchange | undefined;
      for (let i = 0; i < BURST_CEILING; i++) {
        if (ctx.signal.aborted || !ctx.budget.available()) break;
        // A HEAD keeps the burst as cheap as possible while still counting.
        const res = await ctx.http.request({ method: "HEAD", url: endpoint.path, as: "tenantA.user" });
        sent++;
        lastExchange = res.exchange;
        if (res.status === 429 || res.headers["retry-after"] !== undefined) {
          throttledAt = sent;
          break; // self-terminate on first observed throttle (no DoS)
        }
      }

      if (throttledAt !== null) {
        ctx.report({
          kind: "pass",
          probeId: this.manifest.id,
          family: "rate-limit",
          title: `Rate limiting on ${endpoint.id}`,
          endpointId: endpoint.id,
          summary: `Throttle engaged after ${throttledAt} request(s) (429/Retry-After). Burst stopped.`,
        });
        continue;
      }

      // Reached the safe ceiling with no throttle → absence of rate limiting.
      ctx.report(
        buildFinding({
          probeId: this.manifest.id,
          family: "rate-limit",
          title: `No rate limiting on abuse-sensitive endpoint ${endpoint.id}`,
          severity: "MEDIUM",
          confidence: "FIRM",
          cwe: ["CWE-770", "CWE-307"],
          owaspApi: ["API4:2023 Unrestricted Resource Consumption"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path },
          affectedIdentities: ["tenantA.user"],
          locator: "burst",
          evidence: {
            summary: `Accepted ${sent} rapid requests with no 429/Retry-After within the safe ceiling of ${BURST_CEILING}.`,
            exchanges: lastExchange ? [lastExchange] : [],
            reproduction: {
              seed: "see scan config",
              steps: [`Send up to ${BURST_CEILING} rapid requests to ${endpoint.path}.`, `Observe no throttling response.`],
            },
            auditRefs: lastExchange ? [lastExchange.ref] : [],
          },
          remediation: {
            guidance: "Apply per-identity and per-IP rate limiting to abuse-sensitive endpoints (login, OTP, expensive analytics). Return 429 with Retry-After when limits are exceeded.",
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
            codeHints: ["Add a token-bucket or sliding-window limiter keyed on principal and source IP."],
            effort: "moderate",
          },
        }),
      );
    }
  },
};
