import { type Probe, type ProbePlan, skip } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/**
 * injection/sqli-differential (spec §3.3, injection family — SQLi-first).
 *
 * Core question: does untrusted input reach an interpreter? Strategy:
 * non-destructive differential fuzzing — inject syntactically-meaningful but
 * semantically-inert payloads (boolean-equivalent `' AND 1=1 --` vs
 * `' AND 1=2 --`) and compare responses; also detect DB error signatures.
 * Never DROP, never stacked writes (enforced by the engine's outbound
 * inspector). Time-based probes are bounded and opt-in — omitted from this probe.
 */
const TRUE_PAYLOAD = "' AND 1=1 -- ";
const FALSE_PAYLOAD = "' AND 1=2 -- ";
const DB_ERROR_SIGNATURES = [/sql syntax/i, /unclosed quotation/i, /pg_query/i, /sqlite3\./i, /ORA-\d{5}/];

export const sqliDifferential: Probe = {
  manifest: {
    id: "injection/sqli-differential",
    family: "injection",
    version: "0.1.1",
    schemaVersion: "1",
    requires: { endpoints: ["injectableInput"] },
    safety: { class: "read-only", maxRequests: 40, destructive: false },
  },

  async plan(ctx): Promise<ProbePlan | ReturnType<typeof skip>> {
    const targets = ctx.target.endpoints.filter((e) => !e.graphql && (e.injectable?.length ?? 0) > 0);
    if (targets.length === 0) return skip("no endpoint declares injectable input fields");
    return {
      probeId: this.manifest.id,
      steps: targets.flatMap((e) =>
        (e.injectable ?? []).map((field) => ({
          id: `sqli:${e.id}:${field}`,
          description: `differential SQLi on ${e.id}.${field}`,
          endpointId: e.id,
          estimatedRequests: 3, // baseline + true + false
        })),
      ),
    };
  },

  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      const field = step.id.split(":")[2];
      if (!endpoint || !field) continue;

      const url = (val: string) => `${endpoint.path}?${field}=${encodeURIComponent(val)}`;
      // The outbound inspector rejects destructive verbs; these payloads are inert.
      const truthy = await ctx.http.get(url(TRUE_PAYLOAD), { as: "tenantA.user" });
      const falsy = await ctx.http.get(url(FALSE_PAYLOAD), { as: "tenantA.user" });
      const truthyBody = await truthy.text();
      const falsyBody = await falsy.text();

      const errorLeak = DB_ERROR_SIGNATURES.some((re) => re.test(truthyBody) || re.test(falsyBody));
      // Differential: query-structure influence shows as differing responses to
      // logically true vs. false payloads that are otherwise identical.
      const differential = truthy.status !== falsy.status || truthyBody.length !== falsyBody.length;

      if (!errorLeak && !differential) continue;

      ctx.report(
        buildFinding({
          probeId: this.manifest.id,
          family: "injection",
          title: `Possible SQL injection in ${endpoint.id}.${field}`,
          severity: errorLeak ? "HIGH" : "MEDIUM",
          confidence: errorLeak ? "FIRM" : "TENTATIVE",
          cwe: ["CWE-89"],
          owaspApi: ["API8:2023 Security Misconfiguration"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path },
          affectedIdentities: ["tenantA.user"],
          locator: `field:${field}`,
          evidence: {
            summary: errorLeak
              ? `Injected input surfaced a database error signature.`
              : `Boolean-equivalent payloads produced differing responses, indicating query-structure influence.`,
            exchanges: [truthy.exchange, falsy.exchange],
            differential: { baseline: falsy.exchange.ref, probe: truthy.exchange.ref, diff: `1=2 → ${falsy.status}/${falsyBody.length}b\n1=1 → ${truthy.status}/${truthyBody.length}b` },
            reproduction: {
              seed: "see scan config",
              steps: [`Send ${field}=${TRUE_PAYLOAD}`, `Send ${field}=${FALSE_PAYLOAD}`, `Compare responses / look for DB error signatures.`],
            },
            auditRefs: [truthy.exchange.ref, falsy.exchange.ref],
          },
          remediation: {
            guidance: "Use parameterized queries / prepared statements for all user input; never build SQL by string concatenation. Validate and reject unexpected input shapes.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
            codeHints: ["Replace string interpolation in the query with bound parameters."],
            effort: "moderate",
          },
        }),
      );
    }
  },
};
