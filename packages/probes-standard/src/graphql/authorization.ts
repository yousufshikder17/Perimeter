import { graphqlRequest, skip, type Probe, type GuardedResponse } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

/** Compare protected scalar evidence, never infer GraphQL success from HTTP 200. */
export const graphqlAuthorization: Probe = {
  manifest: {
    id: "graphql/authorization", family: "graphql", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["graphqlQuery"] },
    safety: { class: "read-only", maxRequests: 60, destructive: false },
  },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.graphql && e.auth === "required");
    if (!endpoints.length) return skip("no reviewed protected GraphQL query");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `graphql:${e.id}`, endpointId: e.id,
      description: `compare protected GraphQL data for owner, anonymous, and other identity on ${e.id}`, estimatedRequests: 3 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 3) {
        ctx.logger.warn("GraphQL checks incomplete: cancelled or insufficient budget for controls");
        return;
      }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.graphql) continue;
      const model = endpoint.graphql;
      const variables = { ...model.variables };
      const fixture = endpoint.objectRef ? ctx.fixtures.owned(endpoint.objectRef.kind, model.ownerIdentity) : undefined;
      if (endpoint.objectRef) {
        if (!fixture) { ctx.logger.warn("GraphQL check omitted: missing owner scratch fixture", { endpoint: endpoint.id }); continue; }
        variables[endpoint.objectRef.param] = fixture.id;
      }
      const request = graphqlRequest(endpoint, variables);
      const owner = await ctx.http.request({ ...request, as: model.ownerIdentity });
      const baseline = observed(owner, model.resultPath);
      if (owner.status < 200 || owner.status >= 300 || baseline.errors || baseline.marker === undefined ||
          (fixture && String(baseline.marker) !== fixture.id)) {
        ctx.logger.warn("GraphQL check inconclusive: owner control lacks the expected protected scalar evidence", { endpoint: endpoint.id });
        continue;
      }
      for (const [mode, as] of [["anonymous", undefined], ["other-identity", model.otherIdentity]] as const) {
        if (ctx.signal.aborted || !ctx.budget.available()) return;
        const response = await ctx.http.request({ ...request, ...(as ? { as } : {}) });
        const result = observed(response, model.resultPath);
        const exposed = result.marker === baseline.marker;
        if (exposed) {
          ctx.report(buildFinding({
            probeId: this.manifest.id, family: "graphql", title: `Protected GraphQL data served to ${mode} on ${endpoint.id}`,
            severity: "HIGH", confidence: "FIRM", cwe: [mode === "anonymous" ? "CWE-306" : "CWE-639"],
            target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path, tenantScoped: endpoint.tenantScoped,
              ...(endpoint.objectRef ? { objectRef: endpoint.objectRef } : {}) },
            affectedIdentities: as ? [model.ownerIdentity, as] : [model.ownerIdentity],
            locator: `${mode}:${JSON.stringify(model.resultPath)}`,
            evidence: {
              summary: `The owner control and ${mode} returned the same modeled protected scalar at data.${model.resultPath.join(".")}. Review field authorization semantics before confirming a breach.`,
              exchanges: [owner.exchange, response.exchange], auditRefs: [owner.exchange.ref, response.exchange.ref],
              differential: { baseline: owner.exchange.ref, probe: response.exchange.ref, diff: `Owner's protected scalar remained visible to ${mode}, including any partial GraphQL response.` },
              reproduction: { seed: "see scan config", steps: [
                "Provision the modeled owner scratch object when objectRef is configured.",
                `Execute the exact reviewed query as ${model.ownerIdentity} and confirm the protected resultPath.`,
                `Repeat ${as ? `as ${as}` : "without authentication"} with identical variables; inspect the captured data, not just HTTP status.`,
              ] },
            },
            remediation: { guidance: "Enforce object and field authorization inside GraphQL resolvers using the verified principal and tenant. Do not rely solely on authentication at the shared HTTP endpoint.",
              references: ["https://graphql.org/learn/authorization/"], effort: "moderate" },
          }));
        } else if ([401, 403, 404].includes(response.status) ||
          (response.status >= 200 && response.status < 300 && result.denied && result.marker === undefined)) {
          ctx.report({ kind: "pass", probeId: this.manifest.id, family: "graphql", endpointId: endpoint.id,
            title: `GraphQL ${mode} denied on ${endpoint.id}`, summary: "The owner control succeeded and the comparison explicitly rejected access to the selected protected value." });
        } else {
          ctx.logger.warn("GraphQL comparison inconclusive: no matching protected value or explicit denial", { endpoint: endpoint.id, mode });
        }
      }
    }
  },
};

function observed(response: GuardedResponse, path: string[]): { marker?: string | number; errors: boolean; denied: boolean } {
  try {
    // The captured evidence itself must contain the proof; truncated, redacted,
    // or non-JSON captures are inconclusive, even if the full response had data.
    const body: unknown = JSON.parse(response.exchange.response.body ?? "");
    if (!record(body) || (body.errors !== undefined && !Array.isArray(body.errors))) throw new Error();
    const errors = body.errors as unknown[] | undefined;
    let value: unknown = body.data;
    for (const key of path) value = value !== null && typeof value === "object" && Object.hasOwn(value, key)
      ? (value as Record<string, unknown>)[key] : undefined;
    const marker = (typeof value === "string" && value.trim() && !value.includes("«redacted»")) ||
      (typeof value === "number" && Number.isFinite(value)) ? value as string | number : undefined;
    const denied = errors?.some((error) => record(error) && record(error.extensions) &&
      ["FORBIDDEN", "UNAUTHENTICATED"].includes(String(error.extensions.code))) ?? false;
    return { ...(marker !== undefined ? { marker } : {}), errors: !!errors?.length, denied };
  } catch { return { errors: true, denied: false }; }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
