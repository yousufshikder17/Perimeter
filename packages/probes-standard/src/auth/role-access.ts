import { skip, type GuardedResponse, type Probe } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

export const roleAccess: Probe = {
  manifest: { id: "auth/role-access", family: "auth", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["roleAccess"] },
    safety: { class: "read-only", maxRequests: 40, destructive: false } },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.roleAccess);
    if (!endpoints.length) return skip("no reviewed role-access contract");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `role:${e.id}`, endpointId: e.id,
      description: "Verify a declared role boundary after session and privileged-data controls", estimatedRequests: 4 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 4) { ctx.logger.warn("Role checks incomplete: budget or cancellation"); return; }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.roleAccess) continue;
      const model = endpoint.roleAccess;
      const controlEndpoint = ctx.target.endpoints.find((e) => e.id === model.control.endpointId);
      if (!controlEndpoint) continue;
      const get = (path: string, as?: string) => ctx.http.get(path, { ...(as ? { as } : {}), maxResponseBytes: 16384,
        headers: { accept: "application/json", "cache-control": "no-cache, no-store" } });
      const anonymous = await get(controlEndpoint.path);
      if (![401, 403].includes(anonymous.status) || (await observe(anonymous, model.control.resultPath))?.value === model.control.expectedValue) {
        ctx.logger.warn("Role check inconclusive: session control did not deny anonymous access"); continue;
      }
      const session = await get(controlEndpoint.path, model.deniedIdentity);
      if (session.status !== 200 || (await observe(session, model.control.resultPath))?.value !== model.control.expectedValue) {
        ctx.logger.warn("Role check inconclusive: restricted identity could not establish its expected session"); continue;
      }
      const privileged = await get(endpoint.path, model.allowedIdentity);
      const baseline = (await observe(privileged, model.resultPath))?.value;
      if (privileged.status !== 200 || baseline === undefined) {
        ctx.logger.warn("Role check inconclusive: privileged control lacks captured protected data"); continue;
      }
      const restricted = await get(endpoint.path, model.deniedIdentity);
      const observed = await observe(restricted, model.resultPath);
      if (observed?.value === baseline) {
        const exchanges = [anonymous, session, privileged, restricted].map((r) => r.exchange);
        ctx.report(buildFinding({ probeId: this.manifest.id, family: "auth", title: `Restricted role received privileged data on ${endpoint.id}`,
          severity: "HIGH", confidence: "FIRM", cwe: ["CWE-862"], owaspApi: ["API5:2023 Broken Function Level Authorization"],
          target: { endpointId: endpoint.id, method: "GET", path: endpoint.path },
          affectedIdentities: [model.allowedIdentity, model.deniedIdentity],
          locator: `${model.allowedIdentity}:${model.deniedIdentity}:${JSON.stringify(model.resultPath)}`,
          evidence: { summary: "A verified restricted session received the same reviewed protected scalar as the privileged identity on a function explicitly forbidden to that role. The identities belong to the same modeled tenant.",
            exchanges, auditRefs: exchanges.map((e) => e.ref),
            differential: { baseline: privileged.exchange.ref, probe: restricted.exchange.ref, diff: "The protected scalar remained visible to the policy-denied role, regardless of its HTTP status." },
            reproduction: { seed: "see scan config", steps: ["Confirm anonymous denial on the session-control endpoint.",
              "Verify the restricted identity's expected non-secret session marker.", "Read the modeled privileged GET as the allowed identity.",
              "Repeat the identical GET with the restricted identity; compare the captured protected scalar."] } },
          remediation: { guidance: "Enforce server-side role/function authorization on every protected handler using the verified principal. Deny by default; hiding admin UI or checking authentication alone is insufficient.",
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"], effort: "moderate" } }));
      } else if ([401, 403].includes(restricted.status) && observed && observed.value === undefined) {
        ctx.report({ kind: "pass", probeId: this.manifest.id, family: "auth", endpointId: endpoint.id,
          title: `Restricted role denied on ${endpoint.id}`, summary: "Session and privileged-data controls succeeded; the restricted role received 401/403 without the selected protected scalar. This covers only the declared GET and identity pair." });
      } else ctx.logger.warn("Role check inconclusive: neither matching protected data nor an unambiguous denial");
    }
  },
};

async function observe(response: GuardedResponse, path: string[]): Promise<{ value: string | number | undefined } | undefined> {
  try {
    const text = await response.text();
    if (text !== response.exchange.response.body || Number(response.headers.age ?? 0) > 0 ||
        !/^application\/json(?:\s*;|$)/i.test(response.headers["content-type"] ?? "")) return undefined;
    let value: unknown = JSON.parse(text);
    for (const key of path) value = value !== null && typeof value === "object" && Object.hasOwn(value, key)
      ? (value as Record<string, unknown>)[key] : undefined;
    return { value: typeof value === "string" && value.trim() && !value.includes("«redacted»") && !value.includes("«truncated»") ? value :
      typeof value === "number" && Number.isFinite(value) ? value : undefined };
  } catch { return undefined; }
}
