import { scratchPath, skip, type Endpoint, type GuardedResponse, type Probe } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

export const massAssignment: Probe = {
  manifest: {
    id: "mass-assignment/protected-field", family: "mass-assignment", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["massAssignment"] },
    safety: { class: "idempotent-write", maxRequests: 50, destructive: false },
  },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.massAssignment && !e.graphql);
    if (!endpoints.length) return skip("no reviewed scratch mass-assignment contract");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `mass:${e.id}`, endpointId: e.id,
      description: `Verify writable control and protected-field persistence on scratch ${e.id}`, estimatedRequests: 5 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      // Five comparisons plus headroom for this object's engine-owned cleanup.
      if (ctx.signal.aborted || ctx.budget.remaining < 6) {
        ctx.logger.warn("Mass-assignment checks incomplete: insufficient budget or cancellation"); return;
      }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.massAssignment || !endpoint.objectRef) continue;
      const model = endpoint.massAssignment;
      const fixture = ctx.fixtures.owned(endpoint.objectRef.kind, model.identity);
      const reader = ctx.target.endpoints.find((e) => e.id === model.readEndpointId);
      const writeUrl = fixture && scratchPath(endpoint, fixture.id);
      const readUrl = fixture && reader && scratchPath(reader, fixture.id);
      if (!fixture || !writeUrl || !readUrl) {
        ctx.logger.warn("Mass-assignment check omitted: missing scratch fixture or bound route", { endpoint: endpoint.id }); continue;
      }
      const read = () => ctx.http.get(readUrl, { as: model.identity, maxResponseBytes: 16384,
        headers: { accept: "application/json", "cache-control": "no-cache, no-store" } });
      const write = (fields: Record<string, string | number | boolean>) => ctx.http.request({
        method: "PATCH", url: writeUrl, as: model.identity, targetsScratchObjectId: fixture.id,
        headers: { "content-type": "application/json" }, body: JSON.stringify(fields), maxResponseBytes: 16384,
      });
      const before = await read();
      const initial = await observed(before, model, fixture.id);
      if (!initial || initial.control === model.control.value || initial.protected === model.protected.value) {
        ctx.logger.warn("Mass-assignment check inconclusive: missing or non-distinguishing initial control", { endpoint: endpoint.id }); continue;
      }
      const control = await write({ [model.control.field]: model.control.value });
      const controlRead = await read();
      const baseline = await observed(controlRead, model, fixture.id);
      if (![200, 204].includes(control.status) || !baseline || baseline.control !== model.control.value || baseline.protected !== initial.protected) {
        ctx.logger.warn("Mass-assignment check inconclusive: ordinary writable-field control failed", { endpoint: endpoint.id }); continue;
      }
      const attempt = await write({ [model.control.field]: model.control.value, [model.protected.field]: model.protected.value });
      const verification = await read();
      const after = await observed(verification, model, fixture.id);
      if (!after || after.control !== model.control.value) {
        ctx.logger.warn("Mass-assignment check inconclusive: verification control failed", { endpoint: endpoint.id }); continue;
      }
      if (after.protected === model.protected.value) {
        const exchanges = [before, control, controlRead, attempt, verification].map((r) => r.exchange);
        ctx.report(buildFinding({
          probeId: this.manifest.id, family: "mass-assignment", title: `Protected field persisted through ordinary PATCH on ${endpoint.id}`,
          severity: "HIGH", confidence: "FIRM", cwe: ["CWE-915"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path, tenantScoped: endpoint.tenantScoped,
            objectRef: endpoint.objectRef }, affectedIdentities: [model.identity], locator: model.protected.field,
          evidence: { summary: `After a successful writable-field control, a separate GET of the same scratch ID confirmed the modeled protected field ${model.protected.field} changed to the submitted value. Review the declared field policy before confirming impact.`,
            exchanges, auditRefs: exchanges.map((e) => e.ref),
            differential: { baseline: controlRead.exchange.ref, probe: verification.exchange.ref,
              diff: "The protected field changed only after the over-posted PATCH; evidence is read-back persistence, not response reflection." },
            reproduction: { seed: "see scan config", steps: ["Create the modeled disposable scratch record.",
              "Read its ID and both fields; verify an ordinary writable-field PATCH persists without changing the protected field.",
              "PATCH the reviewed protected value as the same identity and verify it through a separate same-ID GET.",
              "Delete the scratch record using the modeled cleanup route."] } },
          remediation: { guidance: "Allow-list fields writable by this principal using a dedicated update DTO/schema. Authorize protected property changes separately; do not bind arbitrary request properties onto stored objects.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"], effort: "moderate" },
        }));
      } else if (after.protected === baseline.protected && [200, 204, 400, 403, 422].includes(attempt.status)) {
        ctx.report({ kind: "pass", probeId: this.manifest.id, family: "mass-assignment", endpointId: endpoint.id,
          title: `Protected field resisted the modeled PATCH on ${endpoint.id}`,
          summary: "The ordinary writable-field control succeeded; the reviewed protected value was rejected or ignored and remained unchanged on immediate read-back. This covers only the modeled synchronous update contract." });
      } else ctx.logger.warn("Mass-assignment check inconclusive: unexpected update status or protected value", { endpoint: endpoint.id });
    }
  },
};

type Scalar = string | number | boolean;
async function observed(response: GuardedResponse, model: NonNullable<Endpoint["massAssignment"]>, id: string): Promise<{ control: Scalar; protected: Scalar } | undefined> {
  try {
    const text = await response.text();
    if (response.status !== 200 || text !== response.exchange.response.body ||
        Number(response.headers.age ?? 0) > 0 || !/^application\/json(?:\s*;|$)/i.test(response.headers["content-type"] ?? "")) return undefined;
    const body: unknown = JSON.parse(text);
    const pick = (path: string[]): unknown => path.reduce<unknown>((value, key) => value !== null && typeof value === "object" && Object.hasOwn(value, key)
      ? (value as Record<string, unknown>)[key] : undefined, body);
    const objectId = pick(model.resultIdPath);
    const control = pick(model.control.resultPath);
    const protectedValue = pick(model.protected.resultPath);
    const scalar = (value: unknown): value is Scalar => typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value)) || (typeof value === "string" && !value.includes("«redacted»"));
    if (!scalar(objectId) || typeof objectId === "boolean" || String(objectId) !== id || !scalar(control) || !scalar(protectedValue)) return undefined;
    return { control, protected: protectedValue };
  } catch { return undefined; }
}
