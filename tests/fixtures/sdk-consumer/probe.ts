// Hand-written compatibility fixture: do not regenerate when changing the SDK.
import { SDK_VERSION, FINDING_SCHEMA_VERSION, isSkip, skip, parseManifest as rootManifest,
  parseFinding as rootFinding, parseTargetModel as rootTarget,
  type Probe, type ProbeContext, type ProbePlan, type ProbePackage, type Skip } from "@perimeter/sdk";
import { parseManifest, type ProbeManifest } from "@perimeter/sdk/manifest";
import { parseFinding, PassSchema, FindingRegistrySchema, type Finding, type Pass } from "@perimeter/sdk/finding";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk/target-model";

export function checkExports(): void {
  if (!SDK_VERSION || !FINDING_SCHEMA_VERSION || rootManifest !== parseManifest || rootFinding !== parseFinding || rootTarget !== parseTargetModel) throw new Error("SDK re-export contract changed");
  const skipped: Skip = skip("compatibility skip");
  if (!isSkip(skipped) || skipped.reason !== "compatibility skip") throw new Error("Skip contract changed");
  if (typeof FindingRegistrySchema.parse !== "function") throw new Error("Missing registry parser");
}

const manifest: ProbeManifest = parseManifest({
  id: "compat/consumer", family: "compat", version: "1.0.0", schemaVersion: "1",
  requires: {}, safety: { class: "read-only", maxRequests: 1, destructive: false },
  configSchema: { type: "object", properties: { mode: { type: "string", enum: ["pass", "finding", "skip"] } }, additionalProperties: false },
});
let plannedOptions: ProbeContext["options"];

export const probe: Probe = {
  manifest,
  async plan(ctx: ProbeContext): Promise<ProbePlan | Skip> {
    checkExports();
    const target: TargetModel = parseTargetModel(ctx.target);
    plannedOptions = ctx.options;
    if (ctx.options && !Object.isFrozen(ctx.options)) throw new Error("Options must be frozen");
    if (ctx.options?.mode === "skip") return skip("configured compatibility skip");
    const endpoint = target.endpoints.find(e => e.id === "health" && e.method === "GET" && e.auth === "none");
    if (!endpoint) return skip("compatibility fixture needs public health endpoint");
    return { probeId: manifest.id, steps: [{ id: "observe", endpointId: endpoint.id, description: "Observe local compatibility fixture", estimatedRequests: 1 }] };
  },
  async run(plan: ProbePlan, ctx: ProbeContext): Promise<void> {
    if (ctx.options !== plannedOptions || plan.probeId !== manifest.id) throw new Error("Lifecycle context changed");
    ctx.signal.throwIfAborted();
    if (!ctx.budget.available()) return;
    const endpoint = ctx.target.endpoints.find(e => e.id === plan.steps[0]?.endpointId);
    if (!endpoint) throw new Error("Missing planned endpoint");
    const response = await ctx.http.get(endpoint.path);
    if (ctx.options?.mode !== "finding") {
      const pass: Pass = PassSchema.parse({ kind: "pass", probeId: manifest.id, family: manifest.family,
        endpointId: endpoint.id, title: "SDK compatibility", summary: "Synthetic fixture observation, not a security verdict" });
      ctx.report(pass);
      return;
    }
    const finding: Finding = parseFinding({ id: "compatibility-finding", fingerprint: "compatibility-finding", schemaVersion: FINDING_SCHEMA_VERSION,
      probeId: manifest.id, family: manifest.family, title: "Synthetic SDK compatibility finding", severity: "HIGH", confidence: "FIRM",
      target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path }, affectedIdentities: [],
      evidence: { summary: "Local fixture only", exchanges: [response.exchange], auditRefs: [response.exchange.ref],
        reproduction: { seed: "compatibility", steps: ["GET /health"] } },
      remediation: { guidance: "Compatibility fixture; not a vulnerability detector", references: [] },
      firstSeen: "2026-09-17", lastSeen: "2026-09-17", status: "open" });
    ctx.report(finding);
  },
};
export const perimeter: ProbePackage["perimeter"] = { probes: [probe] };

// Negative compile contracts: widening these types accidentally must fail this build.
// @ts-expect-error A probe must expose a callable run lifecycle method.
const invalidProbe: Probe = { ...probe, run: 1 };
void invalidProbe;
// @ts-expect-error Package internals are not a supported type import path.
import type { Probe as InternalProbe } from "@perimeter/sdk/dist/probe.js";
const internalImportMustRemainUnavailable: InternalProbe | undefined = undefined;
void internalImportMustRemainUnavailable;
